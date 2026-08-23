import Foundation
import SAFACrypto
import SAFADomain

/// Persists a sudo credential that has already been verified against the
/// remote host by `SudoCredentialVerifier`. This file only performs the
/// vault/Keychain write transaction — it mirrors `PasswordResourceStore`'s
/// create/rotate/rollback shape and never itself contacts SSH.
extension ResourceService {
    public enum SudoEnrollmentMode: Sendable {
        case password(Data)
        case passwordless
    }

    /// Attaches (or replaces) `resource.sudoRef`. Replacing an existing sudo
    /// credential deletes the previous Keychain secret only after the new
    /// vault document has been durably written, matching the rotate-then-
    /// cleanup ordering used by `PasswordResourceStore.editUnlocked`.
    @discardableResult
    public func enrollSudoCredential(
        alias: ResourceAlias,
        mode: SudoEnrollmentMode,
        now: Date = Date()
    ) async throws -> Resource {
        try await mutationGate.withLock { [self] in
            try await enrollSudoCredentialUnlocked(alias: alias, mode: mode, now: now)
        }
    }

    func enrollSudoCredentialUnlocked(
        alias: ResourceAlias,
        mode: SudoEnrollmentMode,
        now: Date
    ) async throws -> Resource {
        var document = try await vault.readDocument()
        guard
            let index = document.resources.firstIndex(where: {
                $0.alias == alias && $0.state != .deleted
            })
        else {
            throw ResourceServiceError.notFound(alias: alias.rawValue)
        }
        var resource = document.resources[index]
        try SudoCredentialPolicy.ensureEligible(resource: resource)

        let previousSudoCredentialID = resource.sudoRef
        let newCredentialID = UUID()
        let newReference: CredentialReference

        switch mode {
        case let .password(secret):
            try SudoCredentialPolicy.validateSecret(secret)
            let credential = PasswordCredential(store: passwordStore)
            let locator = try await credential.create(secret: secret, id: newCredentialID)
            newReference = CredentialReference(
                id: newCredentialID,
                kind: .sudoPassword,
                storageLocator: Data(locator.account.utf8),
                securityDomains: [resource.securityDomain],
                accessClass: .userPresenceRequired,
                health: .ready,
                createdAt: now
            )
        case .passwordless:
            // No secret to store: `publicMaterial` records that this resource
            // was verified for NOPASSWD sudo so callers never mistake a nil
            // storage locator for an unenrolled credential.
            newReference = CredentialReference(
                id: newCredentialID,
                kind: .sudoPassword,
                storageLocator: Data(),
                publicMaterial: "passwordless",
                securityDomains: [resource.securityDomain],
                accessClass: .userPresenceRequired,
                health: .ready,
                createdAt: now
            )
        }

        resource.sudoRef = newCredentialID
        resource.revision += 1
        resource.updatedAt = now
        document.resources[index] = resource
        document.credentialReferences.append(newReference)
        if let previousSudoCredentialID {
            document.credentialReferences.removeAll { $0.id == previousSudoCredentialID }
        }

        do {
            try await writeResourceDocument(document)
        } catch {
            if case .password = mode {
                try? await passwordStore.deleteSecret(id: newCredentialID)
            }
            throw error
        }
        if let previousSudoCredentialID {
            try? await passwordStore.deleteSecret(id: previousSudoCredentialID)
        }
        return resource
    }

    /// Clears `resource.sudoRef` and deletes the underlying secret, if any.
    /// Idempotent-ish: removing an already-absent sudo credential is treated
    /// as success so a retried CLI invocation does not surface a confusing
    /// error.
    @discardableResult
    public func removeSudoCredential(
        alias: ResourceAlias,
        now: Date = Date()
    ) async throws -> Resource {
        try await mutationGate.withLock { [self] in
            var document = try await vault.readDocument()
            guard
                let index = document.resources.firstIndex(where: {
                    $0.alias == alias && $0.state != .deleted
                })
            else {
                throw ResourceServiceError.notFound(alias: alias.rawValue)
            }
            var resource = document.resources[index]
            guard let sudoCredentialID = resource.sudoRef else {
                return resource
            }
            resource.sudoRef = nil
            resource.revision += 1
            resource.updatedAt = now
            document.resources[index] = resource
            document.credentialReferences.removeAll { $0.id == sudoCredentialID }
            try await writeResourceDocument(document)
            try? await passwordStore.deleteSecret(id: sudoCredentialID)
            return resource
        }
    }
}

import Foundation

/// Rules governing whether a `Resource` may have a sudo credential attached and
/// whether a candidate secret is well-formed. This intentionally does not
/// introduce a bespoke "SudoCredential" domain type: a sudo credential is a
/// `CredentialReference` of kind `.sudoPassword`, referenced by
/// `Resource.sudoRef`, exactly like every other credential kind already
/// modeled in `Models.swift`. Byte-level validation mirrors
/// `SAFACrypto.PasswordCredential` (SAFADomain cannot depend on SAFACrypto),
/// since sudo secrets are ultimately stored through that same mechanism.
public enum SudoCredentialPolicyError: Error, Equatable, Sendable {
    case resourceNotActive
    case sshAccessRequired
    case primaryCredentialRequired
    case invalidSecret
}

public enum SudoCredentialPolicy {
    /// Matches `SAFACrypto.PasswordCredential.maximumBytes`. Sudo secrets are
    /// stored through the same Keychain-backed password credential mechanism.
    public static let maximumSecretBytes = 16_384

    /// A resource must be active, reachable over SSH, and already have a
    /// verified primary credential before a sudo credential can be attached
    /// or replaced. Sudo escalation is meaningless without an established
    /// login identity to escalate from.
    public static func ensureEligible(resource: Resource) throws {
        guard resource.state == .active else {
            throw SudoCredentialPolicyError.resourceNotActive
        }
        guard resource.resolvedAccessMethods.contains(.ssh) else {
            throw SudoCredentialPolicyError.sshAccessRequired
        }
        guard resource.authRef != nil else {
            throw SudoCredentialPolicyError.primaryCredentialRequired
        }
    }

    /// Rejects empty, oversized, or control-character-bearing secrets before
    /// they ever reach storage. NUL/CR/LF are rejected because the secret is
    /// later written verbatim to a child process's stdin pipe terminated by
    /// a single trailing newline; embedding one early would truncate what
    /// `sudo -S` reads or corrupt the pipe framing.
    public static func validateSecret(_ secret: Data) throws {
        guard !secret.isEmpty,
            secret.count <= maximumSecretBytes,
            !secret.contains(0),
            !secret.contains(0x0A),
            !secret.contains(0x0D)
        else {
            throw SudoCredentialPolicyError.invalidSecret
        }
    }
}

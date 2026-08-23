import Foundation
import SAFACrypto
import SAFADomain
import SAFAProtocol

enum TrustedHTTPEnrollmentError: Error, Equatable, Sendable {
    case authorizationDenied
    case unsupportedResourceType
    case invalidScheme
    case invalidHost
    case invalidPort
    case invalidPath
}

struct TrustedHTTPEnrollmentFlow: Sendable {
    private let console: any TrustedSetupConsole
    private let authorizer: any UserPresenceAuthorizing
    private let client: any TrustedLocalSetupClient

    init(
        console: any TrustedSetupConsole,
        authorizer: any UserPresenceAuthorizing,
        client: any TrustedLocalSetupClient
    ) {
        self.console = console
        self.authorizer = authorizer
        self.client = client
    }

    func enroll(
        alias: ResourceAlias,
        resourceType: ResourceTypeIdentifier
    ) async throws {
        guard resourceType == .serviceHTTP else {
            throw TrustedHTTPEnrollmentError.unsupportedResourceType
        }
        guard
            await authorizer.authorize(
                reason: "Configure protected HTTP access for SAFA resource \(alias.rawValue)"
            )
        else {
            throw TrustedHTTPEnrollmentError.authorizationDenied
        }

        let enteredScheme = try await readProtectedLine("HTTP scheme [https] (hidden): ")
        let scheme = enteredScheme.isEmpty ? "https" : enteredScheme.lowercased()
        guard scheme == "https" || scheme == "http" else {
            throw TrustedHTTPEnrollmentError.invalidScheme
        }
        let host = try await readProtectedLine("HTTP host (hidden): ")
        guard TrustedSSHEnrollmentInput.validHost(host) else {
            throw TrustedHTTPEnrollmentError.invalidHost
        }
        let defaultPort = scheme == "https" ? "443" : "80"
        let portText = try await readProtectedLine(
            "HTTP port [\(defaultPort)] (hidden): "
        )
        guard let port = UInt16(portText.isEmpty ? defaultPort : portText), port > 0 else {
            throw TrustedHTTPEnrollmentError.invalidPort
        }
        let enteredPath = try await readProtectedLine("HTTP path [/] (hidden): ")
        let path = enteredPath.isEmpty ? "/" : enteredPath
        guard path.hasPrefix("/"), path.utf8.count <= 2_048,
            path.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7F })
        else {
            throw TrustedHTTPEnrollmentError.invalidPath
        }

        var token = try await readSecret("Optional Bearer token [none] (hidden): ")
        defer { token.resetBytes(in: 0..<token.count) }
        let credential = token.isEmpty ? nil : token
        let payload = ProtectedResourceSetupPayload(
            resourceType: resourceType.rawValue,
            accessMethods: [AccessMethodIdentifier.http.rawValue],
            host: host,
            port: port,
            scheme: scheme,
            path: path,
            securityDomain: "resource.\(alias.rawValue)",
            credential: credential,
            credentialKind: credential.map { _ in CredentialKind.apiToken.rawValue },
            credentialRole: ResourceCredentialRole.readOnly.rawValue
        )
        let sessionID = try await client.begin(alias: alias)
        try await client.commit(sessionID: sessionID, payload: payload)
        try await write("SAFA HTTP resource \(alias.rawValue) was registered.\n")
    }

    private func readProtectedLine(_ prompt: String) async throws -> String {
        var value = try await readSecret(prompt)
        defer { value.resetBytes(in: 0..<value.count) }
        guard let decoded = String(data: value, encoding: .utf8) else {
            throw TrustedHTTPEnrollmentError.invalidHost
        }
        return decoded
    }

    private func readSecret(_ prompt: String) async throws -> Data {
        try await Task.detached(priority: .userInitiated) { [console] in
            try console.readSecret(prompt: prompt)
        }.value
    }

    private func write(_ text: String) async throws {
        try await Task.detached(priority: .userInitiated) { [console] in
            try console.write(text)
        }.value
    }
}

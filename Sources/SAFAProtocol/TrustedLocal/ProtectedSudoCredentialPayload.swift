import Foundation

/// Trusted-local-only payload carrying a sudo secret (or a passwordless
/// verification request) from `safa-trusted-setup` to the broker. Never
/// exposed to the Agent-facing XPC surface.
public struct ProtectedSudoCredentialPayload: Codable, Equatable, Sendable {
    public let secret: Data?
    public let passwordlessConfirmed: Bool

    public init(secret: Data) {
        self.secret = secret
        self.passwordlessConfirmed = false
    }

    public init(passwordlessConfirmed: Bool) {
        self.secret = nil
        self.passwordlessConfirmed = passwordlessConfirmed
    }
}

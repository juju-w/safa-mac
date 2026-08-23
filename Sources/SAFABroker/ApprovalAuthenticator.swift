import Foundation
import SAFACrypto

/// Broker-owned indirection over `UserPresenceAuthorizing` so `ApprovalService` depends on a
/// protocol scoped to "decide one approval" rather than on `SAFACrypto`'s general-purpose
/// type directly. Backed by the same macOS-owned Touch ID / device passcode sheet every other
/// trusted-local flow already uses (`TrustedSSHEnrollmentFlow`, `TrustedSudoEnrollmentFlow`).
/// SAFA never renders or receives the biometric or login credential itself.
public protocol ApprovalAuthenticating: Sendable {
    func authorize(reason: String) async -> Bool
}

public struct ApprovalAuthenticator: ApprovalAuthenticating {
    private let authorizer: any UserPresenceAuthorizing

    public init(
        authorizer: any UserPresenceAuthorizing = LocalAuthenticationUserPresenceAuthorizer()
    ) {
        self.authorizer = authorizer
    }

    public func authorize(reason: String) async -> Bool {
        await authorizer.authorize(reason: reason)
    }
}

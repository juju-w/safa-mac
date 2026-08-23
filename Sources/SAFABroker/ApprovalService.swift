import Foundation
import SAFADomain

public enum ApprovalServiceError: Error, Equatable, Sendable {
    case requestNotFound
    case requestNotAwaitingApproval
    case riskAssessmentMissing
    case authorizationDenied
    case invalidScope
}

/// Owns the trusted-local half of approval: rendering the immutable presentation the user
/// reviews, and — separately from whatever a client console already showed — gating the
/// actual decision behind its own OS-rendered Touch ID/passcode prompt built from
/// broker-held request/risk data. A client-side "yes" is only ever an intent to approve;
/// this is what turns that intent into an `ApprovalGrant`.
public actor ApprovalService {
    private static let exactGrantLifetime: TimeInterval = 300
    private static let scopedGrantLifetime: TimeInterval = 900

    private let requests: RequestService
    private let authenticator: any ApprovalAuthenticating

    public init(
        requests: RequestService,
        authenticator: any ApprovalAuthenticating = ApprovalAuthenticator()
    ) {
        self.requests = requests
        self.authenticator = authenticator
    }

    public func presentation(requestID: UUID) async throws -> ApprovalPresentation {
        guard let request = await requests.get(id: requestID) else {
            throw ApprovalServiceError.requestNotFound
        }
        // `approvedByUser` is observable only when a first-use sudo request has passed
        // LocalAuthentication and is waiting for its credential to be verified in the same
        // trusted-local workflow. Re-rendering the immutable presentation lets an interrupted
        // helper resume that short-lived session without asking the user to approve a different
        // command.
        guard request.state == .awaitingApproval || request.state == .approvedByUser else {
            throw ApprovalServiceError.requestNotAwaitingApproval
        }
        guard let assessment = await requests.riskAssessment(requestID: requestID) else {
            throw ApprovalServiceError.riskAssessmentMissing
        }
        guard let alias = await requests.resourceAlias(requestID: requestID) else {
            throw ApprovalServiceError.requestNotFound
        }
        return Self.presentation(for: request, resourceAlias: alias, assessment: assessment)
    }

    /// `approved == false` denies without any authentication prompt — refusing consent never
    /// needs proof of presence. `approved == true` always re-authenticates locally before a
    /// grant is issued, using a reason string this method builds itself from the stored
    /// request/risk data, not from anything the caller supplies.
    @discardableResult
    public func decide(
        requestID: UUID,
        approved: Bool,
        scope: ApprovalScope?,
        policyVersion: String,
        now: Date = Date(),
        monotonicNowNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) async throws -> ApprovalGrant? {
        guard let request = await requests.get(id: requestID) else {
            throw ApprovalServiceError.requestNotFound
        }
        guard request.state == .awaitingApproval else {
            throw ApprovalServiceError.requestNotAwaitingApproval
        }

        guard approved else {
            _ = try await requests.transition(id: requestID, to: .denied)
            return nil
        }

        guard let assessment = await requests.riskAssessment(requestID: requestID) else {
            throw ApprovalServiceError.riskAssessmentMissing
        }
        guard let alias = await requests.resourceAlias(requestID: requestID) else {
            throw ApprovalServiceError.requestNotFound
        }
        let presentation = Self.presentation(
            for: request, resourceAlias: alias, assessment: assessment)
        guard await authenticator.authorize(reason: Self.touchIDReason(for: presentation)) else {
            _ = try await requests.transition(id: requestID, to: .denied)
            throw ApprovalServiceError.authorizationDenied
        }

        let resolvedScope = scope ?? .exact(fingerprint: request.fingerprint)
        guard Self.isConsistent(resolvedScope, with: request) else {
            _ = try await requests.transition(id: requestID, to: .denied)
            throw ApprovalServiceError.invalidScope
        }

        let lifetime = Self.lifetime(for: resolvedScope)
        let grant = ApprovalGrant(
            id: UUID(),
            capabilityHash: request.fingerprint,
            scope: resolvedScope,
            callerBinding: request.caller,
            resourceID: request.resourceID,
            resourceRevision: request.resourceRevision,
            privilegeCeiling: request.privilege,
            policyVersion: policyVersion,
            maxUses: Self.maxUses(for: resolvedScope),
            issuedAt: now,
            expiresAt: now.addingTimeInterval(lifetime),
            monotonicDeadlineNanoseconds: monotonicNowNanoseconds
                + UInt64(lifetime * 1_000_000_000),
            approvalProof: ApprovalProof(method: "local_authentication", authenticatedAt: now)
        )

        _ = try await requests.transition(id: requestID, to: .approvedByUser)
        return grant
    }

    private static func presentation(
        for request: ExecutionRequest,
        resourceAlias: ResourceAlias,
        assessment: RiskAssessment
    ) -> ApprovalPresentation {
        ApprovalPresentation(
            requestID: request.id,
            resourceAlias: resourceAlias,
            privilege: request.privilege,
            commandDescription: describe(request.command),
            intent: request.intent,
            expectedEffect: request.expectedEffect,
            riskLevel: assessment.level,
            findings: assessment.findings
        )
    }

    private static func describe(_ command: CommandSpec) -> String {
        switch command.mode {
        case .exec:
            return (command.arguments ?? []).joined(separator: " ")
        case .shell:
            return command.shellProgram ?? ""
        }
    }

    private static func touchIDReason(for presentation: ApprovalPresentation) -> String {
        let privilegeLabel = presentation.privilege == .sudo ? "sudo command" : "command"
        return
            "Approve \(privilegeLabel) on \(presentation.resourceAlias.rawValue): \(presentation.commandDescription)"
    }

    private static func isConsistent(_ scope: ApprovalScope, with request: ExecutionRequest)
        -> Bool
    {
        switch scope {
        case let .exact(fingerprint):
            return fingerprint == request.fingerprint
        case let .prefix(arguments):
            guard request.privilege != .sudo,
                request.command.mode == .exec,
                request.command.stdinMode == .none,
                !request.command.tty,
                request.command.workingDirectory == nil,
                let requestArguments = request.command.arguments,
                !arguments.isEmpty,
                requestArguments.count >= arguments.count,
                Array(requestArguments.prefix(arguments.count)) == arguments
            else { return false }
            return true
        case .fullAccess:
            // Sudo full-access grants are an explicit-grant capability specified for
            // 002-sudo-execution Phase 6 (scoped/full-access sudo grants), not this phase;
            // Phase 5 only ships exact-once sudo approval.
            return request.privilege != .sudo
        }
    }

    private static func maxUses(for scope: ApprovalScope) -> UInt? {
        switch scope {
        case .exact: return 1
        case .prefix, .fullAccess: return nil
        }
    }

    private static func lifetime(for scope: ApprovalScope) -> TimeInterval {
        switch scope {
        case .exact: return exactGrantLifetime
        case .prefix, .fullAccess: return scopedGrantLifetime
        }
    }
}

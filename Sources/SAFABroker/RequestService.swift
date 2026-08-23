import Foundation
import SAFADomain

public enum RequestServiceError: Error, Equatable, Sendable {
    case notFound
    case invalidTransition
}

/// Owns the lifecycle of every `ExecutionRequest` the broker has accepted. This is
/// deliberately a thin state-machine store: it enforces `RequestState.canTransition`
/// and lets callers (`ExecutionService`, `ApprovalService`) drive transitions with the
/// domain/policy context they hold. It knows nothing about policy, grants, or transport.
public actor RequestService {
    private static let pollInterval: Duration = .milliseconds(200)

    private var requests: [UUID: ExecutionRequest] = [:]
    private var riskAssessments: [UUID: RiskAssessment] = [:]
    private var resourceAliases: [UUID: ResourceAlias] = [:]

    public init() {}

    /// `resourceAlias` is stored alongside the request (rather than looked up later from the
    /// vault by `resourceID`) so the approval presentation always shows the alias exactly as
    /// it was at submission time, even if the resource is later renamed, revised, or removed.
    public func create(_ request: ExecutionRequest, resourceAlias: ResourceAlias) {
        requests[request.id] = request
        resourceAliases[request.id] = resourceAlias
    }

    public func get(id: UUID) -> ExecutionRequest? {
        requests[id]
    }

    public func resourceAlias(requestID: UUID) -> ResourceAlias? {
        resourceAliases[requestID]
    }

    /// Stored alongside the request, keyed by request id (not `RiskAssessment.id`), so the
    /// trusted-local approval flow can reconstruct exactly what policy computed for this
    /// request without re-running `PolicyEngine` against a possibly-different `Policy` later.
    public func attachRiskAssessment(requestID: UUID, assessment: RiskAssessment) {
        riskAssessments[requestID] = assessment
    }

    public func riskAssessment(requestID: UUID) -> RiskAssessment? {
        riskAssessments[requestID]
    }

    @discardableResult
    public func transition(
        id: UUID,
        to newState: RequestState,
        mutate: (inout ExecutionRequest) -> Void = { _ in }
    ) throws -> ExecutionRequest {
        guard var request = requests[id] else { throw RequestServiceError.notFound }
        guard request.state.canTransition(to: newState) else {
            throw RequestServiceError.invalidTransition
        }
        request.state = newState
        mutate(&request)
        requests[id] = request
        return request
    }

    /// Cancels a request that has not yet reached a terminal state. Mirrors `transition`
    /// but exists as a named operation because cancellation is Agent-initiated rather than
    /// a side effect of policy/approval/execution progressing the request forward.
    @discardableResult
    public func cancel(id: UUID) throws -> ExecutionRequest {
        guard let request = requests[id] else { throw RequestServiceError.notFound }
        guard request.state.canTransition(to: .cancelled) else {
            throw RequestServiceError.invalidTransition
        }
        return try transition(id: id, to: .cancelled)
    }

    /// Blocks (via short polling, not a busy loop) until the request reaches a terminal
    /// state or `timeoutSeconds` elapses, whichever comes first. Returns whatever state
    /// the request is in at that point — a non-terminal result on timeout is expected and
    /// is not an error; the caller decides whether to poll again.
    public func wait(id: UUID, timeoutSeconds: UInt) async throws -> ExecutionRequest {
        guard var current = requests[id] else { throw RequestServiceError.notFound }
        if Self.isTerminal(current.state) { return current }
        let deadline = Date().addingTimeInterval(TimeInterval(timeoutSeconds))
        while !Self.isTerminal(current.state), Date() < deadline {
            try? await Task.sleep(for: Self.pollInterval)
            guard let refreshed = requests[id] else { throw RequestServiceError.notFound }
            current = refreshed
        }
        return current
    }

    public static func isTerminal(_ state: RequestState) -> Bool {
        switch state {
        case .denied, .completed, .failed, .timedOut, .cancelled, .expired:
            return true
        case .created, .evaluating, .approvedByPolicy, .awaitingApproval, .approvedByUser,
            .running:
            return false
        }
    }
}

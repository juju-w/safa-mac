import Foundation
import SAFADomain

public enum GrantServiceError: Error, Equatable, Sendable {
    case notFound
}

/// Owns issued `ApprovalGrant` storage: candidate lookup for `GrantMatcher`, consumption
/// bookkeeping, and revocation. Matching logic itself lives in `SAFAPolicy.GrantMatcher`;
/// this service only stores grants and mutates their state as directed by the caller.
public actor GrantService {
    private var grants: [UUID: ApprovalGrant] = [:]

    public init() {}

    public func store(_ grant: ApprovalGrant) {
        grants[grant.id] = grant
    }

    public func get(id: UUID) -> ApprovalGrant? {
        grants[id]
    }

    /// Active grants bound to the same caller and resource as the request under evaluation.
    /// Narrowing here keeps `GrantMatcher.match` calls proportional to one caller/resource's
    /// history rather than every grant the broker has ever issued.
    public func candidates(callerBinding: CallerIdentity, resourceID: UUID) -> [ApprovalGrant] {
        grants.values.filter {
            $0.state == .active && $0.callerBinding == callerBinding
                && $0.resourceID == resourceID
        }.sorted { $0.issuedAt > $1.issuedAt }
    }

    public func list(callerBinding: CallerIdentity? = nil) -> [ApprovalGrant] {
        let values = grants.values.filter { $0.state == .active }
        guard let callerBinding else { return values.sorted { $0.issuedAt > $1.issuedAt } }
        return values.filter { $0.callerBinding == callerBinding }
            .sorted { $0.issuedAt > $1.issuedAt }
    }

    @discardableResult
    public func revoke(id: UUID) throws -> ApprovalGrant {
        guard var grant = grants[id] else { throw GrantServiceError.notFound }
        grant.state = .revoked
        grants[id] = grant
        return grant
    }

    /// Records one use of `grant` and, for a single-use exact grant, marks it consumed so a
    /// later cosmetically-different or replayed request can never match it again.
    @discardableResult
    public func consume(id: UUID) throws -> ApprovalGrant {
        guard var grant = grants[id] else { throw GrantServiceError.notFound }
        grant.uses += 1
        if let maxUses = grant.maxUses, grant.uses >= maxUses {
            grant.state = .consumed
        }
        grants[id] = grant
        return grant
    }

    /// Invalidates every active grant with `privilegeCeiling: .sudo` bound to `resourceID`,
    /// for use when a resource's sudo credential is rotated or removed (`002-sudo-execution`
    /// Phase 6, T037). Exposed now because credential removal already exists; wiring the
    /// caller is future scope, not this pass.
    public func invalidateSudoGrants(resourceID: UUID) {
        for (id, grant) in grants
        where grant.resourceID == resourceID && grant.privilegeCeiling == .sudo
            && grant.state == .active
        {
            var updated = grant
            updated.state = .invalidated
            grants[id] = updated
        }
    }
}

import Foundation
import SAFADomain
import Testing

@Suite("Deterministic topology graph")
struct TopologyGraphTests {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    @Test("100 storage permutations do not change a reachability projection")
    func permutationInvariantReachability() throws {
        let fixture = try TopologyFixture(now: now)
        let expected = try TopologyQueryEngine.query(
            graph: fixture.graph(nodesReversed: false, edgesReversed: false),
            query: .reachability(from: fixture.compute.alias, to: fixture.api.alias),
            now: now
        )
        for seed in 1...100 {
            let permuted = try TopologyQueryEngine.query(
                graph: try fixture.graph(seed: UInt64(seed)),
                query: .reachability(from: fixture.compute.alias, to: fixture.api.alias),
                now: now
            )
            #expect(permuted == expected)
        }

        #expect(expected.answer.outcome == .confirmed)
        #expect(expected.answer.proofEdgeIDs == fixture.pathEdges.map(\.id))
        #expect(expected.ordering == .sourceRootedBreadthFirst)
    }

    @Test("asserted and stale edges never prove reachability")
    func unverifiedEdgesDoNotProveReachability() throws {
        let source = try node("host.source", kind: .resource, resourceKind: "host")
        let target = try node("service.target", kind: .resource, resourceKind: "service")
        let asserted = TopologyEdge(
            id: UUID(uuidString: "20000000-0000-4000-8000-000000000001")!,
            fromNodeID: source.id,
            relation: .canReach,
            toNodeID: target.id,
            layer: .desired,
            verification: .asserted,
            origin: .agent,
            visibility: .agent
        )
        let graph = try TopologyGraph(revision: 3, nodes: [source, target], edges: [asserted])

        let result = try TopologyQueryEngine.query(
            graph: graph,
            query: .reachability(from: source.alias, to: target.alias),
            now: now
        )

        #expect(result.answer.outcome == .notFound)
        #expect(result.answer.proofEdgeIDs.isEmpty)
        #expect(result.edges.first?.verification == .asserted)
    }

    @Test("reachability always returns the edge named by its proof")
    func reachabilityIncludesFreshParallelProofEdge() throws {
        let source = try node("host.source", kind: .resource, resourceKind: "host")
        let target = try node("service.target", kind: .resource, resourceKind: "service")
        let stale = try TopologyEdge.observed(
            id: UUID(uuidString: "20000000-0000-4000-8000-000000000001")!,
            fromNodeID: source.id,
            relation: .canReach,
            toNodeID: target.id,
            verification: .verified,
            origin: .adapter,
            observedAt: now.addingTimeInterval(-600),
            validUntil: now.addingTimeInterval(-300),
            visibility: .agent,
            evidenceReference: UUID()
        )
        let fresh = try observedEdge(
            id: UUID(uuidString: "20000000-0000-4000-8000-000000000002")!,
            from: source,
            to: target,
            relation: .canReach
        )
        let graph = try TopologyGraph(
            revision: 4,
            nodes: [source, target],
            edges: [stale, fresh]
        )

        let result = try TopologyQueryEngine.query(
            graph: graph,
            query: .reachability(from: source.alias, to: target.alias),
            now: now
        )

        #expect(result.answer.proofEdgeIDs == [fresh.id])
        #expect(result.edges.contains { $0.id == fresh.id })
    }

    @Test("reverse dependency traversal returns a stable affected set")
    func dependencyImpact() throws {
        let fixture = try TopologyFixture(now: now)
        let result = try TopologyQueryEngine.query(
            graph: fixture.graph(nodesReversed: true, edgesReversed: false),
            query: .dependencyImpact(of: fixture.storage.alias),
            now: now
        )

        #expect(result.answer.outcome == .found)
        #expect(result.answer.affectedAliases == [fixture.api.alias, fixture.worker.alias])
        #expect(result.ordering == .targetRootedReverseBreadthFirst)
    }

    @Test("parallel evidence edges are valid but duplicate identities are rejected")
    func parallelEdgesAndIdentityValidation() throws {
        let source = try node("host.source", kind: .resource, resourceKind: "host")
        let target = try node("service.target", kind: .resource, resourceKind: "service")
        let first = try observedEdge(
            id: UUID(uuidString: "20000000-0000-4000-8000-000000000001")!,
            from: source,
            to: target,
            relation: .canReach
        )
        let second = try observedEdge(
            id: UUID(uuidString: "20000000-0000-4000-8000-000000000002")!,
            from: source,
            to: target,
            relation: .canReach
        )

        let valid = try TopologyGraph(
            revision: 1, nodes: [source, target], edges: [first, second])
        #expect(valid.edges.count == 2)
        #expect(throws: TopologyValidationError.duplicateEdgeID(first.id)) {
            _ = try TopologyGraph(revision: 1, nodes: [source, target], edges: [first, first])
        }
    }

    @Test("dense relation comparison has a stable alias legend")
    func denseRelationMatrix() throws {
        let fixture = try TopologyFixture(now: now)
        let result = try TopologyQueryEngine.query(
            graph: fixture.graph(nodesReversed: true, edgesReversed: true),
            query: .denseComparison(relation: .dependsOn),
            now: now
        )
        let matrix = try #require(result.matrix)

        #expect(matrix.aliases == matrix.aliases.sorted { $0.rawValue < $1.rawValue })
        #expect(matrix.values.count == matrix.aliases.count)
        #expect(matrix.values.allSatisfy { $0.count == matrix.aliases.count })
        #expect(!result.truncated)
    }

    @Test("dependency cycles are exact and storage-order invariant")
    func cycleDetection() throws {
        let a = try node("service.a", kind: .resource, resourceKind: "service")
        let b = try node("service.b", kind: .resource, resourceKind: "service")
        let c = try node("service.c", kind: .resource, resourceKind: "service")
        let edges = [
            desiredEdge(from: a, to: b),
            desiredEdge(from: b, to: c),
            desiredEdge(from: c, to: a),
        ]
        let cyclic = try TopologyGraph(
            revision: 1, nodes: [c, a, b], edges: Array(edges.reversed()))
        let acyclic = try TopologyGraph(
            revision: 2, nodes: [a, b, c], edges: Array(edges.dropLast()))

        #expect(TopologyQueryEngine.hasCycle(graph: cyclic, relations: [.dependsOn], now: now))
        #expect(!TopologyQueryEngine.hasCycle(graph: acyclic, relations: [.dependsOn], now: now))
    }

    @Test("bounded reachability is explicitly indeterminate when a path may continue")
    func reachabilityTruncation() throws {
        let fixture = try TopologyFixture(now: now)
        let bounds = try TopologyQueryBounds(maximumHops: 1, maximumNodes: 64, maximumEdges: 128)
        let result = try TopologyQueryEngine.query(
            graph: fixture.graph(nodesReversed: false, edgesReversed: false),
            query: .reachability(
                from: fixture.compute.alias,
                to: fixture.api.alias,
                bounds: bounds
            ),
            now: now
        )

        #expect(result.answer.outcome == .indeterminate)
        #expect(result.answer.proofEdgeIDs.isEmpty)
        #expect(result.truncated)
    }

    @Test("decoded graphs pass the same trust validation as in-memory graphs")
    func decodeRevalidatesTrust() throws {
        let source = try node("service.source", kind: .resource, resourceKind: "service")
        let target = try node("service.target", kind: .resource, resourceKind: "service")
        let invalid = TopologyEdge(
            fromNodeID: source.id,
            relation: .canReach,
            toNodeID: target.id,
            layer: .desired,
            verification: .verified,
            origin: .agent,
            visibility: .agent
        )
        let encoder = JSONEncoder()
        let object: [String: Any] = [
            "revision": 1,
            "nodes": try JSONSerialization.jsonObject(with: encoder.encode([source, target])),
            "edges": try JSONSerialization.jsonObject(with: encoder.encode([invalid])),
        ]
        let data = try JSONSerialization.data(withJSONObject: object)

        #expect(throws: TopologyValidationError.invalidEdgeTrust(invalid.id)) {
            _ = try JSONDecoder().decode(TopologyGraph.self, from: data)
        }
    }

    @Test("context aliases are semantic labels rather than network coordinates")
    func contextAliasValidation() throws {
        let network = try TopologyNode.context(
            alias: ResourceAlias("network.office-lan"),
            visibility: .agent
        )
        #expect(network.kind == .networkSegment)

        #expect(throws: TopologyValidationError.invalidContextAlias("network.192.0.2.1")) {
            _ = try TopologyNode.context(
                alias: ResourceAlias("network.192.0.2.1"),
                visibility: .agent
            )
        }
        #expect(throws: TopologyValidationError.invalidContextAlias("service.unregistered")) {
            _ = try TopologyNode.context(
                alias: ResourceAlias("service.unregistered"),
                visibility: .agent
            )
        }
    }

    @Test("resource relationships reconcile into one stable desired topology edge")
    func resourceRelationshipsReconcileIntoTopology() throws {
        let host = try resource(
            id: "10000000-0000-4000-8000-000000000001",
            alias: "host.compute"
        )
        let service = try resource(
            id: "10000000-0000-4000-8000-000000000002",
            alias: "service.api",
            relationships: [
                ResourceRelationship(kind: .hostedOn, targetResourceID: host.id)
            ]
        )

        let reconciled = try TopologyGraph().reconciling(resources: [service, host])
        let edge = try #require(reconciled.edges.first)

        #expect(
            reconciled.nodes.map(\.alias).sorted { $0.rawValue < $1.rawValue }
                == [host.alias, service.alias])
        #expect(reconciled.edges.count == 1)
        #expect(edge.fromNodeID == service.id)
        #expect(edge.relation == .runsOn)
        #expect(edge.toNodeID == host.id)
        #expect(edge.layer == .desired)
        #expect(edge.verification == .asserted)
        #expect(try reconciled.reconciling(resources: [host, service]) == reconciled)
    }

    private func node(
        _ alias: String,
        kind: TopologyNodeKind,
        resourceKind: String? = nil
    ) throws -> TopologyNode {
        try TopologyNode(
            id: UUID(),
            alias: ResourceAlias(alias),
            kind: kind,
            resourceKind: resourceKind.map(ResourceKindIdentifier.init),
            resourceID: kind == .resource ? UUID() : nil,
            visibility: .agent
        )
    }

    private func observedEdge(
        id: UUID,
        from: TopologyNode,
        to: TopologyNode,
        relation: TopologyRelation
    ) throws -> TopologyEdge {
        try TopologyEdge.observed(
            id: id,
            fromNodeID: from.id,
            relation: relation,
            toNodeID: to.id,
            verification: .verified,
            origin: .adapter,
            observedAt: now,
            validUntil: now.addingTimeInterval(300),
            visibility: .agent,
            evidenceReference: UUID()
        )
    }

    private func resource(
        id: String,
        alias: String,
        relationships: [ResourceRelationship] = []
    ) throws -> Resource {
        Resource(
            id: UUID(uuidString: id)!,
            alias: try ResourceAlias(alias),
            resourceType: .hostLinux,
            relationships: relationships,
            endpoint: ResourceEndpoint(host: "host.invalid", port: 22),
            username: "operator",
            securityDomain: "synthetic",
            state: .active,
            createdAt: now,
            updatedAt: now
        )
    }

    private func desiredEdge(from: TopologyNode, to: TopologyNode) -> TopologyEdge {
        TopologyEdge(
            fromNodeID: from.id,
            relation: .dependsOn,
            toNodeID: to.id,
            layer: .desired,
            verification: .asserted,
            origin: .agent,
            visibility: .agent
        )
    }
}

private struct TopologyFixture {
    let now: Date
    let compute: TopologyNode
    let route: TopologyNode
    let api: TopologyNode
    let worker: TopologyNode
    let storage: TopologyNode
    let pathEdges: [TopologyEdge]
    let dependencyEdges: [TopologyEdge]

    init(now: Date) throws {
        self.now = now
        compute = try Self.resource(
            id: "10000000-0000-4000-8000-000000000001",
            alias: "host.compute-a",
            kind: "host"
        )
        route = try TopologyNode(
            id: UUID(uuidString: "10000000-0000-4000-8000-000000000002")!,
            alias: ResourceAlias("route.internal"),
            kind: .route,
            visibility: .agent
        )
        api = try Self.resource(
            id: "10000000-0000-4000-8000-000000000003",
            alias: "service.data-api",
            kind: "service"
        )
        worker = try Self.resource(
            id: "10000000-0000-4000-8000-000000000004",
            alias: "service.worker",
            kind: "service"
        )
        storage = try Self.resource(
            id: "10000000-0000-4000-8000-000000000005",
            alias: "storage.reports",
            kind: "object-storage"
        )
        pathEdges = [
            try Self.observed(
                id: "20000000-0000-4000-8000-000000000001",
                from: compute,
                relation: .routedVia,
                to: route,
                now: now
            ),
            try Self.observed(
                id: "20000000-0000-4000-8000-000000000002",
                from: route,
                relation: .canReach,
                to: api,
                now: now
            ),
        ]
        dependencyEdges = [
            TopologyEdge(
                id: UUID(uuidString: "20000000-0000-4000-8000-000000000003")!,
                fromNodeID: api.id,
                relation: .backedBy,
                toNodeID: storage.id,
                layer: .desired,
                verification: .asserted,
                origin: .user,
                visibility: .agent
            ),
            TopologyEdge(
                id: UUID(uuidString: "20000000-0000-4000-8000-000000000004")!,
                fromNodeID: worker.id,
                relation: .dependsOn,
                toNodeID: api.id,
                layer: .desired,
                verification: .asserted,
                origin: .agent,
                visibility: .agent
            ),
        ]
    }

    func graph(nodesReversed: Bool, edgesReversed: Bool) throws -> TopologyGraph {
        let nodes = [compute, route, api, worker, storage]
        let edges = pathEdges + dependencyEdges
        return try TopologyGraph(
            revision: 9,
            nodes: nodesReversed ? Array(nodes.reversed()) : nodes,
            edges: edgesReversed ? Array(edges.reversed()) : edges
        )
    }

    func graph(seed: UInt64) throws -> TopologyGraph {
        var generator = TopologySeededGenerator(state: seed)
        var nodes = [compute, route, api, worker, storage]
        var edges = pathEdges + dependencyEdges
        nodes.shuffle(using: &generator)
        edges.shuffle(using: &generator)
        return try TopologyGraph(revision: 9, nodes: nodes, edges: edges)
    }

    private static func resource(id: String, alias: String, kind: String) throws -> TopologyNode {
        let resourceID = UUID(uuidString: id)!
        return try TopologyNode(
            id: resourceID,
            alias: ResourceAlias(alias),
            kind: .resource,
            resourceKind: ResourceKindIdentifier(kind),
            resourceID: resourceID,
            visibility: .agent
        )
    }

    private static func observed(
        id: String,
        from: TopologyNode,
        relation: TopologyRelation,
        to: TopologyNode,
        now: Date
    ) throws -> TopologyEdge {
        try TopologyEdge.observed(
            id: UUID(uuidString: id)!,
            fromNodeID: from.id,
            relation: relation,
            toNodeID: to.id,
            verification: .verified,
            origin: .adapter,
            observedAt: now,
            validUntil: now.addingTimeInterval(300),
            visibility: .agent,
            evidenceReference: UUID()
        )
    }
}

private struct TopologySeededGenerator: RandomNumberGenerator {
    var state: UInt64

    mutating func next() -> UInt64 {
        state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
        return state
    }
}

import Foundation
import SAFABroker
import SAFACrypto
import SAFADomain
import SAFAProtocol
import SAFATestFixtures
import Testing

@testable import SAFABroker

@Suite("Broker-owned topology service")
struct TopologyGraphServiceTests {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    @Test("similar topology links reuse a short approval but unlink does not")
    func topologyLinkAuthorizationLease() async throws {
        let source = try resource(id: "10000000-0000-4000-8000-000000000001", alias: "host.one")
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(schemaVersion: 1, resources: [source])
        )
        let authorizer = TopologyPresenceAuthorizer(result: true)
        let service = TopologyGraphService(
            vault: vault,
            userPresenceAuthorizer: authorizer,
            cooldown: 0,
            authorizationReuseInterval: 300
        )
        let first = TopologyMutationRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            action: .link,
            source: source.alias,
            relation: .locatedIn,
            target: try ResourceAlias("site.primary")
        )
        let second = TopologyMutationRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            action: .link,
            source: source.alias,
            relation: .memberOf,
            target: try ResourceAlias("domain.production")
        )
        let unlink = TopologyMutationRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            action: .unlink,
            source: source.alias,
            relation: .memberOf,
            target: try ResourceAlias("domain.production")
        )

        #expect(await service.mutate(first, caller: caller, now: now).status == .completed)
        #expect(
            await service.mutate(
                second,
                caller: caller,
                now: now.addingTimeInterval(60)
            ).status == .completed)
        #expect(
            await service.mutate(
                unlink,
                caller: caller,
                now: now.addingTimeInterval(61)
            ).status == .completed)
        #expect(
            await authorizer.reasons == [
                "Link host.one located-in site.primary in SAFA topology",
                "Unlink host.one member-of domain.production in SAFA topology",
            ])
    }

    @Test("approved Agent link becomes only a desired asserted edge")
    func proposalCannotCreateTrust() async throws {
        let source = try resource(id: "10000000-0000-4000-8000-000000000001", alias: "service.a")
        let target = try resource(id: "10000000-0000-4000-8000-000000000002", alias: "service.b")
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(schemaVersion: 1, resources: [source, target])
        )
        let authorizer = TopologyPresenceAuthorizer(result: true)
        let service = TopologyGraphService(
            vault: vault,
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )
        let request = TopologyMutationRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            action: .link,
            source: source.alias,
            relation: .dependsOn,
            target: target.alias,
            expectedGraphRevision: 0
        )

        let reply = await service.mutate(request, caller: caller, now: now)
        let graph = try #require(await vault.readDocument().topologyGraph)
        let edge = try #require(graph.edges.first)

        #expect(reply.status == .completed)
        #expect(edge.layer == .desired)
        #expect(edge.verification == .asserted)
        #expect(edge.origin == .agent)
        #expect(edge.evidenceReference == nil)
        #expect(
            await authorizer.reasons == ["Link service.a depends-on service.b in SAFA topology"])
    }

    @Test("denied topology mutation leaves encrypted state unchanged")
    func deniedMutationFailsClosed() async throws {
        let source = try resource(id: "10000000-0000-4000-8000-000000000001", alias: "service.a")
        let target = try resource(id: "10000000-0000-4000-8000-000000000002", alias: "service.b")
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(schemaVersion: 1, resources: [source, target])
        )
        let service = TopologyGraphService(
            vault: vault,
            userPresenceAuthorizer: TopologyPresenceAuthorizer(result: false),
            cooldown: 0
        )
        let request = TopologyMutationRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            action: .link,
            source: source.alias,
            relation: .dependsOn,
            target: target.alias
        )

        let reply = await service.mutate(request, caller: caller, now: now)

        #expect(reply.status == .denied)
        #expect(await vault.readDocument().topologyGraph == nil)
    }

    @Test("query returns a simple answer with Broker proof")
    func queryReturnsBrokerProof() async throws {
        let source = try resource(id: "10000000-0000-4000-8000-000000000001", alias: "host.a")
        let target = try resource(id: "10000000-0000-4000-8000-000000000002", alias: "service.b")
        let sourceNode = try TopologyNode(resource: source, visibility: .agent)
        let targetNode = try TopologyNode(resource: target, visibility: .agent)
        let edge = try TopologyEdge.observed(
            id: UUID(uuidString: "20000000-0000-4000-8000-000000000001")!,
            fromNodeID: sourceNode.id,
            relation: .canReach,
            toNodeID: targetNode.id,
            verification: .verified,
            origin: .adapter,
            observedAt: now,
            validUntil: now.addingTimeInterval(300),
            visibility: .agent,
            evidenceReference: UUID()
        )
        let graph = try TopologyGraph(revision: 4, nodes: [sourceNode, targetNode], edges: [edge])
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [source, target],
                topologyGraph: graph
            )
        )
        let service = TopologyGraphService(
            vault: vault,
            userPresenceAuthorizer: TopologyPresenceAuthorizer(result: false),
            cooldown: 0
        )
        let request = TopologyQueryRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            task: .reachability,
            source: source.alias,
            target: target.alias
        )

        let reply = await service.query(request, caller: caller, now: now)

        #expect(reply.status == .completed)
        #expect(reply.projection?.answer.outcome == .confirmed)
        #expect(reply.projection?.answer.proofEdgeIDs == [edge.id.uuidString.lowercased()])
    }

    @Test("placement links that introduce a cycle are rejected")
    func placementCycleRejected() async throws {
        let source = try resource(id: "10000000-0000-4000-8000-000000000001", alias: "service.a")
        let target = try resource(id: "10000000-0000-4000-8000-000000000002", alias: "service.b")
        let sourceNode = try TopologyNode(resource: source, visibility: .agent)
        let targetNode = try TopologyNode(resource: target, visibility: .agent)
        let existing = TopologyEdge(
            fromNodeID: targetNode.id,
            relation: .runsOn,
            toNodeID: sourceNode.id,
            layer: .desired,
            verification: .asserted,
            origin: .user,
            visibility: .agent
        )
        let graph = try TopologyGraph(
            revision: 3,
            nodes: [sourceNode, targetNode],
            edges: [existing]
        )
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [source, target],
                topologyGraph: graph
            )
        )
        let service = TopologyGraphService(
            vault: vault,
            userPresenceAuthorizer: TopologyPresenceAuthorizer(result: true),
            cooldown: 0
        )
        let request = TopologyMutationRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            action: .link,
            source: source.alias,
            relation: .runsOn,
            target: target.alias,
            expectedGraphRevision: 3
        )

        let reply = await service.mutate(request, caller: caller, now: now)

        #expect(reply.status == .failed)
        #expect(reply.error?.code == "topology_cycle_rejected")
        #expect(await vault.readDocument().topologyGraph == graph)
    }

    @Test("approved links create only constrained semantic context nodes")
    func createsSemanticContextNode() async throws {
        let resource = try resource(
            id: "10000000-0000-4000-8000-000000000001", alias: "host.compute-a")
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(schemaVersion: 1, resources: [resource])
        )
        let service = TopologyGraphService(
            vault: vault,
            userPresenceAuthorizer: TopologyPresenceAuthorizer(result: true),
            cooldown: 0
        )
        let contextAlias = try ResourceAlias("network.office-lan")
        let request = TopologyMutationRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            action: .link,
            source: resource.alias,
            relation: .memberOf,
            target: contextAlias
        )

        let reply = await service.mutate(request, caller: caller, now: now)
        let graph = try #require(await vault.readDocument().topologyGraph)
        let context = try #require(graph.nodes.first(where: { $0.alias == contextAlias }))

        #expect(reply.status == .completed)
        #expect(context.kind == .networkSegment)
        #expect(context.visibility == .agent)
        #expect(graph.edges.first?.verification == .asserted)
    }

    @Test("invalid context aliases fail before prompting the user")
    func invalidContextDoesNotPrompt() async throws {
        let resource = try resource(
            id: "10000000-0000-4000-8000-000000000001", alias: "host.compute-a")
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(schemaVersion: 1, resources: [resource])
        )
        let authorizer = TopologyPresenceAuthorizer(result: true)
        let service = TopologyGraphService(
            vault: vault,
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )
        let request = TopologyMutationRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            action: .link,
            source: resource.alias,
            relation: .memberOf,
            target: try ResourceAlias("network.192.0.2.1")
        )

        let reply = await service.mutate(request, caller: caller, now: now)

        #expect(reply.status == .failed)
        #expect(reply.error?.code == "topology_alias_not_found")
        #expect(await authorizer.reasons.isEmpty)
        #expect(await vault.readDocument().topologyGraph == nil)
    }

    @Test("resource links update the encrypted directory and topology together")
    func resourceLinkSynchronizesDirectory() async throws {
        let source = try resource(id: "10000000-0000-4000-8000-000000000001", alias: "service.api")
        let target = try resource(
            id: "10000000-0000-4000-8000-000000000002", alias: "database.main")
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(schemaVersion: 1, resources: [source, target])
        )
        let service = TopologyGraphService(
            vault: vault,
            userPresenceAuthorizer: TopologyPresenceAuthorizer(result: true),
            cooldown: 0
        )
        let link = TopologyMutationRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            action: .link,
            source: source.alias,
            relation: .dependsOn,
            target: target.alias
        )

        let linked = await service.mutate(link, caller: caller, now: now)
        let linkedDocument = await vault.readDocument()
        let storedSource = try #require(
            linkedDocument.resources.first(where: { $0.id == source.id })
        )

        #expect(linked.status == .completed)
        #expect(
            storedSource.resolvedRelationships == [
                ResourceRelationship(
                    kind: .dependsOn,
                    targetResourceID: target.id,
                    origin: .agent
                )
            ])
        #expect(linkedDocument.topologyGraph?.edges.count == 1)

        let unlink = TopologyMutationRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            action: .unlink,
            source: source.alias,
            relation: .dependsOn,
            target: target.alias
        )
        let unlinked = await service.mutate(unlink, caller: caller, now: now)
        let unlinkedDocument = await vault.readDocument()
        let updatedSource = try #require(
            unlinkedDocument.resources.first(where: { $0.id == source.id })
        )

        #expect(unlinked.status == .completed)
        #expect(updatedSource.resolvedRelationships.isEmpty)
        #expect(unlinkedDocument.topologyGraph?.edges.isEmpty == true)
    }

    @Test("trusted observations create a context source and refresh one semantic edge")
    func observationRefreshesOneEdge() async throws {
        let target = try resource(id: "10000000-0000-4000-8000-000000000001", alias: "host.target")
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(schemaVersion: 1, resources: [target])
        )
        let service = TopologyGraphService(
            vault: vault,
            userPresenceAuthorizer: TopologyPresenceAuthorizer(result: false),
            cooldown: 0
        )
        let runtime = try ResourceAlias("runtime.local")

        try await service.recordObservation(
            source: runtime,
            relation: .canReach,
            target: target.alias,
            verification: .verified,
            observedAt: now,
            validUntil: now.addingTimeInterval(300),
            evidenceReference: UUID()
        )
        try await service.recordObservation(
            source: runtime,
            relation: .canReach,
            target: target.alias,
            verification: .verified,
            observedAt: now.addingTimeInterval(60),
            validUntil: now.addingTimeInterval(360),
            evidenceReference: UUID()
        )
        let graph = try #require(await vault.readDocument().topologyGraph)
        let observations = graph.edges.filter {
            $0.relation == .canReach && $0.layer == .observed
        }

        #expect(graph.nodes.contains { $0.alias == runtime && $0.kind == .runtime })
        #expect(observations.count == 1)
        #expect(observations[0].observedAt == now.addingTimeInterval(60))
    }

    private var caller: CallerIdentity {
        CallerIdentity(
            signingIdentifier: "dev.safa.cli",
            teamIdentifier: "TESTTEAM1",
            effectiveUserID: 501,
            auditSessionID: 77
        )
    }

    private func resource(id: String, alias: String) throws -> Resource {
        let date = Date(timeIntervalSince1970: 1_700_000_000)
        return Resource(
            id: UUID(uuidString: id)!,
            alias: try ResourceAlias(alias),
            resourceType: .serviceHTTP,
            accessMethods: [.http],
            transport: nil,
            securityDomain: "synthetic",
            revision: 1,
            state: .active,
            createdAt: date,
            updatedAt: date
        )
    }
}

private actor TopologyPresenceAuthorizer: UserPresenceAuthorizing {
    private let result: Bool
    private(set) var reasons: [String] = []

    init(result: Bool) {
        self.result = result
    }

    func authorize(reason: String) -> Bool {
        reasons.append(reason)
        return result
    }
}

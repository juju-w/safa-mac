import Foundation
import SAFADomain
import Testing

@Suite("Extensible resource directory")
struct ResourceDirectoryTests {
    @Test("resource and access identifiers are namespaced but not closed enums")
    func extensibleIdentifiers() throws {
        #expect(try ResourceTypeIdentifier("host.linux") == .hostLinux)
        #expect(try ResourceTypeIdentifier("database.mysql").rawValue == "database.mysql")
        #expect(try ResourceTypeIdentifier("object-storage.s3").rawValue == "object-storage.s3")
        #expect(try AccessMethodIdentifier("cache.redis").rawValue == "cache.redis")
        #expect(try CredentialKind("database.password").rawValue == "database.password")
        #expect(
            try CredentialKind("object-storage.access-key").rawValue == "object-storage.access-key")
        #expect(throws: ResourceDirectoryValidationError.self) {
            try ResourceTypeIdentifier("My SQL")
        }
    }

    @Test("metadata values preserve their concrete type across persistence")
    func metadataRoundTrip() throws {
        let entries = [
            try ResourceMetadataEntry(key: "host.os.family", value: .text("linux")),
            try ResourceMetadataEntry(key: "host.cpu.logical-count", value: .integer(64)),
            try ResourceMetadataEntry(
                key: "host.memory.total-bytes",
                value: .byteCount(274_877_906_944)
            ),
            try ResourceMetadataEntry(key: "host.docker.available", value: .boolean(true)),
            try ResourceMetadataEntry(
                key: "service.tags",
                value: .textList(["production", "internal"])
            ),
        ]

        let data = try JSONEncoder().encode(entries)
        #expect(try JSONDecoder().decode([ResourceMetadataEntry].self, from: data) == entries)
    }

    @Test("canonical and alternate aliases resolve to the same resource")
    func alternateAliases() throws {
        let resource = TestDirectoryResourceFactory.make(
            alias: "hm-105",
            alternateAliases: ["gpu-worker", "chrome-cluster"]
        )
        let registry = try ResourceRegistry(resources: [resource])

        #expect(try registry.resource(alias: ResourceAlias("hm-105")).id == resource.id)
        #expect(try registry.resource(alias: ResourceAlias("gpu-worker")).id == resource.id)
        #expect(try registry.resource(alias: ResourceAlias("chrome-cluster")).id == resource.id)
    }

    @Test("all canonical and alternate aliases share one collision namespace")
    func aliasCollisions() throws {
        let first = TestDirectoryResourceFactory.make(
            alias: "hm-105",
            alternateAliases: ["gpu-worker"]
        )
        let second = TestDirectoryResourceFactory.make(
            alias: "gpu-worker",
            alternateAliases: []
        )

        #expect(throws: ResourceRegistryError.duplicateAlias(alias: "gpu-worker")) {
            try ResourceRegistry(resources: [first, second])
        }
    }

    @Test("metadata keys are unique within one resource")
    func metadataKeyCollision() throws {
        let resource = TestDirectoryResourceFactory.make(
            alias: "hm-105",
            metadata: [
                try ResourceMetadataEntry(key: "host.os.family", value: .text("linux")),
                try ResourceMetadataEntry(key: "host.os.family", value: .text("ubuntu")),
            ]
        )

        #expect(
            throws: ResourceRegistryError.duplicateMetadataKey(
                resourceAlias: "hm-105",
                key: "host.os.family"
            )
        ) {
            try ResourceRegistry(resources: [resource])
        }
    }

    @Test("resource relationships must target a distinct live resource")
    func relationshipValidation() throws {
        let host = TestDirectoryResourceFactory.make(alias: "hm-107")
        let service = TestDirectoryResourceFactory.make(
            alias: "airflow",
            relationships: [
                ResourceRelationship(kind: .hostedOn, targetResourceID: host.id)
            ]
        )
        #expect(try ResourceRegistry(resources: [host, service]).list().count == 2)

        let invalid = TestDirectoryResourceFactory.make(
            alias: "orphan-service",
            relationships: [
                ResourceRelationship(kind: .hostedOn, targetResourceID: UUID())
            ]
        )
        #expect(throws: ResourceRegistryError.self) {
            try ResourceRegistry(resources: [invalid])
        }

        let forged = TestDirectoryResourceFactory.make(
            alias: "forged-service",
            relationships: [
                ResourceRelationship(
                    kind: .hostedOn,
                    targetResourceID: host.id,
                    origin: .adapter
                )
            ]
        )
        #expect(throws: ResourceRegistryError.self) {
            try ResourceRegistry(resources: [host, forged])
        }
    }

    @Test("legacy relationships decode with import provenance")
    func legacyRelationshipProvenance() throws {
        let target = UUID(uuidString: "10000000-0000-4000-8000-000000000001")!
        let data = Data(
            #"{"kind":"depends-on","target_resource_id":"10000000-0000-4000-8000-000000000001"}"#
                .utf8
        )

        let relationship = try JSONDecoder().decode(ResourceRelationship.self, from: data)

        #expect(relationship.kind == .dependsOn)
        #expect(relationship.targetResourceID == target)
        #expect(relationship.origin == .import)
    }

    @Test("unknown metadata is private unless code explicitly allowlists its key")
    func publicDisclosureIsAllowlisted() throws {
        let resource = TestDirectoryResourceFactory.make(
            alias: "hm-105",
            metadata: [
                try ResourceMetadataEntry(key: "host.os.family", value: .text("linux")),
                try ResourceMetadataEntry(
                    key: "host.docker.available",
                    value: .boolean(true)
                ),
                try ResourceMetadataEntry(
                    key: "host.account.is-root",
                    value: .boolean(false)
                ),
                try ResourceMetadataEntry(
                    key: "host.docker.account-authorized",
                    value: .boolean(true)
                ),
                try ResourceMetadataEntry(
                    key: "private.network.address",
                    value: .text("203.0.113.10")
                ),
                try ResourceMetadataEntry(
                    key: "future.unreviewed-field",
                    value: .text("must remain private")
                ),
            ]
        )

        let projection = SafeResourceProjection(resource: resource)
        #expect(
            projection.summaryMetadata.map(\.key.rawValue) == [
                "host.account.is-root", "host.docker.account-authorized",
                "host.docker.available", "host.os.family",
            ])
        #expect(
            !projection.summaryMetadata.contains { entry in
                if case .text("203.0.113.10") = entry.value { return true }
                return false
            })
    }

    @Test("allowlisted metadata with an invalid type or value remains private")
    func invalidPublicMetadataFailsClosed() throws {
        let resource = TestDirectoryResourceFactory.make(
            alias: "hm-105",
            metadata: [
                try ResourceMetadataEntry(
                    key: "host.docker.available",
                    value: .text("https://private.example.invalid/token")
                ),
                try ResourceMetadataEntry(
                    key: "host.os.family",
                    value: .text("synthetic-secret-token")
                ),
            ]
        )

        #expect(SafeResourceProjection(resource: resource).summaryMetadata.isEmpty)
    }

    @Test("pre-directory resource records decode with safe host defaults")
    func legacyResourceCompatibility() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let legacy = LegacyResourceV1(
            id: UUID(),
            alias: try ResourceAlias("legacy-host"),
            displayName: nil,
            transport: .ssh,
            endpoint: LegacyEndpointV1(host: "203.0.113.9", port: 22),
            username: "operator",
            jumpRoute: [],
            securityDomain: "legacy",
            hostIdentity: nil,
            authRef: nil,
            sudoRef: nil,
            policyRef: nil,
            revision: 1,
            state: .active,
            createdAt: now,
            updatedAt: now
        )

        let resource = try JSONDecoder().decode(
            Resource.self,
            from: JSONEncoder().encode(legacy)
        )
        #expect(resource.resolvedResourceType == .hostLinux)
        #expect(resource.resolvedAlternateAliases.isEmpty)
        #expect(resource.resolvedAccessMethods == [.ssh])
        #expect(resource.resolvedMetadata.isEmpty)
        #expect(
            try JSONDecoder().decode(CredentialKind.self, from: Data("\"ssh_password\"".utf8))
                == .sshPassword)
    }

    @Test("legacy NAS type migrates to a Linux SSH host with a NAS role")
    func legacyNASTypeMigration() throws {
        let resource = TestDirectoryResourceFactory.make(alias: "nas.home")
        var object = try #require(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(resource))
                as? [String: Any]
        )
        var profile = try #require(object["profile"] as? [String: Any])
        profile.removeValue(forKey: "classification")
        profile["resourceType"] = "host.nas"
        object["profile"] = profile

        let migrated = try JSONDecoder().decode(
            Resource.self,
            from: JSONSerialization.data(withJSONObject: object)
        )

        #expect(migrated.resolvedKind == .host)
        #expect(migrated.resolvedTemplate == .sshV1)
        #expect(migrated.resolvedHostPlatform == .linux)
        #expect(migrated.resolvedRoles == [.nas])
        #expect(migrated.resolvedResourceType == .hostLinux)
        #expect(
            !String(decoding: try JSONEncoder().encode(migrated), as: UTF8.self).contains(
                "host.nas"))
    }

    @Test("non-SSH profiles expose only their template capabilities")
    func nonSSHProfile() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let resource = Resource(
            id: UUID(),
            alias: try ResourceAlias("market-data-db"),
            resourceType: .databaseMySQL,
            accessMethods: [.mysql],
            metadata: [
                try ResourceMetadataEntry(key: "database.engine", value: .text("mysql"))
            ],
            transport: nil,
            endpoint: nil,
            username: nil,
            securityDomain: "production-data",
            state: .draft,
            createdAt: now,
            updatedAt: now
        )

        let projection = SafeResourceProjection(resource: resource)
        #expect(projection.resourceType == .databaseMySQL)
        #expect(projection.capabilities.isEmpty)
        #expect(!projection.capabilities.contains("exec"))
        #expect(projection.health == .needsSetup)
        #expect(projection.summaryMetadata.map(\.key.rawValue) == ["database.engine"])
    }

    @Test("built-in templates cover the three host platforms and common middleware")
    func builtInTemplateCoverage() throws {
        let registry = ResourceTemplateRegistry.builtIn
        let expectedTemplateIDs = [
            "elasticsearch", "http", "kafka", "minio", "mongodb", "mysql", "neo4j", "oss",
            "postgresql", "rabbitmq", "redis", "s3", "sqlserver", "ssh",
        ]

        #expect(registry.templates.map(\.id.rawValue) == expectedTemplateIDs)
        #expect(registry.template(resourceType: .hostWindows)?.id == .ssh)
        #expect(registry.template(resourceType: .messagingKafka)?.id == .kafka)
        #expect(registry.template(resourceType: .messagingRabbitMQ)?.id == .rabbitMQ)
        #expect(registry.template(resourceType: .databaseMongoDB)?.id == .mongodb)
        #expect(registry.template(resourceType: .databaseSQLServer)?.id == .sqlServer)
        #expect(registry.template(resourceType: .objectStorageMinIO)?.id == .minio)
        #expect(registry.template(resourceType: .objectStorageOSS)?.id == .oss)
        #expect(registry.template(resourceType: .searchElasticsearch)?.id == .elasticsearch)
        #expect(registry.template(resourceType: .graphNeo4j)?.id == .neo4j)
        #expect(registry.template(resourceType: .serviceHTTP)?.capabilities == ["exec"])
        #expect(registry.template(resourceType: .databaseMySQL)?.capabilities.isEmpty == true)
    }

    @Test("template fields classify protected and secret input")
    func templateFieldSensitivity() throws {
        let registry = ResourceTemplateRegistry.builtIn
        let ssh = try #require(registry.template(id: .ssh))
        let sqlServer = try #require(registry.template(id: .sqlServer))

        #expect(
            ssh.fields.first { $0.id.rawValue == "connection.endpoint" }?.sensitivity
                == .protected
        )
        #expect(
            sqlServer.fields.first { $0.id.rawValue == "credential.password" }?.sensitivity
                == .secret
        )
        #expect(
            sqlServer.fields.first { $0.id.rawValue == "connection.port" }?.defaultValue
                == .integer(1433)
        )
    }

    @Test("active service readiness follows template credential policy")
    func serviceReadiness() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let unauthenticatedHTTP = Resource(
            id: UUID(),
            alias: try ResourceAlias("health-api"),
            resourceType: .serviceHTTP,
            accessMethods: [.http],
            transport: nil,
            endpoint: ResourceEndpoint(scheme: "https", host: "service.invalid", port: 443),
            username: nil,
            securityDomain: "synthetic",
            state: .active,
            createdAt: now,
            updatedAt: now
        )
        let mysqlWithoutCredential = Resource(
            id: UUID(),
            alias: try ResourceAlias("mysql.test"),
            resourceType: .databaseMySQL,
            accessMethods: [.mysql],
            transport: nil,
            endpoint: ResourceEndpoint(host: "mysql.invalid", port: 3306),
            username: "reader",
            securityDomain: "synthetic",
            state: .active,
            createdAt: now,
            updatedAt: now
        )

        #expect(
            SafeResourceProjection(resource: unauthenticatedHTTP).health == .needsVerification)
        #expect(SafeResourceProjection(resource: mysqlWithoutCredential).health == .needsSetup)

        var verifiedHTTP = unauthenticatedHTTP
        verifiedHTTP.verification = ResourceVerification(
            status: .verified,
            adapter: .http,
            checkedAt: now
        )
        #expect(SafeResourceProjection(resource: verifiedHTTP).health == .ready)
    }
}

private struct LegacyEndpointV1: Codable {
    let host: String
    let port: UInt16
}

private struct LegacyResourceV1: Codable {
    let id: UUID
    let alias: ResourceAlias
    let displayName: String?
    let transport: TransportKind
    let endpoint: LegacyEndpointV1
    let username: String
    let jumpRoute: [UUID]
    let securityDomain: String
    let hostIdentity: HostIdentity?
    let authRef: UUID?
    let sudoRef: UUID?
    let policyRef: UUID?
    let revision: UInt64
    let state: ResourceState
    let createdAt: Date
    let updatedAt: Date
}

enum TestDirectoryResourceFactory {
    static func make(
        alias: String,
        alternateAliases: [String] = [],
        metadata: [ResourceMetadataEntry] = [],
        relationships: [ResourceRelationship] = []
    ) -> Resource {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return Resource(
            id: UUID(),
            alias: try! ResourceAlias(alias),
            resourceType: .hostLinux,
            alternateAliases: alternateAliases.map { try! ResourceAlias($0) },
            accessMethods: [.ssh],
            metadata: metadata,
            relationships: relationships,
            endpoint: ResourceEndpoint(host: "203.0.113.10", port: 22),
            username: "operator",
            securityDomain: "synthetic",
            state: .active,
            createdAt: now,
            updatedAt: now
        )
    }
}

import Foundation

public enum ResourceTemplateRegistryError: Error, Equatable, Sendable {
    case duplicateTemplate(String)
    case duplicateResourceType(String)
    case invalidTemplate(String)
}

public struct ResourceTemplateIdentifier: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: String

    public init(_ rawValue: String) throws {
        guard NamespacedIdentifier.validate(rawValue, maximumLength: 64) else {
            throw ResourceDirectoryValidationError.invalidIdentifier(rawValue)
        }
        self.rawValue = rawValue
    }

    public init?(rawValue: String) {
        try? self.init(rawValue)
    }

    public static let ssh = try! Self("ssh")
    public static let mysql = try! Self("mysql")
    public static let postgresql = try! Self("postgresql")
    public static let sqlServer = try! Self("sqlserver")
    public static let s3 = try! Self("s3")
    public static let minio = try! Self("minio")
    public static let oss = try! Self("oss")
    public static let redis = try! Self("redis")
    public static let kafka = try! Self("kafka")
    public static let rabbitMQ = try! Self("rabbitmq")
    public static let mongodb = try! Self("mongodb")
    public static let elasticsearch = try! Self("elasticsearch")
    public static let neo4j = try! Self("neo4j")
    public static let http = try! Self("http")
}

public struct ResourceTemplateFieldIdentifier: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: String

    public init(_ rawValue: String) throws {
        guard NamespacedIdentifier.validate(rawValue) else {
            throw ResourceDirectoryValidationError.invalidIdentifier(rawValue)
        }
        self.rawValue = rawValue
    }

    public init?(rawValue: String) {
        try? self.init(rawValue)
    }
}

public enum ResourceTemplateFieldSensitivity: String, Codable, Sendable {
    case safe
    case protected
    case secret
}

public struct ResourceTemplateFieldDefinition: Codable, Equatable, Sendable {
    public let id: ResourceTemplateFieldIdentifier
    public let sensitivity: ResourceTemplateFieldSensitivity
    public let required: Bool
    public let defaultValue: ResourceMetadataValue?

    public init(
        id: ResourceTemplateFieldIdentifier,
        sensitivity: ResourceTemplateFieldSensitivity,
        required: Bool,
        defaultValue: ResourceMetadataValue? = nil
    ) {
        self.id = id
        self.sensitivity = sensitivity
        self.required = required
        self.defaultValue = defaultValue
    }
}

public struct ResourceTemplateDefinition: Codable, Equatable, Sendable {
    public let id: ResourceTemplateIdentifier
    public let version: UInt
    public let kind: ResourceKindIdentifier
    public let hostPlatforms: [HostPlatform]
    /// Compatibility values for the additive CLI v1 `resource_type` selector.
    public let resourceTypes: [ResourceTypeIdentifier]
    public let accessMethods: [AccessMethodIdentifier]
    public let fields: [ResourceTemplateFieldDefinition]
    public let credentialKinds: [CredentialKind]
    public let credentialRequired: Bool
    public let capabilities: [String]

    public init(
        id: ResourceTemplateIdentifier,
        version: UInt = 1,
        kind: ResourceKindIdentifier,
        hostPlatforms: [HostPlatform] = [],
        resourceTypes: [ResourceTypeIdentifier],
        accessMethods: [AccessMethodIdentifier],
        fields: [ResourceTemplateFieldDefinition],
        credentialKinds: [CredentialKind],
        credentialRequired: Bool,
        capabilities: [String]
    ) {
        self.id = id
        self.version = version
        self.kind = kind
        self.hostPlatforms = hostPlatforms
        self.resourceTypes = resourceTypes
        self.accessMethods = accessMethods
        self.fields = fields
        self.credentialKinds = credentialKinds
        self.credentialRequired = credentialRequired
        self.capabilities = capabilities
    }
}

public struct ResourceTemplateRegistry: Sendable {
    private let templatesByID: [ResourceTemplateIdentifier: ResourceTemplateDefinition]
    private let templatesByType: [ResourceTypeIdentifier: ResourceTemplateDefinition]

    public init(templates: [ResourceTemplateDefinition]) throws {
        var byID: [ResourceTemplateIdentifier: ResourceTemplateDefinition] = [:]
        var byType: [ResourceTypeIdentifier: ResourceTemplateDefinition] = [:]
        for template in templates {
            guard template.version > 0, !template.resourceTypes.isEmpty,
                !template.accessMethods.isEmpty,
                Set(template.fields.map(\.id)).count == template.fields.count
            else {
                throw ResourceTemplateRegistryError.invalidTemplate(template.id.rawValue)
            }
            guard byID.updateValue(template, forKey: template.id) == nil else {
                throw ResourceTemplateRegistryError.duplicateTemplate(template.id.rawValue)
            }
            for resourceType in template.resourceTypes {
                guard byType.updateValue(template, forKey: resourceType) == nil else {
                    throw ResourceTemplateRegistryError.duplicateResourceType(resourceType.rawValue)
                }
            }
        }
        templatesByID = byID
        templatesByType = byType
    }

    public func template(id: ResourceTemplateIdentifier) -> ResourceTemplateDefinition? {
        templatesByID[id]
    }

    public func template(resourceType: ResourceTypeIdentifier) -> ResourceTemplateDefinition? {
        templatesByType[resourceType]
    }

    public func template(binding: ResourceTemplateBinding) -> ResourceTemplateDefinition? {
        guard let template = templatesByID[binding.id], template.version == binding.version else {
            return nil
        }
        return template
    }

    public func template(
        classification: ResourceClassification
    ) -> ResourceTemplateDefinition? {
        guard let template = template(binding: classification.template),
            template.kind == classification.kind
        else {
            return nil
        }
        if classification.kind == .host {
            guard let platform = classification.hostPlatform,
                template.hostPlatforms.contains(platform)
            else {
                return nil
            }
        }
        return template
    }

    public var templates: [ResourceTemplateDefinition] {
        templatesByID.values.sorted { $0.id.rawValue < $1.id.rawValue }
    }

    public static let builtIn = try! Self(templates: BuiltInResourceTemplates.all)
}

private enum BuiltInResourceTemplates {
    static let all: [ResourceTemplateDefinition] = [
        ResourceTemplateDefinition(
            id: .ssh,
            kind: .host,
            hostPlatforms: HostPlatform.allCases,
            resourceTypes: [.hostLinux, .hostMacOS, .hostWindows],
            accessMethods: [.ssh],
            fields: connectionFields(defaultPort: 22, username: true)
                + [
                    field("connection.authentication", .protected, required: true),
                    field("host.identity", .protected, required: true),
                ],
            credentialKinds: [.sshOpenSSH, .sshPassword, .sshSecureEnclaveKey],
            credentialRequired: true,
            capabilities: ["exec"]
        ),
        database(
            id: .mysql,
            type: .databaseMySQL,
            method: .mysql,
            defaultPort: 3306
        ),
        database(
            id: .postgresql,
            type: .databasePostgreSQL,
            method: .postgresql,
            defaultPort: 5432
        ),
        database(
            id: .sqlServer,
            type: .databaseSQLServer,
            method: .sqlServer,
            defaultPort: 1433
        ),
        objectStorage(id: .s3, type: .objectStorageS3),
        objectStorage(id: .minio, type: .objectStorageMinIO),
        objectStorage(id: .oss, type: .objectStorageOSS),
        ResourceTemplateDefinition(
            id: .kafka,
            kind: .messaging,
            resourceTypes: [.messagingKafka],
            accessMethods: [.kafka],
            fields: connectionFields(defaultPort: 9092, username: false)
                + [
                    field("connection.username", .protected, required: false),
                    field("messaging.security-protocol", .protected, required: false),
                    field("credential.password", .secret, required: false),
                ],
            credentialKinds: [.databasePassword],
            credentialRequired: false,
            capabilities: []
        ),
        ResourceTemplateDefinition(
            id: .rabbitMQ,
            kind: .messaging,
            resourceTypes: [.messagingRabbitMQ],
            accessMethods: [.rabbitMQ],
            fields: connectionFields(defaultPort: 5672, username: true)
                + [
                    field("messaging.virtual-host", .protected, required: false),
                    field(
                        "connection.tls", .protected, required: true,
                        defaultValue: .boolean(false)),
                    field("credential.password", .secret, required: true),
                ],
            credentialKinds: [.databasePassword],
            credentialRequired: true,
            capabilities: []
        ),
        ResourceTemplateDefinition(
            id: .mongodb,
            kind: .database,
            resourceTypes: [.databaseMongoDB],
            accessMethods: [.mongodb],
            fields: connectionFields(defaultPort: 27_017, username: false)
                + [
                    field("connection.username", .protected, required: false),
                    field("database.name", .protected, required: false),
                    field("database.authentication-source", .protected, required: false),
                    field(
                        "connection.tls", .protected, required: true,
                        defaultValue: .boolean(false)),
                    field("credential.password", .secret, required: false),
                ],
            credentialKinds: [.databasePassword],
            credentialRequired: false,
            capabilities: []
        ),
        ResourceTemplateDefinition(
            id: .redis,
            kind: .cache,
            resourceTypes: [.cacheRedis],
            accessMethods: [.redis],
            fields: connectionFields(defaultPort: 6379, username: false)
                + [
                    field("cache.database-index", .protected, required: false),
                    field(
                        "connection.tls", .protected, required: true, defaultValue: .boolean(false)),
                    field("credential.password", .secret, required: false),
                ],
            credentialKinds: [.databasePassword],
            credentialRequired: false,
            capabilities: []
        ),
        ResourceTemplateDefinition(
            id: .elasticsearch,
            kind: .search,
            resourceTypes: [.searchElasticsearch],
            accessMethods: [.elasticsearch],
            fields: connectionFields(defaultPort: 9200, username: false)
                + [
                    field(
                        "connection.tls", .protected, required: true, defaultValue: .boolean(false)),
                    field("credential.token", .secret, required: false),
                ],
            credentialKinds: [.apiToken, .databasePassword],
            credentialRequired: false,
            capabilities: []
        ),
        ResourceTemplateDefinition(
            id: .neo4j,
            kind: .graph,
            resourceTypes: [.graphNeo4j],
            accessMethods: [.neo4j],
            fields: connectionFields(defaultPort: 7687, username: true)
                + [
                    field("database.name", .protected, required: false),
                    field(
                        "connection.tls", .protected, required: true, defaultValue: .boolean(false)),
                    field("credential.password", .secret, required: true),
                ],
            credentialKinds: [.databasePassword],
            credentialRequired: true,
            capabilities: []
        ),
        ResourceTemplateDefinition(
            id: .http,
            kind: .service,
            resourceTypes: [.serviceHTTP],
            accessMethods: [.http],
            fields: connectionFields(defaultPort: 443, username: false)
                + [
                    field("connection.path", .protected, required: false),
                    field(
                        "connection.tls", .protected, required: true, defaultValue: .boolean(true)),
                    field("credential.token", .secret, required: false),
                ],
            credentialKinds: [.apiToken],
            credentialRequired: false,
            capabilities: ["exec"]
        ),
    ]

    private static func database(
        id: ResourceTemplateIdentifier,
        type: ResourceTypeIdentifier,
        method: AccessMethodIdentifier,
        defaultPort: Int64
    ) -> ResourceTemplateDefinition {
        ResourceTemplateDefinition(
            id: id,
            kind: .database,
            resourceTypes: [type],
            accessMethods: [method],
            fields: connectionFields(defaultPort: defaultPort, username: true)
                + [
                    field("database.name", .protected, required: false),
                    field(
                        "connection.tls", .protected, required: true, defaultValue: .boolean(true)),
                    field(
                        "connection.certificate-verification", .protected, required: true,
                        defaultValue: .boolean(true)),
                    field("credential.password", .secret, required: true),
                ],
            credentialKinds: [.databasePassword],
            credentialRequired: true,
            capabilities: []
        )
    }

    private static func objectStorage(
        id: ResourceTemplateIdentifier,
        type: ResourceTypeIdentifier
    ) -> ResourceTemplateDefinition {
        ResourceTemplateDefinition(
            id: id,
            kind: .objectStorage,
            resourceTypes: [type],
            accessMethods: [.s3],
            fields: connectionFields(defaultPort: 443, username: false)
                + [
                    field("object-storage.region", .protected, required: false),
                    field("object-storage.bucket", .protected, required: false),
                    field(
                        "connection.tls", .protected, required: true, defaultValue: .boolean(true)),
                    field("credential.access-key-id", .secret, required: true),
                    field("credential.secret-access-key", .secret, required: true),
                ],
            credentialKinds: [.objectStorageAccessKey],
            credentialRequired: true,
            capabilities: []
        )
    }

    private static func connectionFields(
        defaultPort: Int64,
        username: Bool
    ) -> [ResourceTemplateFieldDefinition] {
        var values = [
            field("connection.endpoint", .protected, required: true),
            field(
                "connection.port", .protected, required: true,
                defaultValue: .integer(defaultPort)),
            field("connection.route", .protected, required: false),
        ]
        if username {
            values.append(field("connection.username", .protected, required: true))
        }
        return values
    }

    private static func field(
        _ id: String,
        _ sensitivity: ResourceTemplateFieldSensitivity,
        required: Bool,
        defaultValue: ResourceMetadataValue? = nil
    ) -> ResourceTemplateFieldDefinition {
        ResourceTemplateFieldDefinition(
            id: try! ResourceTemplateFieldIdentifier(id),
            sensitivity: sensitivity,
            required: required,
            defaultValue: defaultValue
        )
    }
}

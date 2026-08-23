import Foundation

public struct ResourceSummaryV1: Codable, Equatable, Sendable {
    public let alias: String
    public let displayName: String?
    public let resourceType: String
    public let kind: String
    public let templateID: String
    public let templateVersion: UInt
    public let hostPlatform: String?
    public let roles: [String]
    public let state: String
    public let health: String
    public let capabilities: [String]
    public let sudoMode: String?
    public let metadata: [ResourceMetadataEntryV1]

    public init(
        alias: String,
        displayName: String?,
        resourceType: String,
        kind: String,
        templateID: String,
        templateVersion: UInt,
        hostPlatform: String?,
        roles: [String],
        state: String,
        health: String,
        capabilities: [String],
        sudoMode: String? = nil,
        metadata: [ResourceMetadataEntryV1]
    ) {
        self.alias = alias
        self.displayName = displayName
        self.resourceType = resourceType
        self.kind = kind
        self.templateID = templateID
        self.templateVersion = templateVersion
        self.hostPlatform = hostPlatform
        self.roles = roles
        self.state = state
        self.health = health
        self.capabilities = capabilities
        self.sudoMode = sudoMode
        self.metadata = metadata
    }

    private enum CodingKeys: String, CodingKey {
        case alias
        case displayName = "display_name"
        case resourceType = "resource_type"
        case kind
        case templateID = "template_id"
        case templateVersion = "template_version"
        case hostPlatform = "host_platform"
        case roles
        case state
        case health
        case capabilities
        case sudoMode = "sudo_mode"
        case metadata
    }
}

public struct ResourceDetailsV1: Codable, Equatable, Sendable {
    public let alias: String
    public let displayName: String?
    public let resourceType: String
    public let kind: String
    public let templateID: String
    public let templateVersion: UInt
    public let hostPlatform: String?
    public let roles: [String]
    public let alternateAliases: [String]
    public let accessMethods: [String]
    public let state: String
    public let health: String
    public let capabilities: [String]
    public let endpoint: ResourceEndpointV1?
    public let username: String?
    public let securityDomain: String
    public let metadata: [ResourceMetadataEntryV1]
    public let relationships: [ResourceRelationshipV1]
    public let hostIdentityStatus: String?
    public let updatedAt: Date

    public init(
        alias: String,
        displayName: String?,
        resourceType: String,
        kind: String,
        templateID: String,
        templateVersion: UInt,
        hostPlatform: String?,
        roles: [String],
        alternateAliases: [String],
        accessMethods: [String],
        state: String,
        health: String,
        capabilities: [String],
        endpoint: ResourceEndpointV1?,
        username: String?,
        securityDomain: String,
        metadata: [ResourceMetadataEntryV1],
        relationships: [ResourceRelationshipV1],
        hostIdentityStatus: String?,
        updatedAt: Date
    ) {
        self.alias = alias
        self.displayName = displayName
        self.resourceType = resourceType
        self.kind = kind
        self.templateID = templateID
        self.templateVersion = templateVersion
        self.hostPlatform = hostPlatform
        self.roles = roles
        self.alternateAliases = alternateAliases
        self.accessMethods = accessMethods
        self.state = state
        self.health = health
        self.capabilities = capabilities
        self.endpoint = endpoint
        self.username = username
        self.securityDomain = securityDomain
        self.metadata = metadata
        self.relationships = relationships
        self.hostIdentityStatus = hostIdentityStatus
        self.updatedAt = updatedAt
    }

    private enum CodingKeys: String, CodingKey {
        case alias
        case displayName = "display_name"
        case resourceType = "resource_type"
        case kind
        case templateID = "template_id"
        case templateVersion = "template_version"
        case hostPlatform = "host_platform"
        case roles
        case alternateAliases = "alternate_aliases"
        case accessMethods = "access_methods"
        case state
        case health
        case capabilities
        case endpoint
        case username
        case securityDomain = "security_domain"
        case metadata
        case relationships
        case hostIdentityStatus = "host_identity_status"
        case updatedAt = "updated_at"
    }
}

public struct ResourceEndpointV1: Codable, Equatable, Sendable {
    public let scheme: String?
    public let host: String
    public let port: UInt16
    public let path: String?

    public init(scheme: String?, host: String, port: UInt16, path: String?) {
        self.scheme = scheme
        self.host = host
        self.port = port
        self.path = path
    }
}

public struct ResourceRelationshipV1: Codable, Equatable, Sendable {
    public let kind: String
    public let targetAlias: String

    public init(kind: String, targetAlias: String) {
        self.kind = kind
        self.targetAlias = targetAlias
    }

    private enum CodingKeys: String, CodingKey {
        case kind
        case targetAlias = "target_alias"
    }
}

public struct ResourceMetadataEntryV1: Codable, Equatable, Sendable {
    public let key: String
    public let value: ResourceMetadataValueV1
    public let observedAt: Date?

    public init(key: String, value: ResourceMetadataValueV1, observedAt: Date? = nil) {
        self.key = key
        self.value = value
        self.observedAt = observedAt
    }

    private enum CodingKeys: String, CodingKey {
        case key
        case value
        case observedAt = "observed_at"
    }
}

public enum ResourceMetadataValueV1: Equatable, Sendable {
    case text(String)
    case integer(Int64)
    case boolean(Bool)
    case byteCount(UInt64)
    case textList([String])
}

extension ResourceMetadataValueV1: Codable {
    private enum ValueType: String, Codable {
        case text
        case integer
        case boolean
        case byteCount = "byte_count"
        case textList = "text_list"
    }

    private enum CodingKeys: String, CodingKey {
        case type
        case value
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(ValueType.self, forKey: .type) {
        case .text: self = .text(try container.decode(String.self, forKey: .value))
        case .integer: self = .integer(try container.decode(Int64.self, forKey: .value))
        case .boolean: self = .boolean(try container.decode(Bool.self, forKey: .value))
        case .byteCount: self = .byteCount(try container.decode(UInt64.self, forKey: .value))
        case .textList: self = .textList(try container.decode([String].self, forKey: .value))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .text(value):
            try container.encode(ValueType.text, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .integer(value):
            try container.encode(ValueType.integer, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .boolean(value):
            try container.encode(ValueType.boolean, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .byteCount(value):
            try container.encode(ValueType.byteCount, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .textList(value):
            try container.encode(ValueType.textList, forKey: .type)
            try container.encode(value, forKey: .value)
        }
    }
}

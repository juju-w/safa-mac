import Foundation
import SAFADomain
import SAFAProtocol

enum ResourceProjectionMapper {
    static func summary(
        _ resource: Resource,
        localClientAvailability: LocalClientAvailability = .current
    ) -> ResourceSummaryV1 {
        summary(
            SafeResourceProjection(resource: resource),
            localClientAvailability: localClientAvailability
        )
    }

    static func summary(
        _ resource: Resource,
        credentialReferences: [CredentialReference],
        localClientAvailability: LocalClientAvailability = .current
    ) -> ResourceSummaryV1 {
        summary(
            SafeResourceProjection(resource: resource),
            sudoMode: sudoMode(resource: resource, credentialReferences: credentialReferences),
            localClientAvailability: localClientAvailability
        )
    }

    static func summary(
        _ projection: SafeResourceProjection,
        sudoMode: String? = nil,
        localClientAvailability: LocalClientAvailability = .current
    ) -> ResourceSummaryV1 {
        ResourceSummaryV1(
            alias: projection.alias.rawValue,
            displayName: projection.displayName,
            resourceType: projection.resourceType.rawValue,
            kind: projection.kind.rawValue,
            templateID: projection.template.id.rawValue,
            templateVersion: projection.template.version,
            hostPlatform: projection.hostPlatform?.rawValue,
            roles: projection.roles.map(\.rawValue),
            state: projection.state.rawValue,
            health: projection.health.rawValue,
            capabilities: localClientAvailability.effectiveCapabilities(for: projection),
            sudoMode: sudoMode,
            metadata: projection.summaryMetadata.map(metadata)
        )
    }

    private static func sudoMode(
        resource: Resource,
        credentialReferences: [CredentialReference]
    ) -> String? {
        guard let sudoRef = resource.sudoRef,
            let reference = credentialReferences.first(where: { $0.id == sudoRef }),
            reference.kind == .sudoPassword
        else {
            return nil
        }
        if reference.publicMaterial == "passwordless", reference.storageLocator.isEmpty {
            return "passwordless"
        }
        if reference.publicMaterial == nil, !reference.storageLocator.isEmpty {
            return "password"
        }
        return nil
    }

    static func details(
        _ resource: Resource,
        allResources: [Resource],
        localClientAvailability: LocalClientAvailability = .current
    ) -> ResourceDetailsV1 {
        let projection = SafeResourceProjection(resource: resource)
        let aliasesByID =
            allResources
            .filter { $0.state != .deleted }
            .reduce(into: [UUID: ResourceAlias]()) { aliases, item in
                aliases[item.id] = item.alias
            }
        let relationships = resource.resolvedRelationships.compactMap { relationship in
            aliasesByID[relationship.targetResourceID].map {
                ResourceRelationshipV1(
                    kind: relationship.kind.rawValue,
                    targetAlias: $0.rawValue
                )
            }
        }
        return ResourceDetailsV1(
            alias: resource.alias.rawValue,
            displayName: resource.displayName,
            resourceType: resource.resolvedResourceType.rawValue,
            kind: resource.resolvedKind.rawValue,
            templateID: resource.resolvedTemplate.id.rawValue,
            templateVersion: resource.resolvedTemplate.version,
            hostPlatform: resource.resolvedHostPlatform?.rawValue,
            roles: resource.resolvedRoles.map(\.rawValue).sorted(),
            alternateAliases: resource.resolvedAlternateAliases.map(\.rawValue).sorted(),
            accessMethods: resource.resolvedAccessMethods.map(\.rawValue).sorted(),
            state: resource.state.rawValue,
            health: projection.health.rawValue,
            capabilities: localClientAvailability.effectiveCapabilities(for: projection),
            endpoint: resource.endpoint.map {
                ResourceEndpointV1(
                    scheme: $0.scheme,
                    host: $0.host,
                    port: $0.port,
                    path: $0.path
                )
            },
            username: resource.username,
            securityDomain: resource.securityDomain,
            metadata: ResourceMetadataPolicy.authorizedEntries(from: resource.resolvedMetadata)
                .sorted { $0.key.rawValue < $1.key.rawValue }
                .map(metadata),
            relationships: relationships.sorted { lhs, rhs in
                if lhs.kind == rhs.kind { return lhs.targetAlias < rhs.targetAlias }
                return lhs.kind < rhs.kind
            },
            hostIdentityStatus: resource.hostIdentity?.status.rawValue,
            updatedAt: resource.updatedAt
        )
    }

    private static func metadata(_ entry: ResourceMetadataEntry) -> ResourceMetadataEntryV1 {
        ResourceMetadataEntryV1(
            key: entry.key.rawValue,
            value: metadataValue(entry.value),
            observedAt: entry.observedAt
        )
    }

    private static func metadataValue(
        _ value: ResourceMetadataValue
    ) -> ResourceMetadataValueV1 {
        switch value {
        case let .text(value): .text(value)
        case let .integer(value): .integer(value)
        case let .boolean(value): .boolean(value)
        case let .byteCount(value): .byteCount(value)
        case let .textList(value): .textList(value)
        }
    }
}

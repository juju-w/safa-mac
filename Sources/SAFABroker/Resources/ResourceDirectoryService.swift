import Foundation
import SAFACrypto
import SAFADomain
import SAFAProtocol

public protocol ResourceDirectoryHandling: Sendable {
    func handle(
        _ request: ResourceDirectoryRequestV1,
        caller: CallerIdentity,
        now: Date
    ) async -> ResourceDirectoryReplyV1
}

public actor ResourceDirectoryService: ResourceDirectoryHandling {
    private let vault: any VaultDocumentStoring
    private let disclosureAuthorizer: any ResourceDisclosureAuthorizing
    private let localClientAvailability: LocalClientAvailability

    public init(
        vault: any VaultDocumentStoring,
        disclosureAuthorizer: any ResourceDisclosureAuthorizing,
        localClientAvailability: LocalClientAvailability = .current
    ) {
        self.vault = vault
        self.disclosureAuthorizer = disclosureAuthorizer
        self.localClientAvailability = localClientAvailability
    }

    public func handle(
        _ request: ResourceDirectoryRequestV1,
        caller _: CallerIdentity,
        now: Date = Date()
    ) async -> ResourceDirectoryReplyV1 {
        do {
            try validateShape(request)
            let document = try await vault.readDocument()
            let registry = try ResourceRegistry(resources: document.resources)
            switch request.action {
            case .list:
                return ResourceDirectoryReplyV1(
                    messageID: request.header.messageID,
                    status: .completed,
                    summaries: registry.list(state: request.state).map {
                        ResourceProjectionMapper.summary(
                            $0,
                            localClientAvailability: localClientAvailability
                        )
                    }
                )
            case .show:
                let alias = try requiredAlias(request)
                let resource = try registry.resource(alias: alias)
                return ResourceDirectoryReplyV1(
                    messageID: request.header.messageID,
                    status: .completed,
                    summaries: [
                        ResourceProjectionMapper.summary(
                            resource,
                            credentialReferences: document.credentialReferences,
                            localClientAvailability: localClientAvailability
                        )
                    ]
                )
            case .inspect:
                let alias = try requiredAlias(request)
                let resource = try registry.resource(alias: alias)
                do {
                    try await disclosureAuthorizer.authorize(alias: resource.alias, now: now)
                } catch ResourceDisclosureAuthorizationError.rateLimited {
                    return denial(
                        messageID: request.header.messageID,
                        code: "resource_details_rate_limited",
                        message: "Resource detail authorization is temporarily rate limited."
                    )
                } catch {
                    return denial(
                        messageID: request.header.messageID,
                        code: "resource_details_denied",
                        message: "Resource details were not authorized by the user."
                    )
                }
                return ResourceDirectoryReplyV1(
                    messageID: request.header.messageID,
                    status: .completed,
                    details: ResourceProjectionMapper.details(
                        resource,
                        allResources: document.resources,
                        localClientAvailability: localClientAvailability
                    )
                )
            }
        } catch ResourceRegistryError.notFound(let alias) {
            return failure(
                messageID: request.header.messageID,
                code: "resource_not_found",
                message: "The requested resource is not registered.",
                details: ["resource": .string(alias)]
            )
        } catch ResourceDirectoryRequestError.aliasRequired {
            return failure(
                messageID: request.header.messageID,
                code: "resource_alias_required",
                message: "This resource query requires an alias."
            )
        } catch ResourceDirectoryRequestError.unexpectedField {
            return failure(
                messageID: request.header.messageID,
                code: "resource_query_invalid",
                message: "This resource query contains fields that are not valid for its action."
            )
        } catch {
            return failure(
                messageID: request.header.messageID,
                code: "resource_directory_failure",
                message: "The resource directory could not complete the request."
            )
        }
    }

    private enum ResourceDirectoryRequestError: Error {
        case aliasRequired
        case unexpectedField
    }

    private func validateShape(_ request: ResourceDirectoryRequestV1) throws {
        switch request.action {
        case .list:
            guard request.alias == nil else {
                throw ResourceDirectoryRequestError.unexpectedField
            }
        case .show, .inspect:
            guard request.alias != nil else { throw ResourceDirectoryRequestError.aliasRequired }
            guard request.state == nil else {
                throw ResourceDirectoryRequestError.unexpectedField
            }
        }
    }

    private func requiredAlias(_ request: ResourceDirectoryRequestV1) throws -> ResourceAlias {
        guard let alias = request.alias else {
            throw ResourceDirectoryRequestError.aliasRequired
        }
        return alias
    }

    private func denial(
        messageID: UUID,
        code: String,
        message: String
    ) -> ResourceDirectoryReplyV1 {
        ResourceDirectoryReplyV1(
            messageID: messageID,
            status: .denied,
            error: SAFAErrorPayload(code: code, message: message, retryable: false)
        )
    }

    private func failure(
        messageID: UUID,
        code: String,
        message: String,
        details: [String: JSONValue] = [:]
    ) -> ResourceDirectoryReplyV1 {
        ResourceDirectoryReplyV1(
            messageID: messageID,
            status: .failed,
            error: SAFAErrorPayload(
                code: code,
                message: message,
                retryable: false,
                details: details
            )
        )
    }

}

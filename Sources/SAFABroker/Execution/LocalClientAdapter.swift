import Foundation
import SAFADomain
import SAFATransport

public enum LocalClientAdapterError: Error, Equatable, Sendable {
    case capabilityNotSupported
    case clientNotInstalled
    case commandNotAllowed
    case endpointInvalid
    case credentialUnavailable
    case credentialTransportInsecure
    case privilegeNotSupported
}

public struct LocalClientExecutionPlan: Sendable {
    public let adapter: AccessMethodIdentifier
    public let invocation: ProcessInvocation
    public let redactionValues: [Data]

    public init(
        adapter: AccessMethodIdentifier,
        invocation: ProcessInvocation,
        redactionValues: [Data]
    ) {
        self.adapter = adapter
        self.invocation = invocation
        self.redactionValues = redactionValues
    }
}

/// Converts a tiny, reviewed Agent-facing operation into an invocation of a
/// source-pinned local client. It never forwards Agent argv to that client.
public struct LocalClientAdapter: Sendable {
    private enum HTTPOperation {
        case get
        case head
    }

    private let curlURL: URL
    private let executableAvailable: @Sendable (URL) -> Bool
    public let availability: LocalClientAvailability

    public init(
        curlURL: URL = URL(fileURLWithPath: "/usr/bin/curl"),
        availability: LocalClientAvailability? = nil,
        executableAvailable: @escaping @Sendable (URL) -> Bool = {
            FileManager.default.isExecutableFile(atPath: $0.path)
        }
    ) {
        self.curlURL = curlURL
        self.availability =
            availability
            ?? (curlURL.path == "/usr/bin/curl"
                ? .current : LocalClientAvailability.detected(curlURL: curlURL))
        self.executableAvailable = executableAvailable
    }

    public func validate(
        resource: Resource,
        command: CommandSpec,
        privilege: Privilege
    ) throws {
        _ = try httpOperation(resource: resource, command: command, privilege: privilege)
        let url = try endpointURL(resource: resource)
        try validateCredentialTransport(resource: resource, url: url)
        guard availability.http == .ready, executableAvailable(curlURL) else {
            throw LocalClientAdapterError.clientNotInstalled
        }
    }

    public func prepare(
        resource: Resource,
        command: CommandSpec,
        privilege: Privilege,
        credential: Data?
    ) throws -> LocalClientExecutionPlan {
        let operation = try httpOperation(
            resource: resource,
            command: command,
            privilege: privilege
        )
        let url = try endpointURL(resource: resource)
        try validateCredentialTransport(resource: resource, url: url)
        guard availability.http == .ready, executableAvailable(curlURL) else {
            throw LocalClientAdapterError.clientNotInstalled
        }

        var lines = [
            "url = \(Self.configValue(url.absoluteString))",
            operation == .head ? "head" : "request = \"GET\"",
            "fail-with-body",
            "silent",
            "show-error",
            "no-progress-meter",
            "connect-timeout = \"10\"",
            "max-time = \(Self.configValue(String(command.timeoutSeconds)))",
        ]
        if let credential {
            guard url.scheme?.lowercased() == "https" else {
                throw LocalClientAdapterError.credentialTransportInsecure
            }
            guard
                !credential.isEmpty,
                credential.count <= 16_384,
                !credential.contains(0),
                !credential.contains(0x0A),
                !credential.contains(0x0D),
                let token = String(data: credential, encoding: .utf8)
            else {
                throw LocalClientAdapterError.credentialUnavailable
            }
            let authorization = "Authorization: Bearer \(token)"
            lines.append("header = \(Self.configValue(authorization))")
        }
        lines.append("")

        return LocalClientExecutionPlan(
            adapter: .http,
            invocation: ProcessInvocation(
                executableURL: curlURL,
                arguments: ["-q", "--config", "-"],
                environment: ["LC_ALL": "C"],
                standardInput: Data(lines.joined(separator: "\n").utf8),
                timeoutSeconds: command.timeoutSeconds,
                outputLimitBytes: command.outputLimitBytes
            ),
            redactionValues: [
                credential,
                Optional(Data(url.absoluteString.utf8)),
                resource.endpoint.map { Data($0.host.utf8) },
            ].compactMap { $0 }.filter { !$0.isEmpty }
        )
    }

    private func httpOperation(
        resource: Resource,
        command: CommandSpec,
        privilege: Privilege
    ) throws -> HTTPOperation {
        guard resource.resolvedAccessMethods.contains(.http),
            resource.resolvedTemplate.id == .http,
            ResourceTemplateRegistry.builtIn.template(
                classification: resource.resolvedClassification
            )?.capabilities.contains("exec") == true
        else {
            throw LocalClientAdapterError.capabilityNotSupported
        }
        guard privilege == .user else {
            throw LocalClientAdapterError.privilegeNotSupported
        }
        guard command.mode == .exec,
            command.stdinMode == .none,
            command.tty == false,
            command.workingDirectory == nil,
            let arguments = command.arguments
        else {
            throw LocalClientAdapterError.commandNotAllowed
        }
        switch arguments {
        case ["curl"]:
            return .get
        case ["curl", "--head"]:
            return .head
        default:
            throw LocalClientAdapterError.commandNotAllowed
        }
    }

    private func endpointURL(resource: Resource) throws -> URL {
        guard let endpoint = resource.endpoint,
            let scheme = endpoint.scheme?.lowercased(),
            scheme == "https" || scheme == "http",
            !endpoint.host.isEmpty,
            endpoint.host.utf8.count <= 253,
            endpoint.host.unicodeScalars.allSatisfy({ scalar in
                scalar.value >= 0x21 && scalar.value <= 0x7E
                    && !"/@?#\\\"".unicodeScalars.contains(scalar)
            }),
            endpoint.path?.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7F })
                ?? true
        else {
            throw LocalClientAdapterError.endpointInvalid
        }

        var components = URLComponents()
        components.scheme = scheme
        components.host = endpoint.host
        components.port = Int(endpoint.port)
        components.path = endpoint.path ?? "/"
        guard let url = components.url,
            url.scheme == scheme,
            url.host == endpoint.host
        else {
            throw LocalClientAdapterError.endpointInvalid
        }
        return url
    }

    private func validateCredentialTransport(resource: Resource, url: URL) throws {
        guard resource.authRef == nil || url.scheme?.lowercased() == "https" else {
            throw LocalClientAdapterError.credentialTransportInsecure
        }
    }

    private static func configValue(_ value: String) -> String {
        let escaped =
            value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "\"\(escaped)\""
    }
}

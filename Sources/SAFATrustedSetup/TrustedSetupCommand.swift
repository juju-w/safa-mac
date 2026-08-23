import ArgumentParser
import Foundation
import SAFACrypto
import SAFADomain

public struct TrustedSetupCommand: AsyncParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "safa-trusted-setup",
        abstract: "System-authenticated local configuration for protected SAFA resource values.",
        subcommands: [TrustedResourceCommand.self, TrustedRequestCommand.self]
    )

    public init() {}
}

struct TrustedRequestCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "request",
        subcommands: [TrustedRequestApproveCommand.self]
    )
}

struct TrustedRequestApproveCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "approve",
        abstract:
            "Review and decide a pending SAFA execution request, including sudo requests."
    )

    @Argument(help: "The pending request id (from the Agent's `safa exec` reply).")
    var requestID: String
    @Flag(name: .customLong("deny"), help: "Deny the request instead of approving it.")
    var deny = false

    mutating func run() async throws {
        let console = try TTYTrustedSetupConsole()
        do {
            guard let id = UUID(uuidString: requestID) else {
                try console.write("Not a valid request id.\n")
                throw ExitCode.failure
            }
            try await TrustedApprovalFlow(
                console: console,
                client: XPCTrustedLocalSetupClient()
            ).decide(requestID: id, approved: !deny)
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try? console.write("SAFA could not process this approval decision.\n")
            throw ExitCode.failure
        }
    }
}

struct TrustedResourceCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "resource",
        subcommands: [TrustedResourceAddCommand.self, TrustedResourceSudoCommand.self]
    )
}

struct TrustedResourceAddCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "add",
        abstract: "Collect protected resource configuration from the controlling terminal."
    )

    @Argument(help: "Safe logical SAFA resource alias.") var alias: String
    @Option(
        name: .customLong("type"),
        help: "Supported type: host.linux, host.macos, host.windows, or service.http."
    ) var resourceType = ResourceTypeIdentifier.hostLinux.rawValue

    mutating func run() async throws {
        let console = try TTYTrustedSetupConsole()
        do {
            let parsedAlias = try ResourceAlias(alias)
            let parsedType = try ResourceTypeIdentifier(resourceType)
            if parsedType == .serviceHTTP {
                try await TrustedHTTPEnrollmentFlow(
                    console: console,
                    authorizer: LocalAuthenticationUserPresenceAuthorizer(),
                    client: XPCTrustedLocalSetupClient()
                ).enroll(alias: parsedAlias, resourceType: parsedType)
            } else {
                try await TrustedSSHEnrollmentFlow(
                    console: console,
                    authorizer: LocalAuthenticationUserPresenceAuthorizer(),
                    scanner: SystemSSHHostKeyScanner(),
                    client: XPCTrustedLocalSetupClient()
                ).enroll(alias: parsedAlias, resourceType: parsedType)
            }
        } catch {
            try? console.write("SAFA protected setup did not complete.\n")
            throw ExitCode.failure
        }
    }
}

struct TrustedResourceSudoCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sudo",
        abstract:
            "Detect passwordless sudo or collect and verify a required password."
    )

    @Argument(help: "Existing SAFA resource alias.") var alias: String
    @Flag(
        name: .customLong("passwordless"),
        help: "Require NOPASSWD sudo; never fall back to collecting a password."
    )
    var passwordless = false
    @Flag(
        name: .customLong("remove"),
        help: "Remove the stored sudo credential instead of enrolling one."
    )
    var remove = false

    mutating func run() async throws {
        let console = try TTYTrustedSetupConsole()
        do {
            guard !(remove && passwordless) else {
                try console.write("--remove and --passwordless cannot be combined.\n")
                throw ExitCode.failure
            }
            let flow = TrustedSudoEnrollmentFlow(
                console: console,
                authorizer: LocalAuthenticationUserPresenceAuthorizer(),
                client: XPCTrustedLocalSetupClient()
            )
            let parsedAlias = try ResourceAlias(alias)
            if remove {
                try await flow.remove(alias: parsedAlias)
            } else {
                try await flow.enroll(alias: parsedAlias, passwordless: passwordless)
            }
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try? console.write("SAFA sudo credential setup did not complete.\n")
            throw ExitCode.failure
        }
    }
}

public enum TrustedSetupRuntime {
    public static func main() async {
        await TrustedSetupCommand.main()
    }
}

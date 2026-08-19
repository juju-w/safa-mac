import Foundation
import SAFADomain
import SAFAProtocol
import Security

enum TrustedResourceSetupLauncherError: Error, Equatable, Sendable {
    case helperUnavailable
    case helperIdentityInvalid
    case setupIncomplete
}

protocol TrustedResourceSetupLaunching: Sendable {
    func launch(alias: ResourceAlias, resourceType: ResourceTypeIdentifier) async throws
    func launchSudo(alias: ResourceAlias, passwordless: Bool, remove: Bool) async throws
}

struct BundledTrustedResourceSetupLauncher: TrustedResourceSetupLaunching {
    func launch(alias: ResourceAlias, resourceType: ResourceTypeIdentifier) async throws {
        let aliasValue = alias.rawValue
        let typeValue = resourceType.rawValue
        try await runHelper(["resource", "add", aliasValue, "--type", typeValue])
    }

    func launchSudo(alias: ResourceAlias, passwordless: Bool, remove: Bool) async throws {
        var arguments = ["resource", "sudo", alias.rawValue]
        if passwordless {
            arguments.append("--passwordless")
        }
        if remove {
            arguments.append("--remove")
        }
        try await runHelper(arguments)
    }

    private func runHelper(_ arguments: [String]) async throws {
        let helper = try Self.helperURL()
        try Self.validateSignature(of: helper)
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        let status = try await Task.detached(priority: .userInitiated) {
            let process = Process()
            process.executableURL = helper
            process.arguments = arguments
            process.environment = [
                "HOME": home,
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            ]
            process.currentDirectoryURL = URL(fileURLWithPath: "/", isDirectory: true)
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus
        }.value
        guard status == 0 else { throw TrustedResourceSetupLauncherError.setupIncomplete }
    }

    private static func helperURL() throws -> URL {
        let executable =
            Bundle.main.executableURL
            ?? URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
        let appHelper = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Library/Helpers/safa-trusted-setup")
        let sibling = executable.deletingLastPathComponent()
            .appendingPathComponent("safa-trusted-setup")
        for candidate in [appHelper, sibling]
        where FileManager.default.isExecutableFile(atPath: candidate.path) {
            return candidate
        }
        throw TrustedResourceSetupLauncherError.helperUnavailable
    }

    private static func validateSignature(of helper: URL) throws {
        let team = try CodeSigningRequirement.currentTeamIdentifier()
        let requirementText = try CodeSigningRequirement.requirement(
            teamIdentifier: team,
            signingIdentifiers: ["dev.safa.trusted-local"]
        )
        var staticCode: SecStaticCode?
        guard
            SecStaticCodeCreateWithPath(helper as CFURL, [], &staticCode) == errSecSuccess,
            let staticCode
        else {
            throw TrustedResourceSetupLauncherError.helperIdentityInvalid
        }
        var requirement: SecRequirement?
        guard
            SecRequirementCreateWithString(requirementText as CFString, [], &requirement)
                == errSecSuccess,
            let requirement,
            SecStaticCodeCheckValidity(staticCode, [], requirement) == errSecSuccess
        else {
            throw TrustedResourceSetupLauncherError.helperIdentityInvalid
        }
    }
}

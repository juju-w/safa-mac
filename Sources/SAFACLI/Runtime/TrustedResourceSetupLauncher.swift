import Darwin
import Foundation
import SAFADomain
import SAFAProtocol
import Security

enum TrustedResourceSetupLauncherError: Error, Equatable, Sendable {
    case helperUnavailable
    case helperIdentityInvalid
    case setupIncomplete
}

struct TrustedHelperProcessRunner: Sendable {
    func run(
        executable: URL,
        arguments: [String],
        environment: [String: String]
    ) async throws -> Int32 {
        try await Task.detached(priority: .userInitiated) {
            try Self.spawnAndWait(
                executable: executable,
                arguments: arguments,
                environment: environment
            )
        }.value
    }

    private static func spawnAndWait(
        executable: URL,
        arguments: [String],
        environment: [String: String]
    ) throws -> Int32 {
        var fileActions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&fileActions) == 0 else {
            throw TrustedResourceSetupLauncherError.setupIncomplete
        }
        defer { posix_spawn_file_actions_destroy(&fileActions) }

        guard
            posix_spawn_file_actions_addopen(
                &fileActions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) == 0,
            posix_spawn_file_actions_addopen(
                &fileActions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0) == 0,
            posix_spawn_file_actions_addopen(
                &fileActions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0,
            posix_spawn_file_actions_addchdir_np(&fileActions, "/") == 0
        else {
            throw TrustedResourceSetupLauncherError.setupIncomplete
        }

        let argumentValues = [executable.path] + arguments
        let environmentValues = environment.keys.sorted().map { "\($0)=\(environment[$0]!)" }
        var processID = pid_t()
        let spawnStatus = withDuplicatedCStrings(argumentValues) { argumentPointers in
            withDuplicatedCStrings(environmentValues) { environmentPointers in
                executable.path.withCString { executablePath in
                    posix_spawn(
                        &processID,
                        executablePath,
                        &fileActions,
                        nil,
                        argumentPointers,
                        environmentPointers
                    )
                }
            }
        }
        guard spawnStatus == 0 else {
            throw TrustedResourceSetupLauncherError.setupIncomplete
        }

        var waitStatus: Int32 = 0
        while waitpid(processID, &waitStatus, 0) == -1 {
            guard errno == EINTR else {
                throw TrustedResourceSetupLauncherError.setupIncomplete
            }
        }
        return waitStatus
    }

    private static func withDuplicatedCStrings<Result>(
        _ values: [String],
        operation: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) throws -> Result
    ) rethrows -> Result {
        var pointers = values.map { strdup($0) }
        pointers.append(nil)
        defer {
            for pointer in pointers where pointer != nil { free(pointer) }
        }
        return try pointers.withUnsafeMutableBufferPointer { buffer in
            try operation(buffer.baseAddress!)
        }
    }
}

protocol TrustedResourceSetupLaunching: Sendable {
    func launch(alias: ResourceAlias, resourceType: ResourceTypeIdentifier) async throws
    func launchSudo(alias: ResourceAlias, passwordless: Bool, remove: Bool) async throws
    func launchApproval(requestID: UUID) async throws
}

struct BundledTrustedResourceSetupLauncher: TrustedResourceSetupLaunching {
    private let processRunner = TrustedHelperProcessRunner()

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

    func launchApproval(requestID: UUID) async throws {
        try await runHelper(["request", "approve", requestID.uuidString.lowercased()])
    }

    private func runHelper(_ arguments: [String]) async throws {
        let helper = try Self.helperURL()
        try Self.validateSignature(of: helper)
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        let status = try await processRunner.run(
            executable: helper,
            arguments: arguments,
            environment: [
                "HOME": home,
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            ]
        )
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

import Foundation
import SAFADomain
import SAFAPolicy
import SAFASSH
import SAFATransport

enum AutoPrivilegeAccountProbeError: Error, Equatable {
    case unsupportedPlatform
    case invalidResult
}

/// Runs a fixed, broker-owned, read-only account probe through the already pinned SSH
/// transport. No Agent text is interpolated into the program and only two booleans are
/// accepted from stdout.
struct OpenSSHAutoPrivilegeAccountProbe: Sendable {
    private let transport: SSHTransport
    private let workingDirectory: URL

    init(transport: SSHTransport, workingDirectory: URL) {
        self.transport = transport
        self.workingDirectory = workingDirectory
    }

    func probe(
        resource: Resource,
        credential: SSHCredentialContext,
        includeDockerAuthorization: Bool,
        observedAt: Date,
        didLaunch: (@Sendable (Int32) -> Void)? = nil
    ) async throws -> AutoPrivilegeAccountObservation {
        guard resource.resolvedHostPlatform == .linux || resource.resolvedHostPlatform == .macOS
        else {
            throw AutoPrivilegeAccountProbeError.unsupportedPlatform
        }

        let program = includeDockerAuthorization ? Self.accountAndDockerProbe : Self.accountProbe
        let result = try await transport.execute(
            resource: resource,
            command: try .exec(
                arguments: ["/bin/sh", "-c", program],
                timeoutSeconds: 10,
                outputLimitBytes: 1_024
            ),
            credential: credential,
            workingRoot: workingDirectory.appendingPathComponent(
                "auto-privilege-\(UUID().uuidString)",
                isDirectory: true
            ),
            didLaunch: didLaunch
        )
        guard result.termination == .exit, result.exitCode == 0,
            !result.stdoutTruncated, !result.stderrTruncated
        else {
            throw AutoPrivilegeAccountProbeError.invalidResult
        }
        return try Self.parse(result.stdout, observedAt: observedAt)
    }

    static func parse(
        _ data: Data,
        observedAt: Date
    ) throws -> AutoPrivilegeAccountObservation {
        guard data.count <= 1_024, let text = String(data: data, encoding: .utf8) else {
            throw AutoPrivilegeAccountProbeError.invalidResult
        }
        var values: [String: String] = [:]
        for line in text.split(whereSeparator: \Character.isNewline) {
            let parts = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { throw AutoPrivilegeAccountProbeError.invalidResult }
            let key = String(parts[0])
            guard ["account_is_root", "docker_account_authorized"].contains(key),
                values[key] == nil
            else {
                throw AutoPrivilegeAccountProbeError.invalidResult
            }
            values[key] = String(parts[1])
        }
        guard let isRoot = Self.boolean(values["account_is_root"]) else {
            throw AutoPrivilegeAccountProbeError.invalidResult
        }
        let dockerAuthorized: Bool?
        switch values["docker_account_authorized"] {
        case nil, "unknown": dockerAuthorized = nil
        case let value?:
            guard let parsed = Self.boolean(value) else {
                throw AutoPrivilegeAccountProbeError.invalidResult
            }
            dockerAuthorized = parsed
        }
        guard !(isRoot && dockerAuthorized == false) else {
            throw AutoPrivilegeAccountProbeError.invalidResult
        }
        return AutoPrivilegeAccountObservation(
            isRoot: isRoot,
            dockerAuthorized: dockerAuthorized,
            observedAt: observedAt
        )
    }

    private static func boolean(_ value: String?) -> Bool? {
        switch value {
        case "true": true
        case "false": false
        default: nil
        }
    }

    private static let accountProbe = #"""
        account_is_root=false
        if [ "$(id -u 2>/dev/null)" = "0" ]; then account_is_root=true; fi
        printf 'account_is_root=%s\n' "$account_is_root"
        printf 'docker_account_authorized=unknown\n'
        """#

    private static let accountAndDockerProbe = #"""
        account_is_root=false
        if [ "$(id -u 2>/dev/null)" = "0" ]; then account_is_root=true; fi
        docker_account_authorized=false
        if [ "$account_is_root" = "true" ]; then
          docker_account_authorized=true
        elif id -Gn 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
          docker_account_authorized=true
        elif [ -S /var/run/docker.sock ] && [ -r /var/run/docker.sock ] && [ -w /var/run/docker.sock ]; then
          docker_account_authorized=true
        elif [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -S "$XDG_RUNTIME_DIR/docker.sock" ] && [ -r "$XDG_RUNTIME_DIR/docker.sock" ] && [ -w "$XDG_RUNTIME_DIR/docker.sock" ]; then
          docker_account_authorized=true
        elif [ -n "${HOME:-}" ] && [ -S "$HOME/.docker/run/docker.sock" ] && [ -r "$HOME/.docker/run/docker.sock" ] && [ -w "$HOME/.docker/run/docker.sock" ]; then
          docker_account_authorized=true
        elif command -v docker >/dev/null 2>&1 && docker version >/dev/null 2>&1; then
          docker_account_authorized=true
        fi
        printf 'account_is_root=%s\n' "$account_is_root"
        printf 'docker_account_authorized=%s\n' "$docker_account_authorized"
        """#
}

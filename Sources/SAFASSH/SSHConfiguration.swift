import CryptoKit
import Foundation
import SAFADomain
import SAFATransport
import Security

public enum SSHCredentialContext: Equatable, Sendable {
    case none
    case password(childBinding: String, askPassExecutable: URL)
    case secureEnclave(agentSocket: URL)
    case openSSH(identityFiles: [URL], identityAgent: URL?)
}

public enum SSHConfigurationError: Error, Equatable, Sendable {
    case resourceInactive
    case missingHostIdentity
    case missingSSHConnection
    case hostIdentityChanged
    case invalidHostIdentity
    case invalidRandomness
    case unsupportedCommand
    case persistenceFailed
    /// `remoteStandardInput` was supplied alongside a `.password` login
    /// credential. That combination pins `StdinNull yes` on the ssh
    /// invocation (required so OpenSSH prefers `SSH_ASKPASS` over reading a
    /// login password from stdin), which leaves no channel to forward a
    /// second secret to the remote command's stdin.
    case stdinForwardingUnavailableForPasswordCredential
}

public struct PreparedSSHExecution: Sendable {
    public let invocation: ProcessInvocation
    public let rootDirectory: URL
    public let configURL: URL
    public let knownHostsURL: URL
    public let opaqueHostAlias: String

    public init(
        invocation: ProcessInvocation,
        rootDirectory: URL,
        configURL: URL,
        knownHostsURL: URL,
        opaqueHostAlias: String
    ) {
        self.invocation = invocation
        self.rootDirectory = rootDirectory
        self.configURL = configURL
        self.knownHostsURL = knownHostsURL
        self.opaqueHostAlias = opaqueHostAlias
    }
}

public struct SSHConfigurationBuilder: Sendable {
    public init() {}

    public func prepare(
        resource: Resource,
        command: CommandSpec,
        credential: SSHCredentialContext,
        rootDirectory: URL,
        randomBytes: Data? = nil,
        remoteStandardInput: Data? = nil
    ) throws -> PreparedSSHExecution {
        guard command.mode == .exec, let commandArguments = command.arguments else {
            throw SSHConfigurationError.unsupportedCommand
        }
        let remoteCommand: String
        if resource.resolvedHostPlatform == .windows {
            remoteCommand = try Self.windowsPowerShellCommand(commandArguments)
        } else {
            remoteCommand = commandArguments.map(Self.posixQuote).joined(separator: " ")
        }
        return try prepare(
            resource: resource,
            remoteCommand: remoteCommand,
            credential: credential,
            rootDirectory: rootDirectory,
            timeoutSeconds: command.timeoutSeconds,
            outputLimitBytes: command.outputLimitBytes,
            randomBytes: randomBytes,
            remoteStandardInput: remoteStandardInput
        )
    }

    /// Trusted adapters use this path for a bounded script they own. Agent command DTOs never
    /// carry this payload, avoiding the second PowerShell/base64 layer that can exceed Windows'
    /// OpenSSH command-line limit.
    public func prepareWindowsPowerShell(
        resource: Resource,
        encodedScript: String,
        credential: SSHCredentialContext,
        rootDirectory: URL,
        timeoutSeconds: UInt,
        outputLimitBytes: UInt,
        randomBytes: Data? = nil
    ) throws -> PreparedSSHExecution {
        guard resource.resolvedHostPlatform == .windows,
            encodedScript.utf8.count <= 6 * 1_024,
            Data(base64Encoded: encodedScript) != nil
        else {
            throw SSHConfigurationError.unsupportedCommand
        }
        return try prepare(
            resource: resource,
            remoteCommand:
                "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand \(encodedScript)",
            credential: credential,
            rootDirectory: rootDirectory,
            timeoutSeconds: timeoutSeconds,
            outputLimitBytes: outputLimitBytes,
            randomBytes: randomBytes,
            remoteStandardInput: nil
        )
    }

    private func prepare(
        resource: Resource,
        remoteCommand: String,
        credential: SSHCredentialContext,
        rootDirectory: URL,
        timeoutSeconds: UInt,
        outputLimitBytes: UInt,
        randomBytes: Data?,
        remoteStandardInput: Data?
    ) throws -> PreparedSSHExecution {
        guard resource.state == .active else { throw SSHConfigurationError.resourceInactive }
        guard resource.resolvedAccessMethods.contains(.ssh),
            let endpoint = resource.endpoint,
            let username = resource.username,
            !username.isEmpty
        else {
            throw SSHConfigurationError.missingSSHConnection
        }
        guard let identity = resource.hostIdentity else {
            throw SSHConfigurationError.missingHostIdentity
        }
        guard identity.status == .trusted else {
            if identity.status == .changed { throw SSHConfigurationError.hostIdentityChanged }
            throw SSHConfigurationError.invalidHostIdentity
        }
        if remoteStandardInput != nil, case .password = credential {
            throw SSHConfigurationError.stdinForwardingUnavailableForPasswordCredential
        }
        let salt = try randomBytes ?? secureRandom(count: 20)
        guard salt.count >= 20 else { throw SSHConfigurationError.invalidRandomness }
        let opaqueAlias = "safa-" + UUID().uuidString.lowercased()
        let configURL = rootDirectory.appendingPathComponent("ssh_config")
        let knownHostsURL = rootDirectory.appendingPathComponent("known_hosts")

        do {
            try FileManager.default.createDirectory(
                at: rootDirectory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            // OpenSSH performs host-key lookup against the command-line alias. Pin the
            // per-request opaque alias explicitly so the temporary known_hosts entry and
            // lookup identity cannot diverge from HostName/port canonicalization details.
            let hostKeyAlias =
                endpoint.port == 22
                ? opaqueAlias
                : "[\(opaqueAlias)]:\(endpoint.port)"
            let hashedHost = hashKnownHost(hostKeyAlias, salt: salt.prefix(20))
            let keyPayload = identity.publicKey.base64EncodedString()
            let knownHosts = "\(hashedHost) \(identity.algorithm) \(keyPayload)\n"
            try writePrivate(Data(knownHosts.utf8), to: knownHostsURL)

            var config = """
                Host \(opaqueAlias)
                    HostName \(endpoint.host)
                    Port \(endpoint.port)
                    User \(username)
                    CanonicalizeHostname no
                    CheckHostIP no
                    ClearAllForwardings yes
                    GlobalKnownHostsFile /dev/null
                    HashKnownHosts yes
                    HostKeyAlias \(hostKeyAlias)
                    IdentitiesOnly yes
                    LogLevel ERROR
                    StrictHostKeyChecking yes
                    UserKnownHostsFile \(Self.quoteConfig(knownHostsURL.path))

                """
            var environment = ["LC_ALL": "C", "LANG": "C"]
            switch credential {
            case .none:
                config +=
                    "    BatchMode yes\n    PasswordAuthentication no\n    PubkeyAuthentication no\n"
            case let .password(childBinding, askPassExecutable):
                config +=
                    "    BatchMode no\n    KbdInteractiveAuthentication no\n    NumberOfPasswordPrompts 1\n    PasswordAuthentication yes\n    PreferredAuthentications password\n    PubkeyAuthentication no\n    StdinNull yes\n"
                environment["SSH_ASKPASS"] = askPassExecutable.path
                environment["SSH_ASKPASS_REQUIRE"] = "force"
                environment["DISPLAY"] = "SAFA"
                environment["SAFA_CHILD_BINDING"] = childBinding
            case let .secureEnclave(agentSocket):
                config +=
                    "    BatchMode yes\n    PasswordAuthentication no\n    PubkeyAuthentication yes\n    IdentityAgent \(agentSocket.path)\n"
            case let .openSSH(identityFiles, identityAgent):
                guard !identityFiles.isEmpty || identityAgent != nil else {
                    throw SSHConfigurationError.missingSSHConnection
                }
                config +=
                    "    BatchMode yes\n    PasswordAuthentication no\n    PubkeyAuthentication yes\n    IgnoreUnknown UseKeychain\n    UseKeychain yes\n"
                if identityFiles.isEmpty {
                    config += "    IdentitiesOnly no\n"
                }
                for identityFile in identityFiles {
                    config += "    IdentityFile \(Self.quoteConfig(identityFile.path))\n"
                }
                if let identityAgent {
                    config += "    IdentityAgent \(Self.quoteConfig(identityAgent.path))\n"
                }
            }
            try writePrivate(Data(config.utf8), to: configURL)

            let invocation = ProcessInvocation(
                executableURL: URL(fileURLWithPath: "/usr/bin/ssh"),
                arguments: ["-F", configURL.path, "-T", "--", opaqueAlias, remoteCommand],
                environment: environment,
                standardInput: remoteStandardInput,
                timeoutSeconds: timeoutSeconds,
                outputLimitBytes: outputLimitBytes
            )
            return PreparedSSHExecution(
                invocation: invocation,
                rootDirectory: rootDirectory,
                configURL: configURL,
                knownHostsURL: knownHostsURL,
                opaqueHostAlias: opaqueAlias
            )
        } catch let error as SSHConfigurationError {
            throw error
        } catch {
            throw SSHConfigurationError.persistenceFailed
        }
    }

    public static func posixQuote(_ argument: String) -> String {
        if argument.isEmpty { return "''" }
        return "'" + argument.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    public static func windowsPowerShellCommand(_ arguments: [String]) throws -> String {
        guard !arguments.isEmpty,
            let argumentData = try? JSONEncoder().encode(arguments)
        else {
            throw SSHConfigurationError.unsupportedCommand
        }
        let encodedArguments = argumentData.base64EncodedString()
        let script = """
            $ErrorActionPreference = 'Stop'
            $values = @([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('\(encodedArguments)')) | ConvertFrom-Json)
            $program = [string]$values[0]
            $programArguments = @()
            if ($values.Count -gt 1) {
              $programArguments = @($values | Select-Object -Skip 1 | ForEach-Object { [string]$_ })
            }
            & $program @programArguments
            if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }
            """
        guard let scriptData = script.data(using: .utf16LittleEndian) else {
            throw SSHConfigurationError.unsupportedCommand
        }
        return
            "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand \(scriptData.base64EncodedString())"
    }

    static func quoteConfig(_ value: String) -> String {
        let escaped =
            value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "\"\(escaped)\""
    }

    private func hashKnownHost(_ host: String, salt: Data.SubSequence) -> String {
        let saltData = Data(salt)
        let digest = HMAC<Insecure.SHA1>.authenticationCode(
            for: Data(host.utf8),
            using: SymmetricKey(data: saltData)
        )
        return "|1|\(saltData.base64EncodedString())|\(Data(digest).base64EncodedString())"
    }

    private func secureRandom(count: Int) throws -> Data {
        var bytes = Data(repeating: 0, count: count)
        let status = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw SSHConfigurationError.invalidRandomness }
        return bytes
    }

    private func writePrivate(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}

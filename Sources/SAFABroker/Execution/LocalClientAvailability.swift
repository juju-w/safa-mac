import Foundation
import SAFADomain
import Security

public enum LocalClientReadiness: String, Equatable, Sendable {
    case ready
    case unavailable
}

public struct CurlClientInspection: Equatable, Sendable {
    public let executable: Bool
    public let applePlatformSigned: Bool
    public let protocols: Set<String>
    public let options: Set<String>

    public init(
        executable: Bool,
        applePlatformSigned: Bool,
        protocols: Set<String>,
        options: Set<String>
    ) {
        self.executable = executable
        self.applePlatformSigned = applePlatformSigned
        self.protocols = protocols
        self.options = options
    }
}

/// One Broker-startup snapshot of source-pinned local client readiness.
/// Resource projections and execution routing share this exact value.
public struct LocalClientAvailability: Equatable, Sendable {
    private static let requiredProtocols: Set<String> = ["http", "https"]
    fileprivate static let requiredOptions: Set<String> = [
        "--config", "--connect-timeout", "--fail-with-body", "--max-time",
        "--no-progress-meter",
    ]

    public static let current = detected()

    public let http: LocalClientReadiness

    public init(http: LocalClientReadiness) {
        self.http = http
    }

    public init(inspection: CurlClientInspection) {
        http =
            inspection.executable
                && inspection.applePlatformSigned
                && inspection.protocols.isSuperset(of: Self.requiredProtocols)
                && inspection.options.isSuperset(of: Self.requiredOptions)
            ? .ready : .unavailable
    }

    public static func detected(
        curlURL: URL = URL(fileURLWithPath: "/usr/bin/curl")
    ) -> LocalClientAvailability {
        LocalClientAvailability(inspection: SystemCurlClientInspector.inspect(at: curlURL))
    }

    func effectiveCapabilities(for projection: SafeResourceProjection) -> [String] {
        guard projection.template.id == .http, http != .ready else {
            return projection.capabilities
        }
        return projection.capabilities.filter { $0 != "exec" }
    }
}

private enum SystemCurlClientInspector {
    static func inspect(at curlURL: URL) -> CurlClientInspection {
        guard curlURL.path == "/usr/bin/curl" else {
            return unavailable
        }
        let executable = FileManager.default.isExecutableFile(atPath: curlURL.path)
        guard executable else { return unavailable }

        let versionOutput = output(from: curlURL, arguments: ["--version"])
        let helpOutput = output(from: curlURL, arguments: ["--help", "all"])
        let protocols = Set(
            versionOutput?
                .split(separator: "\n")
                .first(where: { $0.hasPrefix("Protocols: ") })?
                .dropFirst("Protocols: ".count)
                .split(separator: " ")
                .map { String($0).lowercased() }
                ?? []
        )
        let options = Set(
            LocalClientAvailability.requiredOptions.filter { helpOutput?.contains($0) == true }
        )
        return CurlClientInspection(
            executable: true,
            applePlatformSigned: applePlatformSignatureIsValid(at: curlURL),
            protocols: protocols,
            options: options
        )
    }

    private static let unavailable = CurlClientInspection(
        executable: false,
        applePlatformSigned: false,
        protocols: [],
        options: []
    )

    private static func applePlatformSignatureIsValid(at url: URL) -> Bool {
        var code: SecStaticCode?
        guard
            SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
            let code
        else { return false }

        var requirement: SecRequirement?
        guard
            SecRequirementCreateWithString(
                "anchor apple and identifier \"com.apple.curl\"" as CFString,
                [],
                &requirement
            ) == errSecSuccess,
            let requirement
        else { return false }

        let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures)
        return SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess
    }

    private static func output(from executableURL: URL, arguments: [String]) -> String? {
        let process = Process()
        let standardOutput = Pipe()
        process.executableURL = executableURL
        process.arguments = arguments
        process.environment = ["LC_ALL": "C"]
        process.standardOutput = standardOutput
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            let data = standardOutput.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationReason == .exit, process.terminationStatus == 0 else {
                return nil
            }
            return String(data: data, encoding: .utf8)
        } catch {
            return nil
        }
    }
}

import Foundation
import SAFADomain
import SAFASSH
import SAFATransport

protocol OpenSSHHostInventoryProbing: Sendable {
    func probe(
        resource: Resource,
        credential: SSHCredentialContext,
        observedAt: Date,
        didLaunch: (@Sendable (Int32) -> Void)?
    ) async throws -> HostInventorySnapshot
}

struct OpenSSHHostInventoryProbe: OpenSSHHostInventoryProbing {
    private let transport: SSHTransport
    private let workingDirectory: URL

    init(
        transport: SSHTransport = SSHTransport(),
        workingDirectory: URL
    ) {
        self.transport = transport
        self.workingDirectory = workingDirectory
    }

    func probe(
        resource: Resource,
        credential: SSHCredentialContext,
        observedAt: Date,
        didLaunch: (@Sendable (Int32) -> Void)? = nil
    ) async throws -> HostInventorySnapshot {
        guard let expectedPlatform = resource.resolvedHostPlatform else {
            throw ResourceSetupError.inventoryProbeFailed
        }
        let arguments: [String]
        switch expectedPlatform {
        case .linux:
            arguments = ["/bin/sh", "-c", Self.linuxProbe]
        case .macOS:
            arguments = ["/bin/sh", "-c", Self.macOSProbe]
        case .windows:
            arguments = []
        }

        let result: ProcessExecutionResult
        do {
            let workingRoot = workingDirectory.appendingPathComponent(
                "inventory-\(UUID().uuidString)",
                isDirectory: true
            )
            if expectedPlatform == .windows {
                result = try await transport.executeWindowsPowerShell(
                    resource: resource,
                    encodedScript: Self.windowsProbe,
                    credential: credential,
                    workingRoot: workingRoot,
                    timeoutSeconds: 15,
                    outputLimitBytes: 32 * 1_024,
                    didLaunch: didLaunch
                )
            } else {
                result = try await transport.execute(
                    resource: resource,
                    command: CommandSpec.exec(
                        arguments: arguments,
                        timeoutSeconds: 15,
                        outputLimitBytes: 32 * 1_024
                    ),
                    credential: credential,
                    workingRoot: workingRoot,
                    didLaunch: didLaunch
                )
            }
        } catch {
            throw ResourceSetupError.inventoryProbeFailed
        }
        guard result.termination == .exit, result.exitCode == 0,
            !result.stdoutTruncated, !result.stderrTruncated
        else {
            throw ResourceSetupError.inventoryProbeFailed
        }

        let snapshot: HostInventorySnapshot
        switch expectedPlatform {
        case .linux, .macOS:
            snapshot = try Self.parsePOSIX(result.stdout, observedAt: observedAt)
        case .windows:
            snapshot = try Self.parseWindows(result.stdout, observedAt: observedAt)
        }
        guard snapshot.platform == expectedPlatform else {
            throw ResourceSetupError.platformMismatch
        }
        do {
            try ResourceMetadataPolicy.validateForPersistence(snapshot.metadata)
        } catch {
            throw ResourceSetupError.inventoryProbeFailed
        }
        return snapshot
    }

    static func parsePOSIX(_ data: Data, observedAt: Date) throws -> HostInventorySnapshot {
        guard let text = String(data: data, encoding: .utf8), text.utf8.count <= 32 * 1_024 else {
            throw ResourceSetupError.inventoryProbeFailed
        }
        let values = text.split(whereSeparator: \Character.isNewline).reduce(
            into: [String: String]()
        ) { result, line in
            let parts = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { return }
            result[String(parts[0])] = String(parts[1])
        }
        let platform: HostPlatform
        switch values["platform"] {
        case "linux": platform = .linux
        case "macos": platform = .macOS
        default: throw ResourceSetupError.inventoryProbeFailed
        }
        return HostInventorySnapshot(
            platform: platform,
            metadata: try metadata(values: values, platform: platform, observedAt: observedAt)
        )
    }

    static func parseWindows(_ data: Data, observedAt: Date) throws -> HostInventorySnapshot {
        guard data.count <= 32 * 1_024,
            let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
            object["platform"] as? String == HostPlatform.windows.rawValue
        else {
            throw ResourceSetupError.inventoryProbeFailed
        }
        var values: [String: String] = [:]
        for key in [
            "platform", "architecture", "os_version", "kernel_release", "cpu_model",
            "hardware_vendor", "hardware_model", "docker_version",
        ] {
            if let value = object[key] as? String { values[key] = value }
        }
        for key in [
            "cpu_logical_count", "memory_total_bytes", "storage_total_bytes",
            "storage_available_bytes",
        ] {
            if let value = object[key] as? NSNumber { values[key] = value.stringValue }
        }
        if let available = object["docker_available"] as? Bool {
            values["docker_available"] = available ? "true" : "false"
        }
        return HostInventorySnapshot(
            platform: .windows,
            metadata: try metadata(values: values, platform: .windows, observedAt: observedAt)
        )
    }

    private static func metadata(
        values: [String: String],
        platform: HostPlatform,
        observedAt: Date
    ) throws -> [ResourceMetadataEntry] {
        var entries = [
            try ResourceMetadataEntry(
                key: "host.os.family",
                value: .text(platform.rawValue),
                observedAt: observedAt
            )
        ]
        appendText("architecture", as: "host.architecture", from: values, to: &entries, observedAt)
        appendText("os_version", as: "host.os.version", from: values, to: &entries, observedAt)
        appendText(
            "kernel_release", as: "host.kernel.release", from: values, to: &entries, observedAt)
        appendText("cpu_model", as: "host.cpu.model", from: values, to: &entries, observedAt)
        appendText(
            "hardware_vendor", as: "host.hardware.vendor", from: values, to: &entries,
            observedAt)
        appendText(
            "hardware_model", as: "host.hardware.model", from: values, to: &entries,
            observedAt)
        appendText(
            "docker_version", as: "host.docker.version", from: values, to: &entries,
            observedAt)

        if let value = values["cpu_logical_count"].flatMap(Int64.init),
            (1...65_536).contains(value)
        {
            entries.append(
                try ResourceMetadataEntry(
                    key: "host.cpu.logical-count",
                    value: .integer(value),
                    observedAt: observedAt
                ))
        }
        for (source, target) in [
            ("memory_total_bytes", "host.memory.total-bytes"),
            ("storage_total_bytes", "host.storage.total-bytes"),
            ("storage_available_bytes", "host.storage.available-bytes"),
        ] {
            if let value = values[source].flatMap(UInt64.init), value > 0 {
                entries.append(
                    try ResourceMetadataEntry(
                        key: target,
                        value: .byteCount(value),
                        observedAt: observedAt
                    ))
            }
        }
        if let value = values["docker_available"], let available = Bool(value) {
            entries.append(
                try ResourceMetadataEntry(
                    key: "host.docker.available",
                    value: .boolean(available),
                    observedAt: observedAt
                ))
        }
        for (source, target) in [
            ("account_is_root", "host.account.is-root"),
            ("docker_account_authorized", "host.docker.account-authorized"),
        ] {
            if let value = values[source], let enabled = Bool(value) {
                entries.append(
                    try ResourceMetadataEntry(
                        key: ResourceMetadataKey(target),
                        value: .boolean(enabled),
                        observedAt: observedAt
                    ))
            }
        }
        return entries.sorted { $0.key.rawValue < $1.key.rawValue }
    }

    private static func appendText(
        _ source: String,
        as target: String,
        from values: [String: String],
        to entries: inout [ResourceMetadataEntry],
        _ observedAt: Date
    ) {
        guard let raw = values[source] else { return }
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, value.utf8.count <= 256,
            let entry = try? ResourceMetadataEntry(
                key: target,
                value: .text(value),
                observedAt: observedAt
            ),
            (try? ResourceMetadataPolicy.validateForPersistence([entry])) != nil
        else { return }
        entries.append(entry)
    }

    private static let linuxProbe = #"""
        printf 'platform=linux\n'
        account_is_root=false
        if [ "$(id -u 2>/dev/null)" = "0" ]; then account_is_root=true; fi
        printf 'account_is_root=%s\n' "$account_is_root"
        printf 'architecture='; uname -m 2>/dev/null | head -n 1
        printf 'kernel_release='; uname -r 2>/dev/null | head -n 1
        printf 'os_version='; awk -F= '/^PRETTY_NAME=/{v=$0; sub(/^[^=]*=/,"",v); gsub(/^"|"$/,"",v); print v; exit}' /etc/os-release 2>/dev/null
        printf 'cpu_logical_count='; getconf _NPROCESSORS_ONLN 2>/dev/null | head -n 1
        printf 'cpu_model='; awk -F: '/^(model name|Hardware)/{v=$2; sub(/^[[:space:]]+/,"",v); print v; exit}' /proc/cpuinfo 2>/dev/null
        printf 'memory_total_bytes='; awk '/^MemTotal:/{printf "%.0f\n",$2*1024; exit}' /proc/meminfo 2>/dev/null
        printf 'storage_total_bytes='; df -Pk / 2>/dev/null | awk 'NR==2{printf "%.0f\n",$2*1024}'
        printf 'storage_available_bytes='; df -Pk / 2>/dev/null | awk 'NR==2{printf "%.0f\n",$4*1024}'
        printf 'hardware_vendor='; head -n 1 /sys/class/dmi/id/sys_vendor 2>/dev/null
        printf 'hardware_model='; head -n 1 /sys/class/dmi/id/product_name 2>/dev/null
        if command -v docker >/dev/null 2>&1; then
          printf 'docker_available=true\n'
          printf 'docker_version='; docker --version 2>/dev/null | head -n 1
          docker_account_authorized=false
          if [ "$account_is_root" = "true" ] || id -Gn 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
            docker_account_authorized=true
          elif [ -S /var/run/docker.sock ] && [ -r /var/run/docker.sock ] && [ -w /var/run/docker.sock ]; then
            docker_account_authorized=true
          elif [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -S "$XDG_RUNTIME_DIR/docker.sock" ] && [ -r "$XDG_RUNTIME_DIR/docker.sock" ] && [ -w "$XDG_RUNTIME_DIR/docker.sock" ]; then
            docker_account_authorized=true
          fi
        else
          printf 'docker_available=false\n'
          docker_account_authorized=false
        fi
        printf 'docker_account_authorized=%s\n' "$docker_account_authorized"
        """#

    private static let macOSProbe = #"""
        printf 'platform=macos\n'
        account_is_root=false
        if [ "$(id -u 2>/dev/null)" = "0" ]; then account_is_root=true; fi
        printf 'account_is_root=%s\n' "$account_is_root"
        printf 'architecture='; uname -m 2>/dev/null | head -n 1
        printf 'kernel_release='; uname -r 2>/dev/null | head -n 1
        printf 'os_version=macOS '; sw_vers -productVersion 2>/dev/null | head -n 1
        printf 'cpu_logical_count='; sysctl -n hw.logicalcpu 2>/dev/null | head -n 1
        printf 'cpu_model='; sysctl -n machdep.cpu.brand_string 2>/dev/null | head -n 1
        printf 'memory_total_bytes='; sysctl -n hw.memsize 2>/dev/null | head -n 1
        printf 'storage_total_bytes='; df -Pk / 2>/dev/null | awk 'NR==2{printf "%.0f\n",$2*1024}'
        printf 'storage_available_bytes='; df -Pk / 2>/dev/null | awk 'NR==2{printf "%.0f\n",$4*1024}'
        printf 'hardware_vendor=Apple\n'
        printf 'hardware_model='; sysctl -n hw.model 2>/dev/null | head -n 1
        if command -v docker >/dev/null 2>&1; then
          printf 'docker_available=true\n'
          printf 'docker_version='; docker --version 2>/dev/null | head -n 1
          docker_account_authorized=false
          if [ "$account_is_root" = "true" ] || id -Gn 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
            docker_account_authorized=true
          elif [ -S /var/run/docker.sock ] && [ -r /var/run/docker.sock ] && [ -w /var/run/docker.sock ]; then
            docker_account_authorized=true
          fi
        else
          printf 'docker_available=false\n'
          docker_account_authorized=false
        fi
        printf 'docker_account_authorized=%s\n' "$docker_account_authorized"
        """#

    private static let windowsProbe: String = {
        let script = #"""
            $ErrorActionPreference = 'Stop'
            $ProgressPreference = 'SilentlyContinue'
            [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
            $OutputEncoding = [Console]::OutputEncoding
            $os = Get-CimInstance Win32_OperatingSystem
            $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
            $computer = Get-CimInstance Win32_ComputerSystem
            $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
            $docker = Get-Command docker.exe -ErrorAction SilentlyContinue
            $dockerVersion = if ($docker) { (& docker.exe --version 2>$null | Select-Object -First 1) } else { $null }
            $result = [ordered]@{
              platform = 'windows'
              architecture = $env:PROCESSOR_ARCHITECTURE
              os_version = (($os.Caption + ' ' + $os.Version).Trim())
              kernel_release = [string]$os.BuildNumber
              cpu_model = [string]$cpu.Name
              cpu_logical_count = [uint64]$computer.NumberOfLogicalProcessors
              memory_total_bytes = [uint64]$computer.TotalPhysicalMemory
              storage_total_bytes = [uint64]$disk.Size
              storage_available_bytes = [uint64]$disk.FreeSpace
              hardware_vendor = [string]$computer.Manufacturer
              hardware_model = [string]$computer.Model
              docker_available = [bool]$docker
              docker_version = [string]$dockerVersion
            } | ConvertTo-Json -Compress
            [Console]::Out.Write($result)
            """#
        return script.data(using: .utf16LittleEndian)?.base64EncodedString() ?? ""
    }()
}

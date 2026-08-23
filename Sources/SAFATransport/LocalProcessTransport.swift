import Foundation

/// Executes a broker-built local-client invocation without involving a shell.
/// The adapter, not Agent input, owns the absolute executable, argv, environment,
/// and any broker-controlled stdin bytes.
public struct LocalProcessTransport: Sendable {
    private let runner: any ProcessRunning

    public init(runner: any ProcessRunning = ProcessRunner()) {
        self.runner = runner
    }

    public func execute(_ invocation: ProcessInvocation) async throws -> ProcessExecutionResult {
        try await runner.run(invocation)
    }
}

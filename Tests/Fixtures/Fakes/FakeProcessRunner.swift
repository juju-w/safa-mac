import SAFATransport

public actor FakeProcessRunner: ProcessRunning {
    private let results: [ProcessExecutionResult]
    private var invocations: [ProcessInvocation] = []

    public init(result: ProcessExecutionResult) {
        results = [result]
    }

    public init(results: [ProcessExecutionResult]) {
        precondition(!results.isEmpty)
        self.results = results
    }

    public func run(_ invocation: ProcessInvocation) -> ProcessExecutionResult {
        invocation.didLaunch?(4242)
        invocations.append(invocation)
        return results[min(invocations.count - 1, results.count - 1)]
    }

    public func lastInvocation() -> ProcessInvocation? {
        invocations.last
    }

    public func invocationCount() -> Int {
        invocations.count
    }

    public func invocation(at index: Int) -> ProcessInvocation? {
        guard invocations.indices.contains(index) else { return nil }
        return invocations[index]
    }
}

public typealias FakeTransport = FakeProcessRunner

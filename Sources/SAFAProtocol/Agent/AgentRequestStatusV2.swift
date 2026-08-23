public struct AgentRequestStatusV2: Equatable, Sendable {
    public let state: String
    public let resource: String?
    public let intent: String?
    public let execution: AgentExecutionResultV2?

    public init(
        state: String,
        resource: String? = nil,
        intent: String? = nil,
        execution: AgentExecutionResultV2? = nil
    ) {
        self.state = state
        self.resource = resource
        self.intent = intent
        self.execution = execution
    }
}

public struct AgentSudoStatusV2: Equatable, Sendable {
    public let alias: String
    public let state: String
    public let mode: String?
    public let accountIsRoot: Bool?

    public init(
        alias: String,
        state: String,
        mode: String?,
        accountIsRoot: Bool? = nil
    ) {
        self.alias = alias
        self.state = state
        self.mode = mode
        self.accountIsRoot = accountIsRoot
    }
}

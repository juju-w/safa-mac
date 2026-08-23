import SAFAProtocol

protocol AgentCLIToonPayload: Sendable {
    func toonFields() -> [TOONField]
}

extension AgentNoPayloadV2: AgentCLIToonPayload {
    func toonFields() -> [TOONField] { [] }
}

extension AgentHomePayloadV2: AgentCLIToonPayload {
    func toonFields() -> [TOONField] {
        [
            TOONField(key: "bin", value: .string(binary)),
            TOONField(key: "description", value: .string(description)),
            TOONField(key: "broker", value: .string(broker)),
            TOONField(key: "vault", value: .string(vault)),
        ] + resources.toonFields()
    }
}

extension AgentHelpPayloadV2: AgentCLIToonPayload {
    func toonFields() -> [TOONField] {
        [TOONField(key: "help", value: .string(text))]
    }
}

extension AgentRuntimeStatusV2: AgentCLIToonPayload {
    func toonFields() -> [TOONField] {
        [
            TOONField(key: "broker", value: .string(broker)),
            TOONField(key: "vault", value: .string(vault)),
            TOONField(key: "http_client", value: .string(httpClient)),
        ]
    }
}

extension AgentSudoStatusV2: AgentCLIToonPayload {
    func toonFields() -> [TOONField] {
        [
            TOONField(
                key: "sudo",
                value: .object([
                    TOONField(key: "alias", value: .string(alias)),
                    TOONField(key: "state", value: .string(state)),
                    TOONField(key: "mode", value: mode.map(TOONValue.string) ?? .null),
                    TOONField(
                        key: "account_is_root",
                        value: accountIsRoot.map(TOONValue.boolean) ?? .null
                    ),
                ])
            )
        ]
    }
}

extension AgentBrokerLifecycleV2: AgentCLIToonPayload {
    func toonFields() -> [TOONField] {
        [TOONField(key: "broker_service_status", value: .string(brokerServiceStatus))]
    }
}

extension AgentUsageFailureV2: AgentCLIToonPayload {
    func toonFields() -> [TOONField] {
        [
            TOONField(
                key: "valid_flags",
                value: .array(validFlags.map(TOONValue.string))
            )
        ]
    }
}

extension AgentResourceListV2: AgentCLIToonPayload {
    func toonFields() -> [TOONField] {
        [
            TOONField(
                key: "count",
                value: .object([
                    TOONField(key: "total", value: .integer(Int64(clamping: total))),
                    TOONField(key: "returned", value: .integer(Int64(clamping: returned))),
                    TOONField(key: "truncated", value: .boolean(truncated)),
                ])
            ),
            TOONField(
                key: "resources",
                value: .array(resources.map { $0.toonValue(fields: fields) })
            ),
        ]
    }
}

extension AgentExecutionResultV2: AgentCLIToonPayload {
    func toonFields() -> [TOONField] {
        [
            TOONField(key: "resource", value: .string(resource)),
            TOONField(key: "intent", value: .string(intent)),
            TOONField(
                key: "execution",
                value: .object([
                    TOONField(key: "termination", value: .string(termination)),
                    TOONField(
                        key: "remote_exit_code",
                        value: remoteExitCode.map { .integer(Int64($0)) } ?? .null
                    ),
                    TOONField(key: "stdout", value: stdout.toonValue),
                    TOONField(key: "stderr", value: stderr.toonValue),
                ])
            ),
        ]
    }
}

extension AgentRequestStatusV2: AgentCLIToonPayload {
    func toonFields() -> [TOONField] {
        var fields = [TOONField(key: "request_state", value: .string(state))]
        if let resource {
            fields.append(TOONField(key: "resource", value: .string(resource)))
        }
        if let intent {
            fields.append(TOONField(key: "intent", value: .string(intent)))
        }
        if let execution {
            fields.append(TOONField(key: "execution", value: execution.executionToonValue))
        }
        return fields
    }
}

private extension AgentTextPreviewV2 {
    var toonValue: TOONValue {
        .object([
            TOONField(key: "content_type", value: .string(contentType)),
            TOONField(key: "text", value: .string(text)),
            TOONField(key: "captured_bytes", value: .integer(Int64(clamping: capturedBytes))),
            TOONField(key: "original_bytes", value: .integer(Int64(clamping: originalBytes))),
            TOONField(key: "truncated", value: .boolean(truncated)),
        ])
    }
}

private extension AgentExecutionResultV2 {
    var executionToonValue: TOONValue {
        .object([
            TOONField(key: "termination", value: .string(termination)),
            TOONField(
                key: "remote_exit_code",
                value: remoteExitCode.map { .integer(Int64($0)) } ?? .null
            ),
            TOONField(key: "stdout", value: stdout.toonValue),
            TOONField(key: "stderr", value: stderr.toonValue),
        ])
    }
}

private extension AgentResourceRowV2 {
    func toonValue(fields: [AgentResourceListFieldV2]) -> TOONValue {
        .object(
            fields.map { field in
                switch field {
                case .alias: TOONField(key: field.rawValue, value: .string(alias))
                case .kind: TOONField(key: field.rawValue, value: .string(kind))
                case .state: TOONField(key: field.rawValue, value: .string(state))
                case .health: TOONField(key: field.rawValue, value: .string(health))
                case .resourceType:
                    TOONField(
                        key: field.rawValue,
                        value: resourceType.map(TOONValue.string) ?? .null
                    )
                case .templateID:
                    TOONField(
                        key: field.rawValue,
                        value: templateID.map(TOONValue.string) ?? .null
                    )
                case .hostPlatform:
                    TOONField(
                        key: field.rawValue,
                        value: hostPlatform.map(TOONValue.string) ?? .null
                    )
                }
            }
        )
    }
}

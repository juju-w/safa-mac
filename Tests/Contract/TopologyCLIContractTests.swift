import SAFADomain
import Testing

@testable import SAFACLI

@Suite("Simple topology CLI")
struct TopologyCLIContractTests {
    @Test("the model-facing topology surface has five semantic verbs")
    func commandSurface() throws {
        let names = TopologyCommand.configuration.subcommands.compactMap {
            $0.configuration.commandName
        }
        #expect(names == ["show", "path", "impact", "link", "unlink"])

        let show = try #require(
            try SAFACommand.parseAsRoot([
                "topology", "show", "service.data-api", "--limit", "12", "--fields",
                "alias,kind",
            ])
                as? TopologyShowCommand
        )
        #expect(try show.query().source == ResourceAlias("service.data-api"))
        #expect(try show.query().bounds.maximumNodes == 12)
        #expect(try show.requestedFields() == [.alias, .kind])

        let path = try #require(
            try SAFACommand.parseAsRoot([
                "topology", "path", "host.compute-a", "service.data-api", "--limit", "10",
            ]) as? TopologyPathCommand
        )
        #expect(try path.query().task == .reachability)
        #expect(try path.query().bounds.maximumNodes == 10)

        let impact = try #require(
            try SAFACommand.parseAsRoot(["topology", "impact", "storage.reports"])
                as? TopologyImpactCommand
        )
        #expect(try impact.query().task == .dependencyImpact)

        let link = try #require(
            try SAFACommand.parseAsRoot([
                "topology", "link", "service.worker", "depends-on", "service.data-api",
            ]) as? TopologyLinkCommand
        )
        #expect(try link.mutation().relation == .dependsOn)

        #expect(
            try SAFACommand.parseAsRoot([
                "topology", "unlink", "service.worker", "depends-on", "service.data-api",
            ]) is TopologyUnlinkCommand
        )
    }

    @Test("topology CLI rejects invented relations and all sensitive connection flags")
    func rejectsUnsafeInputs() {
        for arguments in [
            ["topology", "link", "service.a", "invented", "service.b"],
            ["topology", "path", "service.a", "service.b", "--endpoint", "192.0.2.7"],
            ["topology", "show", "service.a", "--username", "root"],
            ["topology", "link", "service.a", "depends-on", "service.b", "--verified"],
        ] {
            #expect(topologyCommandParsingFails(arguments))
        }
    }

    @Test("topology bounds and fields fail before Broker work")
    func projectionInputValidation() throws {
        for limit in ["0", "65"] {
            let command = try #require(
                try SAFACommand.parseAsRoot([
                    "topology", "show", "--limit", limit,
                ]) as? TopologyShowCommand
            )
            #expect(throws: TopologyCLIInputError.invalidLimit) {
                try command.query()
            }
        }

        for fields in ["kind", "alias,endpoint", "alias,alias"] {
            let command = try #require(
                try SAFACommand.parseAsRoot([
                    "topology", "show", "--fields", fields,
                ]) as? TopologyShowCommand
            )
            #expect(throws: TopologyCLIInputError.invalidFields) {
                try command.requestedFields()
            }
        }
    }
}

private func topologyCommandParsingFails(_ arguments: [String]) -> Bool {
    do {
        let command = try SAFACommand.parseAsRoot(arguments)
        if let link = command as? TopologyLinkCommand {
            _ = try link.mutation()
        }
        return false
    } catch {
        return true
    }
}

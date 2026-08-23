import Foundation
import SAFADomain
import SAFAProtocol
import Testing

@testable import SAFACLI

@Suite("Safe resource CLI projection")
struct ResourceCLIContractTests {
    @Test("resource alias completion is sorted, prefix filtered, and duplicate free")
    func resourceAliasCompletion() {
        #expect(
            ResourceCLICompletion.filterAliases(
                ["hm-105", "home-nec-win", "hm-104", "hm-105"],
                prefix: "hm-"
            ) == ["hm-104", "hm-105"]
        )
    }

    @Test(
        "resource CLI exposes the five CRUD commands, an ls alias, and the sudo enrollment command")
    func cliFirstCommandSurface() throws {
        let publicCommands = ResourceCommand.configuration.subcommands
            .compactMap { $0.configuration.commandName }
        #expect(publicCommands == ["list", "show", "add", "edit", "remove", "sudo"])

        #expect(ResourceShowCommand.configuration.abstract.contains("--details"))
        #expect(try SAFACommand.parseAsRoot(["resource", "list"]) is ResourceListCommand)
        #expect(try SAFACommand.parseAsRoot(["resource", "ls"]) is ResourceListCommand)
        #expect(
            try SAFACommand.parseAsRoot(["resource", "sudo", "nas.primary"]) is ResourceSudoCommand)
        #expect(
            try SAFACommand.parseAsRoot(["resource", "sudo", "nas.primary", "--passwordless"])
                is ResourceSudoCommand)
        #expect(
            try SAFACommand.parseAsRoot(["resource", "sudo", "nas.primary", "--status"])
                is ResourceSudoCommand)
        #expect(
            AgentCLIInvocation.validFlags("resource.sudo")
                == ["--status", "--passwordless", "--remove", "--help"])
        #expect(AgentCLIInvocation.validFlags("exec").contains("--privilege"))
        for arguments in [
            ["resource", "sudo", "nas.primary", "--status", "--remove"],
            ["resource", "sudo", "nas.primary", "--passwordless", "--remove"],
        ] {
            #expect(throws: (any Error).self) {
                _ = try SAFACommand.parseAsRoot(arguments)
            }
        }
        let activeList = try #require(
            try SAFACommand.parseAsRoot([
                "resource", "list", "--state", "active", "--limit", "25", "--fields",
                "alias,state,resource_type",
            ])
                as? ResourceListCommand
        )
        #expect(try activeList.requestedState() == .active)
        #expect(try activeList.requestedLimit() == 25)
        #expect(try activeList.requestedFields() == [.alias, .state, .resourceType])
        let detailedShow = try #require(
            try SAFACommand.parseAsRoot(["resource", "show", "nas.home", "--details"])
                as? ResourceShowCommand
        )
        #expect(detailedShow.details)
        #expect(
            try SAFACommand.parseAsRoot([
                "resource", "add", "nas.home", "--from-ssh-config", "home-nas",
            ]) is ResourceAddCommand
        )
        let serviceAdd = try #require(
            try SAFACommand.parseAsRoot([
                "resource", "add", "mysql.test", "--template", "mysql",
            ]) as? ResourceAddCommand
        )
        let (_, serviceMutation) = try serviceAdd.mutationInput()
        #expect(serviceMutation.templateID == .mysql)
        #expect(serviceMutation.resourceType == .databaseMySQL)
        let mismatchedTemplate = try #require(
            try SAFACommand.parseAsRoot([
                "resource", "add", "mysql.test", "--template", "mysql", "--type",
                "host.windows",
            ]) as? ResourceAddCommand
        )
        #expect(throws: ResourceMutationInputError.typeDoesNotMatchTemplate) {
            try mismatchedTemplate.mutationInput()
        }
        let edit = try #require(
            try SAFACommand.parseAsRoot([
                "resource", "edit", "nas.home", "--from-ssh-config", "home-nas",
            ]) as? ResourceEditCommand
        )
        let (_, editMutation) = try edit.mutationInput()
        #expect(editMutation.desiredState == nil)

        let disable = try #require(
            try SAFACommand.parseAsRoot([
                "resource", "edit", "nas.home", "--state", "disabled",
            ]) as? ResourceEditCommand
        )
        let (_, disableMutation) = try disable.mutationInput()
        #expect(disableMutation.desiredState == .disabled)

        let enable = try #require(
            try SAFACommand.parseAsRoot([
                "resource", "edit", "nas.home", "--state", "active",
                "--from-ssh-config", "home-nas",
            ]) as? ResourceEditCommand
        )
        let (_, enableMutation) = try enable.mutationInput()
        #expect(enableMutation.desiredState == .active)
        #expect(enableMutation.sourceSSHConfigAlias.rawValue == "home-nas")

        #expect(
            try SAFACommand.parseAsRoot(["resource", "remove", "nas.home"])
                is ResourceRemoveCommand
        )
        #expect(try SAFACommand.parseAsRoot(["setup", "status"]) is SetupStatusCommand)
        #expect(try SAFACommand.parseAsRoot(["setup", "activate"]) is SetupActivateCommand)
        #expect(try SAFACommand.parseAsRoot(["setup", "deactivate"]) is SetupDeactivateCommand)

        for retiredLifecycleCommand in ["inspect", "setup", "disable", "enable"] {
            #expect(
                commandParsingFails(["resource", retiredLifecycleCommand, "nas.home"])
            )
        }

        for forbiddenSecretInput in [
            ["resource", "add", "nas.home", "--password", "secret"],
            ["resource", "add", "nas.home", "--host", "10.0.0.7"],
            ["resource", "add", "nas.home", "--username", "root"],
            ["resource", "edit", "nas.home", "--private-key", "/tmp/id"],
            ["resource", "edit", "nas.home", "--sudo-password", "secret"],
            ["resource", "add", "nas.home", "--display-name", "Private name"],
            ["setup", "open"],
            ["exec", "nas.home", "--intent", "check", "--sudo", "--", "uptime"],
        ] {
            #expect(commandParsingFails(forbiddenSecretInput))
        }
    }

    @Test("exec privilege is typed and omission remains user")
    func typedExecPrivilege() async throws {
        let omitted = try await ExecCommand.asyncParse([
            "worker.batch", "--intent", "Read uid", "--", "id", "-u",
        ])
        let automatic = try await ExecCommand.asyncParse([
            "worker.batch", "--intent", "Read uid", "--privilege", "auto", "--", "id", "-u",
        ])

        #expect(omitted.privilege == .user)
        #expect(automatic.privilege == .auto)
    }

    @Test("sudo enrollment returns a non-agent local retry when protected setup is incomplete")
    func sudoEnrollmentLocalRetry() throws {
        let alias = try ResourceAlias("nas.primary")
        let response = ResourceSudoCommand.localActionRequired(
            alias: alias,
            passwordless: false,
            remove: false
        )

        #expect(response.status == .userActionRequired)
        #expect(response.error?.code == "sudo.enrollment_incomplete")
        #expect(response.next.count == 1)
        #expect(response.next[0].command == "safa resource sudo nas.primary")
        #expect(!response.next[0].safeForAgent)

        #expect(
            ResourceSudoCommand.trustedLocalCommand(
                alias: alias,
                passwordless: true,
                remove: false
            ) == "safa resource sudo nas.primary --passwordless"
        )
        #expect(
            ResourceSudoCommand.trustedLocalCommand(
                alias: alias,
                passwordless: false,
                remove: true
            ) == "safa resource sudo nas.primary --remove"
        )
    }

    @Test("sudo status is safe, explicit, and reports credential mode")
    func sudoStatusProjection() {
        let passwordless = ResourceSummaryV1(
            alias: "nas.primary",
            displayName: nil,
            resourceType: "host.linux",
            kind: "host",
            templateID: "linux-host",
            templateVersion: 1,
            hostPlatform: "linux",
            roles: [],
            state: "active",
            health: "ready",
            capabilities: ["exec", "sudo"],
            sudoMode: "passwordless",
            metadata: []
        )
        let ready = ResourceSudoCommand.statusResponse(summary: passwordless)
        #expect(ready.command == "resource.sudo.status")
        #expect(ready.status == .completed)
        #expect(ready.payload.state == "ready")
        #expect(ready.payload.mode == "passwordless")
        #expect(ready.next.isEmpty)

        let missing = ResourceSummaryV1(
            alias: "nas.primary",
            displayName: nil,
            resourceType: "host.linux",
            kind: "host",
            templateID: "linux-host",
            templateVersion: 1,
            hostPlatform: "linux",
            roles: [],
            state: "active",
            health: "ready",
            capabilities: ["exec"],
            metadata: []
        )
        let absent = ResourceSudoCommand.statusResponse(summary: missing)
        #expect(absent.payload.state == "missing")
        #expect(absent.payload.mode == nil)
        #expect(absent.next.count == 1)
        #expect(absent.next[0].command == "safa resource sudo nas.primary")
        #expect(!absent.next[0].safeForAgent)

        let incomplete = ResourceSummaryV1(
            alias: "nas.primary",
            displayName: nil,
            resourceType: "host.linux",
            kind: "host",
            templateID: "linux-host",
            templateVersion: 1,
            hostPlatform: "linux",
            roles: [],
            state: "active",
            health: "ready",
            capabilities: ["exec", "sudo"],
            metadata: []
        )
        let invalid = ResourceSudoCommand.statusResponse(summary: incomplete)
        #expect(invalid.payload.state == "invalid")
        #expect(invalid.next[0].command == "safa resource sudo nas.primary")
        #expect(!invalid.next[0].safeForAgent)

        let rootAccount = ResourceSummaryV1(
            alias: "nas.primary",
            displayName: nil,
            resourceType: "host.linux",
            kind: "host",
            templateID: "linux-host",
            templateVersion: 1,
            hostPlatform: "linux",
            roles: [],
            state: "active",
            health: "ready",
            capabilities: ["exec"],
            metadata: [
                ResourceMetadataEntryV1(
                    key: "host.account.is-root",
                    value: .boolean(true)
                )
            ]
        )
        let root = ResourceSudoCommand.statusResponse(summary: rootAccount)
        #expect(root.payload.state == "not_required")
        #expect(root.payload.accountIsRoot == true)
        #expect(root.next.isEmpty)
        let enrollmentNoOp = ResourceSudoCommand.rootAccountEnrollmentNoOp(summary: rootAccount)
        #expect(enrollmentNoOp?.command == "resource.sudo")
        #expect(enrollmentNoOp?.status == .noOp)
        #expect(enrollmentNoOp?.payload.state == "not_required")
        #expect(ResourceSudoCommand.rootAccountEnrollmentNoOp(summary: missing) == nil)
    }

    @Test("resource list rejects unknown and deleted state filters")
    func listStateValidation() throws {
        for state in ["unknown", "deleted"] {
            let command = try #require(
                try SAFACommand.parseAsRoot(["resource", "list", "--state", state])
                    as? ResourceListCommand
            )
            #expect(throws: ResourceListInputError.invalidState) {
                try command.requestedState()
            }
        }
    }

    @Test("resource list bounds rows and rejects unsafe field selections")
    func listProjectionValidation() throws {
        for arguments in [
            ["resource", "list", "--limit", "0"],
            ["resource", "list", "--limit", "501"],
        ] {
            let command = try #require(
                try SAFACommand.parseAsRoot(arguments) as? ResourceListCommand
            )
            #expect(throws: ResourceListInputError.invalidLimit) {
                try command.requestedLimit()
            }
        }

        for fields in ["state,health", "alias,endpoint", "alias,alias"] {
            let command = try #require(
                try SAFACommand.parseAsRoot([
                    "resource", "list", "--fields", fields,
                ]) as? ResourceListCommand
            )
            #expect(throws: ResourceListInputError.invalidFields) {
                try command.requestedFields()
            }
        }
    }

    @Test("resource edit rejects unsupported or ambiguous state changes")
    func editStateValidation() throws {
        let draft = try #require(
            try SAFACommand.parseAsRoot([
                "resource", "edit", "nas.home", "--state", "draft",
            ]) as? ResourceEditCommand
        )
        #expect(throws: ResourceMutationInputError.unsupportedDesiredState) {
            try draft.mutationInput()
        }

        let combined = try #require(
            try SAFACommand.parseAsRoot([
                "resource", "edit", "nas.home", "--state", "disabled",
                "--type", "host.linux",
            ]) as? ResourceEditCommand
        )
        #expect(throws: ResourceMutationInputError.stateCannotCombineWithConfiguration) {
            try combined.mutationInput()
        }
    }

    @Test("add launches only reviewed SSH and HTTP trusted setup flows")
    func trustedSetupRemediationSelection() {
        #expect(
            ResourceAddCommand.shouldLaunchTrustedSetup(
                errorCode: "ssh_config_alias_not_found",
                resourceType: .hostLinux,
                hasExplicitSSHConfigAlias: false
            )
        )
        #expect(
            ResourceAddCommand.shouldLaunchTrustedSetup(
                errorCode: "ssh_authentication_setup_required",
                resourceType: .hostLinux,
                hasExplicitSSHConfigAlias: true
            )
        )
        #expect(
            !ResourceAddCommand.shouldLaunchTrustedSetup(
                errorCode: "host_identity_setup_required",
                resourceType: .hostLinux,
                hasExplicitSSHConfigAlias: false
            )
        )
        #expect(
            ResourceAddCommand.shouldLaunchTrustedSetup(
                errorCode: "trusted_service_setup_required",
                resourceType: .serviceHTTP,
                hasExplicitSSHConfigAlias: false
            )
        )
        #expect(
            !ResourceAddCommand.shouldLaunchTrustedSetup(
                errorCode: "trusted_service_setup_required",
                resourceType: .databaseMySQL,
                hasExplicitSSHConfigAlias: false
            )
        )
    }

    @Test("resource list exposes only logical operational metadata")
    func safeProjection() throws {
        let resource = TestResourceFactory.active(
            alias: "nas.home",
            metadata: [
                try ResourceMetadataEntry(key: "host.os.family", value: .text("linux")),
                try ResourceMetadataEntry(key: "host.kernel.release", value: .text("6.8.0")),
                try ResourceMetadataEntry(key: "private.network.address", value: .text("10.0.0.7")),
            ]
        )
        let registry = try ResourceRegistry(resources: [resource])
        let projection = try #require(registry.list(state: .active).first)
        let bytes = try CanonicalCodec.encode(projection)
        let text = try #require(String(data: bytes, encoding: .utf8))

        #expect(projection.alias.rawValue == "nas.home")
        #expect(projection.displayName == nil)
        #expect(projection.resourceType == .hostLinux)
        #expect(projection.capabilities == ["exec"])
        #expect(projection.summaryMetadata.map(\.key.rawValue) == ["host.os.family"])
        #expect(!text.contains("203.0.113.10"))
        #expect(!text.contains("10.0.0.7"))
        #expect(!text.contains("6.8.0"))
        #expect(!text.contains("diagnostic-user"))
        #expect(!text.contains(resource.id.uuidString))
        #expect(!text.contains(resource.authRef!.uuidString))
    }

    @Test("unknown aliases produce a non-secret not-found error")
    func unknownResource() throws {
        let registry = try ResourceRegistry(resources: [])
        #expect(throws: ResourceRegistryError.notFound(alias: "missing.host")) {
            try registry.resource(alias: ResourceAlias("missing.host"))
        }
    }
}

private func commandParsingFails(_ arguments: [String]) -> Bool {
    do {
        _ = try SAFACommand.parseAsRoot(arguments)
        return false
    } catch {
        return true
    }
}

enum TestResourceFactory {
    static func active(
        alias: String,
        metadata: [ResourceMetadataEntry] = []
    ) -> Resource {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return Resource(
            id: UUID(uuidString: "10000000-0000-4000-8000-000000000001")!,
            alias: try! ResourceAlias(alias),
            resourceType: .hostLinux,
            accessMethods: [.ssh],
            metadata: metadata,
            endpoint: ResourceEndpoint(host: "203.0.113.10", port: 2222),
            username: "diagnostic-user",
            securityDomain: "synthetic",
            hostIdentity: HostIdentity(
                algorithm: "ssh-ed25519",
                publicKey: Data(repeating: 7, count: 32),
                fingerprint: "SHA256:synthetic",
                verifiedAt: now,
                verificationMethod: .manual,
                status: .trusted
            ),
            authRef: UUID(uuidString: "20000000-0000-4000-8000-000000000001"),
            revision: 1,
            state: .active,
            createdAt: now,
            updatedAt: now
        )
    }
}

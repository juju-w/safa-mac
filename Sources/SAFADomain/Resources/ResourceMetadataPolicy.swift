import Foundation

public enum ResourceMetadataPolicyError: Error, Equatable, Sendable {
    case sensitiveOrInvalidValue(String)
}

/// Keeps credential and key material out of typed resource metadata while
/// preserving non-secret extension fields as protected detail.
public enum ResourceMetadataPolicy {
    public static func validateForPersistence(_ entries: [ResourceMetadataEntry]) throws {
        for entry in entries {
            guard isApprovedAuthorizedEntry(entry) else {
                throw ResourceMetadataPolicyError.sensitiveOrInvalidValue(entry.key.rawValue)
            }
        }
    }

    public static func authorizedEntries(from entries: [ResourceMetadataEntry])
        -> [ResourceMetadataEntry]
    {
        entries.filter(isApprovedAuthorizedEntry)
    }

    private static func isApprovedAuthorizedEntry(_ entry: ResourceMetadataEntry) -> Bool {
        if ResourceSummaryDisclosure.allowedMetadataKeys.contains(entry.key) {
            return ResourceSummaryDisclosure.isApprovedPublicEntry(entry)
        }
        switch (entry.key.rawValue, entry.value) {
        case ("host.architecture", .text(let value)),
            ("host.os.version", .text(let value)),
            ("host.kernel.release", .text(let value)),
            ("host.cpu.model", .text(let value)),
            ("host.docker.version", .text(let value)),
            ("host.hardware.vendor", .text(let value)),
            ("host.hardware.model", .text(let value)):
            return isSafeOperationalText(value)
        case ("host.cpu.logical-count", .integer(let value)):
            return (1...65_536).contains(value)
        case ("host.memory.total-bytes", .byteCount),
            ("host.storage.total-bytes", .byteCount),
            ("host.storage.available-bytes", .byteCount):
            return true
        default:
            return !isSensitiveKey(entry.key) && isSafeExtensionValue(entry.value)
        }
    }

    private static func isSensitiveKey(_ key: ResourceMetadataKey) -> Bool {
        let components = key.rawValue.split(whereSeparator: { $0 == "." || $0 == "-" })
            .map(String.init)
        guard components.first != "ssh" else { return true }

        let forbiddenComponents: Set<String> = [
            "accesskey", "apikey", "auth", "authentication", "authorization", "authheader", "cert",
            "certificate", "certificates", "connectionstring", "credential", "credentials", "dsn",
            "fingerprint", "identity", "jwk", "jwks", "key", "keychain", "keypair", "keypairs",
            "keys", "locator", "passcode", "passcodes", "passphrase", "passphrases", "passwd",
            "password", "passwords", "pem", "pin", "pincode", "pincodes", "pins", "privatekey",
            "publickey", "secret", "secretkey", "secrets", "token", "tokens",
        ]
        guard !components.contains(where: forbiddenComponents.contains) else { return true }

        return components.indices.dropLast().contains { index in
            components[index] == "connection"
                && components[components.index(after: index)] == "string"
        }
    }

    private static func isSafeExtensionValue(_ value: ResourceMetadataValue) -> Bool {
        switch value {
        case .text(let value):
            return isSafeOperationalText(value)
        case .integer, .boolean, .byteCount:
            return true
        case .textList(let values):
            return values.count <= 64 && values.allSatisfy(isSafeOperationalText)
                && isSafeTextContent(values.joined())
                && isSafeTextContent(values.joined(separator: " "))
        }
    }

    private static func isSafeOperationalText(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 256,
            value.unicodeScalars.allSatisfy({
                !CharacterSet.controlCharacters.contains($0)
            })
        else { return false }

        return isSafeTextContent(value)
    }

    private static func isSafeTextContent(_ value: String) -> Bool {
        let lowered = value.lowercased()
        let forbiddenFormats = [
            "-----begin ", "private-lines:", "private-mac:", "putty-user-key-file-",
        ]
        guard !forbiddenFormats.contains(where: lowered.contains),
            !containsOpenSSHPublicKey(value),
            !containsEncodedKeyMaterial(value),
            !containsAuthorizationCredential(value),
            !containsCompactJOSECredential(value),
            !containsCredentialBearingURI(value),
            !containsJSONDocument(value)
        else { return false }

        let forbiddenTerms: Set<String> = [
            "accesskey", "apikey", "cert", "certificate", "certificates", "credential",
            "credentials", "identity", "key", "keychain", "keypair", "keypairs", "keys",
            "locator", "passwd", "password", "passwords", "pem", "privatekey", "publickey",
            "secret", "secretkey", "secrets", "token", "tokens",
        ]
        let terms = lowered.split(whereSeparator: { !$0.isLetter && !$0.isNumber })
            .map(String.init)
        return !terms.contains(where: forbiddenTerms.contains)
    }

    private static func containsOpenSSHPublicKey(_ value: String) -> Bool {
        let fields = value.split(whereSeparator: { $0.isWhitespace })
        guard fields.count >= 2 else { return false }

        return fields.indices.dropLast().contains { index in
            let algorithm = fields[index].lowercased()
            let payload = fields[fields.index(after: index)]
            return isOpenSSHAlgorithm(algorithm) && payload.hasPrefix("AAAA")
        }
    }

    private static func isOpenSSHAlgorithm(_ value: some StringProtocol) -> Bool {
        let algorithm = value.lowercased()
        return algorithm.hasPrefix("ssh-")
            || algorithm.hasPrefix("ecdsa-sha2-")
            || algorithm.hasPrefix("sk-ssh-")
            || algorithm.hasPrefix("sk-ecdsa-sha2-")
    }

    private static func containsEncodedKeyMaterial(_ value: String) -> Bool {
        let base64Characters = CharacterSet(
            charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_="
        )
        let fragments = value.split(whereSeparator: { $0.isWhitespace }).map {
            String($0)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"',;"))
        }
        guard fragments.count <= 64 else { return true }

        for startIndex in fragments.indices {
            var candidate = ""
            for fragmentIndex in startIndex..<fragments.endIndex {
                let fragment = fragments[fragmentIndex]
                guard !fragment.isEmpty,
                    fragment.unicodeScalars.allSatisfy(base64Characters.contains)
                else { break }
                candidate += fragment
                guard candidate.utf8.count >= 20,
                    let decoded = decodeBase64URL(candidate)
                else { continue }

                if containsEncodedKeyMaterial([UInt8](decoded)) {
                    return true
                }
            }
        }
        return false
    }

    private static func containsEncodedKeyMaterial(_ bytes: [UInt8]) -> Bool {
        bytes.starts(with: [UInt8]("openssh-key-v1\0".utf8))
            || isOpenSSHPublicKeyWireFormat(bytes)
            || isDERPrivateKey(bytes)
            || isDERPKCS12(bytes)
            || isDERCertificate(bytes)
            || isDERSubjectPublicKeyInfo(bytes)
            || isDERRSAPublicKey(bytes)
    }

    private static func isDERRSAPublicKey(_ bytes: [UInt8]) -> Bool {
        guard let publicKey = derElement(in: bytes, at: 0),
            publicKey.tag == 0x30,
            publicKey.nextIndex == bytes.count,
            let modulus = derElement(in: bytes, at: publicKey.contentRange.lowerBound),
            modulus.tag == 0x02,
            modulus.contentRange.count >= 64,
            let exponent = derElement(in: bytes, at: modulus.nextIndex),
            exponent.tag == 0x02,
            (1...5).contains(exponent.contentRange.count),
            exponent.nextIndex == publicKey.contentRange.upperBound
        else { return false }

        var exponentValue: UInt64 = 0
        for byte in bytes[exponent.contentRange] {
            exponentValue = (exponentValue << 8) | UInt64(byte)
        }
        return exponentValue > 1 && exponentValue.isMultiple(of: 2) == false
    }

    private static func isDERPKCS12(_ bytes: [UInt8]) -> Bool {
        guard let pfx = derElement(in: bytes, at: 0),
            pfx.tag == 0x30,
            pfx.nextIndex == bytes.count,
            let version = derElement(in: bytes, at: pfx.contentRange.lowerBound),
            version.tag == 0x02,
            version.contentRange.count == 1,
            version.contentRange.first.map({ bytes[$0] }) == 3,
            let authSafe = derElement(in: bytes, at: version.nextIndex),
            authSafe.tag == 0x30,
            let contentType = derElement(in: bytes, at: authSafe.contentRange.lowerBound),
            contentType.tag == 0x06,
            let contentTypeIdentifier = decodeDERObjectIdentifier(bytes[contentType.contentRange]),
            ["1.2.840.113549.1.7.1", "1.2.840.113549.1.7.2"]
                .contains(contentTypeIdentifier),
            let content = derElement(in: bytes, at: contentType.nextIndex),
            content.tag == 0xA0,
            content.nextIndex == authSafe.contentRange.upperBound
        else { return false }

        if authSafe.nextIndex == pfx.contentRange.upperBound {
            return true
        }
        guard let macData = derElement(in: bytes, at: authSafe.nextIndex),
            macData.tag == 0x30,
            macData.nextIndex == pfx.contentRange.upperBound
        else { return false }
        return true
    }

    private static func isOpenSSHPublicKeyWireFormat(_ bytes: [UInt8]) -> Bool {
        guard let algorithmField = sshWireField(in: bytes, at: 0),
            let algorithm = String(bytes: bytes[algorithmField], encoding: .utf8),
            isOpenSSHAlgorithm(algorithm)
        else { return false }

        var cursor = algorithmField.upperBound
        var payloadFieldCount = 0
        while cursor < bytes.count {
            guard let field = sshWireField(in: bytes, at: cursor) else { return false }
            payloadFieldCount += 1
            cursor = field.upperBound
        }
        return payloadFieldCount > 0
    }

    private static func sshWireField(in bytes: [UInt8], at index: Int) -> Range<Int>? {
        guard index >= 0, index + 4 <= bytes.count else { return nil }
        let length =
            (Int(bytes[index]) << 24)
            | (Int(bytes[index + 1]) << 16)
            | (Int(bytes[index + 2]) << 8)
            | Int(bytes[index + 3])
        let contentStart = index + 4
        guard length <= bytes.count - contentStart else { return nil }
        return contentStart..<(contentStart + length)
    }

    private static func isDERPrivateKey(_ bytes: [UInt8]) -> Bool {
        guard let outer = derElement(in: bytes, at: 0),
            outer.tag == 0x30,
            outer.nextIndex == bytes.count,
            let first = derElement(in: bytes, at: outer.contentRange.lowerBound)
        else { return false }

        if first.tag == 0x30,
            let encryptedData = derElement(in: bytes, at: first.nextIndex),
            encryptedData.tag == 0x04,
            encryptedData.nextIndex == outer.contentRange.upperBound,
            isPasswordBasedEncryptionAlgorithm(in: bytes, algorithm: first)
        {
            return true
        }

        guard first.tag == 0x02,
            first.contentRange.count == 1,
            let versionValue = first.contentRange.first.map({ bytes[$0] }),
            versionValue == 0 || versionValue == 1,
            let second = derElement(in: bytes, at: first.nextIndex)
        else { return false }

        if second.tag == 0x02 || (versionValue == 1 && second.tag == 0x04) {
            return true
        }
        guard second.tag == 0x30,
            let privateKey = derElement(in: bytes, at: second.nextIndex)
        else { return false }
        return privateKey.tag == 0x04
    }

    private static func isPasswordBasedEncryptionAlgorithm(
        in bytes: [UInt8],
        algorithm: DERElement
    ) -> Bool {
        guard let identifier = derElement(in: bytes, at: algorithm.contentRange.lowerBound),
            identifier.tag == 0x06,
            let objectIdentifier = decodeDERObjectIdentifier(bytes[identifier.contentRange])
        else { return false }

        let pkcs5EncryptionSchemes: Set<String> = [
            "1.2.840.113549.1.5.1",
            "1.2.840.113549.1.5.3",
            "1.2.840.113549.1.5.4",
            "1.2.840.113549.1.5.6",
            "1.2.840.113549.1.5.10",
            "1.2.840.113549.1.5.11",
            "1.2.840.113549.1.5.13",
        ]
        if pkcs5EncryptionSchemes.contains(objectIdentifier) {
            return true
        }

        let pkcs12Prefix = "1.2.840.113549.1.12.1."
        guard objectIdentifier.hasPrefix(pkcs12Prefix),
            let scheme = Int(objectIdentifier.dropFirst(pkcs12Prefix.count))
        else { return false }
        return (1...6).contains(scheme)
    }

    private static func decodeDERObjectIdentifier(_ bytes: ArraySlice<UInt8>) -> String? {
        var subidentifiers: [UInt64] = []
        var current: UInt64 = 0
        var isComplete = true

        for byte in bytes {
            guard current <= (UInt64.max >> 7) else { return nil }
            current = (current << 7) | UInt64(byte & 0x7F)
            isComplete = byte & 0x80 == 0
            if isComplete {
                subidentifiers.append(current)
                current = 0
            }
        }
        guard isComplete, let firstSubidentifier = subidentifiers.first else { return nil }

        let firstArc = min(firstSubidentifier / 40, 2)
        let secondArc = firstSubidentifier - firstArc * 40
        return ([firstArc, secondArc] + subidentifiers.dropFirst()).map(String.init)
            .joined(separator: ".")
    }

    private static func isDERCertificate(_ bytes: [UInt8]) -> Bool {
        guard let certificate = derElement(in: bytes, at: 0),
            certificate.tag == 0x30,
            certificate.nextIndex == bytes.count,
            let tbsCertificate = derElement(in: bytes, at: certificate.contentRange.lowerBound),
            tbsCertificate.tag == 0x30,
            let signatureAlgorithm = derElement(in: bytes, at: tbsCertificate.nextIndex),
            signatureAlgorithm.tag == 0x30,
            let signatureValue = derElement(in: bytes, at: signatureAlgorithm.nextIndex),
            signatureValue.tag == 0x03,
            signatureValue.nextIndex == certificate.contentRange.upperBound
        else { return false }

        var cursor = tbsCertificate.contentRange.lowerBound
        guard var serialNumber = derElement(in: bytes, at: cursor) else { return false }
        if serialNumber.tag == 0xA0 {
            cursor = serialNumber.nextIndex
            guard let versionedSerialNumber = derElement(in: bytes, at: cursor) else {
                return false
            }
            serialNumber = versionedSerialNumber
        }
        guard serialNumber.tag == 0x02 else { return false }

        guard let tbsSignatureAlgorithm = derElement(in: bytes, at: serialNumber.nextIndex),
            tbsSignatureAlgorithm.tag == 0x30,
            let issuer = derElement(in: bytes, at: tbsSignatureAlgorithm.nextIndex),
            issuer.tag == 0x30,
            let validity = derElement(in: bytes, at: issuer.nextIndex),
            validity.tag == 0x30,
            let subject = derElement(in: bytes, at: validity.nextIndex),
            subject.tag == 0x30,
            let subjectPublicKeyInfo = derElement(in: bytes, at: subject.nextIndex),
            subjectPublicKeyInfo.tag == 0x30,
            subjectPublicKeyInfo.nextIndex <= tbsCertificate.contentRange.upperBound,
            containsDERValidity(in: bytes, element: validity),
            containsDERSubjectPublicKeyInfo(in: bytes, element: subjectPublicKeyInfo)
        else { return false }

        return true
    }

    private static func containsDERValidity(in bytes: [UInt8], element: DERElement) -> Bool {
        guard let notBefore = derElement(in: bytes, at: element.contentRange.lowerBound),
            notBefore.tag == 0x17 || notBefore.tag == 0x18,
            let notAfter = derElement(in: bytes, at: notBefore.nextIndex),
            notAfter.tag == 0x17 || notAfter.tag == 0x18,
            notAfter.nextIndex == element.contentRange.upperBound
        else { return false }
        return true
    }

    private static func containsDERSubjectPublicKeyInfo(
        in bytes: [UInt8],
        element: DERElement
    ) -> Bool {
        guard let algorithm = derElement(in: bytes, at: element.contentRange.lowerBound),
            algorithm.tag == 0x30,
            let publicKey = derElement(in: bytes, at: algorithm.nextIndex),
            publicKey.tag == 0x03,
            publicKey.nextIndex == element.contentRange.upperBound
        else { return false }
        return true
    }

    private static func isDERSubjectPublicKeyInfo(_ bytes: [UInt8]) -> Bool {
        guard let subjectPublicKeyInfo = derElement(in: bytes, at: 0),
            subjectPublicKeyInfo.tag == 0x30,
            subjectPublicKeyInfo.nextIndex == bytes.count
        else { return false }
        return containsDERSubjectPublicKeyInfo(in: bytes, element: subjectPublicKeyInfo)
    }

    private static func derElement(in bytes: [UInt8], at index: Int) -> DERElement? {
        guard index >= 0, index + 2 <= bytes.count else { return nil }
        let tag = bytes[index]
        let firstLengthByte = bytes[index + 1]
        var contentStart = index + 2
        let contentLength: Int

        if firstLengthByte & 0x80 == 0 {
            contentLength = Int(firstLengthByte)
        } else {
            let lengthByteCount = Int(firstLengthByte & 0x7F)
            guard (1...4).contains(lengthByteCount),
                contentStart + lengthByteCount <= bytes.count
            else { return nil }
            var decodedLength = 0
            for byte in bytes[contentStart..<(contentStart + lengthByteCount)] {
                decodedLength = decodedLength * 256 + Int(byte)
            }
            contentStart += lengthByteCount
            contentLength = decodedLength
        }

        guard contentLength <= bytes.count - contentStart else { return nil }
        let contentEnd = contentStart + contentLength
        return DERElement(
            tag: tag,
            contentRange: contentStart..<contentEnd,
            nextIndex: contentEnd
        )
    }

    private static func containsAuthorizationCredential(_ value: String) -> Bool {
        containsBasicAuthorization(value) || containsBearerAuthorization(value)
    }

    private static func containsCompactJOSECredential(_ value: String) -> Bool {
        value.split(whereSeparator: { $0.isWhitespace }).contains { field in
            let candidate = String(field)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"'(),;[]{}"))
            let segments = candidate.split(separator: ".", omittingEmptySubsequences: false)
            guard segments.count == 3 || segments.count == 5,
                let headerData = decodeBase64URL(String(segments[0])),
                let header = try? JSONSerialization.jsonObject(with: headerData)
                    as? [String: Any],
                header["alg"] is String,
                segments.allSatisfy(isBase64URLSegment)
            else { return false }

            if segments.count == 3 {
                return !segments[0].isEmpty && !segments[1].isEmpty
            }
            return header["enc"] is String
                && !segments[0].isEmpty
                && !segments[2].isEmpty
                && !segments[3].isEmpty
                && !segments[4].isEmpty
        }
    }

    private static func isBase64URLSegment(_ segment: Substring) -> Bool {
        segment.unicodeScalars.allSatisfy {
            CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_" || $0 == "="
        }
    }

    private static func decodeBase64URL(_ value: String) -> Data? {
        var base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.utf8.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64)
    }

    private static func containsBasicAuthorization(_ value: String) -> Bool {
        let fields = value.split(whereSeparator: { $0.isWhitespace || $0 == ":" })
        guard fields.count >= 2 else { return false }
        let base64Characters = CharacterSet(
            charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        )

        for index in fields.indices.dropLast() where fields[index].lowercased() == "basic" {
            var candidate = ""
            for fragmentIndex in fields.indices where fragmentIndex > index {
                let fragment = String(fields[fragmentIndex])
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\"',;"))
                guard !fragment.isEmpty,
                    fragment.unicodeScalars.allSatisfy(base64Characters.contains)
                else { break }
                candidate += fragment
                if let decoded = Data(base64Encoded: candidate),
                    decoded.contains(UInt8(ascii: ":"))
                {
                    return true
                }
            }
        }
        return false
    }

    private static func containsBearerAuthorization(_ value: String) -> Bool {
        let fields = value.split(whereSeparator: { $0.isWhitespace || $0 == ":" })
        guard fields.count >= 2 else { return false }
        let bearerCharacters = CharacterSet(
            charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/="
        )
        let credentialSyntaxCharacters = CharacterSet(charactersIn: "0123456789._~+/=")

        for index in fields.indices.dropLast() where fields[index].lowercased() == "bearer" {
            var candidate = ""
            let hasAuthorizationHeader = fields[..<index].contains {
                $0.lowercased() == "authorization"
            }
            for fragmentIndex in fields.indices where fragmentIndex > index {
                let fragment = String(fields[fragmentIndex])
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\"',;"))
                guard !fragment.isEmpty,
                    fragment.unicodeScalars.allSatisfy(bearerCharacters.contains)
                else { break }
                candidate += fragment
                if hasAuthorizationHeader && !candidate.isEmpty {
                    return true
                }
                if candidate.utf8.count >= 16,
                    candidate.unicodeScalars.contains(where: credentialSyntaxCharacters.contains)
                {
                    return true
                }
            }
        }
        return false
    }

    private static func containsCredentialBearingURI(_ value: String) -> Bool {
        let pattern = #"[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+"#
        guard let expression = try? NSRegularExpression(pattern: pattern) else { return true }
        let range = NSRange(value.startIndex..<value.endIndex, in: value)

        return expression.matches(in: value, range: range).contains { match in
            guard let matchRange = Range(match.range, in: value),
                let components = URLComponents(string: String(value[matchRange]))
            else { return true }
            return components.user != nil || components.password != nil
        }
    }

    private static func containsJSONDocument(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("{") || trimmed.hasPrefix("[") else { return false }
        return (try? JSONSerialization.jsonObject(with: Data(trimmed.utf8))) != nil
    }

    private struct DERElement {
        let tag: UInt8
        let contentRange: Range<Int>
        let nextIndex: Int
    }
}

public enum ResourceSummaryDisclosure {
    /// Only keys reviewed in source code may cross the non-interactive public
    /// projection. Imported or future keys fail closed as private.
    public static let allowedMetadataKeys: Set<ResourceMetadataKey> = Set(
        [
            "host.os.family",
            "host.account.is-root",
            "host.docker.available",
            "host.docker.account-authorized",
            "database.engine",
            "object-storage.provider",
            "cache.engine",
            "service.protocol",
        ].compactMap(ResourceMetadataKey.init(rawValue:))
    )

    public static func publicEntries(from entries: [ResourceMetadataEntry])
        -> [ResourceMetadataEntry]
    {
        entries
            .filter(isApprovedPublicEntry)
            .sorted { $0.key.rawValue < $1.key.rawValue }
    }

    public static func isApprovedPublicEntry(_ entry: ResourceMetadataEntry) -> Bool {
        switch (entry.key.rawValue, entry.value) {
        case ("host.account.is-root", .boolean),
            ("host.docker.available", .boolean),
            ("host.docker.account-authorized", .boolean):
            return true
        case ("host.os.family", .text(let value)):
            return ["linux", "macos", "windows"].contains(value)
        case ("database.engine", .text(let value)):
            return ["mariadb", "mysql", "oracle", "postgresql", "sql-server", "sqlite"]
                .contains(value)
        case ("object-storage.provider", .text(let value)):
            return ["aliyun-oss", "aws-s3", "ceph", "minio", "s3", "truenas"]
                .contains(value)
        case ("cache.engine", .text(let value)):
            return ["memcached", "redis", "valkey"].contains(value)
        case ("service.protocol", .text(let value)):
            return ["grpc", "http", "https", "tcp", "udp"].contains(value)
        default:
            return false
        }
    }
}

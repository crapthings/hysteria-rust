import Foundation
import Darwin

// Exercises the C ABI using raw IPv4 TCP and UDP packets, without an OS tunnel.
enum SmokeFailure: Error { case failed(String) }

func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw SmokeFailure.failed(message) }
}

func put16(_ bytes: inout [UInt8], _ offset: Int, _ value: UInt16) {
    bytes[offset] = UInt8(value >> 8)
    bytes[offset + 1] = UInt8(value & 0xff)
}

func put32(_ bytes: inout [UInt8], _ offset: Int, _ value: UInt32) {
    put16(&bytes, offset, UInt16(value >> 16))
    put16(&bytes, offset + 2, UInt16(value & 0xffff))
}

func checksum(_ bytes: [UInt8]) -> UInt16 {
    var sum: UInt32 = 0
    var index = 0
    while index < bytes.count {
        let low = index + 1 < bytes.count ? UInt32(bytes[index + 1]) : 0
        sum += (UInt32(bytes[index]) << 8) | low
        index += 2
    }
    while sum > 0xffff { sum = (sum & 0xffff) + (sum >> 16) }
    return ~UInt16(sum)
}

func ipv4(protocolNumber: UInt8, length: Int) -> [UInt8] {
    var packet = [UInt8](repeating: 0, count: length)
    packet[0] = 0x45
    put16(&packet, 2, UInt16(length))
    packet[8] = 64
    packet[9] = protocolNumber
    packet.replaceSubrange(12..<16, with: [10, 0, 0, 2])
    packet.replaceSubrange(16..<20, with: [127, 0, 0, 1])
    put16(&packet, 10, checksum(Array(packet[0..<20])))
    return packet
}

func udpPacket(port: UInt16, payload: [UInt8]) -> [UInt8] {
    var packet = ipv4(protocolNumber: 17, length: 28 + payload.count)
    put16(&packet, 20, 12345)
    put16(&packet, 22, port)
    put16(&packet, 24, UInt16(8 + payload.count))
    packet.replaceSubrange(28..<packet.count, with: payload)
    return packet
}

func tcpPacket(port: UInt16, sequence: UInt32, acknowledgement: UInt32,
               flags: UInt8, payload: [UInt8] = []) -> [UInt8] {
    var packet = ipv4(protocolNumber: 6, length: 40 + payload.count)
    put16(&packet, 20, 12345)
    put16(&packet, 22, port)
    put32(&packet, 24, sequence)
    put32(&packet, 28, acknowledgement)
    packet[32] = 0x50
    packet[33] = flags
    put16(&packet, 34, 65535)
    packet.replaceSubrange(40..<packet.count, with: payload)
    var pseudo = Array(packet[12..<20]) + [0, 6, 0, 0]
    put16(&pseudo, 10, UInt16(20 + payload.count))
    pseudo += packet[20...]
    put16(&packet, 36, checksum(pseudo))
    return packet
}

func read32(_ bytes: [UInt8], _ index: Int) -> UInt32 {
    bytes[index..<(index + 4)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
}

func status(_ handle: OpaquePointer) throws -> [String: Any] {
    var bytes = [UInt8](repeating: 0, count: 8192)
    var length = 0
    let result = bytes.withUnsafeMutableBufferPointer {
        hy2_packet_bridge_status(handle, $0.baseAddress, $0.count, &length)
    }
    try require(result == 0 && length <= bytes.count, "status failed: \(result)")
    let object = try JSONSerialization.jsonObject(with: Data(bytes.prefix(length)))
    guard let dictionary = object as? [String: Any] else { throw SmokeFailure.failed("invalid status JSON") }
    return dictionary
}

func write(_ handle: OpaquePointer, _ packet: [UInt8]) throws {
    let deadline = Date().addingTimeInterval(10)
    while Date() < deadline {
        let result = packet.withUnsafeBufferPointer {
            hy2_packet_bridge_write(handle, $0.baseAddress, $0.count)
        }
        if result == 0 { return }
        try require(result == 2, "packet write failed: \(result)")
        usleep(5000)
    }
    throw SmokeFailure.failed("packet input remained full")
}

func read(_ handle: OpaquePointer, verifyShortBuffer: Bool = false) throws -> [UInt8] {
    let deadline = Date().addingTimeInterval(10)
    while Date() < deadline {
        if verifyShortBuffer {
            var required = 0
            let result = hy2_packet_bridge_read(handle, nil, 0, &required)
            if result == 1 { usleep(5000); continue }
            try require(result == 6 && required > 0, "short-buffer probe failed: \(result)")
            var packet = [UInt8](repeating: 0, count: required)
            var length = 0
            let retry = packet.withUnsafeMutableBufferPointer {
                hy2_packet_bridge_read(handle, $0.baseAddress, $0.count, &length)
            }
            try require(retry == 0 && length == required, "packet was not retained after short buffer")
            return packet
        }
        var packet = [UInt8](repeating: 0, count: 65_535)
        var length = 0
        let result = packet.withUnsafeMutableBufferPointer {
            hy2_packet_bridge_read(handle, $0.baseAddress, $0.count, &length)
        }
        if result == 1 { usleep(5000); continue }
        try require(result == 0 && length <= packet.count, "packet read failed: \(result)")
        return Array(packet.prefix(length))
    }
    throw SmokeFailure.failed("packet output timed out")
}

func main() throws {
    try require(CommandLine.arguments.count == 3, "expected UDP and TCP echo ports")
    guard let udpPort = UInt16(CommandLine.arguments[1]), let tcpPort = UInt16(CommandLine.arguments[2]) else {
        throw SmokeFailure.failed("invalid echo ports")
    }
    let config = FileHandle.standardInput.readDataToEndOfFile()
    try require(hy2_packet_bridge_version() == 1, "wrong ABI version")
    var invalid: OpaquePointer?
    let badJSON = Array("{invalid".utf8)
    let invalidResult = badJSON.withUnsafeBufferPointer {
        hy2_packet_bridge_create($0.baseAddress, $0.count, &invalid)
    }
    try require(invalidResult == 7 && invalid == nil, "invalid config was accepted")
    var instance: OpaquePointer?
    let created = config.withUnsafeBytes {
        hy2_packet_bridge_create($0.bindMemory(to: UInt8.self).baseAddress, $0.count, &instance)
    }
    try require(created == 0, "create failed: \(created)")
    guard let handle = instance else { throw SmokeFailure.failed("missing handle") }
    defer { if let remaining = instance { _ = hy2_packet_bridge_destroy(remaining) } }

    var invalidPacket = [UInt8](repeating: 0, count: 20)
    invalidPacket[0] = 0x45
    let invalidPacketResult = invalidPacket.withUnsafeBufferPointer {
        hy2_packet_bridge_write(handle, $0.baseAddress, $0.count)
    }
    try require(invalidPacketResult == 5, "malformed packet was accepted")
    let deadline = Date().addingTimeInterval(10)
    var ready = false
    while Date() < deadline {
        let snapshot = try status(handle)
        guard let client = snapshot["client"] as? [String: Any] else { throw SmokeFailure.failed("missing client status") }
        if snapshot["worker"] as? String == "failed" { throw SmokeFailure.failed("worker failed during startup") }
        if (client["ready_components"] as? [String] ?? []).contains("tun"), client["connection"] as? String == "connected" {
            ready = true
            break
        }
        usleep(10_000)
    }
    try require(ready, "client was not ready and connected")

    let udpPayload = Array("swift-udp-roundtrip".utf8)
    try write(handle, udpPacket(port: udpPort, payload: udpPayload))
    let udpReply = try read(handle, verifyShortBuffer: true)
    try require(udpReply.count >= 28 && udpReply[9] == 17, "invalid UDP reply")
    let udpHeader = Int(udpReply[0] & 15) * 4
    try require(Array(udpReply[(udpHeader + 8)...]) == udpPayload, "UDP payload mismatch")
    print("Swift UDP raw packet and short-buffer retry: OK")

    try write(handle, tcpPacket(port: tcpPort, sequence: 1, acknowledgement: 0, flags: 0x02))
    let synAck = try read(handle)
    try require(synAck.count >= 20, "truncated SYN-ACK")
    let ipHeader = Int(synAck[0] & 15) * 4
    try require(synAck.count >= ipHeader + 20 && synAck[ipHeader + 13] & 0x12 == 0x12, "missing SYN-ACK")
    let acknowledgement = read32(synAck, ipHeader + 4) &+ 1
    try write(handle, tcpPacket(port: tcpPort, sequence: 2, acknowledgement: acknowledgement, flags: 0x10))
    let tcpPayload = Array("swift-tcp-roundtrip".utf8)
    try write(handle, tcpPacket(port: tcpPort, sequence: 2, acknowledgement: acknowledgement, flags: 0x18, payload: tcpPayload))
    var received: [UInt8] = []
    while received.count < tcpPayload.count {
        let reply = try read(handle)
        try require(reply.count >= 20, "truncated IP reply")
        let ip = Int(reply[0] & 15) * 4
        try require(reply.count >= ip + 20, "truncated TCP reply")
        let tcp = Int(reply[ip + 12] >> 4) * 4
        try require(reply.count >= ip + tcp, "invalid TCP header")
        received += reply[(ip + tcp)...]
    }
    try require(received == tcpPayload, "TCP payload mismatch")
    print("Swift TCP raw packet handshake and payload: OK")

    try require(hy2_packet_bridge_shutdown(handle) == 0, "shutdown failed")
    try require(hy2_packet_bridge_shutdown(handle) == 0, "shutdown was not idempotent")
    let stopDeadline = Date().addingTimeInterval(10)
    var stopped = false
    while Date() < stopDeadline {
        let snapshot = try status(handle)
        if snapshot["worker"] as? String == "stopped" { stopped = true; break }
        if snapshot["worker"] as? String == "failed" { throw SmokeFailure.failed("worker failed on shutdown") }
        usleep(10_000)
    }
    try require(stopped, "worker did not stop")
    let destroyed = hy2_packet_bridge_destroy(handle)
    instance = nil
    try require(destroyed == 0, "destroy failed")
    print("Swift startup validation, status, shutdown and destroy: OK")

    guard var badConfig = try JSONSerialization.jsonObject(with: config) as? [String: Any] else {
        throw SmokeFailure.failed("invalid fixture config")
    }
    badConfig["auth"] = "deliberately-wrong"
    let badConfigData = try JSONSerialization.data(withJSONObject: badConfig)
    var failedInstance: OpaquePointer?
    let failedCreate = badConfigData.withUnsafeBytes {
        hy2_packet_bridge_create($0.bindMemory(to: UInt8.self).baseAddress, $0.count, &failedInstance)
    }
    try require(failedCreate == 0, "valid config failed before asynchronous startup")
    guard let failedHandle = failedInstance else { throw SmokeFailure.failed("missing failure-test handle") }
    defer { if let remaining = failedInstance { _ = hy2_packet_bridge_destroy(remaining) } }
    let failureDeadline = Date().addingTimeInterval(10)
    var failed = false
    while Date() < failureDeadline {
        let snapshot = try status(failedHandle)
        if snapshot["worker"] as? String == "failed" {
            let client = snapshot["client"] as? [String: Any]
            try require(client?["error_code"] is String, "startup failure did not expose an error code")
            failed = true
            break
        }
        usleep(10_000)
    }
    try require(failed, "authentication failure was not reported")
    let failureDestroy = hy2_packet_bridge_destroy(failedHandle)
    failedInstance = nil
    try require(failureDestroy == 8, "failed runtime was not reported by destroy")
    print("Swift authentication startup failure and cleanup: OK")
}

do {
    try main()
} catch {
    fputs("Swift packet bridge test failed: \(error)\n", stderr)
    exit(1)
}

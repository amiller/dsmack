// CRC-32 (ISO-HDLC, reflected, poly 0xEDB88320) — identical to zlib.crc32 and
// the channel lane's Rust const-table codec. Known answer (unit-tested):
// crc32("123456789") == 0xCBF43926.
import Foundation

public enum CRC32 {
    static let table: [UInt32] = {
        (0..<256).map { i -> UInt32 in
            var c = UInt32(i)
            for _ in 0..<8 { c = (c & 1) == 1 ? (0xEDB88320 ^ (c >> 1)) : (c >> 1) }
            return c
        }
    }()

    public static func checksum(_ data: some Sequence<UInt8>) -> UInt32 {
        var crc: UInt32 = 0xFFFFFFFF
        for byte in data { crc = table[Int((crc ^ UInt32(byte)) & 0xff)] ^ (crc >> 8) }
        return crc ^ 0xFFFFFFFF
    }
}

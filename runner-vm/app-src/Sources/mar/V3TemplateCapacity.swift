// Generic runner resource ceilings. A profile still selects exact template size/hash.
enum V3TemplateCapacity {
    static let scratchMaxBytes = 4 << 30
    static let resultMaxBytes = 1 << 30
    static func admitsScratch(_ bytes: Int) -> Bool {
        bytes > 0 && bytes % 512 == 0 && bytes <= scratchMaxBytes
    }
    static func admitsResult(_ bytes: Int) -> Bool {
        bytes > 0 && bytes % 512 == 0 && bytes <= resultMaxBytes
    }
}

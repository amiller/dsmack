@main enum TemplateCapacityControls {
    static func main() {
        var checks = 0
        func verify(_ size: Int, scratch: Bool, result: Bool) {
            precondition(V3TemplateCapacity.admitsScratch(size) == scratch)
            precondition(V3TemplateCapacity.admitsResult(size) == result)
            checks += 2
        }
        verify(-512, scratch: false, result: false)
        verify(0, scratch: false, result: false)
        verify(511, scratch: false, result: false)
        verify(512, scratch: true, result: true)
        verify(1 << 30, scratch: true, result: true)
        verify((1 << 30) + 1, scratch: false, result: false)
        verify((1 << 30) + 512, scratch: true, result: false)
        verify(4 << 30, scratch: true, result: false)
        verify((4 << 30) + 1, scratch: false, result: false)
        verify((4 << 30) + 512, scratch: false, result: false)
        verify(Int.max, scratch: false, result: false)
        print("{\"schema\":\"dsmack-swift-template-capacity-controls/1\",\"checks\":\(checks),\"passed\":true}")
    }
}

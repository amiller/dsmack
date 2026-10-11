import Foundation

// Validate the central AND local ZIP records before invoking the system extractor.
// This deliberately supports only ordinary, non-symlink Node.app ZIPs, not ZIP64.
enum NativeUpdateArchive {
    static func validate(_ url:URL,expectedBytes:Int) throws {
        let data=try Data(contentsOf:url,options:.mappedIfSafe)
        guard data.count==expectedBytes,data.count>=22 else {throw NativeUpdateError("The update download is incomplete.")}
        func u16(_ i:Int)throws->Int {guard i>=0,i+2<=data.count else {throw NativeUpdateError("Truncated update archive.")};return Int(data[i])|Int(data[i+1])<<8}
        func u32(_ i:Int)throws->Int {return try u16(i)|(u16(i+2)<<16)}
        var end:Int?
        for i in stride(from:data.count-22,through:max(0,data.count-65557),by:-1) {
            if try u32(i)==0x06054b50, i+22+(try u16(i+20))==data.count {end=i;break}
        }
        guard let e=end,try u16(e+4)==0,try u16(e+6)==0 else {throw NativeUpdateError("Unsupported update archive.")}
        let count=try u16(e+10),size=try u32(e+12),start=try u32(e+16)
        guard count>0,count<=4096,try u16(e+8)==count,start+size==e else {throw NativeUpdateError("Unsupported update archive directory.")}
        var cursor=start,total=0,names=Set<String>(),ranges=[Range<Int>]()
        for _ in 0..<count {
            guard try u32(cursor)==0x02014b50 else {throw NativeUpdateError("Invalid update archive entry.")}
            let flags=try u16(cursor+8),method=try u16(cursor+10),compressed=try u32(cursor+20),expanded=try u32(cursor+24),n=try u16(cursor+28),extra=try u16(cursor+30),comment=try u16(cursor+32),offset=try u32(cursor+42),attributes=try u32(cursor+38)
            guard n>0,n<=512,cursor+46+n+extra+comment<=e,flags & ~0x808 == 0,[0,8].contains(method),try u16(cursor+34)==0 else {throw NativeUpdateError("Unsupported update archive entry.")}
            // Reject extra records rather than permit ZIP64/Unicode path overrides
            // or platform-specific extraction behavior not represented by our checks.
            guard extra==0 else {throw NativeUpdateError("Update ZIP extra fields are not supported.")}
            let raw=data.subdata(in:cursor+46..<cursor+46+n)
            guard let name=String(data:raw,encoding:.utf8),!name.contains("\\"),!name.contains("\0"),name=="Node.app/" || name.hasPrefix("Node.app/"),
                  !name.split(separator:"/",omittingEmptySubsequences:false).dropLast().contains(where:{$0.isEmpty || $0=="." || $0==".."}),
                  ![".",".."].contains(String(name.split(separator:"/",omittingEmptySubsequences:false).last ?? "")),names.insert(name).inserted else {throw NativeUpdateError("Unsafe update archive path.")}
            let kind=(attributes>>16)&0xf000
            guard [0,0x8000,0x4000].contains(kind),expanded<=250_000_000,expanded<=max(1,compressed)*200 else {throw NativeUpdateError("Unsupported update archive file type or size.")}
            total+=expanded;guard total<=600_000_000 else {throw NativeUpdateError("Expanded update exceeds the size limit.")}
            guard offset>=0,offset+30<=start,try u32(offset)==0x04034b50,try u16(offset+6)==flags,try u16(offset+8)==method,try u16(offset+26)==n else {throw NativeUpdateError("Update ZIP records disagree.")}
            let localExtra=try u16(offset+28),localEnd=offset+30+n+localExtra+compressed
            guard localExtra==0 else {throw NativeUpdateError("Update ZIP extra fields are not supported.")}
            if flags & 8 == 0 {
                guard try u32(offset+14)==u32(cursor+16),try u32(offset+18)==compressed,try u32(offset+22)==expanded else {throw NativeUpdateError("Update ZIP CRC or sizes disagree.")}
            } else {
                // Require a signed 16-byte descriptor and compare all its fields.
                guard localEnd+16<=start,try u32(localEnd)==0x08074b50,
                      try u32(localEnd+4)==u32(cursor+16),try u32(localEnd+8)==compressed,try u32(localEnd+12)==expanded else {throw NativeUpdateError("Update ZIP data descriptor disagrees.")}
            }
            guard localEnd<=start,data.subdata(in:offset+30..<offset+30+n)==raw else {throw NativeUpdateError("Update ZIP records disagree.")}
            let range=offset..<(localEnd+(flags & 8 == 0 ? 0:16))
            guard !ranges.contains(where:{$0.overlaps(range)}) else {throw NativeUpdateError("Overlapping update ZIP entries.")}
            ranges.append(range);cursor+=46+n+extra+comment
        }
        guard cursor==e,names.contains("Node.app/Contents/Info.plist"),names.contains("Node.app/Contents/MacOS/node"),names.contains("Node.app/Contents/Resources/dsmack-release.json") else {throw NativeUpdateError("The update does not contain the required signed release metadata.")}
    }
}

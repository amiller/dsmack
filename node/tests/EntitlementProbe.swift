import Foundation
import Security

// Reports which entitlements the running process has, for scripts/release/slot5_probe.py.
@_silgen_name("csops") func csops(_ pid:pid_t,_ ops:UInt32,_ buf:UnsafeMutableRawPointer?,_ size:Int) -> Int32
func blob(_ op:UInt32) -> String {
    var b=[UInt8](repeating:0,count:65536)
    guard csops(getpid(),op,&b,b.count)==0 else {return "csops \(op) errno \(errno)"}
    let n=Int(b[4])<<24|Int(b[5])<<16|Int(b[6])<<8|Int(b[7])
    return n<8 ? "empty" : Data(b[8..<n]).base64EncodedString()
}
var status:UInt32=0
_=csops(getpid(),0,&status,4)                                   // CS_OPS_STATUS
let task=SecTaskCreateFromSelf(nil)!
var r:[String:Any]=["csStatus":String(format:"0x%08x",status),"getTaskAllowFlag":status & 0x4 != 0,
    "xmlBlob":blob(7),"derBlob":blob(16)]                      // CS_OPS_ENTITLEMENTS_BLOB, CS_OPS_DER_ENTITLEMENTS_BLOB
for k in ["com.apple.security.get-task-allow","com.apple.security.cs.disable-library-validation"] {
    r[k]=SecTaskCopyValueForEntitlement(task,k as CFString,nil).map{"\($0)"} ?? "nil"
}
print(String(decoding:try! JSONSerialization.data(withJSONObject:r,options:[.sortedKeys]),as:UTF8.self))

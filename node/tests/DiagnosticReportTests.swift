import AppKit

/// Runs the production exporter through a test-only same-file extension.
/// Does not open a picker, start a participant or access any real credentials.
@main struct DiagnosticReportTests {
    static func main() throws {
        _=NSApplication.shared
        let app=ParticipantApp()
        let secret="0x"+String(repeating:"a9",count:32)
        let publicPoint="0x04"+String(repeating:"b8",count:64)
        let endpoint="https://build-user:sensitive-pass@rpc.example:8545/private-token?apiKey=test-api-secret"
        let events:[[String:Any]]=[
            ["event":"start","rpc":endpoint],
            ["event":"retrying","error":"HTTP 403 /private-token "+endpoint+" sensitive-pass test-api-secret"],
            ["event":"diagnostic-fixture","nested":["privateKey":secret,"groupPublic":publicPoint],"error":"upstream echoed "+secret],
            ["event":"apple operation failed","errorChain":[["domain":"com.apple.devicecheck.error","code":3]]]
        ]
        let lines=try events.map {String(decoding:try JSONSerialization.data(withJSONObject:$0,options:[.sortedKeys]),as:UTF8.self)}
        let report=app.testDiagnosticReport(lines:lines)
        for forbidden in ["build-user","sensitive-pass","private-token","test-api-secret",secret,"privateKey"] {
            try need(!report.contains(forbidden),"diagnostic redaction failed")
        }
        try need(report.contains("https:\\/\\/rpc.example:8545") || report.contains("https://rpc.example:8545"),"RPC origin lost")
        try need(report.contains(publicPoint),"public key evidence lost")
        let decoded=try report.split(separator:"\n").map {try JSONSerialization.jsonObject(with:Data($0.utf8)) as! [String:Any]}
        try need(decoded.count==4,"JSONL records lost")
        let chain=decoded[3]["errorChain"] as! [[String:Any]]
        try need((chain[0]["code"] as? NSNumber)?.intValue==3 && chain[0]["domain"] as? String=="com.apple.devicecheck.error","error chain damaged")
        try need(CommandLine.arguments.count==2,"output path required")
        let path=URL(fileURLWithPath:CommandLine.arguments[1])
        try report.write(to:path,atomically:true,encoding:.utf8)
        try need(try String(contentsOf:path,encoding:.utf8)==report,"saved diagnostic bytes differ")
        print("PASS RPC origin retained; URL credentials, path and query values removed")
        print("PASS credential echoes and nested private-key field removed")
        print("PASS public key and Apple domain/code preserved; four valid JSONL records")
        print("PASS exported report file roundtrip")
        print("Scope: actual production exporter with injected synthetic events; no save-picker automation or live credential access.")
    }
}

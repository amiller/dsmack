import Foundation

func emit(_ event: String,_ fields: [String:Any]) {
    var f=fields;f["event"]=event;f["t"]=Date().timeIntervalSince1970
    print(String(decoding:try! JSONSerialization.data(withJSONObject:f,options:[.sortedKeys]),as:UTF8.self));fflush(stdout)
}
func runCLI() {
    do {
        let args=CommandLine.arguments
        try need(args.count==3 && ["listen","connect","participate","seed"].contains(args[2]),"usage: node <config.json> listen|connect|participate|seed")
        guard let d=try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:args[1]))) as? [String:Any] else {throw DemoError.invalid("config JSON")}
        let node=Node(try Config(d,path:URL(fileURLWithPath:args[1])),log:emit)
        if args[2]=="seed" {node.maintainSeed()} else if args[2]=="listen" {try node.listen()} else if args[2]=="participate" {try node.participate()} else {try node.connect()}
        emit("done",[:])
    } catch {emit("error",["error":"\(error)"]);exit(1)}
}
/// Own measurement inputs for MeasurementRegistry.register, and M.
if CommandLine.arguments.count==2 && CommandLine.arguments[1]=="--measure" {
    do {
        let x=try CodeMeasurement.ofSelf()
        emit("measurement",["M":hex(try x.value()),"cdhash":hex(Data(CodeMeasurement.sha(x.cd))),"cd":hex(Data(x.cd)),"page0":hex(Data(x.page0)),"ent":hex(Data(x.ent)),"L":x.L,"S":x.S])
        exit(0)
    } catch {emit("error",["error":"\(error)"]);exit(1)}
}
#if GUI
if CommandLine.arguments.count==3 && CommandLine.arguments[1]=="--dsmack-finish-update" {NativeUpdater.finishHandoff(CommandLine.arguments[2])}
if CommandLine.arguments.count==3 && ["listen","connect","participate","seed"].contains(CommandLine.arguments[2]) {runCLI()} else {runParticipantApp()}
#else
runCLI()
#endif

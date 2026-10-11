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
        let node=Node(try Config(d),log:emit)
        if args[2]=="seed" {node.maintainSeed()} else if args[2]=="listen" {try node.listen()} else if args[2]=="participate" {try node.participate()} else {try node.connect()}
        emit("done",[:])
    } catch {emit("error",["error":"\(error)"]);exit(1)}
}
#if GUI
if CommandLine.arguments.count==3 && ["listen","connect","participate","seed"].contains(CommandLine.arguments[2]) {runCLI()} else {runParticipantApp()}
#else
runCLI()
#endif

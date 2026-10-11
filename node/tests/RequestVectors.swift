import Foundation

// Golden ABI vectors generated independently with Python eth_abi + eth_utils.
@main struct RequestVectors {
    static func main() throws {
        let owner="0x"+String(repeating:"11",count:20)
        let registry="0x"+String(repeating:"22",count:20)
        let request=Request(action:3,category:Data(repeating:0x33,count:32),owner:owner,
            session:Data(repeating:0x44,count:32),nonce:5,deadline:1234567890,
            scope:Data(repeating:0,count:32),x:word(1),y:word(2),envelope:Data(repeating:0x55,count:32))
        let vectors:[(Int,UInt64,String)]=[
            (1,0,"fe5f86828e0becd603e0754f1bce23d8d333552b1f6dde1ec914dff8ac409ab6"),
            (2,0,"e4bbc7ed34872c4b54faf862c69000c00bac46be7770c84af28655e13a835d62"),
            (2,7,"6855d6270ccee539d801d790bc65aef6e06590a274e7094e33256c2b5ba6badf")]
        for (version,epoch,expected) in vectors {
            try need(try request.context(registry:registry,chainId:84532,protocolVersion:version,keyEpoch:epoch)==unhex(expected),"request ABI vector mismatch")
        }
        do {
            _=try request.context(registry:registry,chainId:84532,keyEpoch:1)
            fatalError("V1 must reject key epochs")
        } catch DemoError.invalid(_) {}
        let badge=BadgeClaim(recipient:owner,keyId:Data(repeating:0x33,count:32),level:1,parent:0,deadline:1800000000)
        try need(try badge.digest(chainId:84532,badges:registry)==unhex("a6ffae0033cc6a16e1787730640fc275926061e41275b535bd9ff3d5f63b81a8"),"badge claim ABI vector")
        let roundtrip=try JSONDecoder().decode(Request.self,from:JSONEncoder().encode(request))
        try need(try roundtrip.words()==request.words(),"request file roundtrip")
        let malformed=Request(action:3,category:Data(repeating:0x33,count:31),owner:owner,session:Data(repeating:0x44,count:33),nonce:5,deadline:1234567890,scope:Data(repeating:0,count:32),x:word(1),y:word(2),envelope:Data(repeating:0x55,count:32))
        do {_=try malformed.words();fatalError("misaligned request fields must be rejected")}
        catch DemoError.invalid(_) {}
        print("Request ABI vectors passed (V1, V2 epoch 0, V2 epoch 7)")
    }
}

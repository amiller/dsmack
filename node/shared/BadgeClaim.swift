import Foundation

extension Node {
    func attemptParticipantBadge() {
        guard badgeParticipation && !badgeComplete && Date()>=nextBadgeAttempt && cfg.badges != nil else {return}
        nextBadgeAttempt=Date().addingTimeInterval(60)
        do {try claimParticipantBadge();badgeComplete=true}
        catch DemoError.invalid(let reason) where reason=="Waiting for approval in the original app" {log("upgrade awaiting approval",[:])}
        catch {log("badge retrying",["error":String(describing:error),"retryAfterSeconds":60])}
    }
    func claimParticipantBadge() throws {
        guard let badges=cfg.badges,let factory=cfg.accountFactory,let group=held[zero32],let kid=Data(base64Encoded:keyID) else {throw DemoError.invalid("badge setup unavailable")}
        let personal=try personalKey()
        let coordinates=Data(personal.publicPoint.dropFirst())
        let invitation=try linkedAccount(personal)
        let account=try invitation?.account ?? defaultPersonalAccount(personal)
        log("badge preparing",["personalAccount":account])
        guard let code=try chain.rpc("eth_getCode",[account,"latest"]) as? String else {throw DemoError.invalid("account code")}
        if code=="0x" {
            let digest=try keccak(keccak(Data("ATTEST_PERSONAL_CREATE_V1".utf8))+word(cfg.chainId)+addressWord(factory)+kid+coordinates)
            let (_,request)=try executeDetailed(3,group:group,envelope:digest)
            _=try relay("personal-account",["x":hex(coordinates.prefix(32)),"y":hex(coordinates.suffix(32)),"keyId":hex(kid),"request":request.json])
        }
        try need(try chain.call("badges()",to:account)==addressWord(badges),"personal account badge policy")
        if try chain.call("keyX()",to:account)+chain.call("keyY()",to:account) != coordinates {
            if invitation == nil {log("account handed off",["personalAccount":account]);return}
            throw DemoError.invalid("Waiting for approval in the original app")
        }
        var token=try smallWord(chain.call("participantOf(address)",addressWord(account),to:badges))
        var transaction=""
        if token==0 {
            log("badge claiming",["personalAccount":account])
            let claim=BadgeClaim(recipient:account,keyId:kid,level:1,parent:0,deadline:try chain.requestDeadline())
            let digest=try claim.digest(chainId:cfg.chainId,badges:badges)
            try need(try chain.call("claimDigest((address,bytes32,uint8,uint256,uint64))",claim.words(),to:badges)==digest,"badge claim ABI")
            let generation=try smallWord(chain.call("generation()",to:account))
            let signature=try personal.consent(chainId:cfg.chainId,account:account,generation:generation,claim:digest)
            let (_,request)=try executeDetailed(3,group:group,envelope:digest)
            let response=try relay("badge-claim",["claim":claim.json,"request":request.json,"recipientSignature":hex(signature)])
            transaction=response["tx"] as? String ?? ""
            token=try smallWord(chain.call("participantOf(address)",addressWord(account),to:badges))
        }
        try need(token>0,"NFT claim not confirmed yet")
        try need(try chain.call("ownerOf(uint256)",word(token),to:badges)==addressWord(account),"NFT recipient mismatch")
        log("badge claimed",["badgeLevel":1,"badgeToken":token,"badgeContract":badges,"personalAccount":account,"badgeTransaction":transaction,"chainId":cfg.chainId])
        if let invitation {
            try need(invitation.participantToken==token,"linked participant NFT mismatch")
            try claimBuilderBadge(account:account,parent:token,key:personal)
        }
    }
}

extension Node {
    func claimBuilderBadge(account:String,parent:UInt64,key:PersonalAccountKey) throws {
        let policy=try badgePolicy()
        guard let group=held[zero32],let kid=Data(base64Encoded:keyID) else {throw DemoError.invalid("Join the network before claiming the builder NFT")}
        var token=try smallWord(chain.call("builderOf(uint256)",word(parent),to:policy.badges))
        var transaction=""
        if token==0 {
            let team=try verifiedTeam(keyId:kid,forAccount:account)
            try requireIndependentTeam(team)
            try need(try smallWord(chain.call("builderTeamClaimed(bytes32)",team,to:policy.badges))==0,"This developer team already claimed its builder NFT")
            let claim=BadgeClaim(recipient:account,keyId:kid,level:2,parent:parent,deadline:try chain.requestDeadline())
            let digest=try claim.digest(chainId:cfg.chainId,badges:policy.badges)
            let generation=try smallWord(chain.call("generation()",to:account))
            let signature=try key.consent(chainId:cfg.chainId,account:account,generation:generation,claim:digest)
            log("builder claiming",["personalAccount":account,"participantToken":parent])
            let (_,request)=try executeDetailed(3,group:group,envelope:digest)
            let response=try relay("badge-claim",["claim":claim.json,"request":request.json,"recipientSignature":hex(signature)])
            transaction=response["tx"] as? String ?? ""
            token=try smallWord(chain.call("builderOf(uint256)",word(parent),to:policy.badges))
        }
        try need(token>0,"Builder NFT claim not confirmed yet")
        try need(try chain.call("ownerOf(uint256)",word(token),to:policy.badges)==addressWord(account),"builder NFT recipient mismatch")
        let record=try chain.call("badges(uint256)",word(token),to:policy.badges)
        try need(record.count==128 && smallWord(record.subdata(in:64..<96))==2 && smallWord(record.suffix(32))==parent,"builder NFT parent mismatch")
        log("badge claimed",["badgeLevel":2,"badgeToken":token,"participantToken":parent,"badgeContract":policy.badges,"personalAccount":account,"badgeTransaction":transaction,"chainId":cfg.chainId])
    }
}

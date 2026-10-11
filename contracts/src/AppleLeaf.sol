// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {StrictDER as D} from "./StrictDER.sol";
library AppleLeaf {
    struct Parsed {bytes32 tbsHash;uint256 x;uint256 y;uint64 expires;uint256 rhi;uint256 rlo;uint256 shi;uint256 slo;}
    function parse(bytes memory cert,bytes32 issuerHash,bytes32 nonce,bytes32 acl) internal view returns(Parsed memory result){
        require(cert.length<=4096,"certificate size");
        D.Node memory outer=D.expect(cert,0,cert.length,0x30);require(outer.end==cert.length,"certificate trailing");
        D.Node memory tbs=D.expect(cert,outer.body,outer.end,0x30);
        result.tbsHash=sha256(D.encoded(cert,tbs));
        D.Node memory alg=D.expect(cert,tbs.end,outer.end,0x30);
        require(keccak256(D.encoded(cert,alg))==keccak256(hex"300a06082a8648ce3d040302"),"signature algorithm");
        D.Node memory bits=D.expect(cert,alg.end,outer.end,3);require(bits.end==outer.end && cert[bits.body]==0,"certificate signature bits");
        D.Node memory seq=D.expect(cert,bits.body+1,bits.end,0x30);require(seq.end==bits.end,"signature trailing");
        D.Node memory r=D.expect(cert,seq.body,seq.end,2);D.Node memory s=D.expect(cert,r.end,seq.end,2);require(s.end==seq.end,"signature fields");
        bytes memory rb=D.integer(cert,r,48);bytes memory sb=D.integer(cert,s,48);
        (result.rhi,result.rlo)=scalar(rb);(result.shi,result.slo)=scalar(sb);
        D.Node memory n=D.expect(cert,tbs.body,tbs.end,0xa0);
        require(keccak256(D.encoded(cert,n))==keccak256(hex"a003020102"),"certificate version");
        n=D.expect(cert,n.end,tbs.end,2);D.integer(cert,n,20);
        n=D.expect(cert,n.end,tbs.end,0x30);require(keccak256(D.encoded(cert,n))==keccak256(D.encoded(cert,alg)),"inner signature algorithm");
        n=D.expect(cert,n.end,tbs.end,0x30);require(keccak256(D.encoded(cert,n))==issuerHash,"issuer name");
        n=D.expect(cert,n.end,tbs.end,0x30);
        D.Node memory before=D.expect(cert,n.body,n.end,0x17);D.Node memory after_=D.expect(cert,before.end,n.end,0x17);
        require(after_.end==n.end,"validity trailing");result.expires=D.utc(cert,after_);
        require(block.timestamp>=D.utc(cert,before) && block.timestamp<=result.expires,"certificate validity");
        n=D.expect(cert,n.end,tbs.end,0x30); // signed subject, not an authority input
        n=D.expect(cert,n.end,tbs.end,0x30);
        D.Node memory pkalg=D.expect(cert,n.body,n.end,0x30);
        require(keccak256(D.encoded(cert,pkalg))==keccak256(hex"301306072a8648ce3d020106082a8648ce3d030107"),"P256 SPKI");
        D.Node memory pk=D.expect(cert,pkalg.end,n.end,3);
        require(pk.end==n.end && pk.end-pk.body==66 && cert[pk.body]==0 && cert[pk.body+1]==0x04,"public key encoding");
        bytes memory point=D.slice(cert,pk.body+2,pk.end);
        uint256 x;uint256 y;assembly{x:=mload(add(point,32)) y:=mload(add(point,64))}result.x=x;result.y=y;
        n=D.expect(cert,n.end,tbs.end,0xa3);require(n.end==tbs.end,"TBS trailing");
        seq=D.expect(cert,n.body,n.end,0x30);require(seq.end==n.end,"extensions trailing");
        extensions(cert,seq,nonce,acl);
    }
    function scalar(bytes memory raw) internal pure returns(uint256 hi,uint256 lo){
        assembly{hi:=shr(128,mload(add(raw,32))) lo:=mload(add(raw,48))}
        require(hi!=0 || lo!=0,"zero scalar");
        uint256 nhi=0xffffffffffffffffffffffffffffffff;
        uint256 nlo=0xffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973;
        require(hi<nhi || (hi==nhi && lo<nlo),"scalar range");
    }
    function extensions(bytes memory cert,D.Node memory seq,bytes32 nonce,bytes32 acl) internal pure {
        uint256 p=seq.body;uint256 count;uint256 required;bytes32[16] memory seen;
        while(p<seq.end){
            require(count<16,"too many extensions");D.Node memory ext=D.expect(cert,p,seq.end,0x30);p=ext.end;
            D.Node memory oid=D.expect(cert,ext.body,ext.end,6);bytes32 id=keccak256(D.contents(cert,oid));
            for(uint256 i;i<count;i++)require(seen[i]!=id,"duplicate certificate extension");seen[count++]=id;
            D.Node memory value=D.node(cert,oid.end,ext.end);bool critical;
            if(value.tag==1){require(value.end-value.body==1 && cert[value.body]==0xff,"critical encoding");critical=true;value=D.node(cert,value.end,ext.end);}
            require(value.tag==4 && value.end==ext.end,"extension value");bytes32 hash=keccak256(D.contents(cert,value));
            if(id==keccak256(hex"551d13")){require(critical && hash==keccak256(hex"3000"),"leaf constraints");required|=1;}
            else if(id==keccak256(hex"551d0f")){require(critical && hash==keccak256(hex"030204f0"),"leaf usage");required|=2;}
            else {
                require(!critical,"unsupported critical extension");
                if(id==keccak256(hex"551d25")){require(hash==keccak256(hex"300b06092a864886f763640418"),"Apple EKU");required|=4;}
                else if(id==keccak256(hex"2a864886f763640802")){require(hash==keccak256(abi.encodePacked(hex"3024a1220420",nonce)),"certificate nonce");required|=8;}
                else if(id==keccak256(hex"2a864886f763640806")){require(hash==acl,"key ACL");required|=16;}
            }
        }
        require(required==31,"missing certificate extension");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// Narrow canonical CBOR profile observed in macOS 27 and iOS 27 App Attest; iOS adds
/// apple_bundle_version_01 as a text string (parsed, not policy). Unknown
/// extensions reject rather than silently changing admission policy semantics.
library AppleAuthData {
    function head(bytes memory b,uint256 p,uint8 major) internal pure returns(uint256 n,uint256 next){
        require(p<b.length,"CBOR truncated");uint8 h=uint8(b[p++]);require(h>>5==major,"CBOR type");
        n=h&31;require(n<26,"CBOR length profile");
        if(n==24){require(p<b.length,"CBOR truncated");n=uint8(b[p++]);require(n>=24,"CBOR nonminimal");}
        else if(n==25){require(p+2<=b.length,"CBOR truncated");n=(uint256(uint8(b[p]))<<8)|uint8(b[p+1]);p+=2;require(n>255,"CBOR nonminimal");}
        return(n,p);
    }
    function item(bytes memory b,uint256 p,uint8 major) internal pure returns(bytes memory out,uint256 next){
        (uint256 size,uint256 start)=head(b,p,major);require(start+size<=b.length,"CBOR bounds");
        out=new bytes(size);for(uint256 i;i<size;i++)out[i]=b[start+i];return(out,start+size);
    }
    function check(bytes memory auth,bytes16 aaguid,bool enrollment,uint256 x,uint256 y,uint32 category)
        internal pure returns(uint32 counter,bytes32 kid,bytes32 cdhash,bytes32 rp){
        require(auth.length>=37 && auth.length<=1024,"auth size");
        assembly{rp:=mload(add(auth,32))}
        uint8 flags=uint8(auth[32]);require(flags&0x3e==0 && flags&0x80!=0,"auth flags");
        for(uint256 i=33;i<37;i++)counter=(counter<<8)|uint8(auth[i]);
        uint256 p=37;
        if(enrollment){
            require(flags&0x40!=0 && counter==0 && auth.length>=164,"enrollment flags/counter");
            bytes16 guid;assembly{guid:=mload(add(auth,69)) kid:=mload(add(auth,87))}
            require(guid==aaguid && auth[53]==0 && auth[54]==0x20,"AAGUID/credential length");
            require(kid==sha256(abi.encodePacked(bytes1(0x04),x,y)),"credential key");
            bytes memory cose=abi.encodePacked(hex"a5010203262001215820",x,hex"225820",y);
            p=87+cose.length;require(auth.length>=p,"COSE truncated");
            for(uint256 i;i<cose.length;i++)require(auth[87+i]==cose[i],"COSE key");
        }
        (uint256 count,uint256 start)=head(auth,p,5);p=start;
        uint256 seen;
        for(uint256 i;i<count;i++){
            bytes memory key;bytes memory value;(key,p)=item(auth,p,3);
            bytes32 h=keccak256(key);uint256 flag;
            if(h==keccak256("apple_bundle_version_01")){flag=8;(value,p)=item(auth,p,3);}
            else {
                (value,p)=item(auth,p,2);
                if(h==keccak256("apple_cd_hash_hash_01")){flag=1;require(value.length==32,"CDHash length");cdhash=bytes32(value);}
                else if(h==keccak256("apple_cd_hash_type_01")){flag=2;require(value.length==1 && value[0]==0x02,"CDHash type");}
                else if(h==keccak256("apple_validation_category_01")){flag=4;require(value.length==4
                    && uint8(value[0])==uint8(category) && uint8(value[1])==uint8(category>>8)
                    && uint8(value[2])==uint8(category>>16) && uint8(value[3])==uint8(category>>24),"validation category");}
                else revert("unknown extension");
            }
            require(seen&flag==0,"duplicate extension");seen|=flag;
        }
        require(seen&7==7,"missing extension");require(p==auth.length,"auth trailing data");
    }
}

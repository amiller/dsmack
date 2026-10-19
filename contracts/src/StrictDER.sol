// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// Bounded canonical DER for the supported Apple leaf certificate profile.
library StrictDER {
    struct Node { uint256 start; uint256 body; uint256 end; uint8 tag; }
    function node(bytes memory b, uint256 at, uint256 limit) internal pure returns(Node memory n) {
        require(limit<=b.length && at+2<=limit,"DER bounds");
        n.start=at; n.tag=uint8(b[at]); require(n.tag&31!=31,"DER long tag");
        uint256 len=uint8(b[at+1]); n.body=at+2;
        if(len>=128){
            uint256 count=len&127; require(count>0 && count<=2 && n.body+count<=limit,"DER length");
            require(b[n.body]!=0,"DER leading length zero"); len=0;
            for(uint256 i;i<count;i++)len=(len<<8)|uint8(b[n.body++]);
            require(len>=128,"DER nonminimal length");
        }
        n.end=n.body+len;require(n.end<=limit,"DER truncated");
    }
    function expect(bytes memory b,uint256 at,uint256 limit,uint8 tag) internal pure returns(Node memory n){
        n=node(b,at,limit);require(n.tag==tag,"DER tag");
    }
    function slice(bytes memory b,uint256 at,uint256 end) internal pure returns(bytes memory v){
        require(at<=end && end<=b.length,"DER slice");v=new bytes(end-at);
        for(uint256 i;i<v.length;i++)v[i]=b[at+i];
    }
    function contents(bytes memory b,Node memory n) internal pure returns(bytes memory){return slice(b,n.body,n.end);}
    function encoded(bytes memory b,Node memory n) internal pure returns(bytes memory){return slice(b,n.start,n.end);}
    function integer(bytes memory b,Node memory n,uint256 maxBytes) internal pure returns(bytes memory value){
        require(n.tag==2 && n.end>n.body,"DER integer");uint256 start=n.body;
        require(uint8(b[start])<128,"DER negative integer");
        if(b[start]==0 && n.end-start>1){require(uint8(b[start+1])>=128,"DER padded integer");start++;}
        require(n.end-start<=maxBytes,"DER integer width");
        value=new bytes(maxBytes);
        for(uint256 i;i<n.end-start;i++)value[maxBytes-(n.end-start)+i]=b[start+i];
    }
    function utc(bytes memory b,Node memory n) internal pure returns(uint64){
        require(n.tag==0x17 && n.end-n.body==13 && b[n.end-1]==0x5a,"UTC profile");
        uint256[6] memory v;
        for(uint256 i;i<6;i++){
            uint8 a=uint8(b[n.body+2*i]);uint8 c=uint8(b[n.body+2*i+1]);
            require(a>=48 && a<=57 && c>=48 && c<=57,"UTC digit");v[i]=(a-48)*10+c-48;
        }
        uint256 year=2000+v[0];require(year>=2020 && year<=2049 && v[1]>=1 && v[1]<=12 && v[3]<24 && v[4]<60 && v[5]<60,"UTC range");
        uint256[12] memory daysIn=[uint256(31),28,31,30,31,30,31,31,30,31,30,31];
        if(year%4==0)daysIn[1]=29;
        require(v[2]>=1 && v[2]<=daysIn[v[1]-1],"UTC day");
        uint256 totalDays=0;for(uint256 y=1970;y<year;y++)totalDays+=y%4==0?366:365;
        for(uint256 m=1;m<v[1];m++)totalDays+=daysIn[m-1];totalDays+=v[2]-1;
        return uint64(totalDays*86400+v[3]*3600+v[4]*60+v[5]);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {AppleAttest} from "attest/AppleAttest.sol";
import {AppleEndorsements} from "attest/AppleEndorsements.sol";
import {P384} from "attest/P384.sol";
import {RootKey} from "mutations/RootKey.sol";

contract SyntheticEndorsements is AppleEndorsements {
    function _rootKey() internal pure override returns(P384.C384Elm memory){return RootKey.key();}
}
contract Enrollment is AppleAttest {
    constructor(AppleEndorsements e,bytes16 a,uint32 c,bool ios) AppleAttest(e,msg.sender,a,c,ios){}
    function admit(bytes32,bytes32) internal pure override {}
}
contract AttestMutationsTest is Test {
    string constant DIR="fixtures/local-data/mutations/";
    function check(string memory f) external {
        AppleEndorsements e=keccak256(bytes(vm.parseJsonString(f,".testRoot")))==keccak256("root.json")?new SyntheticEndorsements():new AppleEndorsements();
        bytes memory der=vm.parseJsonBytes(f,".intermediate");
        string memory action=vm.parseJsonString(f,".action");
        if(keccak256(bytes(action))==keccak256("warp"))vm.warp(1800000000);
        bytes32 id=e.endorseIntermediate(der);
        vm.warp(vm.parseJsonUint(f,".timestamp"));
        if(keccak256(bytes(action))==keccak256("duplicate")){e.endorseIntermediate(der);return;}
        if(keccak256(bytes(action))==keccak256("rotate")){
            bytes32 second=e.endorseIntermediate(vm.parseJsonBytes(f,".secondIntermediate"));
            require(id!=second,"rotation id");
            require(e.get(id).subject==e.get(second).subject && e.get(id).notAfter!=0 && e.get(second).notAfter!=0,"rotation entries");return;
        }
        if(keccak256(bytes(vm.parseJsonString(f,".stage")))==keccak256("endorsement"))return;
        if(keccak256(bytes(action))==keccak256("wrong-key")){
            AppleEndorsements.Intermediate memory entry=e.get(id);
            uint256 i=vm.parseJsonUint(f,".wrongLimb");
            if(i==0)entry.key.xhi^=1<<0;
            else if(i==1)entry.key.xlo^=1<<128;
            else if(i==2)entry.key.xlo^=1;
            else if(i==3)entry.key.yhi^=1;
            else if(i==4)entry.key.ylo^=1<<128;
            else entry.key.ylo^=1;
            bytes32 slot=keccak256(abi.encode(id,uint256(0)));
            vm.store(address(e),bytes32(uint256(slot)+1),bytes32(entry.key.xhi));
            vm.store(address(e),bytes32(uint256(slot)+2),bytes32(entry.key.xlo));
            vm.store(address(e),bytes32(uint256(slot)+3),bytes32(entry.key.yhi));
            vm.store(address(e),bytes32(uint256(slot)+4),bytes32(entry.key.ylo));
        }
        uint32 category=uint32(vm.parseJsonUint(f,".category"));
        Enrollment a=new Enrollment(e,bytes16(vm.parseJsonBytes(f,".aaguid")),category,category==5);
        a.enroll(vm.parseJsonBytes(f,".cert"),vm.parseJsonBytes(f,".auth"),vm.parseJsonBytes(f,".clientData"),id);
    }
    function test_mutations() public {
        string[] memory ids=vm.parseJsonStringArray(vm.readFile(string.concat(DIR,"manifest.json")),".ids");
        for(uint256 i;i<ids.length;i++){
            string memory f=vm.readFile(string.concat(DIR,ids[i],".json"));vm.warp(vm.parseJsonUint(f,".timestamp"));
            try this.check(f){emit log(string.concat("VERDICT|",ids[i],"|ACCEPT|"));}
            catch(bytes memory reason){emit log(string.concat("VERDICT|",ids[i],"|REJECT|",vm.toString(reason)));}
        }
    }
}

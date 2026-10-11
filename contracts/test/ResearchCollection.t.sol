// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {ResearchBadgesTest} from "./ResearchBadges.t.sol";
import {ResearchBadges} from "../src/application/ResearchBadges.sol";
import {DemoV1} from "../src/application/DemoV1.sol";
import {ResearchCollection} from "../src/application/ResearchCollection.sol";

contract ResearchCollectionTest is ResearchBadgesTest {
    ResearchCollection collection;
    function setUp() public override {
        super.setUp();
        collection = new ResearchCollection(badge,address(this));
    }
    function publish(uint256 id) internal {
        collection.publishArtwork(id,"https://example.org/fold.png",bytes32(uint256(101)),bytes32(uint256(102)));
    }
    function test_IssueToExistingOwnerWithoutChangingReceipt() public {
        uint256 id=participant();publish(id);
        vm.prank(address(123));collection.issueReceipt(id);
        assertEq(collection.ownerOf(id),recipient);
        assertEq(badge.ownerOf(id),recipient);
        assertEq(collection.issueReceipt(id),id);
        assertEq(collection.balanceOf(recipient),1);
        assertEq(badge.nextId(),2);
    }
    function test_ArtworkRequiredBeforeIssuing() public {
        uint256 id=participant();
        vm.expectRevert("artwork pending");collection.issueReceipt(id);
        vm.expectRevert();collection.issueReceipt(id+1);
    }
    function test_ArtworkPublisherCannotChangeReceiptOwnership() public {
        uint256 id=participant();publish(id);collection.issueReceipt(id);
        vm.prank(address(123));vm.expectRevert("Ownable: caller is not the owner");publish(id);
        vm.prank(recipient);vm.expectRevert("non-transferable");collection.transferFrom(recipient,address(123),id);
        vm.prank(recipient);vm.expectRevert("non-transferable");collection.approve(address(123),id);
        vm.expectRevert("non-transferable");collection.setApprovalForAll(address(123),true);
    }
    function test_FreezePreventsArtReplacement() public {
        uint256 id=participant();publish(id);collection.issueReceipt(id);collection.freezeArtwork(id);
        vm.expectRevert("artwork frozen");publish(id);
        vm.expectRevert("artwork state");collection.freezeArtwork(id);
        assertEq(collection.ownerOf(id),recipient);
    }
    function test_RejectsMetadataInjectionAndEmptyHashes() public {
        uint256 id=participant();
        vm.expectRevert("artwork hashes");collection.publishArtwork(id,"https://example.org/a.png",0,bytes32(uint256(202)));
        vm.expectRevert("image URI scheme");collection.publishArtwork(id,"http://example.org/a.png",bytes32(uint256(201)),bytes32(uint256(202)));
        vm.expectRevert("image URI character");collection.publishArtwork(id,'https://example.org/"bad',bytes32(uint256(201)),bytes32(uint256(202)));
        vm.expectRevert();publish(id+1);
    }
    function decodeMetadata(string memory uri) internal pure returns(string memory) {
        bytes memory input=bytes(uri);bytes memory out=new bytes(input.length);uint256 count;uint256 bits;uint256 acc;
        for(uint256 i=29;i<input.length && input[i]!="=";i++) {
            uint8 c=uint8(input[i]);uint256 value;
            if(c>=65 && c<=90) value=c-65;
            else if(c>=97 && c<=122) value=c-71;
            else if(c>=48 && c<=57) value=c+4;
            else if(c==43) value=62;
            else {require(c==47,"base64");value=63;}
            acc=(acc<<6)|value;bits+=6;
            if(bits>=8){bits-=8;out[count++]=bytes1(uint8(acc>>bits));}
        }
        assembly {mstore(out,count)}
        return string(out);
    }
    function test_MetadataAndBuilderProvenance() public {
        uint256 parent=participant();
        (ResearchBadges.Claim memory c,DemoV1.Request memory r,bytes memory sig)=prepare(2,parent,FRIEND);
        uint256 id=badge.claim(c,r,sig);publish(id);collection.issueReceipt(id);
        assertEq(collection.ownerOf(id),recipient);
        assertEq(address(collection.receipts()),address(badge));
        string memory metadata=decodeMetadata(collection.tokenURI(id));
        assertEq(vm.parseJsonString(metadata,".name"),"Attest Independent Builder #2");
        assertEq(vm.parseJsonString(metadata,".image"),"https://example.org/fold.png");
        assertEq(vm.parseJsonAddress(metadata,".receipt_contract"),address(badge));
        assertEq(vm.parseJsonUint(metadata,".receipt_token"),id);
        assertEq(vm.parseJsonUint(metadata,".level"),2);
        assertEq(vm.parseJsonUint(metadata,".parent"),parent);
        assertEq(vm.parseJsonBytes32(metadata,".image_sha256"),bytes32(uint256(101)));
        assertEq(vm.parseJsonBytes32(metadata,".renderer_sha256"),bytes32(uint256(102)));
        assertTrue(collection.supportsInterface(0x49064906));
        assertTrue(collection.supportsInterface(0x80ac58cd));
        vm.expectRevert();collection.tokenURI(id+1);
    }
}

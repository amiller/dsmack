// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {PersonalBadgeAccount,PersonalBadgeAccountFactory} from "../src/application/PersonalBadgeAccount.sol";
import {P256Verifier} from "./P256Verifier.sol";
import {Test} from "forge-std/Test.sol";
import {ResearchBadges} from "../src/application/ResearchBadges.sol";
import {DemoV1} from "../src/application/DemoV1.sol";
import {DemoV2} from "../src/application/DemoV2.sol";
import {AppleAttestRegistryV1} from "../src/AppleAttestRegistryV1.sol";

// Policy-only tests: mock the already-verified evidence boundary explicitly.
// AppleAttestRegistryV1Test separately uses real certificate/assertion fixtures.
contract BadgePolicyAdapter {
    address public registry;
    address public cds;
    constructor(address n){registry=n;cds=address(this);}
}
contract ResearchBadgesTest is Test {
    DemoV2 network;
    ResearchBadges badge;
    BadgePolicyAdapter adapter;
    bytes32 category;
    bytes32 constant KID = bytes32(uint256(7));
    bytes32 constant CD = bytes32(uint256(8));
    bytes32 constant RP = bytes32(uint256(9));
    bytes32 constant PUBLISHER = bytes32(uint256(10));
    bytes32 constant FRIEND = bytes32(uint256(11));
    uint256 constant RECIPIENT_KEY = 12345;
    address recipient;
    function setUp() public virtual {
        recipient=vm.addr(RECIPIENT_KEY);network=new DemoV2(address(this));
        adapter=new BadgePolicyAdapter(address(network));
        category=network.addCategory(bytes32(uint256(1)),bytes32(uint256(2)),address(adapter),true);
        network.setCategoryEnabled(category,true);network.setPaused(false);
        badge=new ResearchBadges(network,AppleAttestRegistryV1(address(adapter)),category,PUBLISHER);
    }
    function prepare(uint8 level,uint256 parent,bytes32 team) internal returns(ResearchBadges.Claim memory c,DemoV1.Request memory r,bytes memory sig) {
        c=ResearchBadges.Claim(recipient,KID,level,parent,uint64(block.timestamp+55));
        r=DemoV1.Request(DemoV1.Action.Receipt,category,address(123),address(123),bytes32(uint256(3)),0,uint64(block.timestamp+55),0,1,2,badge.claimDigest(c));
        (uint8 v,bytes32 a,bytes32 b)=vm.sign(RECIPIENT_KEY,badge.claimDigest(c));sig=abi.encodePacked(a,b,v);
        vm.mockCall(address(adapter),abi.encodeWithSignature("assertionEvidence(bytes32)",KID),abi.encode(network.contextHash(r),CD,RP,uint64(block.timestamp),uint32(1)));
        vm.mockCall(address(adapter),abi.encodeWithSignature("rpIdHash(bytes32)",CD),abi.encode(RP));
        vm.mockCall(address(adapter),abi.encodeWithSignature("teamIdHash(bytes32)",CD),abi.encode(team));
        vm.mockCall(address(adapter),abi.encodeWithSignature("bundleIdHash(bytes32)",CD),abi.encode(sha256(bytes(badge.builderBundleId(recipient)))));
        vm.mockCall(address(network),abi.encodeCall(network.isActive,(keccak256(abi.encode(category,KID)))),abi.encode(true));
    }
    function participant() internal returns(uint256) {
        (ResearchBadges.Claim memory c,DemoV1.Request memory r,bytes memory sig)=prepare(1,0,PUBLISHER);
        return badge.claim(c,r,sig);
    }
    function test_SponsorCannotReceiveOrRedirectParticipantNFT() public {
        (ResearchBadges.Claim memory c,DemoV1.Request memory r,bytes memory sig)=prepare(1,0,PUBLISHER);
        vm.prank(address(123));uint256 id=badge.claim(c,r,sig);assertEq(badge.ownerOf(id),recipient);
        assertEq(badge.participantOf(recipient),id);
        c.recipient=address(123);vm.expectRevert("recipient consent");badge.claim(c,r,sig);
    }
    function test_ReplayCannotMintTwice() public {
        (ResearchBadges.Claim memory c,DemoV1.Request memory r,bytes memory sig)=prepare(1,0,PUBLISHER);
        badge.claim(c,r,sig);vm.expectRevert("participant already claimed/parent");badge.claim(c,r,sig);
    }
    function test_IndependentBuilderLinksToSameRecipient() public {
        uint256 parent=participant();
        (ResearchBadges.Claim memory c,DemoV1.Request memory r,bytes memory sig)=prepare(2,parent,FRIEND);
        uint256 id=badge.claim(c,r,sig);assertEq(badge.ownerOf(id),recipient);
        (,bytes32 team,uint8 level,uint256 linked)=badge.badges(id);
        assertEq(team,FRIEND);assertEq(level,2);assertEq(linked,parent);assertEq(badge.builderOf(parent),id);
        vm.expectRevert("independent team");badge.claim(c,r,sig);
    }
    function test_PublisherOrUnknownTeamCannotEarnBuilder() public {
        uint256 parent=participant();
        (ResearchBadges.Claim memory c,DemoV1.Request memory r,bytes memory sig)=prepare(2,parent,PUBLISHER);
        vm.expectRevert("independent team");badge.claim(c,r,sig);
        (c,r,sig)=prepare(2,parent,0);vm.expectRevert("independent team");badge.claim(c,r,sig);
    }
    function test_ContextAndReceiptCannotBeSubstituted() public {
        (ResearchBadges.Claim memory c,DemoV1.Request memory r,bytes memory sig)=prepare(1,0,PUBLISHER);
        r.nonce++;vm.expectRevert("assertion evidence");badge.claim(c,r,sig);
        r.envelopeDigest=0;vm.expectRevert("receipt binding");badge.claim(c,r,sig);
    }
    function test_ExpiredAndInactiveClaimsFail() public {
        (ResearchBadges.Claim memory c,DemoV1.Request memory r,bytes memory sig)=prepare(1,0,PUBLISHER);
        vm.mockCall(address(network),abi.encodeCall(network.isActive,(keccak256(abi.encode(category,KID)))),abi.encode(false));
        vm.expectRevert("inactive member");badge.claim(c,r,sig);
        vm.warp(block.timestamp+56);vm.expectRevert("claim expiry");badge.claim(c,r,sig);
    }
    function test_BuilderCannotAttachAnotherRecipientsNFT() public {
        uint256 parent=participant();
        recipient=address(999);
        (ResearchBadges.Claim memory c,DemoV1.Request memory r,)=prepare(2,parent,FRIEND);
        // A consenting smart account still cannot take another account's parent.
        vm.etch(recipient,hex"00");
        vm.mockCall(recipient,abi.encodeWithSelector(bytes4(0x1626ba7e),badge.claimDigest(c),bytes("")),abi.encode(bytes4(0x1626ba7e)));
        vm.expectRevert("parent");badge.claim(c,r,"");
    }
    function test_ContractRecipientConsentAndMetadata() public {
        recipient=address(999);vm.etch(recipient,hex"00");
        (ResearchBadges.Claim memory c,DemoV1.Request memory r,)=prepare(1,0,PUBLISHER);
        vm.mockCall(recipient,abi.encodeWithSelector(bytes4(0x1626ba7e),badge.claimDigest(c),bytes("")),abi.encode(bytes4(0x1626ba7e)));
        uint256 id=badge.claim(c,r,"");assertEq(badge.ownerOf(id),recipient);
        assertTrue(bytes(badge.tokenURI(id)).length > 100);
    }
    function test_MalformedContractConsentRejected() public {
        recipient=address(999);vm.etch(recipient,hex"00");
        (ResearchBadges.Claim memory c,DemoV1.Request memory r,)=prepare(1,0,PUBLISHER);
        vm.mockCall(recipient,abi.encodeWithSelector(bytes4(0x1626ba7e),badge.claimDigest(c),bytes("")),hex"1626ba7e");
        vm.expectRevert("recipient consent");badge.claim(c,r,"");
    }
    function test_WithdrawnBuildCannotClaim() public {
        (ResearchBadges.Claim memory c,DemoV1.Request memory r,bytes memory sig)=prepare(1,0,PUBLISHER);
        vm.mockCall(address(adapter),abi.encodeWithSignature("rpIdHash(bytes32)",CD),abi.encode(bytes32(0)));
        vm.expectRevert("admitted build");badge.claim(c,r,sig);
    }
    function test_ClaimSignatureCannotCrossBadgeDeployments() public {
        (ResearchBadges.Claim memory c,,bytes memory sig)=prepare(1,0,PUBLISHER);
        ResearchBadges other=new ResearchBadges(network,AppleAttestRegistryV1(address(adapter)),category,PUBLISHER);
        DemoV1.Request memory r;
        vm.expectRevert("recipient consent");other.claim(c,r,sig);
    }
    function test_PersonalAccountHandoffThenBuilderClaim() public {
        P256Verifier verifier=new P256Verifier();vm.etch(address(0x100),address(verifier).code);
        PersonalBadgeAccountFactory factory=new PersonalBadgeAccountFactory(address(badge));
        PersonalBadgeAccount account=factory.create(
            0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
            0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5);
        recipient=address(account);
        (ResearchBadges.Claim memory c,DemoV1.Request memory r,)=prepare(1,0,PUBLISHER);
        (bytes32 a,bytes32 b)=vm.signP256(1,account.consentDigest(badge.claimDigest(c)));
        uint256 parent=badge.claim(c,r,abi.encodePacked(a,b));
        uint256 nx=0x7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978;
        uint256 ny=0x07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1;
        uint64 deadline=uint64(block.timestamp+300);
        bytes32 handoff=account.handoffDigest(nx,ny,deadline);
        (a,b)=vm.signP256(1,handoff);bytes memory original=abi.encodePacked(a,b);
        (a,b)=vm.signP256(2,handoff);account.handoff(nx,ny,deadline,original,abi.encodePacked(a,b));
        (c,r,)=prepare(2,parent,FRIEND);
        (a,b)=vm.signP256(1,account.consentDigest(badge.claimDigest(c)));
        vm.expectRevert("recipient consent");badge.claim(c,r,abi.encodePacked(a,b));
        (a,b)=vm.signP256(2,account.consentDigest(badge.claimDigest(c)));
        uint256 builder=badge.claim(c,r,abi.encodePacked(a,b));
        assertEq(badge.ownerOf(parent),address(account));assertEq(badge.ownerOf(builder),address(account));
        assertTrue(badge.upgraded(parent));
    }
    function test_SponsoredAccountCreationRequiresBoundAdmission() public {
        PersonalBadgeAccountFactory factory=new PersonalBadgeAccountFactory(address(badge));
        (,DemoV1.Request memory r,)=prepare(1,0,PUBLISHER);
        uint256 x=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296;
        uint256 y=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5;
        vm.expectRevert("creation binding");factory.createForMember(x,y,KID,r);
        r.envelopeDigest=factory.creationDigest(x,y,KID);
        vm.expectRevert("creation evidence");factory.createForMember(x,y,KID,r);
        vm.mockCall(address(adapter),abi.encodeWithSignature("assertionEvidence(bytes32)",KID),abi.encode(network.contextHash(r),CD,RP,uint64(block.timestamp),uint32(2)));
        PersonalBadgeAccount account=factory.createForMember(x,y,KID,r);
        assertEq(address(account),factory.accountAddress(x,y));assertTrue(factory.isAccount(address(account)));
        assertEq(address(factory.createForMember(x,y,KID,r)),address(account));
        vm.mockCall(address(network),abi.encodeCall(network.isActive,(keccak256(abi.encode(category,KID)))),abi.encode(false));
        vm.expectRevert("inactive member");factory.createForMember(x,y,KID,r);
    }
    function test_BorrowedIndependentBuildCannotClaimForAnotherAccount() public {
        uint256 parent=participant();
        (ResearchBadges.Claim memory c,DemoV1.Request memory r,bytes memory sig)=prepare(2,parent,FRIEND);
        vm.mockCall(address(adapter),abi.encodeWithSignature("bundleIdHash(bytes32)",CD),abi.encode(sha256(bytes(badge.builderBundleId(address(999))))));
        vm.expectRevert("recipient-bound build");badge.claim(c,r,sig);
        assertFalse(badge.builderTeamClaimed(FRIEND));assertFalse(badge.upgraded(parent));
    }
    function test_NFTCannotTransfer() public {
        uint256 id=participant();vm.prank(recipient);vm.expectRevert("non-transferable");badge.transferFrom(recipient,address(123),id);
    }
}

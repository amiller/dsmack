// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Test} from "forge-std/Test.sol";
import {PersonalBadgeAccount,PersonalBadgeAccountFactory} from "../src/application/PersonalBadgeAccount.sol";
import {P256Verifier} from "./P256Verifier.sol";
contract PersonalBadgeAccountTest is Test {
    // Public test keys 1 and 2, never used by the app or a deployed participant.
    uint256 constant X1=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296;
    uint256 constant Y1=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5;
    uint256 constant X2=0x7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978;
    uint256 constant Y2=0x07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1;
    PersonalBadgeAccount account;
    PersonalBadgeAccountFactory factory;
    bytes32 constant CLAIM=bytes32(uint256(777));
    function setUp() public {
        P256Verifier p=new P256Verifier();vm.etch(address(0x100),address(p).code);
        factory=new PersonalBadgeAccountFactory(address(this));account=factory.create(X1,Y1);
    }
    function sign(uint256 key,bytes32 digest) internal pure returns(bytes memory) {
        (bytes32 r,bytes32 s)=vm.signP256(key,digest);return abi.encodePacked(r,s);
    }
    function test_RealP256ConsentAndRestrictedVerifier() public {
        bytes memory sig=sign(1,account.consentDigest(CLAIM));
        assertEq(account.isValidSignature(CLAIM,sig),bytes4(0x1626ba7e));
        vm.prank(address(123));assertEq(account.isValidSignature(CLAIM,sig),bytes4(0xffffffff));
        assertEq(account.isValidSignature(bytes32(uint256(778)),sig),bytes4(0xffffffff));
        assertEq(account.isValidSignature(CLAIM,hex"01"),bytes4(0xffffffff));
    }
    function test_ConsentCannotCrossChainOrAccount() public {
        bytes memory sig=sign(1,account.consentDigest(CLAIM));
        PersonalBadgeAccount other=new PersonalBadgeAccount(address(this),X1,Y1);
        assertEq(other.isValidSignature(CLAIM,sig),bytes4(0xffffffff));
        vm.chainId(block.chainid+1);assertEq(account.isValidSignature(CLAIM,sig),bytes4(0xffffffff));
    }
    function test_DeterministicDeploymentCannotBeRedirected() public {
        assertEq(address(account),factory.accountAddress(X1,Y1));
        vm.prank(address(123));assertEq(address(factory.create(X1,Y1)),address(account));
        assertTrue(factory.accountAddress(X2,Y2)!=address(account));
    }
    function test_HandoffPreservesAddressAndInvalidatesOldConsent() public {
        bytes memory oldConsent=sign(1,account.consentDigest(CLAIM));
        uint64 deadline=uint64(block.timestamp+300);bytes32 digest=account.handoffDigest(X2,Y2,deadline);
        bytes memory oldSig=sign(1,digest);bytes memory newSig=sign(2,digest);
        account.handoff(X2,Y2,deadline,oldSig,newSig);
        assertEq(account.generation(),1);assertEq(account.keyX(),X2);
        assertEq(account.isValidSignature(CLAIM,oldConsent),bytes4(0xffffffff));
        assertEq(account.isValidSignature(CLAIM,sign(2,account.consentDigest(CLAIM))),bytes4(0x1626ba7e));
        vm.expectRevert("new key");account.handoff(X2,Y2,deadline,oldSig,newSig);
        // Returning to the first key must not revive its old consent.
        digest=account.handoffDigest(X1,Y1,deadline);
        bytes memory a=sign(2,digest);bytes memory b=sign(1,digest);
        account.handoff(X1,Y1,deadline,a,b);
        assertEq(account.isValidSignature(CLAIM,oldConsent),bytes4(0xffffffff));
        vm.expectRevert("current key consent");account.handoff(X2,Y2,deadline,oldSig,newSig);
    }
    function test_HandoffRequiresBothKeysAndValidPoint() public {
        uint64 deadline=uint64(block.timestamp+300);bytes32 digest=account.handoffDigest(X2,Y2,deadline);
        bytes memory a=sign(1,digest);bytes memory b=sign(2,digest);
        vm.expectRevert("current key consent");account.handoff(X2,Y2,deadline,b,b);
        vm.expectRevert("new key possession");account.handoff(X2,Y2,deadline,a,a);
        vm.expectRevert("new key");account.handoff(1,1,deadline,a,b);
        vm.warp(block.timestamp+301);vm.expectRevert("handoff expiry");account.handoff(X2,Y2,deadline,a,b);
    }
    function test_MissingPrecompileFailsClosed() public {
        bytes memory sig=sign(1,account.consentDigest(CLAIM));vm.etch(address(0x100),hex"");
        assertEq(account.isValidSignature(CLAIM,sig),bytes4(0xffffffff));
    }
    /// Captured from CryptoKit on mini-mesh using node/tests/PersonalAccountVectors.swift.
    function test_SwiftCryptoKitInteroperability() public {
        bytes32 consent=sha256(abi.encode(account.CONSENT_DOMAIN(),uint256(84532),address(0x1111111111111111111111111111111111111111),uint256(2),CLAIM));
        assertEq(consent,0x2df8f1c27b1e058d0efafdd5d5beb887d8c2650c854408996c4d04366d719f32);
        bytes32 handoff=sha256(abi.encode(account.HANDOFF_DOMAIN(),uint256(84532),address(0x1111111111111111111111111111111111111111),uint256(2),X2,Y2,uint64(1800000000)));
        assertEq(handoff,0xbcecee4309169ca1d70f98d8cf7d90c2497e0deb3d3552fcb572c54c66b39b52);
        (bool ok,bytes memory result)=address(0x100).staticcall(abi.encode(consent,
            uint256(0x00d88907c1a552fb0146c08ee5718a79050f1c09c9bf861a521cd613324a3ced),
            uint256(0xf74a49a53cbd7176e5c4c9ee7a8274fbbdd2677c36a54308fb4e00ec1232241d),X1,Y1));
        assertTrue(ok);assertEq(abi.decode(result,(uint256)),1);
        (ok,result)=address(0x100).staticcall(abi.encode(handoff,
            uint256(0xbf3d26a42c3193b80521f3a211b126cfb4312630ce1a413dea3c6b4bf15e38f7),
            uint256(0xb201eef59ede0eec116facaf89e37e15814286425f875855a851065117030702),X1,Y1));
        assertTrue(ok);assertEq(abi.decode(result,(uint256)),1);
    }
    function test_InvalidPointCannotCreateAccount() public {
        vm.expectRevert("account policy/key");factory.create(0,0);
        vm.expectRevert("account policy/key");factory.create(1,1);
    }
}

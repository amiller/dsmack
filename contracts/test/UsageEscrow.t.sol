// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {UsageEscrow} from "../src/UsageEscrow.sol";
interface Cheat {
 function chainId(uint256) external; function warp(uint256) external; function deal(address,uint256) external;
 function addr(uint256) external returns(address); function prank(address) external;
 function sign(uint256,bytes32) external returns(uint8,bytes32,bytes32);
 function expectRevert(bytes calldata) external;
}
contract UsageEscrowTest {
 Cheat constant vm=Cheat(address(uint160(uint256(keccak256("hevm cheat code")))));
 string expected; UsageEscrow e; bytes32 constant NODE=keccak256("class"); bytes32 constant COMPOSE=keccak256("compose"); bytes32 constant IMAGE=keccak256("image"); address constant OP=address(0x1111);
 function setUp() public {vm.chainId(84532);vm.warp(120000);vm.deal(address(this),1 ether);e=new UsageEscrow(address(this));e.registerBroker(vm.addr(123));e.registerNode(NODE,OP,1,1000,30,COMPOSE,IMAGE);}
 receive() external payable {}
 function sig(uint256 key,bytes32 digest) internal returns(bytes memory) {(uint8 v,bytes32 r,bytes32 s)=vm.sign(key,digest);return abi.encodePacked(r,s,v);}
 function bind() internal returns(UsageEscrow.NodeBinding memory) {return UsageEscrow.NodeBinding(NODE,OP,vm.addr(456),COMPOSE,IMAGE,keccak256("fresh run"),uint64(block.timestamp+600));}
 function buy(uint128 amount) internal returns(uint256) {return e.buy{value:uint256(amount)*e.quote(NODE)}(NODE,1,amount,keccak256("buyer"));}
 function submit(uint256 id,uint64 seq,uint128 used,bool finalReceipt,UsageEscrow.NodeBinding memory b) internal {
  UsageEscrow.Receipt[] memory rs=new UsageEscrow.Receipt[](1);rs[0]=UsageEscrow.Receipt(id,seq,used,uint64(block.timestamp),finalReceipt);
  bytes[] memory ss=new bytes[](1);ss[0]=sig(456,e.receiptDigest(rs[0]));bytes memory bs=sig(123,e.bindingDigest(b));if(bytes(expected).length>0)vm.expectRevert(bytes(expected));e.settle(rs,ss,b,bs);
 }
 function testPurchaseBeforeRunAndSettlementAfterExit() public {uint256 id=buy(20);vm.warp(block.timestamp+1200);UsageEscrow.NodeBinding memory b=bind();vm.warp(block.timestamp+5);submit(id,1,5,true,b);require(e.credits(OP)==5000 && e.credits(address(this))==15000);uint256 before=OP.balance;vm.prank(OP);e.withdraw();require(OP.balance==before+5000);before=address(this).balance;e.withdraw();require(address(this).balance==before+15000);}
 function testTwoBuyersRaisePriceThenIdleDecays() public {buy(30);vm.prank(address(0x2222));vm.deal(address(0x2222),1 ether);e.buy{value:30000}(NODE,1,30,keccak256("second buyer"));vm.warp(block.timestamp+60);require(e.quote(NODE)==1125);vm.warp(120120);require(e.quote(NODE)==1000);}
 function testPremiumCannotReachOperator() public {buy(60);vm.warp(block.timestamp+60);uint256 id=buy(10);UsageEscrow.NodeBinding memory b=bind();submit(id,1,4,true,b);require(e.credits(OP)==4000 && e.lockedPremium()==500 && e.credits(address(this))==6750);}
 function testUnservedPurchaseRefundsAfterGrace() public {uint256 id=buy(20);vm.warp(block.timestamp+7200);e.refund(id);require(e.credits(address(this))==20000);}
 function testBrokerCanOnlyBePinnedOnce() public {vm.expectRevert(bytes("broker admission"));e.registerBroker(vm.addr(789));}
 function testBindingCannotRedirectOperator() public {uint256 id=buy(20);UsageEscrow.NodeBinding memory b=bind();b.operator=address(0x3333);expected="binding operator";submit(id,1,2,true,b);}
 function testWrongMeasurementBindingRefused() public {uint256 id=buy(20);UsageEscrow.NodeBinding memory b=bind();b.composeHash=keccak256("other");expected="binding measurements";submit(id,1,2,true,b);}
 function testPurchaseCannotSwitchRuns() public {uint256 id=buy(20);UsageEscrow.NodeBinding memory b=bind();submit(id,1,2,false,b);b.runId=keccak256("another run");expected="binding changed";submit(id,2,3,true,b);}
 function testBindingMayExpireBeforeSubmissionButReceiptMustPrecedeExpiry() public {uint256 id=buy(20);UsageEscrow.NodeBinding memory b=bind();b.expires=uint64(block.timestamp+5);UsageEscrow.Receipt[] memory rs=new UsageEscrow.Receipt[](1);rs[0]=UsageEscrow.Receipt(id,1,3,b.expires,true);bytes[] memory ss=new bytes[](1);ss[0]=sig(456,e.receiptDigest(rs[0]));vm.warp(block.timestamp+1200);bytes memory bs=sig(123,e.bindingDigest(b));if(bytes(expected).length>0)vm.expectRevert(bytes(expected));e.settle(rs,ss,b,bs);require(e.credits(OP)==3000);}
 function testForgedBrokerRefused() public {uint256 id=buy(20);UsageEscrow.NodeBinding memory b=bind();UsageEscrow.Receipt[] memory rs=new UsageEscrow.Receipt[](1);rs[0]=UsageEscrow.Receipt(id,1,2,uint64(block.timestamp),true);bytes[] memory ss=new bytes[](1);ss[0]=sig(456,e.receiptDigest(rs[0]));bytes memory bs=sig(789,e.bindingDigest(b));vm.expectRevert(bytes("broker signer"));e.settle(rs,ss,b,bs);}
}

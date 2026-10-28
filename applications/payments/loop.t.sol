// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {UsageEscrow} from "usage/UsageEscrow.sol";
interface VM {
 function chainId(uint256) external; function warp(uint256) external;function deal(address,uint256) external;
 function prank(address) external;function addr(uint256) external returns(address);
 function sign(uint256,bytes32) external returns(uint8,bytes32,bytes32);
 function readFile(string calldata) external view returns(string memory);
 function parseJsonUint(string calldata,string calldata) external pure returns(uint256);
 function parseJsonBytes32(string calldata,string calldata) external pure returns(bytes32);
 function parseJsonBytes(string calldata,string calldata) external pure returns(bytes memory);
 function parseJsonAddress(string calldata,string calldata) external pure returns(address);
 function etch(address,bytes calldata) external;
 function parseJsonString(string calldata,string calldata) external pure returns(string memory);
 function parseUint(string calldata) external pure returns(uint256);
}
contract PaymentsLoop {
 VM constant vm=VM(address(uint160(uint256(keccak256("hevm cheat code")))));
 address constant OPERATOR=address(0x1111);address constant BUYER=address(0x2222);
 bytes32 constant NODE=keccak256("compute node");
 event Evidence(string label,uint256 amount);
 receive() external payable {}
 function testFullLoopPriceCutoffSettlementAndRefund() external {
  vm.chainId(84532);vm.warp(120000);vm.deal(address(this),1 ether);vm.deal(BUYER,1 ether);
  UsageEscrow e=new UsageEscrow(address(this));
  e.registerNode(NODE,OPERATOR,vm.addr(123),keccak256("attested memory key"),1,1000,30,uint64(block.timestamp+86400));
  uint256 initial=e.quote(NODE);
  e.buy{value:30*initial}(NODE,1,30,keccak256("buyer 1"));
  vm.prank(BUYER);e.buy{value:30*initial}(NODE,1,30,keccak256("buyer 2"));
  vm.warp(block.timestamp+60);uint256 peak=e.quote(NODE);require(peak>initial,"two buyers must raise price");
  uint256 id=e.buy{value:10*peak}(NODE,1,10,keccak256("buyer 3"));
  vm.warp(block.timestamp+4);
  UsageEscrow.Receipt[] memory receipts=new UsageEscrow.Receipt[](1);receipts[0]=UsageEscrow.Receipt(id,1,4,uint64(block.timestamp),true);
  bytes[] memory sigs=new bytes[](1);(uint8 v,bytes32 r,bytes32 s)=vm.sign(123,e.receiptDigest(receipts[0]));sigs[0]=abi.encodePacked(r,s,v);
  e.settle(receipts,sigs);
  require(e.getPurchase(id).closed && e.getPurchase(id).used==4,"final usage cutoff");
  require(e.credits(OPERATOR)==4000,"operator floor payout");require(e.lockedPremium()==4*(peak-initial),"premium locked");
  uint256 beforeOperator=OPERATOR.balance;vm.prank(OPERATOR);e.withdraw();require(OPERATOR.balance-beforeOperator==4000,"operator receives ETH");
  uint256 beforeBuyer=address(this).balance;e.withdraw();require(address(this).balance-beforeBuyer==6*peak,"buyer receives unused ETH");
  vm.warp(block.timestamp+180);require(e.quote(NODE)==initial,"idle node price returns to floor");
  vm.warp(127200);e.refund(1);vm.prank(BUYER);e.refund(2);require(e.credits(address(this))==30*initial && e.credits(BUYER)==30*initial,"expired unused purchases refunded");
  emit Evidence("initial wei/second",initial);emit Evidence("two-buyer peak wei/second",peak);emit Evidence("used seconds",4);emit Evidence("operator received wei",4000);emit Evidence("buyer refunded wei",6*peak);
 }
 // Consume a real Go secp256k1 receipt with Solidity's production ecrecover path.
 function testGuestReceiptSettlesInContract() external {settleFixture("guest-interop.json");}
 function testComputeCutoffSettlesInContract() external {settleFixture("compute-cutoff.json");}
 function testComputeUnusedRefundSettlesInContract() external {settleFixture("compute-unused.json");}
 function settleFixture(string memory name) internal {
  string memory f=vm.readFile(name);
  vm.chainId(84532);vm.warp(vm.parseJsonUint(f,".receipt.receipt.endedAt")-1);vm.deal(address(this),1 ether);
  UsageEscrow template=new UsageEscrow(address(this));address addressPin=vm.parseJsonAddress(f,".escrow");
  vm.etch(addressPin,address(template).code);UsageEscrow e=UsageEscrow(addressPin);
  require(e.owner()==address(this),"owner immutable");
  bytes32 node=vm.parseJsonBytes32(f,".registration.node");
  address signer=vm.parseJsonAddress(f,".registration.receiptSigner");
  bytes32 buyer=vm.parseJsonBytes32(f,".grant.grant.buyerKey");
  e.registerNode(node,OPERATOR,signer,keccak256("attested receipt binding"),1,1000,30,uint64(block.timestamp+3600));
  // etch skips constructor storage initialization; consume ID zero before the signed ID one.
  uint128 amount=uint128(vm.parseUint(vm.parseJsonString(f,".grant.grant.amount")));
  e.buy{value:uint256(amount)*1000}(node,1,amount,buyer);
  uint256 id=e.buy{value:uint256(amount)*1000}(node,1,amount,buyer);require(id==1,"fixture purchase ID");
  vm.warp(block.timestamp+1);
  UsageEscrow.Receipt[] memory receipts=new UsageEscrow.Receipt[](1);
  receipts[0]=UsageEscrow.Receipt(id,uint64(vm.parseJsonUint(f,".receipt.receipt.sequence")),
    uint128(vm.parseUint(vm.parseJsonString(f,".receipt.receipt.used"))),uint64(block.timestamp),true);
  require(e.receiptDigest(receipts[0])==vm.parseJsonBytes32(f,".receiptDigest"),"Go and Solidity receipt digests differ");
  bytes[] memory sigs=new bytes[](1);sigs[0]=vm.parseJsonBytes(f,".receipt.signature");e.settle(receipts,sigs);
  require(e.credits(OPERATOR)==uint256(receipts[0].used)*1000 && e.credits(address(this))==uint256(amount-receipts[0].used)*1000,"compute receipt operator and refund credits");
  emit Evidence("Go signed receipt settled wei",uint256(receipts[0].used)*1000);

 }
}

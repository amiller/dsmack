// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {ERC721} from "openzeppelin-contracts/contracts/token/ERC721/ERC721.sol";
import {Strings} from "openzeppelin-contracts/contracts/utils/Strings.sol";

contract DemoTokenV1 is ERC20 {
    constructor() ERC20("TEE Interop Demo", "TEED") { _mint(msg.sender, 10_000 ether); }
}

/// Historical membership receipt, not a physical-device or current-status claim.
contract MembershipReceiptV1 is ERC721 {
    address public immutable registry;
    mapping(uint256 => bytes32) public categoryOf;
    constructor() ERC721("TEE Interop Membership Receipt", "TEEM") { registry = msg.sender; }
    function mint(address to, uint256 id, bytes32 category) external {
        require(msg.sender == registry, "registry only");
        categoryOf[id] = category;
        // No receiver callback: ownership is recorded only to the consenting caller.
        _mint(to, id);
    }
    function approve(address, uint256) public pure override { revert("non-transferable"); }
    function setApprovalForAll(address, bool) public pure override { revert("non-transferable"); }
    function _beforeTokenTransfer(address from, address to, uint256 firstId, uint256 batchSize) internal override {
        require(from == address(0), "non-transferable");
        super._beforeTokenTransfer(from, to, firstId, batchSize);
    }
    function tokenURI(uint256 id) public view override returns (string memory) {
        _requireMinted(id);
        return string(abi.encodePacked('data:application/json;utf8,{"name":"TEE membership receipt","description":"Historical member receipt; not unique-device identity or current eligibility","member":"', Strings.toHexString(id,32), '","category":"', Strings.toHexString(uint256(categoryOf[id]),32), '"}'));
    }
}

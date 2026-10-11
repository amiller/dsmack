// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {ERC721} from "openzeppelin-contracts/contracts/token/ERC721/ERC721.sol";
import {Strings} from "openzeppelin-contracts/contracts/utils/Strings.sol";
import {Base64} from "openzeppelin-contracts/contracts/utils/Base64.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {ResearchBadges} from "./ResearchBadges.sol";

/// Main artwork collection backed by the existing, non-transferable research
/// receipts. No custody migration: each token is issued to its receipt's owner.
/// The receipt contract remains the attestation/claim/account-consent mechanism.
contract ResearchCollection is ERC721, Ownable {
    ResearchBadges public immutable receipts;
    struct Artwork {string image; bytes32 imageSHA256; bytes32 rendererSHA256; bool frozen;}
    mapping(uint256 => Artwork) public artwork;
    event ArtworkPublished(uint256 indexed tokenId, bytes32 imageSHA256, bytes32 rendererSHA256);
    event ArtworkFrozen(uint256 indexed tokenId);
    event ReceiptIssued(uint256 indexed tokenId, address indexed recipient, address indexed receiptContract);
    // ERC-4906 metadata refresh signal; art changes never change receipt facts.
    event MetadataUpdate(uint256 _tokenId);

    constructor(ResearchBadges receipts_, address publisher)
        ERC721("Attest Testnet Research Badges", "ATTEST")
    {
        require(address(receipts_).code.length != 0 && publisher != address(0), "collection policy");
        receipts = receipts_;
        _transferOwnership(publisher);
    }

    function publishArtwork(uint256 tokenId, string calldata image, bytes32 imageSHA256, bytes32 rendererSHA256)
        external onlyOwner
    {
        receipts.ownerOf(tokenId); // No art registration for nonexistent receipts.
        require(!artwork[tokenId].frozen, "artwork frozen");
        require(imageSHA256 != 0 && rendererSHA256 != 0, "artwork hashes");
        bytes memory uri = bytes(image);
        require(uri.length > 8 && uri.length <= 512, "image URI length");
        bool https = uri[0]=="h" && uri[1]=="t" && uri[2]=="t" && uri[3]=="p" && uri[4]=="s" && uri[5]==":" && uri[6]=="/" && uri[7]=="/";
        bool ipfs = uri[0]=="i" && uri[1]=="p" && uri[2]=="f" && uri[3]=="s" && uri[4]==":" && uri[5]=="/" && uri[6]=="/";
        require(https || ipfs, "image URI scheme");
        for(uint256 i; i<uri.length; i++)
            require(uint8(uri[i])>=33 && uint8(uri[i])<=126 && uri[i]!='"' && uri[i]!='\\' && uri[i]!='<' && uri[i]!='>', "image URI character");
        artwork[tokenId] = Artwork(image,imageSHA256,rendererSHA256,false);
        emit ArtworkPublished(tokenId,imageSHA256,rendererSHA256);
        if(_exists(tokenId)) emit MetadataUpdate(tokenId);
    }

    function freezeArtwork(uint256 tokenId) external onlyOwner {
        require(bytes(artwork[tokenId].image).length != 0 && !artwork[tokenId].frozen, "artwork state");
        artwork[tokenId].frozen = true;
        emit ArtworkFrozen(tokenId);
        if(_exists(tokenId)) emit MetadataUpdate(tokenId);
    }

    /// Anyone may pay to issue a prepared token, but cannot redirect ownership.
    /// Idempotent so a sponsored retry cannot duplicate a receipt.
    function issueReceipt(uint256 tokenId) external returns(uint256) {
        if(_exists(tokenId)) return tokenId;
        address recipient = receipts.ownerOf(tokenId);
        require(bytes(artwork[tokenId].image).length != 0, "artwork pending");
        _mint(recipient,tokenId);
        emit ReceiptIssued(tokenId,recipient,address(receipts));
        return tokenId;
    }

    function tokenURI(uint256 tokenId) public view override returns(string memory) {
        _requireMinted(tokenId);
        (bytes32 member,bytes32 team,uint8 level,uint256 parent) = receipts.badges(tokenId);
        Artwork storage art = artwork[tokenId];
        bytes memory metadata = abi.encodePacked('{"name":"Attest ',level==1 ? "Participant" : "Independent Builder",' #',Strings.toString(tokenId),
            '","description":"Fold: porcelain and vermilion. Historical research receipt; not unique-person or unique-device identity. No monetary value.","image":"',art.image,
            '","image_sha256":"',Strings.toHexString(uint256(art.imageSHA256),32),'","renderer_sha256":"',Strings.toHexString(uint256(art.rendererSHA256),32),
            '","receipt_contract":"',Strings.toHexString(uint160(address(receipts)),20),'","receipt_token":',Strings.toString(tokenId),
            ',"level":',Strings.toString(level),',"parent":',Strings.toString(parent),',"member":"',Strings.toHexString(uint256(member),32),
            '","teamHash":"',Strings.toHexString(uint256(team),32),'","attributes":[{"trait_type":"Level","value":',Strings.toString(level),
            '},{"trait_type":"Material","value":"Porcelain and vermilion"},{"trait_type":"Artwork frozen","value":"',art.frozen ? "yes" : "no",'"}]}');
        return string.concat("data:application/json;base64,",Base64.encode(metadata));
    }
    function supportsInterface(bytes4 interfaceId) public view override returns(bool) {
        return interfaceId == bytes4(0x49064906) || super.supportsInterface(interfaceId);
    }
    function approve(address,uint256) public pure override {revert("non-transferable");}
    function setApprovalForAll(address,bool) public pure override {revert("non-transferable");}
    function _beforeTokenTransfer(address from,address to,uint256 firstId,uint256 batchSize) internal override {
        require(from==address(0),"non-transferable");
        super._beforeTokenTransfer(from,to,firstId,batchSize);
    }
}

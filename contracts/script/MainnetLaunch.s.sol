// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Script, console2} from "forge-std/Script.sol";
import {AppleEndorsements} from "attest/AppleEndorsements.sol";
import {CDRegistry} from "../src/CDRegistry.sol";
import {AppleAttestRegistryV1} from "../src/AppleAttestRegistryV1.sol";
import {Canary, IAttestVerifier} from "../src/Canary.sol";
import {LayoverCredit} from "../src/LayoverCredit.sol";
import {GuestEscrow, IGuestAttest} from "../src/GuestEscrow.sol";
import {UsageEscrow} from "../src/UsageEscrow.sol";

/// Layover on Base mainnet, every contract from one deployer EOA in nine transactions. The deployer holds no role afterwards:
/// BUILD_OWNER approves runner builds (CDRegistry), ESCROW_OWNER approves guest builds (GuestEscrow), MINT_OWNER mints LAYC
/// and receives GENESIS, USAGE_OWNER registers the couch broker and classes (UsageEscrow). Two registries are bound to their
/// consumer at deploy, so the order is fixed and the consumer addresses are predicted from the deployer's nonce.
contract MainnetLaunch is Script {
    bytes16 constant AAGUID = "appattest";
    uint32 constant CATEGORY = 3; // Apple Development, as on Base Sepolia
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

    function run() external {
        require(block.chainid == 8453, "Base mainnet only");
        (address buildOwner, address escrowOwner, address mintOwner, address usageOwner) =
            (vm.envAddress("BUILD_OWNER"), vm.envAddress("ESCROW_OWNER"), vm.envAddress("MINT_OWNER"), vm.envAddress("USAGE_OWNER"));
        uint256 genesis = vm.envUint("GENESIS");
        require(keccak256(bytes(_symbol(USDC))) == keccak256("USDC"), "USDC");
        bytes memory der = vm.readFileBinary("../app-attest/contracts/fixtures/apple-intermediate.der");

        vm.startBroadcast();
        address deployer = msg.sender;
        require(buildOwner != deployer && escrowOwner != deployer && mintOwner != deployer && usageOwner != deployer, "deployer keeps no role");
        AppleEndorsements endorsements = new AppleEndorsements();
        bytes32 intermediate = endorsements.endorseIntermediate(der);
        CDRegistry cds = new CDRegistry(buildOwner);
        address canaryAt = vm.computeCreateAddress(deployer, vm.getNonce(deployer) + 1);
        AppleAttestRegistryV1 directory = new AppleAttestRegistryV1(endorsements, canaryAt, cds, AAGUID, CATEGORY, false);
        Canary canary = new Canary(IAttestVerifier(address(directory)));
        LayoverCredit layc = new LayoverCredit(mintOwner, genesis);
        address escrowAt = vm.computeCreateAddress(deployer, vm.getNonce(deployer) + 1);
        AppleAttestRegistryV1 verifier = new AppleAttestRegistryV1(endorsements, escrowAt, cds, AAGUID, CATEGORY, false);
        GuestEscrow escrow = new GuestEscrow(address(layc), escrowOwner, IGuestAttest(address(verifier)));
        UsageEscrow usage = new UsageEscrow(USDC, usageOwner);
        vm.stopBroadcast();

        require(address(canary) == canaryAt && address(escrow) == escrowAt, "predicted address");
        require(directory.registry() == address(canary) && verifier.registry() == address(escrow), "registry binding");
        require(cds.owner() == buildOwner && escrow.owner() == escrowOwner && layc.owner() == mintOwner && usage.owner() == usageOwner, "owners");
        require(layc.balanceOf(mintOwner) == genesis && layc.totalSupply() == genesis, "genesis");
        console2.log("deployer", deployer);
        console2.log("AppleEndorsements", address(endorsements));
        console2.log("intermediateId");
        console2.logBytes32(intermediate);
        console2.log("CDRegistry", address(cds));
        console2.log("AppleAttestRegistryV1 directory (registry = Canary)", address(directory));
        console2.log("Canary", address(canary));
        console2.log("LayoverCredit", address(layc));
        console2.log("AppleAttestRegistryV1 verifier (registry = GuestEscrow)", address(verifier));
        console2.log("GuestEscrow", address(escrow));
        console2.log("UsageEscrow (USDC)", address(usage));
    }

    function _symbol(address t) internal view returns (string memory) {
        (bool ok, bytes memory r) = t.staticcall(abi.encodeWithSignature("symbol()"));
        require(ok, "symbol()");
        return abi.decode(r, (string));
    }
}

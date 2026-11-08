// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {Script, console2} from "forge-std/Script.sol";
import {AppleEndorsements} from "attest/AppleEndorsements.sol";
import {CDRegistry} from "../src/CDRegistry.sol";
import {AppleAttestRegistryV1, AppleAttestAnyBuildV1} from "../src/AppleAttestRegistryV1.sol";
import {Canary, IAttestVerifier} from "../src/Canary.sol";
import {LayoverCredit} from "../src/LayoverCredit.sol";
import {GuestEscrow, IGuestAttest} from "../src/GuestEscrow.sol";
import {UsageEscrow} from "../src/UsageEscrow.sol";

/// Layover on Base mainnet, in eight transactions after LAYC exists. LAYC is created by LastResortBuyer (the issuance
/// lane), its sole minter, with no genesis; pass its address as LAYC. OWNER holds every owner role (CDRegistry setBuild,
/// GuestEscrow setWorkload, UsageEscrow broker and classes) and can hand each one on with transferOwnership/acceptOwnership.
/// Two registries are bound to their consumer at deploy, so the order is fixed and the consumers' addresses are predicted.
contract MainnetLaunch is Script {
    bytes16 constant AAGUID = "appattest";
    uint32 constant CATEGORY = 3; // Apple Development + Developer ID (registry policy accepts 3 and 6)
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

    function run() external {
        require(block.chainid == 8453, "Base mainnet only");
        (address owner, LayoverCredit layc) = (vm.envAddress("OWNER"), LayoverCredit(vm.envAddress("LAYC")));
        require(layc.totalSupply() == 0 && layc.owner().code.length > 0, "LAYC: no genesis, minted only by a contract");
        require(keccak256(bytes(_symbol(USDC))) == keccak256("USDC"), "USDC");
        bytes memory der = vm.readFileBinary("../app-attest/contracts/fixtures/apple-intermediate.der");

        vm.startBroadcast();
        address deployer = msg.sender;
        AppleEndorsements endorsements = new AppleEndorsements();
        bytes32 intermediate = endorsements.endorseIntermediate(der);
        CDRegistry cds = new CDRegistry(owner);
        address canaryAt = vm.computeCreateAddress(deployer, vm.getNonce(deployer) + 1);
        // The Canary's verifier admits any build CDRegistry ever approved, so a setBuild does not strand armed entries.
        AppleAttestAnyBuildV1 directory = new AppleAttestAnyBuildV1(endorsements, canaryAt, cds, AAGUID, CATEGORY, false);
        Canary canary = new Canary(IAttestVerifier(address(directory)));
        address escrowAt = vm.computeCreateAddress(deployer, vm.getNonce(deployer) + 1);
        AppleAttestRegistryV1 verifier = new AppleAttestRegistryV1(endorsements, escrowAt, cds, AAGUID, CATEGORY, false);
        GuestEscrow escrow = new GuestEscrow(address(layc), owner, IGuestAttest(address(verifier)));
        UsageEscrow usage = new UsageEscrow(USDC, owner);
        vm.stopBroadcast();

        require(address(canary) == canaryAt && address(escrow) == escrowAt, "predicted address");
        require(directory.registry() == address(canary) && verifier.registry() == address(escrow), "registry binding");
        require(cds.owner() == owner && escrow.owner() == owner && usage.owner() == owner, "owners");
        console2.log("deployer", deployer);
        console2.log("owner", owner);
        console2.log("LayoverCredit (minter)", address(layc), layc.owner());
        console2.log("AppleEndorsements", address(endorsements));
        console2.log("intermediateId");
        console2.logBytes32(intermediate);
        console2.log("CDRegistry", address(cds));
        console2.log("AppleAttestAnyBuildV1 directory (registry = Canary)", address(directory));
        console2.log("Canary", address(canary));
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

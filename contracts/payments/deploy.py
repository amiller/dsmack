#!/usr/bin/env python3
"""Deploy from the sprint test funding wallet on Base Sepolia."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from eth_account import Account
from eth_utils import keccak, to_checksum_address
from rpc import CHAIN_ID, Quorum, call

OWNER = "0x1FBe7a7b3f7a37A967F3d927Abd6f04DB2766c5b"
MIN_RESERVE_WEI = 20_000_000_000_000_000
CONTRACTS = Path(__file__).resolve().parents[1]


def load_owner(key_path):
    # Refuse the unrelated deployer file without opening it.
    if Path(key_path).name == "deployer-new.key":
        raise ValueError("use only the sprint funding wallet")
    # This is the FIRST operation: no RPC, build or transaction before identity check.
    try:
        raw = Path(key_path).read_text().strip()
        account = Account.from_key(raw)
    except Exception:
        raise ValueError("cannot load a valid raw owner key") from None
    if account.address.lower() != OWNER.lower():
        raise ValueError("deployer key does not derive the required 0x1FBe...6c5b funding wallet")
    return account


def persist(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def wait_receipt(quorum, tx_hash):
    for _ in range(180):
        receipt = quorum.read("eth_getTransactionReceipt", [tx_hash])
        if receipt:
            if int(receipt["status"], 16) != 1:
                raise RuntimeError(f"transaction reverted: {tx_hash}")
            return receipt
        time.sleep(2)
    raise RuntimeError(f"receipt timeout; inspect transaction before rerunning: {tx_hash}")


def send(account, quorum, output, label, *, value=0, data="0x", to=None):
    # Pending nonce must agree too; a chainId=84532 signature cannot replay on mainnet.
    tx = {"chainId": CHAIN_ID, "nonce": int(quorum.read("eth_getTransactionCount", [account.address, "pending"]), 16),
          "value": value, "data": data}
    if to:
        tx["to"] = to_checksum_address(to)
    url = quorum.urls[0]
    gas_price = int(quorum.read("eth_gasPrice", []), 16)
    if gas_price > 100_000_000_000:
        raise RuntimeError("gas price exceeds 100 gwei testnet cap")
    tx["gasPrice"] = gas_price
    estimate = call(url, "eth_estimateGas", [{"from": account.address, "data": data,
                        "value": hex(value), **({"to": tx["to"]} if to else {})}])
    tx["gas"] = int(estimate, 16) * 12 // 10
    if tx["gas"] > 5_000_000:
        raise RuntimeError("gas estimate exceeds deployment cap")
    head=quorum.finalized()
    balance=int(quorum.at("eth_getBalance",[account.address],head),16)
    if balance-value-tx["gas"]*gas_price < MIN_RESERVE_WEI:
        raise RuntimeError("transaction would breach the 0.02 ETH reserve")
    signed = account.sign_transaction(tx)
    tx_hash = "0x" + keccak(signed.raw_transaction).hex()
    # Save the intended hash BEFORE sending so a timeout never encourages a blind resend.
    persist(output / f"{label}-transaction.json", {"hash": tx_hash, "chainId": CHAIN_ID,
                "from": account.address, "to": to, "nonce": tx["nonce"], "value": value})
    submitted = call(url, "eth_sendRawTransaction", ["0x" + signed.raw_transaction.hex()])
    if submitted.lower() != tx_hash.lower():
        raise RuntimeError("RPC returned a different transaction hash")
    print(f"{label}: {tx_hash}", flush=True)
    receipt = wait_receipt(quorum, tx_hash)
    persist(output / f"{label}-receipt.json", receipt)
    return receipt


def main():
    if len(sys.argv) != 3:
        raise ValueError("usage: deploy.py RAW_OWNER_KEY_FILE PAYMENTS_DIR")
    account = load_owner(sys.argv[1])
    print(f"Owner address verified: {account.address}", flush=True)
    payments = Path(sys.argv[2]).resolve()
    output = payments / "contract"
    output.mkdir(parents=True, exist_ok=True)
    funding = to_checksum_address((payments / "funding-wallet.address").read_text().strip())
    if funding.lower() != account.address.lower():
        raise ValueError("owner must be the configured sprint funding wallet")
    # No auto retry/resume after any partially submitted deployment.
    if any((output / f"{label}-transaction.json").exists() for label in ("deploy", "funding")):
        raise RuntimeError("existing submitted transaction record; inspect receipts before any new deployment")
    quorum = Quorum(tuple(os.environ.get("PAYMENTS_RPC_URLS", "").split(","))) if os.environ.get("PAYMENTS_RPC_URLS") else Quorum()
    header = quorum.finalized()
    if int(quorum.at("eth_getBalance",[account.address],header),16)<20_000_000_000_000_000:
        raise RuntimeError("funding wallet has not reached 0.02 ETH")
    persist(output / "deployment-preflight.json", {"chainId": CHAIN_ID, "finalized": header,
                                                  "fundingWallet": funding})
    subprocess.run(["forge", "build", "--root", str(CONTRACTS), "--skip", "test", "--offline"], check=True)
    artifact = json.loads((CONTRACTS / "out/UsageEscrow.sol/UsageEscrow.json").read_text())
    bytecode = artifact["bytecode"]["object"]
    if not bytecode.startswith("0x"):
        bytecode = "0x" + bytecode
    deploy = send(account, quorum, output, "deploy", data=bytecode + OWNER[2:].lower().zfill(64))
    address = to_checksum_address(deploy["contractAddress"])
    # Check exact compiled runtime, including the immutable owner, at the receipt's block hash.
    expected = bytearray.fromhex(artifact["deployedBytecode"]["object"].removeprefix("0x"))
    for offsets in artifact["deployedBytecode"]["immutableReferences"].values():
        for offset in offsets:
            expected[offset["start"]:offset["start"] + offset["length"]] = int(OWNER, 16).to_bytes(offset["length"], "big")
    code = quorum.at("eth_getCode", [address], {"hash": deploy["blockHash"]})
    if bytes.fromhex(code.removeprefix("0x")) != expected:
        raise RuntimeError("deployed runtime/owner differs from compiled artifact; funding stopped")
    persist(output / "deployment.json", {"chainId": CHAIN_ID, "address": address, "owner": OWNER,
                "transactionHash": deploy["transactionHash"], "runtimeKeccak": "0x" + keccak(expected).hex(),
                "fundingWallet": funding})
    persist(output / "deployed.json", json.loads((output / "deployment.json").read_text()))
    print(f"Contract: {address}\nFunding wallet / owner: {funding}", flush=True)
    print(f"Next: bash {CONTRACTS / 'payments/verify.sh'} {address}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Never print argv, signing inputs, private keys or exception object reprs.
        print(f"Deployment stopped: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)

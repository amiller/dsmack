#!/usr/bin/env python3
"""Read-only verification of a participant NFT receipt; optional linked builder NFT.

Requires the same Python web3 dependency as the deployment scripts. Reads the
pinned deployment and generated ABI, never any private key. RPC is trusted for
chain responses; this is not a light-client proof.
"""
import argparse,json
from pathlib import Path
from web3 import Web3

ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--rpc',default='https://sepolia.base.org')
p.add_argument('--deployment',type=Path,default=ROOT/'contracts/network/deploy-nft-base-sepolia.json')
p.add_argument('--account',required=True)
p.add_argument('--token',type=int,required=True)
p.add_argument('--mint-tx',required=True)
p.add_argument('--builder-token',type=int)
a=p.parse_args()
d=json.loads(a.deployment.read_text());abis=json.loads((ROOT/'node/relay-hosted/badge-abi.json').read_text())
w=Web3(Web3.HTTPProvider(a.rpc,request_kwargs={'timeout':60}))
if w.eth.chain_id!=d['chainId'] or d['chainId'] not in (31337,84532):raise SystemExit('Wrong test chain')
account=Web3.to_checksum_address(a.account)
b=w.eth.contract(address=d['ResearchBadges'],abi=abis['badges'])
f=w.eth.contract(address=d['PersonalBadgeAccountFactory'],abi=abis['factory'])
def require(condition,message):
 if not condition:raise SystemExit(message)
require(account.lower()!=d['admin'].lower(),'Recipient is the sponsor')
require(f.functions.isAccount(account).call(),'Recipient is not a factory personal account')
require(b.functions.ownerOf(a.token).call()==account,'Participant owner differs')
member,team,level,parent=b.functions.badges(a.token).call()
require(level==1 and parent==0,'Not a participant badge')
require(b.functions.participantClaimed(member).call(),'Participant claim marker absent')
receipt=w.eth.get_transaction_receipt(a.mint_tx)
require(receipt['status']==1 and receipt['to'].lower()==b.address.lower(),'Mint transaction failed or targets another contract')
transfer=Web3.keccak(text='Transfer(address,address,uint256)')
require(any(log['address'].lower()==b.address.lower() and len(log['topics'])==4 and log['topics'][0]==transfer and int.from_bytes(log['topics'][1],'big')==0 and int.from_bytes(log['topics'][2],'big')==int(account,16) and int.from_bytes(log['topics'][3],'big')==a.token for log in receipt['logs']),'Receipt does not mint this token to this account')
result={'chainId':d['chainId'],'contract':b.address,'account':account,'participantToken':a.token,'participantTeamHash':Web3.to_hex(team),'mintTransaction':a.mint_tx,'mintBlock':receipt['blockNumber'],'nextId':b.functions.nextId().call(),'verified':True,'scope':'RPC-backed receipt and current ownership; not proof of clean installation or unique person/device'}
if a.builder_token is not None:
 require(b.functions.ownerOf(a.builder_token).call()==account,'Builder owner differs')
 _,builder_team,builder_level,builder_parent=b.functions.badges(a.builder_token).call()
 require(builder_level==2 and builder_parent==a.token,'Builder does not link to participant')
 require(builder_team!=bytes(32) and builder_team!=b.functions.publisherTeam().call(),'Builder team is not independent')
 require(b.functions.builderOf(a.token).call()==a.builder_token and b.functions.builderTeamClaimed(builder_team).call(),'Builder claim markers differ')
 result.update(builderToken=a.builder_token,builderTeamHash=Web3.to_hex(builder_team))
print(json.dumps(result,indent=2))

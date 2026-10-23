"""Explicit Developer ID metadata policy; never invokes tools or grants admission.

Caller must first authenticate its release inventory, codesign --verify the app,
and independently compare the extracted leaf certificate digest and entitlements.
Metadata parsing alone cannot prove certificate identity or timestamp validity.
Engineering signing_policy.py remains unchanged and Development-only.
"""
import re

POLICY_VERSION='dsmack-developer-id-signing/1'
TEAM_ID='DC9JH5DRMY'
BUNDLE_ID='dev.dsmack.provider'
AUTHORITY='Developer ID Application: Honey Badger Coop. Labs Inc. (DC9JH5DRMY)'

def need(ok,label):
 if not ok:raise ValueError(label)

def one(text,key):
 rows=re.findall(r'^'+re.escape(key)+r'=(.*)$',text,re.M)
 need(len(rows)==1,'metadata_'+key)
 return rows[0]

def check_metadata(text,*,policy_version,expected_cdhash):
 need(policy_version==POLICY_VERSION,'explicit_developer_id_policy_required')
 need(isinstance(text,str) and len(text)<=65536,'bounded_metadata')
 need(isinstance(expected_cdhash,str) and re.fullmatch('[0-9a-f]{64}',expected_cdhash),'trusted_expected_cdhash')
 need(one(text,'Identifier')==BUNDLE_ID,'metadata_identifier')
 need(one(text,'TeamIdentifier')==TEAM_ID,'metadata_team')
 lines=re.findall(r'^Authority=(.*)$',text,re.M)
 need(lines and lines[0]==AUTHORITY,'developer_id_authority')
 need(not any(x.startswith('Apple Development') for x in lines),'development_authority_forbidden')
 cd=re.findall(r'^CodeDirectory v=\d+ .*?flags=0x([0-9a-fA-F]+)\(.*?\)',text,re.M)
 need(len(cd)==1,'metadata_codedirectory')
 flags=int(cd[0],16)
 need(flags&0x10000 and not flags&(0x2|0x20000),'metadata_runtime_flags')
 need(one(text,'CandidateCDHashFull sha256')==expected_cdhash,'metadata_full_cdhash')
 timestamp=one(text,'Timestamp')
 need(timestamp.strip() and timestamp.lower().strip() not in ('none','not set','unavailable'),'trusted_timestamp_required')
 return {'policy_version':POLICY_VERSION,'team_id':TEAM_ID,'bundle_id':BUNDLE_ID,'cdhash_full':expected_cdhash,'attestation_category':6,'timestamp_metadata_present':True,'apple_signature_verified':False,'leaf_certificate_checked':False,'notarization_checked':False,'launch_ready':False}

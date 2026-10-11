#!/usr/bin/env python3
"""Build the current contracts and export the relay's NFT/account interfaces."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
subprocess.run(['forge', 'build', '--root', str(ROOT / 'contracts'), '-q'], check=True)
contracts = {'registry': ('CDRegistry', 'CDRegistry'), 'badges': ('ResearchBadges', 'ResearchBadges'),
             'factory': ('PersonalBadgeAccount', 'PersonalBadgeAccountFactory'),
             'account': ('PersonalBadgeAccount', 'PersonalBadgeAccount')}
abi = {key: json.loads((ROOT / f'contracts/out/{source}.sol/{name}.json').read_text())['abi']
       for key, (source, name) in contracts.items()}
(ROOT / 'node/relay-hosted/badge-abi.json').write_text(json.dumps(abi, indent=2) + '\n')

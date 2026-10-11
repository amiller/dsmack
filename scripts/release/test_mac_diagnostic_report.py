#!/usr/bin/env python3
"""Exercise the actual native report exporter with synthetic credential fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
SOURCES=['node/shared/Protocol.swift','node/shared/PersonalAccount.swift','node/shared/BadgeClaim.swift','node/shared/Upgrade.swift','node/shared/Chain.swift','node/shared/NativeAttestation.swift','node/shared/Node.swift','node/mac/NetworkConfig.swift']

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    source=(ROOT/'node/mac/GUI.swift').read_text()
    extension='\nextension ParticipantApp { func testDiagnosticReport(lines:[String])->String { eventLines=lines;return diagnosticReport() } }\n'
    with tempfile.TemporaryDirectory(prefix='attest-diagnostics-') as temporary:
        root=Path(temporary);gui=root/'GUI.swift';gui.write_text(source+extension)
        binary=root/'diagnostic-tests'
        subprocess.run(['xcrun','swiftc','-O','-D','GUI','-framework','DeviceCheck','-framework','AppKit',*SOURCES,str(gui),'node/tests/DiagnosticReportTests.swift','-o',str(binary)],cwd=ROOT,check=True)
        result=subprocess.run([str(binary),str(args.out.resolve()/'synthetic-report.jsonl')],cwd=ROOT,capture_output=True,text=True,check=True)
    (args.out/'results.txt').write_text(result.stdout)
    record={'result':'passed','scope':'Actual exporter with synthetic events and file roundtrip; no picker, network, Keychain, live credentials or production mutation.','gui_sha256':hashlib.sha256(source.encode()).hexdigest(),'tests_sha256':hashlib.sha256((ROOT/'node/tests/DiagnosticReportTests.swift').read_bytes()).hexdigest()}
    (args.out/'verification.json').write_text(json.dumps(record,indent=2)+'\n')
    print(result.stdout,end='')

if __name__=='__main__':main()

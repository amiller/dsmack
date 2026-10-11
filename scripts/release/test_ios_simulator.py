#!/usr/bin/env python3
"""Mac-only iPhone UI/native callback checks; never proves hardware attestation.

Use a dedicated booted simulator. A lower simulator runtime is supported only by
editing an isolated source copy; the checked-in device target stays iOS 27.
"""
import argparse,json,re,shutil,subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--device',required=True)
 p.add_argument('--runtime',default='27.0')
 p.add_argument('--out',type=Path,required=True,help='New output directory')
 a=p.parse_args()
 if not re.fullmatch(r'[0-9]+\.[0-9]+',a.runtime):p.error('runtime must be major.minor')
 out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
 def run(args):return subprocess.check_output(args,text=True).strip()
 devices=json.loads(run(['xcrun','simctl','list','devices','booted','-j']))
 if not any(d['udid']==a.device for ds in devices['devices'].values() for d in ds):p.error('dedicated simulator must already be booted')
 shutil.copytree(ROOT/'node',out/'node',ignore=shutil.ignore_patterns('build'))
 project=out/'node/ios/AttestNode.xcodeproj'
 f=project/'project.pbxproj';f.write_text(f.read_text().replace('IPHONEOS_DEPLOYMENT_TARGET = 27.0',f'IPHONEOS_DEPLOYMENT_TARGET = {a.runtime}'))
 subprocess.run(['xcrun','swiftc',str(ROOT/'node/shared/NativeAttestation.swift'),str(ROOT/'node/tests/NativeAttestationTests.swift'),'-o',str(out/'native-tests')],check=True)
 (out/'native-tests.txt').write_text(run([str(out/'native-tests')])+'\n')
 cmd=['xcodebuild','-project',str(project),'-scheme','AttestNode','-configuration','Debug','-destination',f'platform=iOS Simulator,id={a.device}','-derivedDataPath',str(out/'derived'),'-resultBundlePath',str(out/'ui.xcresult'),'CODE_SIGNING_ALLOWED=NO','test']
 (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
 with (out/'xcodebuild.log').open('w') as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
 if r.returncode:raise SystemExit('UI tests failed; inspect '+str(out/'xcodebuild.log'))
 (out/'summary.json').write_text(run(['xcrun','xcresulttool','get','test-results','summary','--path',str(out/'ui.xcresult'),'--format','json'])+'\n')
 report=run(['xcrun','simctl','pbpaste',a.device]);events=[json.loads(line) for line in report.splitlines()]
 assert any(e.get('scenario')=='apple-failure' for e in events),'Copied report missing simulator label'
 failure=next(e for e in events if e.get('event')=='apple operation failed')
 assert failure['stage']=='attestKey' and failure['errorChain'][0]['code']==0 and failure['errorChain'][1]['code']==-3,'Incomplete copied error report'
 (out/'copied-report.jsonl').write_text(report+'\n')
 subprocess.run(['xcrun','xcresulttool','export','attachments','--path',str(out/'ui.xcresult'),'--output-path',str(out/'attachments')],check=True)
 print('UI and injected callback tests passed; copied report verified. No hardware attestation or NFT mint was performed.')
if __name__=='__main__':main()

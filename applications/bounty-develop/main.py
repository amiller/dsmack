"""Pinned application entrypoint; workload only, never a host orchestration tool."""
import argparse,importlib.util,os,sys,tempfile
from pathlib import Path
ROOT=Path('/opt/applications/bounty-runtime')
sys.path.insert(0,str(ROOT));sys.path.insert(0,'/opt/bounty-judges')
import generate as qualified
from observation import append_observation
from output_bundle import pack
import core
p=core.p

def main():
    ap=argparse.ArgumentParser()
    for n in('request','stage-profile','driver','plan'):ap.add_argument('--expected-'+n+'-sha256',required=True)
    a=ap.parse_args();core.need(os.getuid()==1000 and os.getgid()==1000 and os.getpid()==1,'private UID1000 PID1 entrypoint required')
    core.protect_parent()
    public=Path('/workspace/inputs');paths={n:public/n for n in core.SLOTS};paths['suite']=None
    core.need(not(public/'suite').exists()and not(public/'suite').is_symlink(),'unexpected suite')
    result=core.audit(paths,a.expected_request_sha256,a.expected_stage_profile_sha256,a.expected_driver_sha256,a.expected_plan_sha256)
    state=Path('/workspace/state');out=Path('/workspace/artifacts')
    for root in(state,out):core.need(root.is_dir()and not root.is_symlink()and not any(root.iterdir()),'fresh ordinary workspace required')
    checks={'schema':'dsmack-bounty-develop-checks/1','completed':False,'candidate_tree_sha256':None}
    outcome={'schema':'dsmack-bounty-develop-outcome/1','status':'infrastructure_failed','error_class':None,'cli_exit':None,'seconds':core.SECONDS,'turns':core.TURNS}
    projection={};code=2;quiesced=False;version=None;transcript=None;stderr=None;prepared={}
    try:
        repo=state/'repo';projection=core.materialize(result,repo)
        context=state/'context';context.mkdir(mode=0o700)
        _,env=qualified.runtime_environment(context,os.environ.get('DSMACK_SENTINEL_ENDPOINT'))
        cli=Path('/usr/local/bin/claude');core.need(qualified.file_sha(cli)==qualified.CLI_SHA256,'fixed CLI binary')
        version,err,rc,failure=qualified.bounded_process([str(cli),'--version'],b'',context,env,10,4096,4096)
        core.need(not failure and rc==0 and qualified.re.fullmatch(rb'2\.1\.187 \(Claude Code\)\s*',version),'fixed CLI version')
        prompt='Implement the following task in the current repository. Preserve all files except the three explicitly allowed board source files. Do not add dependencies or configuration. The independent reviewer determines success.\n'+result['specification']
        transcript,stderr,rc,failure=qualified.bounded_process(core.command(cli,prompt),b'',repo,env,core.SECONDS,4*1024*1024,65536)
        outcome['cli_exit']=rc
        # Stop every remaining same-namespace writer before ANY source capture.
        core.quiesce();quiesced=True
        core.need(not any(out.iterdir()),'child touched artifact namespace')
        core.need(not failure and rc==0,'CLI infrastructure/turn/deadline failure')
        observed=core.observe(transcript)
        bundle,manifest,transform=core.capture(repo,result)
        prepared={'observed-model.json':p.canonical_json(observed),'source-delivery.tar':bundle,'candidate-manifest.json':manifest,'admission-transform.json':p.canonical_json(transform)}
        checks.update(completed=True,candidate_tree_sha256=transform['candidate_tree_manifest_sha256']);outcome['status']='completed';code=0
    except Exception as error:
        outcome['error_class']=type(error).__name__
        # Raw exception text may contain run-local capability. Preserve no text.
        try:core.quiesce();quiesced=True
        except Exception:quiesced=False;outcome['error_class']='UnconfirmedNamespaceQuiescence'
    core.need(quiesced,'no publication before namespace quiescence')
    # Child may write only state; precreated artifact names refuse publication.
    core.need(not any(out.iterdir()),'child touched artifact namespace')
    for name,data in prepared.items():
        with(out/name).open('xb')as f:f.write(data)
    for name,data in [('cli-version.txt',version),('session-transcript.jsonl',transcript),('cli-stderr.txt',stderr)]:
        if data is not None:
            with(out/name).open('xb')as f:f.write(data)
    for name,data in [('checks.json',checks),('develop-outcome.json',outcome)]:
        with(out/name).open('xb')as f:f.write(qualified.canonical(data))
    append_observation(out,result,projection);pack(out)
    return code
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print('DEVELOP_REFUSED '+type(error).__name__,file=sys.stderr);raise SystemExit(2)

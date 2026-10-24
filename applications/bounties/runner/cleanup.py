"""Evidence-first exact owned cleanup. No secure erase or mutable scratch reads."""
import hashlib,json,os,shutil,stat,subprocess
from pathlib import Path
s=Path(__file__).with_name('portable.py');p={'__name__':'arcade_portable','__file__':str(s)};exec(compile(s.read_bytes(),str(s),'exec'),p)
need=p['need'];read=p['read'];pin=p['pin'];doc=p['document'];canonical=p['canonical'];exclusive=p['exclusive'];protected=p['protected']

def gone(pid):
    need(type(pid)is int and pid>0,'native process ID')
    try:os.kill(pid,0)
    except ProcessLookupError:return
    raise ValueError('owned native process not confirmed absent')

def no_refs(paths):
    result=subprocess.run(['/usr/sbin/lsof','-Fpf','--',*[str(x)for x in paths]],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,env={'HOME':str(Path.home()),'PATH':'/usr/bin:/bin'})
    need(result.returncode==1 and not result.stdout and not result.stderr,'open references or unavailable probe; preserve files')

def retire(config,packet,local,verdict):
    local=protected(local,True);native=packet['native_execution_id'];out=local/('attempt-'+native)
    need(verdict.get('verification_level')=='full'and verdict.get('execution_valid')is True and verdict.get('attempt_id')==packet['attempt_id']and verdict.get('manifest_sha256')==packet['manifest_sha256'],'selected complete full proof required')
    observation=doc(read(local/('attempt-'+native+'.control')/'controller-result.json'));need(observation.get('controller_returned')is True,'controller terminal required')
    report=observation['observation'];helper=report['helper'];need(report['output_complete']is True and helper['quiescence']=='native-confirmed'and not helper['cleanup_errors'],'native quiescence required');gone(helper['pid'])
    originals=p['evidence_manifest'](out);exclusive(local/'PRESERVED-ORIGINALS.json',canonical(originals));proof=verdict['cleanup_evidence']
    exclusive(local/'full-report.json',canonical(proof['report']));exclusive(local/'cleanup-checker-context.json',canonical(proof['context']))
    alpha,auth,checked=p['release'](config);profile=checked['profile'];files={r['path']:r for r in checked['inventory']['files']}
    role=lambda name:files[profile['roles'][name]]
    q={'schema':'dsmack-native-quiescence/1','run_id':native,'attempt_dir':str(out),'native_pids':[helper['pid']]};exclusive(local/'QUIESCENCE.json',canonical(q))
    task=doc(read(local/'task.json'));context=doc(read(task['checker_context']['path']))
    selection={'schema':'dsmack-scratch-retirement/1','run_id':native,'attempt_dir':str(out),'closure':task['closure_context'],'checker_context':pin(local/'cleanup-checker-context.json'),'report':pin(local/'full-report.json'),'report_key':{'key_id':context['report_key_id'],'public_key_b64':context['report_verify_key_b64']},'quiescence':pin(local/'QUIESCENCE.json'),'public_template':{k:role('scratch_template')[k]for k in ('bytes','sha256')}}
    exclusive(local/'scratch-selection.json',canonical(selection));script=Path(__file__).parents[2]/'pilot-client/retire-scratch.mjs'
    bootstrap=doc(read(config['bootstrap']));node=bootstrap['node'];need(pin(node['path'],268435456)==node,'selected Node runtime changed')
    before=shutil.disk_usage(local).free
    result=subprocess.run([node['path'],str(script),str(local/'scratch-selection.json'),pin(local/'scratch-selection.json')['sha256']],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,env={'HOME':str(Path.home()),'PATH':'/usr/bin:/bin'})
    exclusive(local/'SCRATCH-RETIRE.stdout',result.stdout);exclusive(local/'SCRATCH-RETIRE.stderr',result.stderr);need(result.returncode==0,'qualified scratch retirement refused; no retry')
    targets=[(local/'workload.img',task['workload_disk']),(out/'workload.img.staged',task['workload_disk']),(out/'system.img.staged',role('system_disk')),(out/'result-template.img.staged',role('result_template'))]
    snapshots=[]
    for path,expected in targets:
        d=pin(path,1<<34);s=path.lstat();need(s.st_uid==os.getuid()and not s.st_mode&0o077 and all(d[k]==expected[k]for k in ('bytes','sha256')),'exact owned public copy required');snapshots.append((path,d,s))
    no_refs([x[0]for x in snapshots]);gone(helper['pid']);exclusive(local/'PUBLIC-RETIRE-INTENT.json',canonical({'targets':[{'path':str(path),'bytes':d['bytes'],'sha256':d['sha256']}for path,d,_ in snapshots]}))
    for path,d,s in snapshots:
        now=path.lstat();need((now.st_dev,now.st_ino,now.st_size,now.st_mtime_ns,now.st_ctime_ns)==(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns),'public copy changed');no_refs([path]);path.unlink()
    need(p['evidence_manifest'](out)==originals,'original evidence changed')
    logical=2*selection['public_template']['bytes']+sum(d['bytes']for _,d,_ in snapshots)
    record={'schema':'dsmack-arcade-owned-cleanup/1','original21_preserved':True,'native_quiescent':True,'scratch_files':2,'public_files':4,'retired_logical_bytes':logical,'free_bytes_before':before,'free_bytes_after':shutil.disk_usage(local).free,'secure_erase_claim':False,'credentials_or_archive_deleted':False}
    exclusive(local/'CLEANUP-COMPLETE.json',canonical(record));return record

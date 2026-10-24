// One-off backfill: publish evidence for attempts accepted before publishEvidence existed.
// Run where the service runs: ARCADE_CONFIG=/path/config.json node publish-evidence.mjs
import {readFileSync} from 'node:fs';
import {Pilot} from './core.mjs';
const c=JSON.parse(readFileSync(process.env.ARCADE_CONFIG));const p=new Pilot({...c,adapters:{}});p.basePath=c.basePath??'';
for(const {body} of p.db.prepare("SELECT body FROM records WHERE kind='attempt'").all()){const a=JSON.parse(body);if(a.verdict?.accepted!==true||p.get('submission',a.submission_id).files[0].url)continue;p.tx(()=>p.publishEvidence(a));console.log('published',a.id,a.submission_id);}
p.close();

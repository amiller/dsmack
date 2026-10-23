// Trusted controller: imports Playwright only; candidate JavaScript runs in browser.
import {rename} from 'node:fs/promises';
import {chromium} from '/opt/checker/node_modules/playwright/index.mjs';
const [origin,out]=process.argv.slice(2);
const tests=[];let browser,context,page,current='board-add-save',outcome='infrastructure_failure';
class Assertion extends Error{}
const need=(v)=>{if(!v)throw new Assertion('functional assertion');};
async function check(id,fn){current=id;await fn();tests.push({id,status:'passed'});}
try{
 browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
 context=await browser.newContext({serviceWorkers:'block',acceptDownloads:true,recordVideo:{dir:out,size:{width:960,height:720}}});
 await context.route('**/*',route=>{const u=new URL(route.request().url());return u.origin===origin?route.continue():route.abort();});
 await context.tracing.start({screenshots:true,snapshots:true});page=await context.newPage();page.setDefaultTimeout(5000);
 const card=col=>page.locator(`[data-testid="column-${col}"] [data-testid="card"]:visible`);
 const wait=async(predicate)=>{const end=Date.now()+5000;while(Date.now()<end){if(await predicate())return;await new Promise(r=>setTimeout(r,30));}throw new Assertion('functional assertion');};
 let saved=0;
 const add=async(col,text)=>{await page.getByTestId('new-'+col).fill(text);await page.getByTestId('add-'+col).click();saved++;await wait(async()=>await page.getByTestId('board').getAttribute('data-saved')===String(saved));};
 const counts=async values=>{for(const[col,n]of Object.entries(values))need(await card(col).count()===n);};
 await check('board-add-save',async()=>{await page.goto(origin+'/apps/board/');await page.getByTestId('board').waitFor();await wait(async()=>await page.getByTestId('board').getAttribute('data-ready')==='true');await add('todo','Apple');await add('todo','Grape');await add('doing','apricot');await add('done','Ship');await counts({todo:2,doing:1,done:1});});
 const search=()=>page.getByTestId('search');
 await check('search-control',async()=>{need(await search().count()===1);await search().fill('  AP  ');});
 await check('substring-case-trim',async()=>{await wait(async()=>await card('done').count()===0);await counts({todo:2,doing:1,done:0});need((await page.getByTestId('column-todo').locator('h2').innerText()).includes('2/2'));need((await page.getByTestId('column-doing').locator('h2').innerText()).includes('1/1'));need((await page.getByTestId('column-done').locator('h2').innerText()).includes('0/1'));});
 await check('blank-and-counts',async()=>{await search().fill('   ');await counts({todo:2,doing:1,done:1});need(!(await page.getByTestId('column-todo').locator('h2').innerText()).includes('/'));await search().fill('gr');await counts({todo:1,doing:0,done:0});});
 await check('view-only-export',async()=>{const got=page.waitForEvent('download');await page.getByTestId('export').click();const stream=await(await got).createReadStream();let s='';for await(const b of stream)s+=b;const data=JSON.parse(s);need(JSON.stringify(data)==JSON.stringify({nextId:5,columns:{todo:[{id:'c1',text:'Apple'},{id:'c2',text:'Grape'}],doing:[{id:'c3',text:'apricot'}],done:[{id:'c4',text:'Ship'}]}}));});
 await check('filtered-move',async()=>{await card('todo').locator('[data-action="right"]').click();saved++;await wait(async()=>await page.getByTestId('board').getAttribute('data-saved')===String(saved));await counts({todo:0,doing:1,done:0});need((await card('doing').innerText()).includes('Grape'));});
 await check('reload-view-reset',async()=>{await page.reload();await wait(async()=>await page.getByTestId('board').getAttribute('data-ready')==='true');need(await search().inputValue()==='');await counts({todo:1,doing:2,done:1});need((await card('todo').innerText()).includes('Apple'));need((await card('doing').allInnerTexts()).some(x=>x.includes('Grape')));});
 outcome='passed';
}catch(e){console.error(String(e.name)+': '+String(e.message).slice(0,2000));const functional=e instanceof Assertion;tests.push({id:current,status:functional?'assertion_failed':'infrastructure_failure'});outcome=functional?'functional_failure':'infrastructure_failure';}
finally{
 try{if(page)await page.screenshot({path:out+'/final.png'});if(context)await context.tracing.stop({path:out+'/trace.zip'});const video=page?.video();if(context)await context.close();if(video)await rename(await video.path(),out+'/video.webm');if(browser)await browser.close();}catch{outcome='infrastructure_failure';}
}
console.log(JSON.stringify({outcome,tests}));process.exitCode=outcome==='passed'?0:outcome==='functional_failure'?3:4;

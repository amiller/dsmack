import { chromium } from 'playwright'
import fs from 'node:fs/promises'
const [url, dir]=process.argv.slice(2)
const browser=await chromium.launch({headless:true,args:['--no-sandbox']})
try {
 const page=await browser.newPage(); const events=[]
 page.on('websocket',ws=>events.push({type:'websocket',url:ws.url(),time:new Date().toISOString()}))
 page.on('console',msg=>events.push({type:'console',text:msg.text()}))
 page.on('pageerror',e=>events.push({type:'pageerror',text:e.stack}))
 // Fail if any browser fetch or WebSocket attempts a private mesh connection.
 await page.route('**/*',route=>{const u=new URL(route.request().url());if(u.hostname.startsWith('192.168.100.'))throw Error('private mesh request');return route.continue()})
 const cdp=await page.context().newCDPSession(page)
 await cdp.send('Network.enable');cdp.on('Network.webSocketWillSendHandshakeRequest',e=>events.push({type:'handshakeRequest',...e}));cdp.on('Network.webSocketHandshakeResponseReceived',e=>events.push({type:'handshakeResponse',...e}))
 await page.goto(url)
 await page.waitForFunction(()=>window.result || window.failure,{},{timeout:65000})
 await page.screenshot({path:dir+'/browser.png',fullPage:true})
 const result=await page.evaluate(()=>({result:window.result,failure:window.failure}))
 await fs.writeFile(dir+'/browser-events.json',JSON.stringify(events,null,2))
 await fs.writeFile(dir+'/browser-result.json',JSON.stringify(result,null,2))
 if(result.failure)throw Error(result.failure)
 await fs.writeFile(dir+'/attestation.bin',Buffer.from(result.result.attestationHex,'hex'))
 console.log(JSON.stringify({...result.result,attestationHex:undefined},null,2))
} finally {await browser.close()}

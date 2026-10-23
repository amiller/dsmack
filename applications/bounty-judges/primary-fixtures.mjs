// This file is image-owned. Original browser specs get ONE import rewrite here.
import {test as base,expect} from '/opt/checker/node_modules/@playwright/test/index.mjs';
export {expect};
export const test=base.extend({
  page:async({page,context},use,testInfo)=>{
    const origin='http://127.0.0.1:4173';
    let infrastructure=null;
    await context.route('**/*',route=>{
      const request=route.request(),url=request.url();
      if(request.method()==='GET' && url.startsWith(origin+'/') && !url.includes('?') && !url.includes('#'))return route.continue();
      return route.abort('blockedbyclient');
    });
    await context.routeWebSocket('**/*',socket=>socket.close());
    page.on('crash',()=>{infrastructure='renderer crash';});
    page.on('pageerror',error=>{infrastructure=String(error.message).slice(0,1000);});
    page.on('console',message=>{if(message.type()==='error')infrastructure=String(message.text()).slice(0,1000);});
    page.on('popup',popup=>{infrastructure='unexpected popup';popup.close().catch(()=>{});});
    try {await use(page);} finally {
      if(infrastructure!==null) {
        testInfo.annotations.push({type:'primary-infrastructure',description:infrastructure});
        throw new Error('primary renderer infrastructure failure: '+infrastructure);
      }
    }
  },
});

const enc = new TextEncoder();
export const bytes = (value) => enc.encode(typeof value === 'string' ? value : JSON.stringify(value));
export const b64 = (value) => btoa(String.fromCharCode(...new Uint8Array(value))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
export const unb64 = (value) => Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')), c=>c.charCodeAt(0));
export const digest = async(value) => b64(await crypto.subtle.digest('SHA-256',bytes(value)));
export const random = (size=32) => b64(crypto.getRandomValues(new Uint8Array(size)));
export async function ephemeral() {
  const pair = await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
  return {privateKey:pair.privateKey,publicKey:b64(await crypto.subtle.exportKey('raw',pair.publicKey))};
}
async function key(privateKey,publicKey,context) {
  const pub=await crypto.subtle.importKey('raw',unb64(publicKey),{name:'ECDH',namedCurve:'P-256'},false,[]);
  const secret=await crypto.subtle.deriveBits({name:'ECDH',public:pub},privateKey,256);
  const material=await crypto.subtle.importKey('raw',secret,'HKDF',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:bytes('dsmack-email-gate/1'),info:bytes(context)},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
export async function seal(privateKey,publicKey,value,context) {
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:bytes(context)},await key(privateKey,publicKey,context),bytes(value));
  return {iv:b64(iv),ciphertext:b64(ciphertext)};
}
export async function open(privateKey,publicKey,sealed,context) {
  const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(sealed.iv),additionalData:bytes(context)},await key(privateKey,publicKey,context),unb64(sealed.ciphertext));
  return JSON.parse(new TextDecoder().decode(plain));
}
export async function quoteBinding(nonce,publicKey) {
  return new Uint8Array([...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes({v:1,service:'dsmack-email-gate',nonce,publicKey}))),...new Uint8Array(32)]);
}
export const emailRecoveryLabel=(email,userId)=>JSON.stringify(['dsmack.email-recovery/1',email.trim().toLowerCase(),userId]);
export async function emailRecoveryNonce(publicKey,userId,ts) {
  const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',new Uint8Array([...unb64(publicKey),...bytes(userId),...bytes(String(ts))])));
  const alphabet='abcdefghijklmnopqrstuvwxyz234567';let bits=0,value=0,result='';
  for(const byte of hash){value=(value<<8)|byte;bits+=8;while(bits>=5){result+=alphabet[(value>>>(bits-5))&31];bits-=5;}}
  return result.slice(0,26);
}

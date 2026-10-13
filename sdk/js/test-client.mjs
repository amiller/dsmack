// Prints the JS client's view of a socket plus known-answer derivations, for sdk/test_sdk.py.
import { Client, appRoot, leaf } from './index.mjs';
const c = new Client(process.argv[2]);
const root = appRoot(Buffer.alloc(32, 7), 31337, '0x' + '11'.repeat(20), '0x' + '22'.repeat(20), '00'.repeat(32), 1, 'ab'.repeat(32));
console.log(JSON.stringify({
  info: await c.info(), get_key: await c.getKey('demo', 'ed25519:demo'),
  vectors: { app_root: root.toString('hex'), leaf: leaf(root, 'near-account', 'ed25519:near-account').toString('hex') },
}));

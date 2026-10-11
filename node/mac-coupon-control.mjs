// Private control transport only: exact loopback destination through the
// measured runner CONNECT allowlist; signed controls remain worker authority.
import net from 'node:net';

export async function connectMacControl(port) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('invalid Mac control port');
  const socket = net.createConnection({ path: '/run/egress.sock' });
  socket.setTimeout(15000, () => socket.destroy(new Error('Mac control timeout')));
  try {
    await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
    socket.write(`CONNECT 127.0.0.1:${port} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n\r\n`);
    let header = Buffer.alloc(0);
    while (!header.includes('\r\n\r\n')) {
      const chunk = socket.read(1);
      if (chunk) { header = Buffer.concat([header, chunk]); if (header.length > 4096) throw new Error('Mac control refused'); }
      else await new Promise((resolve, reject) => {
        const cleanup = () => { socket.off('readable', ready); socket.off('error', fail); socket.off('end', closed); socket.off('close', closed); };
        const ready = () => { cleanup(); resolve(); };
        const fail = error => { cleanup(); reject(error); };
        const closed = () => fail(new Error('Mac control closed'));
        socket.once('readable', ready); socket.once('error', fail); socket.once('end', closed); socket.once('close', closed);
      });
    }
    if (!/^HTTP\/1\.[01] 200(?: |\r)/.test(header.toString('ascii'))) throw new Error('Mac control refused');
    return socket;
  } catch { socket.destroy(); throw new Error('Mac control unavailable'); }
}

export async function readControlChallenge(lines) {
  const { value, done } = await lines.next();
  if (done) throw new Error('Mac control challenge required');
  const v = JSON.parse(value.toString('utf8'));
  if (!v || Object.keys(v).sort().join(',') !== 'challenge_hex,op' || v.op !== 'challenge'
      || typeof v.challenge_hex !== 'string' || !/^[0-9a-f]{64}$/.test(v.challenge_hex)) throw new Error('Mac control challenge refused');
  return v.challenge_hex;
}

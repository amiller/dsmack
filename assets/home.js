const DIRECTORY = 'https://pod.dstack.soc1024.com/apple-attest-p2p-relay/nft/directory';
const $ = id => document.getElementById(id);
const text = (tag, cls, s) => Object.assign(document.createElement(tag), {className: cls, textContent: s});

function row(n) {
  const li = document.createElement('li');
  const img = Object.assign(document.createElement('img'), {src: 'assets/mini-top.png', alt: ''});
  const fresh = n.checkIn.status === 'fresh';
  const state = text('span', fresh ? 'on' : 'off', fresh ? 'Online' : 'Stale');
  state.prepend(Object.assign(document.createElement('span'), {className: 'dot', ariaHidden: 'true'}));
  li.append(img, text('span', 'name', n.label || n.id.slice(0, 10) + '…'), text('span', 'mono dim', n.version.selfReported), state, text('span', 'dim', 'Epoch ' + n.sync.keyEpoch));
  return li;
}

async function load() {
  const r = await fetch(DIRECTORY, {cache: 'no-store'});
  if (!r.ok) throw new Error('directory returned ' + r.status);
  const d = await r.json();
  const online = d.nodes.filter(n => n.checkIn.status === 'fresh');
  const epoch = Math.max(...online.map(n => Number(n.sync.keyEpoch)));
  $('online').textContent = online.length;
  $('online-word').textContent = online.length === 1 ? 'node online now' : 'nodes online now';
  $('summary').textContent = (online.length ? 'Epoch ' + epoch + ' · ' : '') + online.length + ' online · ';
  $('summary').append(Object.assign(document.createElement('a'), {href: 'nodes/', textContent: 'All nodes'}));
  $('rows').replaceChildren(...d.nodes.map(row));
}

load().catch(e => { $('summary').textContent = 'Directory read failed: ' + e.message; });

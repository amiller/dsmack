import base64
import importlib.util
import json
from pathlib import Path
import socket
import threading
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('proxy',Path(__file__).with_name('connect-proxy.py'))
proxy=importlib.util.module_from_spec(spec);spec.loader.exec_module(proxy)

class MacRouteTests(unittest.TestCase):
    def test_mac_proxy_admits_only_its_broker_and_tunnel_and_preserves_bytes(self):
        allowed={'pod.example.com','pool.trycloudflare.com'}
        with proxy.Server(('127.0.0.1',0),proxy.Handler) as server:
            server.allowed_hosts=allowed
            server.resolved_hosts={'pool.trycloudflare.com':'203.0.113.7'}
            t=threading.Thread(target=server.serve_forever);t.start()
            try:
                with patch.object(proxy.socket,'create_connection',side_effect=AssertionError('unapproved dial')):
                    with socket.socket() as client:
                        client.settimeout(2);client.connect(server.server_address)
                        client.sendall(b'CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n')
                        self.assertIn(b'403',client.recv(1024))
                for host in allowed:
                    upstream,peer=socket.socketpair()
                    with peer, patch.object(proxy.socket,'create_connection',return_value=upstream) as dial:
                        peer.settimeout(2)
                        with socket.socket() as client:
                            client.settimeout(2);client.connect(server.server_address)
                            client.sendall(f'CONNECT {host}:443 HTTP/1.1\r\n\r\n'.encode())
                            self.assertIn(b'200',client.recv(1024));client.sendall(b'opaque TLS bytes')
                            self.assertEqual(peer.recv(1024),b'opaque TLS bytes')
                            peer.sendall(b'opaque reply');self.assertEqual(client.recv(1024),b'opaque reply')
                        dial.assert_called_once_with((server.resolved_hosts.get(host,host),443),timeout=10)
            finally:server.shutdown();t.join()


class BrowsePolicyTests(unittest.TestCase):
    POLICIES={'a'*32:{'mode':'open','hosts':[],'expires_at':2**40},'b'*32:{'mode':'named','hosts':['shop.example'],'expires_at':2**40}}
    def connect(self,host,token=None,address='93.184.215.14'):
        def policy(t):
            if t not in self.POLICIES:raise PermissionError('unknown browse token')
            return self.POLICIES[t]
        auth=f'Proxy-Authorization: Basic {base64.b64encode(("browse:"+token).encode()).decode()}\r\n' if token else ''
        with proxy.Server(('127.0.0.1',0),proxy.Handler) as server:
            server.allowed_hosts={'pod.example.com'};server.package_hosts={'registry.npmjs.org'};server.policy=policy
            t=threading.Thread(target=server.serve_forever);t.start()
            try:
                upstream,peer=socket.socketpair()
                with peer,patch.object(proxy.socket,'getaddrinfo',return_value=[(2,1,6,'',(address,443))]),\
                        patch.object(proxy.socket,'create_connection',return_value=upstream) as dial,socket.socket() as client:
                    client.settimeout(2);client.connect(server.server_address)
                    client.sendall(f'CONNECT {host}:443 HTTP/1.1\r\n{auth}\r\n'.encode())
                    reply=client.recv(1024)
                    return reply.split(b' ')[1].decode(),dial.call_args
            finally:server.shutdown();t.join()

    def test_package_hosts_need_no_token(self):
        self.assertEqual(self.connect('registry.npmjs.org')[0],'200')

    def test_without_a_token_only_operator_and_package_hosts(self):
        self.assertEqual(self.connect('shop.example')[0],'403')

    def test_named_admits_exactly_its_hosts_and_dials_the_checked_address(self):
        status,call=self.connect('shop.example','b'*32)
        self.assertEqual((status,call.args[0]),('200',('93.184.215.14',443)))
        self.assertEqual(self.connect('other.example','b'*32)[0],'403')

    def test_open_admits_public_hosts_and_refuses_private_loopback_and_cgnat(self):
        self.assertEqual(self.connect('any.example','a'*32)[0],'200')
        for address in ('192.168.1.10','127.0.0.1','10.0.0.1','100.64.0.1','169.254.169.254'):
            self.assertEqual(self.connect('rebind.example','a'*32,address)[0],'403',address)

    def test_unknown_token_is_refused(self):
        self.assertEqual(self.connect('any.example','c'*32)[0],'403')

    def test_browse_report_returns_the_policy_it_enforces(self):
        with proxy.Server(('127.0.0.1',0),proxy.Handler) as server:
            server.policy=lambda token:self.POLICIES[token]
            t=threading.Thread(target=server.serve_forever);t.start()
            try:
                with socket.socket() as client:
                    client.settimeout(2);client.connect(server.server_address)
                    auth=base64.b64encode(('browse:'+'b'*32).encode()).decode()
                    client.sendall(f'GET /browse HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n'.encode())
                    self.assertEqual(json.loads(client.recv(4096).split(b'\r\n\r\n',1)[1]),self.POLICIES['b'*32])
                with socket.socket() as client:
                    client.settimeout(2);client.connect(server.server_address)
                    auth=base64.b64encode(('browse:'+'c'*32).encode()).decode()
                    server.policy=lambda token:(_ for _ in ()).throw(PermissionError('unknown browse token'))
                    client.sendall(f'GET /browse HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n'.encode())
                    self.assertIn(b' 403 ',client.recv(4096))
            finally:server.shutdown();t.join()

    def test_policy_lookup_is_per_mac_rechecked_and_a_dead_stays_token_stops(self):
        from http.server import BaseHTTPRequestHandler,HTTPServer
        records={'d'*32:{'mode':'open','hosts':[],'expires_at':2**40},'e'*32:{'mode':'named','hosts':['Bad_Host'],'expires_at':2**40},
                 'f'*32:{'mode':'open','hosts':[],'expires_at':1}}
        seen=[]
        class Broker(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path);token=self.path.split('/')[-1].split('?')[0]
                if token not in records:self.send_response(404);self.end_headers();return
                body=json.dumps(records[token]).encode();self.send_response(200);self.end_headers();self.wfile.write(body)
            def log_message(self,*a):pass
        with HTTPServer(('127.0.0.1',0),Broker) as broker:
            t=threading.Thread(target=broker.serve_forever);t.start()
            try:
                server=proxy.Server.__new__(proxy.Server);server.publisher='0x'+'a1'*20
                server.browse_url=f'http://127.0.0.1:{broker.server_address[1]}/agent/browse/'
                clock=[1000.0]
                with patch.object(proxy.time,'monotonic',lambda:clock[0]):
                    self.assertEqual(server.policy('d'*32)['mode'],'open');server.policy('d'*32)
                    self.assertEqual(seen,['/agent/browse/'+'d'*32+'?publisher=0x'+'a1'*20])
                    del records['d'*32]  # the stay ended: the broker no longer answers for its token
                    clock[0]+=proxy.POLICY_TTL+1
                    with self.assertRaises(OSError):server.policy('d'*32)
                    with self.assertRaises(OSError):server.policy('d'*32)
                    self.assertEqual(len(seen),3)
                for token,message in (('e'*32,'malformed'),('f'*32,'expired'),('not-hex','unknown')):
                    with self.assertRaisesRegex(PermissionError,message):server.policy(token)
            finally:broker.shutdown();t.join()


if __name__=='__main__':unittest.main()

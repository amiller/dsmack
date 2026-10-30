import importlib.util
from pathlib import Path
import socket
import threading
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('proxy',Path(__file__).with_name('connect-proxy.py'))
proxy=importlib.util.module_from_spec(spec);spec.loader.exec_module(proxy)

class ProxyTests(unittest.TestCase):
    def test_unapproved_destinations_never_dial(self):
        with proxy.Server(('127.0.0.1',0),proxy.Handler) as server:
            t=threading.Thread(target=server.serve_forever);t.start()
            try:
                with patch.object(proxy.socket,'create_connection',side_effect=AssertionError('proxy dialed')):
                    for line in (b'CONNECT example.com:443 HTTP/1.1\r\n',b'CONNECT api.anthropic.com:80 HTTP/1.1\r\n',
                                 b'CONNECT api.anthropic.com.evil:443 HTTP/1.1\r\n',b'GET https://api.anthropic.com HTTP/1.1\r\n'):
                        with socket.socket() as client:
                            client.connect(server.server_address);client.sendall(line+b'\r\n')
                            self.assertIn(b'403',client.recv(1024))
            finally:
                server.shutdown();t.join()

if __name__=='__main__':unittest.main()

class ProviderRouteTests(unittest.TestCase):
    def test_connect_target_preserves_provider_tls_verification(self):
        import os,sys
        source=Path(__file__).resolve().parents[2]/'base-vm/browser-sandbox-v1/source/guest/sentinel'
        sys.path.insert(0,str(source))
        from harness.sentinel.sentinel import provider_connection,SentinelError
        with patch.dict(os.environ,{'HTTPS_PROXY':'http://192.0.2.3:18443'}):
            with patch('http.client.HTTPSConnection') as make, patch('ssl.create_default_context') as context:
                conn=provider_connection('api.anthropic.com','ca.pem',10)
                make.assert_called_once_with('192.0.2.3',18443,timeout=10,context=context.return_value)
                conn.set_tunnel.assert_called_once_with('api.anthropic.com',443)
                context.assert_called_once_with(cafile='ca.pem')
            with self.assertRaises(SentinelError):provider_connection('other.example','ca.pem',10)

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

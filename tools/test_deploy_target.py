"""Production's source gate uses real git history and never needs a remote fetch."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from deploy_target import source_ref, project_name, WEBHOST

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class SourceGateTests(unittest.TestCase):
    def test_clean_main_ancestor_passes_and_dirty_or_unmerged_source_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp)
            def git(*args):
                return subprocess.check_output(['git', '-C', tmp, *args], text=True).strip()
            git('init', '-q', '-b', 'fixture')
            git('config', 'user.name', 'Fixture'); git('config', 'user.email', 'fixture@example.invalid')
            (repo/'source').write_text('first')
            git('add', '.'); git('commit', '-qm', 'first')
            first=source_ref(repo, 'staging')
            with self.assertRaisesRegex(ValueError, 'locally recorded'):
                source_ref(repo, 'production')
            git('update-ref', 'refs/heads/main', first)
            self.assertEqual(source_ref(repo, 'production'), first)
            (repo/'source').write_text('next')
            with self.assertRaisesRegex(ValueError, 'clean'):
                source_ref(repo, 'production')
            self.assertEqual(source_ref(repo, 'staging'), first)
            git('add', '.'); git('commit', '-qm', 'next')
            second=source_ref(repo, 'staging')
            with self.assertRaisesRegex(ValueError, 'contained'):
                source_ref(repo, 'production')
            git('update-ref', 'refs/remotes/origin/main', first)
            git('update-ref', 'refs/heads/main', second)
            self.assertEqual(source_ref(repo, 'production'), second)
            git('checkout', '-q', '--detach', first)
            self.assertEqual(source_ref(repo, 'production'), first)
            (repo/'untracked').write_text('not reviewed')
            with self.assertRaisesRegex(ValueError, 'clean'):
                source_ref(repo, 'production')

    def test_staging_package_routes_page_to_separate_broker_and_tunnels(self):
        page=load('page_deploy', ROOT/'applications/private-agent-web/deploy.py')
        bundle=load('page_bundle', ROOT/'applications/private-agent-web/bundle.py')
        with tempfile.TemporaryDirectory() as tmp:
            dist=Path(tmp)
            (dist/'index.html').write_text('page')
            (dist/'config.json').write_text(json.dumps(dict(broker='https://pod.dstack.soc1024.com/relay-broker-staging', tunnels='https://private-agent-staging.dstack.soc1024.com/tunnels', brokerKey='staged-key')))
            public_config=dist.parent/(dist.name+'-staging.json')
            self.addCleanup(public_config.unlink)
            public_config.write_text(json.dumps(dict(broker='production', tunnels='production', brokerKey='staged-key')))
            data=bundle.payload(dist)
            own=bundle.cid(data)
            (dist/'page-bundle.tar').write_bytes(data)
            (dist/'index.html').write_text(f'<meta name="page-bundle-cid" content="{own}">page')
            with patch.object(page.subprocess, 'check_output', return_value=b'export default () => new Response("page");'):
                archive=page.package(dist, 'staging', public_config)
            with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as package:
                config=json.load(package.extractfile('dist/config.json'))
                self.assertEqual(package.extractfile('dist/page-bundle.tar').read(), data)
                self.assertEqual(package.extractfile('dist/config.json').read(), (dist/'config.json').read_bytes())
            public_config.write_text(json.dumps(dict(broker='production', tunnels='production', brokerKey='wrong-key')))
            with self.assertRaisesRegex(ValueError, 'Build with PAGE_CONFIG'):
                page.package(dist, 'staging', public_config)
            self.assertEqual(config['brokerKey'], 'staged-key')
            self.assertEqual(config['broker'], 'https://pod.dstack.soc1024.com/relay-broker-staging')
            self.assertEqual(config['tunnels'], 'https://private-agent-staging.dstack.soc1024.com/tunnels')
            self.assertEqual(project_name('private-agent', 'staging'), 'private-agent-staging')
            self.assertEqual(project_name('relay-broker', 'production'), 'relay-broker')

    def test_page_refuses_before_packaging_or_reading_credentials(self):
        page=load('page_deploy_gate', ROOT/'applications/private-agent-web/deploy.py')
        with patch('sys.argv', ['deploy.py', '--target', 'production', '--evidence', 'unused',
                                '--page-env', 'unused', '--registry-account', 'fixture', '--operator-token-sha256', 'a'*64]), \
             patch.object(page, 'source_ref', side_effect=ValueError('clean tree required')), \
             patch.object(page, 'token') as token, patch.object(page, 'package') as package:
            with self.assertRaisesRegex(ValueError, 'clean tree'):
                page.main()
            token.assert_not_called(); package.assert_not_called()

    def test_broker_staging_package_and_upload_use_separate_project_and_keep_idle_guard(self):
        broker=load('broker_deploy_stage', ROOT/'applications/relay-broker/deploy-inference.py')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            config=root/'config.json'
            config.write_text(json.dumps(dict(payments={'chainId':31337}, inference=dict(origins=['production']), browser_origins=['production'])))
            def bundle(command, **kwargs):
                Path(command[-1]).write_text('export default {};')
            with patch.object(broker, 'source_ref', return_value='prepared-commit'), patch.object(broker.subprocess, 'run', side_effect=bundle):
                broker.prepare(SimpleNamespace(target='staging', config=config, operator_token_sha256='a'*64,
                                               encrypted_env=None, out=root/'prepared', staging_origin='https://private-agent-staging.dstack.soc1024.com'))
            with tarfile.open(root/'prepared/relay-broker.tgz') as package:
                packed=json.load(package.extractfile('applications/relay-broker/config.json'))
            self.assertEqual(packed['browser_origins'], ['https://private-agent-staging.dstack.soc1024.com'])
            self.assertEqual(packed['inference']['origins'], packed['browser_origins'])
            paths=[]
            def api(path, **kwargs):
                paths.append(path)
                if path == '/_api/projects':
                    self.assertIn(b'"name": "relay-broker-staging"', kwargs['body'])
                    return dict(runtime='deno', isolation='shared', mode='dev')
                if path.endswith('/promote'):
                    return dict(mode='attested')
                return {}
            # Staging may deploy a preparation from an earlier commit.
            with patch.object(broker, 'source_ref', return_value='another-commit'), \
                 patch.object(broker, 'token', return_value='fixture-only'), \
                 patch.object(broker, 'client', return_value=api), patch.object(broker, 'wait_for_idle') as guard:
                broker.deploy(SimpleNamespace(target='staging', prepared=root/'prepared', evidence=root/'evidence',
                                              apply=True, url='local-fixture', wait_idle_minutes=1))
            self.assertEqual(paths, ['/_api/projects', '/_api/projects/relay-broker-staging/promote', '/relay-broker-staging/key'])
            guard.assert_called_once_with('local-fixture', 1)

    def test_production_safe_block_tag_only_on_base_sepolia(self):
        broker=load('broker_deploy_safe', ROOT/'applications/relay-broker/deploy-inference.py')
        self.assertEqual(broker.payments_chain(), 84532)
        def bundle(command, **kwargs):
            Path(command[-1]).write_text('export default {};')
        def prepare(root, chain):
            config=root/'config.json'
            config.write_text(json.dumps(dict(payments={'blockTag':'safe'}, inference={'origins':[]})))
            with patch.object(broker, 'source_ref', return_value='c'), patch.object(broker.subprocess, 'run', side_effect=bundle), \
                 patch.object(broker, 'payments_chain', return_value=chain):
                broker.prepare(SimpleNamespace(target='production', config=config, operator_token_sha256='a'*64, encrypted_env=None,
                                               out=root/'prepared', staging_origin='https://private-agent-staging.dstack.soc1024.com'))
        with tempfile.TemporaryDirectory() as tmp:
            prepare(Path(tmp), 84532)
            with tarfile.open(Path(tmp)/'prepared/relay-broker.tgz') as package:
                self.assertEqual(json.load(package.extractfile('applications/relay-broker/config.json'))['payments']['blockTag'], 'safe')
        for chain, message in ((8453, 'finalized only'), (1, 'finalized only'), (31337, 'unknown payments chain')):
            with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(ValueError, message):
                prepare(Path(tmp), chain)
        with patch.object(broker, 'REPO', Path('/nonexistent')), self.assertRaises(FileNotFoundError):
            broker.payments_chain()

    def test_path_host_staging_routes_and_deploys_without_a_chain_transaction(self):
        page=load('page_deploy_path', ROOT/'applications/private-agent-web/deploy.py')
        bundle=load('page_bundle_path', ROOT/'applications/private-agent-web/bundle.py')
        broker=load('broker_deploy_path', ROOT/'applications/relay-broker/deploy-inference.py')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            config=root/'broker.json'
            config.write_text(json.dumps(dict(payments={'chainId':84532}, inference=dict(origins=['production']), browser_origins=['production'])))
            def bundle_module(command, **kwargs):
                Path(command[-1]).write_text('export default {};')
            with patch.object(broker, 'source_ref', return_value='test-commit'), patch.object(broker.subprocess, 'run', side_effect=bundle_module):
                broker.prepare(SimpleNamespace(target='staging', config=config, operator_token_sha256='a'*64,
                                               encrypted_env=None, out=root/'prepared', staging_origin=WEBHOST))
            with tarfile.open(root/'prepared/relay-broker.tgz') as archive:
                packed=json.load(archive.extractfile('applications/relay-broker/config.json'))
            self.assertEqual(packed['browser_origins'], [WEBHOST])
            self.assertEqual(packed['inference']['origins'], [WEBHOST])

            dist=root/'dist'; dist.mkdir()
            (dist/'index.html').write_text('page')
            (dist/'config.json').write_text(json.dumps(dict(
                broker=WEBHOST+'/relay-broker-staging', tunnels=WEBHOST+'/private-agent-staging/tunnels')))
            payload=bundle.payload(dist); own=bundle.cid(payload)
            (dist/'page-bundle.tar').write_bytes(payload)
            (dist/'index.html').write_text(f'<meta name="page-bundle-cid" content="{own}">page')
            html=(dist/'index.html').read_bytes()
            page_env=root/'page-env.json'; page_env.write_text('{"EMAIL_RECOVERY_ADDRESS":"recovery@example.invalid"}')
            calls=[]
            class Opener:
                def open(self, request, timeout):
                    calls.append(request.full_url)
                    if request.full_url.endswith('/_api/substrate'):
                        return io.BytesIO(b'{"isolation_modes":["shared"]}')
                    if request.full_url.endswith('/_api/projects'):
                        return io.BytesIO(b'{"runtime":"deno","isolation":"shared","mode":"attested"}')
                    return io.BytesIO(html)
            with patch('sys.argv', ['deploy.py', '--target', 'staging', '--staging-origin', WEBHOST,
                                    '--skip-registry-publication', '--dist', str(dist), '--page-env', str(page_env),
                                    '--operator-token-sha256', 'a'*64, '--evidence', str(root/'evidence')]), \
                 patch.object(page, 'source_ref', return_value='test-commit'), patch.object(page, 'token', return_value='fixture-only'), \
                 patch.object(page, 'build_opener', return_value=Opener()), patch.object(page, 'wait_for_idle') as guard, \
                 patch.object(page.subprocess, 'check_output', return_value=b'export default {};') as output, \
                 patch.object(page.subprocess, 'run') as run:
                page.main()
            run.assert_not_called()
            self.assertTrue(all(command.args[0][0]=='deno' for command in output.call_args_list))
            guard.assert_called_once_with(WEBHOST, 10)
            result=json.loads((root/'evidence/result.json').read_text())
            self.assertIsNone(result['registry'])
            self.assertEqual(result['url'], WEBHOST+'/private-agent-staging/')
            self.assertEqual(calls, [WEBHOST+'/_api/substrate', WEBHOST+'/_api/projects', WEBHOST+'/private-agent-staging/'])

    def test_production_cannot_skip_registry_publication(self):
        page=load('page_deploy_no_chain', ROOT/'applications/private-agent-web/deploy.py')
        with patch('sys.argv', ['deploy.py', '--target', 'production', '--skip-registry-publication',
                                '--evidence', 'unused', '--page-env', 'unused', '--operator-token-sha256', 'a'*64]), \
             patch.object(page, 'source_ref', return_value='test-commit'), patch.object(page, 'token') as token:
            with self.assertRaisesRegex(ValueError, 'require --target staging'):
                page.main()
            token.assert_not_called()

    def test_registry_readback_does_not_inherit_signing_keystore_options(self):
        page=load('page_deploy_readback', ROOT/'applications/private-agent-web/deploy.py')
        own='bafkrei'+'a'*52
        wallet_options=dict(ETH_PASSWORD='/fixture/password-file', ETH_KEYSTORE='/fixture/keystore', ETH_KEYSTORE_ACCOUNT='publisher')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'index.html').write_text('page')
            (root/'config.json').write_text(json.dumps(dict(
                pageBundleRegistry=dict(registry='0x'+'11'*20, rpcs=['https://rpc-a.invalid', 'https://rpc-b.invalid']))))
            page_env=root/'page-env.json'; page_env.write_text('{"EMAIL_RECOVERY_ADDRESS":"recovery@example.invalid"}')
            class Opener:
                def open(self, request, timeout):
                    if request.full_url.endswith('/_api/substrate'):
                        return io.BytesIO(b'{"isolation_modes":["shared"]}')
                    if request.full_url.endswith('/_api/projects'):
                        return io.BytesIO(b'{"runtime":"deno","isolation":"shared","mode":"attested"}')
                    return io.BytesIO(b'page')
            def read_registry(command, *, text, env):
                self.assertEqual(command[:2], ['cast', 'call'])
                self.assertFalse(set(wallet_options) & env.keys())
                self.assertEqual(env['RPC_ENV_MARKER'], 'retained')
                self.assertEqual(page.os.environ['ETH_PASSWORD'], wallet_options['ETH_PASSWORD'])
                return '"'+own+'"'
            with patch('sys.argv', ['deploy.py', '--target', 'staging', '--registry-account', 'publisher',
                                    '--dist', str(root), '--page-env', str(page_env),
                                    '--operator-token-sha256', 'a'*64, '--evidence', str(root/'evidence')]), \
                 patch.dict(page.os.environ, {**wallet_options, 'RPC_ENV_MARKER':'retained'}), \
                 patch.object(page, 'source_ref', return_value='test-commit'), patch.object(page, 'token', return_value='fixture-only'), \
                 patch.object(page, 'check_bundle', return_value=own), patch.object(page, 'package', return_value=b'archive'), \
                 patch.object(page, 'build_opener', return_value=Opener()), patch.object(page, 'wait_for_idle'), \
                 patch.object(page.subprocess, 'check_output', side_effect=read_registry) as reads, \
                 patch.object(page.subprocess, 'run') as send:
                page.main()
            send.assert_called_once()
            self.assertEqual(send.call_args.args[0][:2], ['cast', 'send'])
            self.assertNotIn('env', send.call_args.kwargs)
            self.assertEqual(reads.call_count, 2)


if __name__ == '__main__':
    unittest.main()

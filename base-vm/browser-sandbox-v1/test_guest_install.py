import importlib.util,pathlib,subprocess,tempfile,unittest
here=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('check_rootfs',here/'check_rootfs.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
B44={'usr/local/lib/dsmack/compose-runner/SHA256SUMS':b'x',
     'usr/local/lib/dsmack/compose-runner/dsmack_compose_runner/runner.py':b'stale',
     'usr/local/lib/dsmack/guest-io/SHA256SUMS':b'x',
     'usr/local/lib/dsmack/net/guest-network.env':b'stale',
     'usr/local/bin/dsmack-guest-io':b'stale',
     'usr/bin/dsmack-supervisor':b'stale',
     'etc/docker/daemon.json':b'stale'}

def b44_tree(d):
    root=pathlib.Path(d)
    for p,b in B44.items():(root/p).parent.mkdir(parents=True,exist_ok=True);(root/p).write_bytes(b)
    return root

class GuestInstall(unittest.TestCase):
    def test_inherited_files_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(len(c.problems(b44_tree(d))),len(B44))

    def test_installed_tree_is_repo_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root=b44_tree(d)
            subprocess.run(['bash',here/'install-guest.sh',c.REPO,root],check=True)
            self.assertEqual(c.problems(root),[])
            for p in ('usr/local/lib/dsmack/compose-runner/lib/dsmack_compose_contract/manifest.py',
                      'usr/local/lib/dsmack/guest-io/dsmack_guest_io/cli.py','usr/local/lib/dsmack/net/guest-network.env',
                      'usr/local/bin/dsmack-compose-runner','usr/local/bin/dsmack-guest-io'):
                self.assertTrue((root/p).is_file(),p)
            self.assertFalse((root/'usr/local/lib/dsmack/compose-runner/lib/dsmack_compose_verifier').exists())

if __name__=='__main__':unittest.main()

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from .mac_init import initialize

class MacInitTests(unittest.TestCase):
    def test_root_initializes_only_control_then_drops_authority(self):
        with tempfile.TemporaryDirectory() as name:
            volume = Path(name)
            (volume / '.abalone-persistent').write_text('ab' * 32 + '\n')
            with patch('os.getuid', side_effect=[0, 1000]), patch('os.getgid', return_value=1000), patch('os.chown') as chown, patch('os.setgroups') as groups, patch('os.setgid') as gid, patch('os.setuid') as uid:
                initialize(volume)
            chown.assert_called_once_with(volume / 'control', 1000, 1000)
            groups.assert_called_once_with([]); gid.assert_called_once_with(1000); uid.assert_called_once_with(1000)
            self.assertEqual((volume / 'control').stat().st_mode & 0o777, 0o700)
            self.assertEqual(sorted(p.name for p in volume.iterdir()), ['.abalone-persistent', 'control'])

    def test_missing_invalid_or_symlink_marker_refuses_before_drop(self):
        with tempfile.TemporaryDirectory() as name:
            volume = Path(name)
            for value in (None, '00\n', 'a' * 65):
                marker = volume / '.abalone-persistent'
                if value is not None: marker.write_text(value)
                with patch('os.setuid') as uid:
                    with self.assertRaises(ValueError): initialize(volume)
                    uid.assert_not_called()
            marker.unlink(); target = volume / 'other'; target.write_text('ab' * 32 + '\n'); marker.symlink_to(target)
            with self.assertRaises(OSError): initialize(volume)

    def test_public_or_symlink_control_refuses_before_drop(self):
        with tempfile.TemporaryDirectory() as name:
            volume = Path(name); (volume / '.abalone-persistent').write_text('ab' * 32 + '\n')
            directory = volume / 'control'; directory.mkdir(mode=0o755)
            with self.assertRaises(ValueError): initialize(volume)
            directory.rmdir(); directory.symlink_to(volume)
            with self.assertRaises(ValueError): initialize(volume)

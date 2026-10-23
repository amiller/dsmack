import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import output_bundle as b
from source_bundle import protocol as p,sha


def fixture():
    files={'checks.json':b'{}','public-input-audit.json':b'{}','test-01.webm':b'webm data'}
    manifest=p.canonical_json({'schema':'dsmack-bounty-output-manifest/1','files':[{'name':name,'size':len(raw),'sha256':sha(raw)}for name,raw in sorted(files.items())]})
    return files,manifest


def checksum(raw):
    raw=bytearray(raw);raw[148:156]=b' '*8;raw[148:156]=('%06o\0 '%sum(raw[:512])).encode();return bytes(raw)


class BundleControls(unittest.TestCase):
    def test_exact_roundtrip_original_manifest_and_determinism(self):
        files,manifest=fixture();raw=b.encode(files,manifest)
        self.assertEqual(b.decode(raw),(manifest,files));self.assertEqual(raw,b.encode(files,manifest))
        self.assertEqual(raw[-1024:],bytes(1024))
    def test_valid_checksums_do_not_admit_other_tar_metadata(self):
        files,manifest=fixture();raw=b.encode(files,manifest)
        for offset,value in [(100,ord('1')),(108,ord('1')),(116,ord('1')),(136,ord('1')),
                             (156,ord('x')),(157,ord('a')),(257,ord('X')),(263,ord('1')),
                             (265,ord('a')),(297,ord('a')),(329,ord('1')),(337,ord('1')),
                             (345,ord('a')),(500,1),(0,255)]:
            changed=bytearray(raw);changed[offset]=value;changed=checksum(changed)
            with self.assertRaises((ValueError,UnicodeDecodeError),msg=str(offset)):b.decode(changed)
    def test_payload_padding_checksum_trailing_and_duplicate_refuse(self):
        files,manifest=fixture();raw=b.encode(files,manifest)
        variants=[raw+b'\0'*512,raw[:-1],raw[:148]+b'000000\0 '+raw[156:],
                  raw[:512]+b'X'+raw[513:],raw[:514]+b'X'+raw[515:],raw[:-1024]+raw[:1024]+bytes(1024)]
        for value in variants:
            with self.assertRaises(ValueError):b.decode(value)
    def test_case_path_alias_and_nul_tail_refuse(self):
        files,manifest=fixture();raw=b.encode(files,manifest)
        for name in (b'Checks.json',b'checks.json/x',b'../checks.json',b'checks.json\0evil'):
            changed=bytearray(raw);changed[:100]=name+bytes(100-len(name));changed=checksum(changed)
            with self.assertRaises(ValueError):b.decode(changed)
    def test_manifest_tamper_or_unknown_member_refuse(self):
        files,manifest=fixture()
        with self.assertRaises(ValueError):b.encode({**files,'extra.txt':b'unknown'},manifest)
        with self.assertRaises(ValueError):b.encode({**files,'checks.json':b'changed'},manifest)
        with self.assertRaises(ValueError):b.encode(files,b' '+manifest)
        extra={**files,'result-files':b'alias'}
        alias=p.canonical_json({'schema':'dsmack-bounty-output-manifest/1','files':[{'name':n,'size':len(v),'sha256':sha(v)}for n,v in sorted(extra.items())]})
        with self.assertRaises(ValueError):b.encode(extra,alias)
    def test_boolean_or_float_manifest_size_refuses(self):
        files={'checks.json':b'x','public-input-audit.json':b'y'}
        for size in (True,1.0):
            rows=[{'name':name,'size':size,'sha256':sha(raw)}for name,raw in sorted(files.items())]
            raw=json.dumps({'schema':'dsmack-bounty-output-manifest/1','files':rows},sort_keys=True,separators=(',',':')).encode()
            with self.assertRaises(ValueError):b.encode(files,raw)

    def test_header_and_manifest_count_against_archive_cap(self):
        files,manifest=fixture()
        with patch.object(b,'ARCHIVE_CAP',2048):
            with self.assertRaises(ValueError):b.encode(files,manifest)
        with patch.object(b,'MEMBER_CAP',3):
            with self.assertRaises(ValueError):b.encode(files,manifest)
    def test_pack_retains_manifest_and_refuses_links_reuse_extra(self):
        files,manifest=fixture()
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory)
            for name,raw in files.items():(root/name).write_bytes(raw)
            (root/b.MANIFEST).write_bytes(manifest)
            result=b.pack(root);self.assertGreater(result['bytes'],0)
            self.assertEqual((root/b.MANIFEST).read_bytes(),manifest)
            self.assertEqual(b.decode((root/b.BUNDLE).read_bytes()),(manifest,files))
            with self.assertRaises(ValueError):b.pack(root)
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory)
            for name,raw in files.items():(root/name).write_bytes(raw)
            (root/b.MANIFEST).write_bytes(manifest);(root/'checks.json').unlink();(root/'checks.json').symlink_to(root/'public-input-audit.json')
            with self.assertRaises(ValueError):b.pack(root)

if __name__=='__main__':unittest.main()

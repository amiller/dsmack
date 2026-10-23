import hashlib
import io
import tarfile
import unittest
from source_bundle import decode_source, admission_relation, protocol, BOARD


def fixture(files):
    manifest=[{'path':name,'mode':420,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in sorted(files.items())]
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for row in manifest:
            info=tarfile.TarInfo(row['path']);info.size=row['bytes'];info.mode=420
            archive.addfile(info,io.BytesIO(files[row['path']]))
    # tarfile pads to a record boundary; protocol admits exactly two terminators.
    size=sum(512+((r['bytes']+511)//512)*512 for r in manifest)
    raw=out.getvalue()[:size+1024]
    return raw,protocol.canonical_json(manifest),protocol.tree_digest(manifest)


class SourceControls(unittest.TestCase):
    def test_roundtrip(self):
        files={BOARD[0]:b'html',BOARD[1]:b'logic',BOARD[2]:b'ui'}
        a,b,c=fixture(files);self.assertEqual(decode_source(a,b,c)[1],files)
    def test_tampering_and_trailing(self):
        a,b,c=fixture({BOARD[0]:b'html'})
        for altered in (a+b'\0'*512,a[:-1],a[:512]+b'X'+a[513:],bytes(512)+a[512:]):
            with self.assertRaises(ValueError):decode_source(altered,b,c)
        with self.assertRaises(ValueError):decode_source(a,b,'0'*64)
    def test_relation_exact_and_nonempty(self):
        base={BOARD[0]:b'a','README.md':b'readme'};candidate={**base,BOARD[0]:b'b'}
        bm,bf=decode_source(*fixture(base));cm,cf=decode_source(*fixture(candidate))
        record=admission_relation(bm,bf,cm,cf)
        self.assertEqual(record['changed_files'],[BOARD[0]])
        self.assertEqual(record['schema'],'dsmack-bounty-admission-transform/2')
        with self.assertRaises(ValueError):admission_relation(bm,bf,bm,bf)
        cm,cf=decode_source(*fixture({**base,'README.md':b'evil'}))
        with self.assertRaises(ValueError):admission_relation(bm,bf,cm,cf)
    def test_source_case_alias(self):
        a,b,c=fixture({'README.md':b'a','readme.md':b'b'})
        with self.assertRaises(ValueError):decode_source(a,b,c)

if __name__=='__main__':unittest.main()

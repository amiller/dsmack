import importlib.util
from pathlib import Path
import tarfile
import io
import pytest

spec = importlib.util.spec_from_file_location('bundle', Path(__file__).with_name('bundle.py'))
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)

def test_bundle_content_and_label(tmp_path):
    (tmp_path / 'index.html').write_text('<head></head>')
    (tmp_path / 'app.js').write_text('console.log("hello")')
    data = bundle.payload(tmp_path)
    own = bundle.cid(data)
    (tmp_path / 'page-bundle.tar').write_bytes(data)
    (tmp_path / 'index.html').write_text(f'<head><meta name="page-bundle-cid" content="{own}"></head>')
    assert bundle.check(tmp_path) == own
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        assert archive.extractfile('app.js').read() == b'console.log("hello")'
    (tmp_path / 'app.js').write_text('different code')
    with pytest.raises(ValueError, match='changed after build'):
        bundle.check(tmp_path)

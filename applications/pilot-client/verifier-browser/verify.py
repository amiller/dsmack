#!/usr/bin/env python3
"""Linux run-result verifier: `operator` CLI or `prepare` app-evidence tool."""
import argparse,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('command',choices=('operator','prepare'))
 parser.add_argument('args',nargs=argparse.REMAINDER)
 a=parser.parse_args(argv)
 sys.path.insert(0,str(ROOT))
 from runresult_ref.extraction import sandbox_available
 if not sandbox_available():raise SystemExit('Linux namespace sandbox unavailable')
 if a.command=='operator':from runresult_ref.operator_cli import main as entry
 else:from tools.prepare_app_evidence import main as entry
 return entry(a.args)
if __name__=='__main__':sys.exit(main())

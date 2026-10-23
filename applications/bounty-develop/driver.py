"""Measured thin launcher; all implementation remains in admitted OCI bytes."""
import os,sys
from pathlib import Path
if not sys.flags.isolated or not sys.flags.dont_write_bytecode or Path(__file__)!=Path('/workspace/inputs/driver'):
    raise SystemExit(2)
sys.path.insert(0,'/opt/bounty-develop')
import main
if Path(main.__file__)!=Path('/opt/bounty-develop/main.py'):raise SystemExit(2)
try:raise SystemExit(main.main())
except Exception as error:
    print('DEVELOP_REFUSED '+type(error).__name__,file=sys.stderr);raise SystemExit(2)

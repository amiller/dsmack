#!/usr/bin/python3
# Immutable measured script slot. The implementation is the selected OCI.
import sys
if sys.flags.isolated != 1 or not sys.flags.dont_write_bytecode:
    raise RuntimeError('isolated no-bytecode interpreter required')
if __file__ != '/workspace/inputs/driver':
    raise RuntimeError('measured driver slot must be executed')
sys.path.insert(0,'/opt/applications/bounty-runtime')
import entrypoint
if entrypoint.__file__ != '/opt/applications/bounty-runtime/entrypoint.py':
    raise RuntimeError('fixed image-owned application module required')
if __name__=='__main__':
    try:sys.exit(entrypoint.main())
    except Exception as error:
        print(type(error).__name__+': '+str(error)[:1000],file=sys.stderr)
        sys.exit(2)

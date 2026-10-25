#!/usr/bin/env python3
"""Prepare public checker inputs for one operator-selected Arcade task."""
import argparse,runpy
from pathlib import Path
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--task',required=True);parser.add_argument('--out',required=True);a=parser.parse_args()
 factory=runpy.run_path(str(Path(__file__).with_name('task_factory.py')))
 print(factory['prepare_checker'](a.task,Path(a.out)))

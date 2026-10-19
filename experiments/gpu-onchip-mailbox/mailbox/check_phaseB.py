#!/usr/bin/env python3
# Pass/fail verdict over run_phaseB.sh output: both system-scope configs complete
# 10 x 1000 trips with no value or command-buffer error, and both device-scope
# controls cap-hit on trip 1. usage: check_phaseB.py <logs/phaseB>
import glob, json, sys
d = sys.argv[1]
def chunks(c): return [json.load(open(f))["chunks_arr"][0] for f in sorted(glob.glob(f"{d}/{c}/chunk_*.json"))]
sys_ok = all(len(chunks(c)) == 10 and all(j["kernel_status_name"] == "done" and j["trips_done"] == 1000 and not j["kernel_wrong_echo"]
             and not j["cpu_wrong_val"] and not j["cb_errored"] for j in chunks(c)) for c in ("sys_default", "sys_dsbsy"))
dev_ok = all(len(chunks(c)) == 10 and all(j["kernel_status_name"] == "cap_hit" and j["trips_done"] == 0 for j in chunks(c)) for c in ("dev_default", "dev_dsbsy"))
print("PASS" if sys_ok and dev_ok else f"FAIL sys_ok={sys_ok} dev_ok={dev_ok}")
sys.exit(0 if sys_ok and dev_ok else 1)

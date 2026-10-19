#!/bin/bash
# Mac with App Attest (macOS 27, SIP + Full Security) and the build-app.sh signing variables.
# Enrolls key a with the honest build, asserts with it, then asserts with the modified build using the same key.
set -euo pipefail
cd "$(dirname "$0")"
../build-app.sh build/honest Probe.swift
../build-app.sh build/modified -D MODIFIED Probe.swift
for step in a-enroll a-assert b-old-key; do ./run_step.sh "$step"; done
grep '^CDHash=' captures/*/codesign.txt

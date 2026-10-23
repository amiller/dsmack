# Nonbounty generation reliability measurement

This separate diagnostic never supplies a bounty suite, acceptance, or retry.
It loads the exact pinned image generate.py into a fresh private module, changes
only its process observer and wall allowance (180 to 480 seconds), and reuses its
CLI 2.1.187, Opus4.8, two turns, candidate-blind prompt, environment, model
observer and strict suite validator. The paid generator remains unchanged.

The fresh manifest measures three readonly files: this driver, the exact held
GEN1 base.json and spec.txt. Mount flat inputs at /workspace/inputs/{driver,base.json,spec.txt}; invoke
--public /workspace/inputs --flat-public --snapshot-sha256 with the held snapshot
digest. After initial empty-state checks, only bounded base/spec bytes are copied
to a fresh temporary closed public directory. Both public copies and raw output
are removed before report export; extra flat files are never snapshot inputs. The profile is diagnostic/nonfunded, compose timeout550,
native600, existing B44/d912/app. No old broker GET/POST probe runs first.

Only generation-reliability.json is exported. Its closed fields contain counts,
booleans, coarse outcome/exit categories, byte counts and elapsed milliseconds.
The timestamps describe CLI-observed event arrival, not provider first-token
latency: the existing broker buffers SSE. Raw streams, prompt and any suite are
removed from temporary guest state before the report is written. No exception
text, endpoint, token, header, event content or suite is exported. Observation
completion returns0 even if model generation fails; bounty_acceptance is false.

Measured budget planning: approximately54 seconds boot +480 generation +10
CLI version probe +5 reap +5 validator +5 export =559 seconds, leaving41 under
native600. This is an estimate, not a guarantee. Existing upstream210/handler220/
idle10 broker limits remain. The diagnostic cannot guarantee one API request
will remain open480 seconds. Timeout/bound kills and reaps the owned CLI group.

Offline controls:
python3 -B applications/bounty-develop/test_generation_reliability.py

## Prospective retry-policy discussion (not adopted)

For a future version only, decide before claim whether exactly one new physical
attempt is allowed after authenticated infrastructure failure with zero assistant
events, zero result events and no suite. Preserve the first failure, same prompt,
model, two turns, blindness and strict grammar; require fresh challenge and explicit
root selection. Grammar failures, semantic failures or observed candidate failures
must not qualify. All three independently generated suites must still pass.
This draft grants no retry, funding, provider-call or VM authority and changes no
existing task, policy, report or selected admission.

# Deterministic Arcade testnet checks

These task profiles use the fixed `5c76d40` application base and the feature
requirements published in issues 2, 5, 6, 7, 10 and 12 with checker source `8232383`.
They are explicit new testnet offers with deterministic checks. They do not
satisfy or replace the original issues' three-model judging procedure.

Each profile projects only the submitted app's `index.html`, `logic.js` and
`ui.js` onto the base. Puzzle levels and Routes samples remain the base files.
The protected controller imports candidate logic only inside Chromium, serves
read-only inputs, blocks outside network requests and exports results and media.
The base must fail a feature assertion; the candidate must pass every group.
An initialization, browser or deadline failure is not an accepted negative check.

## Board undo and redo — `board-undo-testnet-1`

1. **undo-controls:** both buttons exist and are disabled on a fresh board.
2. **history-api:** `createHistory`, `record`, `undo`, `redo` return new histories;
   add a, add b, undo gives a, redo gives a/b, without changing the input history.
3. **history-limit:** 60 adds retain 50 past states; 50 undos leave 10 cards;
   another undo throws an error containing “nothing to undo”.
4. **edit-delete-move:** UI add, cross-column move, edit, delete and reorder can
   be undone/redone with the correct card positions and saved-state increments.
5. **redo-branch:** a new action after undo clears the redo states in API and UI.
6. **import-clears:** importing a board clears both history stacks, replaces the
   displayed board and stores the change; the API yields empty past/future.
7. **shortcuts-reload:** Ctrl/Meta+Z and Ctrl/Meta+Shift+Z work outside text inputs;
   each change is saved; reload retains the board and disables both history buttons.

## Puzzle corner deadlocks — `puzzle-deadlock-testnet-1`

1. **deadlock-api:** `deadBoxes` is exported.
2. **level-starts:** every bundled level starts with no dead boxes.
3. **corner-indices:** published move sequences produce exactly `[28]` and `[33]`;
   two non-goal corner boxes return sorted `[9,14]` even when input order is reversed.
4. **non-dead-cases:** a goal-corner box and a box against only one wall return `[]`.
5. **corner-warning:** level 1 keyboard Down/Left/Down/Right marks only cell 28 and displays the exact
   “Stuck: a box is in a corner” warning.
6. **undo-restart:** button undo, Z undo and restart clear the dead marking and warning.
7. **second-level-warning:** level 4 U/R/U/R/D/D marks only cell 33; restart clears it.

## Routes segments and gaps — `routes-segments-testnet-1`

1. **segments-api:** two track segments with 2/3 points return two arrays and a
   five-point flat list in the same order.
2. **gap-distance:** distance sums only in-segment haversine distances, within 1 m.
3. **gap-elevation:** elevations 100/110 and 500/490 give gain 10, loss 10.
4. **default-stats:** omitting the segments option retains flat-list distance and
   gain/loss, including the intervening jump.
5. **samples-unchanged:** bundled samples retain one segment and distances
   4020.8 m / 9105.4 m (within 1 m); default and segment-aware stats agree.
6. **upload-segments:** the published two-segment upload displays `3.34 km` and
   exactly two polylines containing 2/3 points.
7. **sample-switch:** choosing either original sample restores one polyline and
   its original `9.11 km` / `4.02 km` display.

## Flight seeded wind — `flight-wind-testnet-1`

1. **wind-hud:** `/apps/flight/` shows `#wind` / `data-testid="wind"` matching `^-?\d+ m/s$`.
2. **wind-seeded:** `makeLevel(seed).wind` for seeds 1–500 is a repeatable number in [-12, 12] with both signs.
3. **wind-display:** for five seeds with |wind| ≥ 1, Restart shows wind matching the module's sign and within 1 m/s; not all equal.
4. **wind-reload:** after reload the same seeds show identical wind text.
5. **ground-speed:** hands-off for 10 s, HUD speed on the first tailwind seed (> 10) exceeds the first headwind seed (< -10).
6. **tailwind-ground:** on a flat hand-built level starting at `vx = CRUISE + wind`, wind 10 covers more ground in 20 s than wind -10.
7. **no-wind-unchanged:** a hand-built level without `wind` flies 600 fixed inputs to the base state within 1e-9.

## Flight run recording and replay — `flight-replay-testnet-1`

1. **replay-api:** `encodeRun`, `decodeRun` and `replay` are exported.
2. **run-roundtrip:** `decodeRun(encodeRun(seed, inputs))` returns `{seed, inputs}` for fixed, mixed and empty runs.
3. **run-url-safe:** encodings match `^[A-Za-z0-9_-]+$`.
4. **run-length:** 3600 identical inputs encode in fewer than 100 characters for each of the nine inputs.
5. **replay-fold:** `replay(seed, inputs, 1/60)` equals folding `step` from `initialState(makeLevel(seed))`; both fixtures end not flying.
6. **link-replay:** `?run=` for seed 3 × 300 dives and seed 5 throttle-climb-dive sets the seed input and reaches `replay`'s status with no keys.
7. **keyboard-share:** seed 7, throttle up then dive until crashed; the share link replays to crashed with identical score, speed, altitude and throttle.

## Routes time, moving time and speed — `routes-time-testnet-1`

1. **timing-api:** `timing` and `formatDuration` are exported; `parseGpx` gives `time` in ms and omits it for untimed points.
2. **timing-stops:** a 1:02:03 track with two 600 s walks (≈1.9 m/s) and two stops gives elapsed 3723000, moving 1200000 and haversine distance / moving time.
3. **timing-missing:** a point without time makes all three values null.
4. **format-duration:** `3723000` → `1:02:03`, `null` → `—`.
5. **untimed-default:** after `4.02 km`, `stat-elapsed` and `stat-moving` read `—`.
6. **untimed-switch:** after selecting `riverside-loop.gpx` both still read `—`.
7. **timed-upload:** uploading that track shows `1:02:03` and `0:20:00`.

Prepare a profile's three public checker files:

```sh
python3 -I applications/bounties/examples/arcade/prepare_checker.py \
  --task puzzle-deadlock-testnet-1 --out /absolute/new/checker-inputs
```

Select these files as the publisher's `checker` descriptors, with `task_slug`
matching the profile. The existing seven-slot manifest is shared. New task configurations select
`applications/bounties/examples/arcade/bonus_guest_driver.py` as their
`guest_driver` descriptor. The original Board-search pilot keeps `guest_driver.py`.
The new supervisor exports eight result/media files for valid checker executions,
including negative outcomes, and exits zero when that export completes. The host
factory independently requires the expected base failure and all candidate checks
to pass before authorizing any reward; an execution record alone is not acceptance.
Run `check.py --base-dir BASE --candidate-dir CANDIDATE --out OUTPUTS` in the
reference browser image to exercise a projected tree. The base and candidate
outputs are distinct; the checker source and acceptance rules stay outside the
candidate tree.

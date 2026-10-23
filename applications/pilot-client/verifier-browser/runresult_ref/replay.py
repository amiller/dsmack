"""R03 — per-key + issued-challenge atomic replay transaction with a
durable report outbox.

Design (closed):
  * Challenges are ISSUED before use: a challenge record carries owner
    key_id, bound task manifest digest, issue time and expiry.  Unissued
    challenges can never be consumed.
  * commit() runs ONE sqlite transaction (BEGIN IMMEDIATE = single writer):
      1. re-read the challenge row: must exist, belong to this key, bind
         this task manifest, be unexpired AT COMMIT TIME, and be unused;
      2. re-read the per-key effective counter floor;
      3. require launch_counter > floor and result_counter > launch_counter;
      4. advance the floor monotonically to result_counter, mark the
         challenge consumed, and INSERT the signed report into the outbox —
         all in the same transaction;
      5. COMMIT (WAL + synchronous=FULL → durable before success returns).
  * Crash before COMMIT: nothing persists — challenge unused, floor
    unchanged, no report.  Crash after COMMIT: the report is durably
    retrievable from the outbox (fetch_report) and the challenge stays
    consumed; re-verification of the same pair refuses.
  * Concurrent DISTINCT challenges for one key both re-check the floor
    INSIDE their transactions: after the first commits floor=result_counter,
    a second pair whose launch_counter is not above the NEW floor refuses
    (stale_counter_floor), even though both passed any earlier pre-check.
  * The frozen /4 verifier is never invoked with these challenges; this
    store is a separate namespace, so no legacy path can pre-consume a
    pair challenge.
"""
import json
import sqlite3
import time

from .errors import Refusal, need

_SCHEMA = """
CREATE TABLE IF NOT EXISTS key_floor (
  key_id TEXT PRIMARY KEY,
  counter_floor INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS enrollment_floor (
  key_id TEXT PRIMARY KEY,
  min_counter INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS challenge (
  challenge TEXT PRIMARY KEY,
  key_id TEXT NOT NULL,
  task_manifest_sha256 TEXT NOT NULL,
  issued_unix_s INTEGER NOT NULL,
  expires_unix_s INTEGER NOT NULL,
  consumed_unix_s INTEGER
);
CREATE TABLE IF NOT EXISTS outbox (
  challenge TEXT PRIMARY KEY REFERENCES challenge(challenge),
  key_id TEXT NOT NULL,
  report_json BLOB NOT NULL,
  committed_unix_s INTEGER NOT NULL,
  delivered_unix_s INTEGER
);
"""


class ReplayStore:
    def __init__(self, path):
        self.path = str(path)
        connection = self._connect()
        with connection:
            connection.executescript(_SCHEMA)
        connection.close()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30.0,
                                     isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    # ---- issuance ----
    def issue_challenge(self, challenge, key_id_b64, task_manifest_sha256,
                        ttl_seconds, now_unix_s=None):
        need(isinstance(challenge, str) and challenge, "bad_challenge")
        need(0 < ttl_seconds <= 86400, "bad_challenge_ttl")
        now = int(now_unix_s if now_unix_s is not None else time.time())
        connection = self._connect()
        try:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT 1 FROM challenge WHERE challenge=?",
                    (challenge,)).fetchone()
                need(row is None, "challenge_already_issued")
                connection.execute(
                    "INSERT INTO challenge VALUES (?,?,?,?,?,NULL)",
                    (challenge, key_id_b64, task_manifest_sha256,
                     now, now + int(ttl_seconds)))
        finally:
            connection.close()

    # ---- authenticated enrollment-floor contract ----
    def set_enrollment_floor(self, key_id_b64, min_counter):
        """Record the authenticated minimum counter for a key, established by
        the authenticated enrollment path (never from a request).  The commit
        transaction rechecks launch_counter against max(this, the advancing
        replay floor), so an unknown key is NOT silently admitted at floor
        zero once an enrollment floor has been authenticated for it."""
        need(isinstance(min_counter, int) and not isinstance(min_counter, bool)
             and min_counter >= 0, "bad_enrollment_floor")
        connection = self._connect()
        try:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO enrollment_floor VALUES (?,?)"
                    " ON CONFLICT(key_id) DO UPDATE SET min_counter="
                    "excluded.min_counter WHERE excluded.min_counter"
                    " > enrollment_floor.min_counter",
                    (key_id_b64, int(min_counter)))
        finally:
            connection.close()

    # ---- the atomic pair commit ----
    def commit(self, challenge, key_id_b64, task_manifest_sha256,
               launch_counter, result_counter, report_json_bytes,
               now_unix_s=None, crash_before_commit=False, trusted_clock=None,
               require_enrollment_floor=False):
        """All-or-nothing: floor recheck + advance, challenge consumption and
        durable report publication in ONE transaction.  crash_before_commit
        simulates a process death inside the transaction (tests).

        REF05: the freshness authority (expiry check) is sampled from the
        TRUSTED clock AFTER acquiring BEGIN IMMEDIATE, never a value sampled
        before verification/extraction.  ``now_unix_s`` is used only to stamp
        the recorded consumption/commit time; ``trusted_clock`` (default
        ``time.time``) supplies the in-transaction current time and tests may
        inject it to advance time during verification.
        """
        need(isinstance(report_json_bytes, bytes) and report_json_bytes,
             "bad_report_bytes")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            # trusted current time, sampled INSIDE the write transaction
            commit_now = int(trusted_clock() if trusted_clock is not None
                             else time.time())
            stamp = int(now_unix_s if now_unix_s is not None else commit_now)
            row = connection.execute(
                "SELECT key_id, task_manifest_sha256, expires_unix_s,"
                " consumed_unix_s FROM challenge WHERE challenge=?",
                (challenge,)).fetchone()
            need(row is not None, "challenge_not_issued")
            owner, task, expires, consumed = row
            need(owner == key_id_b64, "challenge_wrong_key")
            need(task == task_manifest_sha256, "challenge_wrong_task")
            need(consumed is None, "challenge_consumed")
            need(commit_now <= expires, "challenge_expired",
                 "commit_now %d > expires %d" % (commit_now, expires))
            floor_row = connection.execute(
                "SELECT counter_floor FROM key_floor WHERE key_id=?",
                (key_id_b64,)).fetchone()
            enroll_row = connection.execute(
                "SELECT min_counter FROM enrollment_floor WHERE key_id=?",
                (key_id_b64,)).fetchone()
            # REF02: a production commit MUST have an authenticated enrollment
            # floor for the key; an ABSENT floor can no longer be silently
            # admitted as zero (which would let an unknown/not-yet-enrolled key
            # through at the lowest possible floor).
            if require_enrollment_floor:
                need(enroll_row is not None, "enrollment_floor_absent",
                     key_id_b64)
            floor = max(floor_row[0] if floor_row else 0,
                        enroll_row[0] if enroll_row else 0)
            need(launch_counter > floor, "stale_counter_floor",
                 "launch %d <= floor %d" % (launch_counter, floor))
            need(result_counter > launch_counter, "counter_order")
            connection.execute(
                "INSERT INTO key_floor VALUES (?,?) ON CONFLICT(key_id)"
                " DO UPDATE SET counter_floor=excluded.counter_floor"
                " WHERE excluded.counter_floor > key_floor.counter_floor",
                (key_id_b64, result_counter))
            connection.execute(
                "UPDATE challenge SET consumed_unix_s=? WHERE challenge=?",
                (stamp, challenge))
            connection.execute(
                "INSERT INTO outbox VALUES (?,?,?,?,NULL)",
                (challenge, key_id_b64, report_json_bytes, stamp))
            if crash_before_commit:
                # Simulated crash: the connection dies without COMMIT; sqlite
                # rolls the whole transaction back on next open.
                connection.close()
                raise Refusal("simulated_crash_before_commit")
            connection.execute("COMMIT")
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise Refusal("replay_store_error", str(exc)) from exc
        except Refusal:
            if not crash_before_commit:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise
        finally:
            try:
                connection.close()
            except sqlite3.Error:
                pass

    # ---- durable retrieval (crash recovery / relying-party pickup) ----
    def fetch_report(self, challenge):
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT report_json, committed_unix_s, delivered_unix_s"
                " FROM outbox WHERE challenge=?", (challenge,)).fetchone()
            if row is None:
                return None
            return {"report_json": row[0], "committed_unix_s": row[1],
                    "delivered_unix_s": row[2]}
        finally:
            connection.close()

    def mark_delivered(self, challenge, now_unix_s=None):
        now = int(now_unix_s if now_unix_s is not None else time.time())
        connection = self._connect()
        try:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "UPDATE outbox SET delivered_unix_s=? WHERE challenge=?"
                    " AND delivered_unix_s IS NULL", (now, challenge))
        finally:
            connection.close()

    def state(self, key_id_b64=None, challenge=None):
        connection = self._connect()
        try:
            out = {}
            if key_id_b64 is not None:
                row = connection.execute(
                    "SELECT counter_floor FROM key_floor WHERE key_id=?",
                    (key_id_b64,)).fetchone()
                out["counter_floor"] = row[0] if row else 0
            if challenge is not None:
                row = connection.execute(
                    "SELECT consumed_unix_s FROM challenge WHERE challenge=?",
                    (challenge,)).fetchone()
                out["issued"] = row is not None
                out["consumed"] = row is not None and row[0] is not None
            return out
        finally:
            connection.close()

# Publication crash

Contract: `sealr.publication-crash.v1`.

This document specifies what a later process observes when the materializing
process dies at the no-replace rename. The tests are process death on a machine
that keeps running. The kernel page cache remains, so another process can read
writes that have reached the kernel. This is not a power-loss test. It does not
add a policy field, a receipt durability string, a worker byte, or a CLI flag.
`FlushOnly`, `MemberSync`, and `DirectorySync` keep their existing meanings.

## Barriers

Publication rechecks the retained stage, optionally syncs staged directories,
then renames that directory onto an absent destination name. Two test-only
exits surround that rename. They are compiled only into test builds.

| Barrier | When the process exits | What remains |
|---|---|---|
| Before publication | After staged-directory sync, when that sync was requested, and after the test-only destination plant. The exit is immediate, before `rename_noreplace` is called. | The destination name does not exist. The stage directory still holds the audited tree. A retention file written for this operation still names that stage. |
| After publication | Immediately after `rename_noreplace` returns. The stage handle is still open. Destination-parent sync and retention discard have not run. | The destination exists and contains the audited tree. The recorded stage component is gone. The retention file, if one was written, still names that absent component. |

The before-publication test uses `Policy::default_v1()`, which is flush-only.
The after-publication test uses `Policy::default_v12()` with
`Durability::DirectorySync`, so staged-directory sync has already succeeded and
destination-parent sync has not run. A kill before the retention file is
written still has no record. This contract does not invent one.

## Recovery after each barrier

`recover_abandoned_stage` is unchanged. It opens the recorded stage component
from the admitted parent. It does not list the parent, search by device,
inode, or file identifier, or select another name.

Before publication, that open finds the stage. Recovery removes only that
directory. A same-shaped lookalike and an unrelated neighbor stay. The
destination name stays absent.

After publication, the recorded component is gone. The same directory object
now has the destination name, but recovery does not follow it. The open fails
with `materialize.io` and the detail prefix
`open abandoned stage without following links:`. The published tree, the
lookalike, and the neighbor stay.

## What this is not

Directory sync remains `sealr.policy-directory-sync.v1`. It syncs completed
member files, then every staged directory with children before parents, then
the destination parent after the rename. It does not sync every ancestor. A
parent sync failure after publication still leaves the outcome `committed`,
reports `member-sync`, and records the finding. That order is not a power-loss
claim, and this contract does not strengthen it.

The tests exit before the rename call or after that call has returned. They do
not interrupt the kernel during the rename, and they do not remove power.
Power loss can discard dirty pages and volatile drive caches. Authenticated
crash recovery and repeated hostile race testing remain stable-release gates.
This contract does not authenticate a receipt, contain a same-user attacker, or
authorize a sweeper, a startup scan, or filename-pattern cleanup.

Other systems draw a useful boundary and are not a claim that Sealr matches
them. SQLite's [atomic commit](https://www.sqlite.org/atomiccommit.html)
describes transactions that still look complete or absent after an operating
system crash or power failure, under its assumptions about sector writes,
fsync, and file deletion. Sealr does not implement a journal and does not test
those failures. PostgreSQL's
[reliability notes](https://www.postgresql.org/docs/current/wal-reliability.html)
require committed data to reach nonvolatile storage and call out volatile
controller and drive caches. Sealr does not make that claim. POSIX `rename`
changes a name within one directory as one action on a running system, and
`RENAME_NOREPLACE` leaves an existing destination untouched. A system crash
during the call is outside this contract.

## Evidence

| Interruption | Observed result |
|---|---|
| Process exits immediately before the no-replace rename, flush-only policy v1 | The child exits 87. The destination name does not exist. The stage contains `kept.txt` and `nested/other.txt`. Recovery with the retention file removes only that stage. A lookalike directory and `unrelated.txt` stay. |
| Process exits immediately after the no-replace rename, directory sync on policy v12, before parent sync and retention discard | The child exits 88. The destination contains both audited members. The recorded stage component is absent. Recovery fails when it opens that component and leaves the destination, the lookalike, and `unrelated.txt` in place. The retention file still names the absent component. |

The tests are
`killed_apply_before_publication_leaves_the_stage_and_not_the_destination` and
`killed_apply_after_publication_keeps_the_destination_and_refuses_stage_recovery`.
They run on Linux, macOS, and Windows. The exits are 87 and 88 so a missed
barrier cannot be mistaken for the older retention-file exit 86. A missed
barrier exits 2. These tests do not qualify power-loss durability.

`SEALR_KILL_BEFORE_PUBLICATION` and `SEALR_KILL_AFTER_PUBLICATION` exist only
in test builds. `SEALR_KILL_AFTER_STAGE_RETENTION` remains the earlier
retention-file barrier in the [abandoned-stage contract](abandoned-stage.md)
and is not this contract.

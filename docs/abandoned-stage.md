# Abandoned stage ownership

Contract: `sealr.abandoned-stage.v1`.

This document specifies how a materialization stage is owned, how the current
operation removes or publishes it, and what recovery must prove.
`recover_abandoned_stage` removes one directory only when the caller presents
the record from a failed cleanup or from a caller-chosen retention file. A
process killed before that file is written still has no record.
`Durability::FlushOnly` and `Durability::MemberSync` do not change. Directory sync is the separate `Durability::DirectorySync` selection on policy v12. This contract does not define it. Process death at the no-replace rename is the separate [publication-crash contract](publication-crash.md). The retention-file kill below is an earlier barrier and is not that evidence.

## Live ownership

A live stage is the directory capability retained by the materializer that
created it, together with the already-admitted destination parent capability
and the exact final component. `StageWriteRoot` receives only a clone of the
stage capability. It cannot name the parent or the final component, and it
cannot publish or remove the stage.

On Linux and macOS the parent must be owned by the effective user or root, and
it must deny group and other write unless it is sticky and has a trusted owner.
The stage must be owned by the effective user, and its mode must grant nothing
to group or other (`mode & 0o077 == 0`). macOS also rejects an extended ACL on
the parent or the stage, including when the ACL query fails. On Windows the
parent must be non-remote writable NTFS with persistent ACLs, and the stage
must verify the protected effective-token-user DACL before member writes.

The stage component is `.sealr-stage-` plus 32 lowercase hexadecimal digits,
created with an exclusive directory operation. That shape is a label for the
object this operation just created. It is not a search key.

Immediately before publication, the operation reopens that exact component
with no-follow semantics and requires it to name the retained stage
capability. Linux and macOS compare the device and inode. Windows compares
the 128-bit file identifier. A mismatch is `materialize.commit` and does not
publish. While the stage handle remains open, Windows also denies delete
sharing, so a rename or removal of that object fails with a sharing violation
and publication uses the retained handle.

## What is not ownership

The following are not proof that a directory is this operation's stage:

- a name that begins with `.sealr-stage-`;
- mode `0700`, a private DACL, or effective-user ownership by themselves;
- an unsigned `sealr.materialization.v2` receipt;
- a directory listing of the destination parent.

Same-user processes, root, administrators, SYSTEM, a principal matching the
effective token's default-owner SID, and holders of filesystem-override or
handle-duplication rights can create or replace a private directory. They
remain outside the in-process containment claim. A later process must not treat
a private directory it did not retain as its stage.

## Cleanup and publication today

Publication is the platform no-replace rename of the retained object to the
absent final component. An existing destination, including one that appears
after staging, is left unchanged. The receipt outcome is `committed` and
cleanup is `not-applicable-after-commit` only after that rename succeeds.

On rejection, cleanup runs at most twice. Each attempt prefers the retained
stage capability and removes that open directory. A parent-relative removal of
the exact component is used only when the capability was not opened, or when
setup cleanup's open-directory removal fails. The receipt then says `removed`
or, after both attempts fail, `failed`. `removed` means the retained object was
removed. It does not mean every `.sealr-stage-*` entry is gone.

If the stage name is replaced after audit, abort still removes the retained
directory object. The directory that now occupies the old name is left in
place, and the final destination is not created. Drop runs cleanup only while
cleanup is `pending`. A receipt that already says `failed` is not cleaned again
on drop.

A killed process does not run drop. The stage directory can remain. The receipt,
if the process died before writing one, does not exist. The receipt does not
contain the stage name, device, inode, or Windows file identifier. A
caller-chosen retention file written before the kill is the record a later
process can present. A kill before that write leaves none.

## Recovery

`recover_abandoned_stage` may remove one directory only when all of the
following are true:

1. The caller presents the destination parent and the exact stage component
   retained from the creating operation. The operation must not list the parent
   or select names by a pattern.
2. The parent is admitted again with the current namespace checks.
3. The component is opened no-follow from that parent and passes the current
   stage namespace check, including reparse-point rejection.
4. The caller proves that this object is the one the creating operation
   retained, using a witness recorded by that operation. On Linux and macOS the
   witness is the device and inode. On Windows it is the volume serial and the
   128-bit file identifier, checked through a newly opened handle that also
   passes the protected DACL verification.

`sealr.stage-witness.v1` is the Linux and macOS witness: the device and inode
of the retained stage directory. `sealr.windows-file-id.v1` is the Windows
witness: the volume serial number and that same object's 128-bit file
identifier, written as 32 lowercase hexadecimal digits. Windows reads it with
`FileIdInfo` through a handle. It does not use the 64-bit file index. An
all-zero identifier is not a witness. Volume serial zero is a real volume and
is accepted. A witness from another platform fails closed before any directory
is opened. Neither witness is a stage name or a parent listing. Neither is a
field of `sealr.materialization.v2` or `sealr.receipt.v3`.

When cleanup fails, `Outcome::stage_retention` returns
`sealr.stage-retention.v1`: the exact stage component plus the platform
witness. That record is not written into `sealr.materialization.v2` or
`sealr.receipt.v3`. The caller stores it. A later process presents the parent
and that record. Recovery opens the exact component without listing the parent
and removes the opened directory only when the witness matches. A mismatch, a
link, a failed parent check, or a failed DACL check leaves the object in place.
On Windows, that removal resolves the path of the handle that passed the
identifier and DACL checks. It does not list the parent or choose another name.

A caller that needs the record to survive process death passes
`ApplyOptions::with_stage_retention_path` before the operation. After the
stage exists, sealr creates that file without following its final component
and does not write it inside the stage. On Linux and macOS the file mode is
`0600`. On Windows the file is created with the same protected
effective-token-user DACL as a stage, so it never exists without that DACL.
A failed create leaves no file. An existing file is left untouched. The file is removed when the stage
is removed or published. A process killed after the write leaves the file.
`read_stage_retention` opens that exact file without following a link. Syncing
the file is not directory sync and not a power-loss guarantee.

A process killed before the file is written still has no record, and recovery
must not invent one by listing `.sealr-stage-*`. Successful cleanup does not
return a record and does not leave the file, because the directory is already
gone and its identifier may be reused.

If any check fails, the object stays. Recovery must not fall back to deleting
the name. It must not publish, replace an existing destination, sync
directories, or change the meaning of `flush-only` or `member-sync`. A stronger
durability mode needs its own policy value, migration contract, and fault
evidence.

## Evidence for this revision

| Interruption | Observed result |
|---|---|
| Destination already exists at setup | No stage is created. Cleanup is `not-created`. The destination bytes stay. |
| Stage namespace check fails after creation | The retained handle is removed first. The exact component is retried only if that removal fails. |
| Member verification fails | The stage is aborted. One retry follows. Cleanup is `removed`, or `failed` when both attempts fail. The destination does not appear. |
| Staged tree disagrees with the admitted IR | `materialize.audit`. The retained stage is removed. The destination does not appear. A planted reparse point does not receive the member write. |
| Destination appears before publication | `materialize.exists`. The existing destination stays. The retained stage is removed. |
| Stage name no longer identifies the retained object | `materialize.commit`. Abort removes the retained object and leaves the substitute directory. Linux and macOS compare device and inode. Windows compares the file identifier. |
| Windows rename while the stage handle is open | Sharing violation. Publication writes the retained tree, not a substitute planted beside it. |
| Both cleanup attempts fail | The stage remains. A later materialization of a different destination in the same parent leaves that stage, a same-shaped directory, a link to an outside directory, an unrelated file, and a pre-existing directory in place. |
| Process killed after the retention file is written | Drop does not run. The stage directory and the caller-chosen file both remain. Recovery with that file removes only the matching directory. A kill before the write still has no record. This is not a power-loss test. |

The preservation test is
`later_materialization_preserves_abandoned_stage_lookalike_and_neighbor`.
The identity test is `commit_rejects_stage_name_substitution_after_audit`.
Windows identity is `windows_commit_rejects_a_substituted_stage_name` and
`windows_retention_file_is_private_and_recovery_requires_the_same_id`.
The process-death test is `killed_apply_leaves_the_named_retention_file`.
The native lifecycle oracle covers publication, setup collision, verification
abort, and a destination that appears before publication. Those tests are the
fault evidence for this contract. They do not qualify publication-crash
recovery or power-loss durability. Process death at the rename is
[publication-crash.md](publication-crash.md).

## Non-claims

This contract does not make `FlushOnly` or `MemberSync` durable across power
loss. It does not sync parent directories. It does not authenticate a receipt.
It does not contain a same-user attacker. It does not authorize a sweeper,
a startup scan, or a hidden retry that deletes matching names.

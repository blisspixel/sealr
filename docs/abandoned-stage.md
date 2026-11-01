# Abandoned stage ownership

Contract: `sealr.abandoned-stage.v1`.

This document specifies how a materialization stage is owned, how the current
operation removes or publishes it, and what a later recovery operation would
have to prove. Recovery after the creating process is gone is not implemented.
`Durability::FlushOnly` and `Durability::MemberSync` do not change.

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

Immediately before publication, Linux and macOS reopen that exact component
with no-follow semantics and require its device and inode to match the retained
stage capability. A mismatch is `materialize.commit` and does not publish.
Windows does not perform that device and inode comparison. While the stage
handle remains open, Windows denies delete sharing, so a rename or removal of
that object fails with a sharing violation and publication uses the retained
handle.

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
if the process died before writing one, does not exist. The receipt, if a
cleanup failure was recorded, does not contain the stage name, device, inode,
or Windows file identifier.

## Recovery is not implemented

A future recovery operation may remove one directory only when all of the
following are true:

1. The caller presents the destination parent and the exact stage component
   retained from the creating operation. The operation must not list the parent
   or select names by a pattern.
2. The parent is admitted again with the current namespace checks.
3. The component is opened no-follow from that parent and passes the current
   stage namespace check, including reparse-point rejection.
4. The caller proves that this object is the one the creating operation
   retained, using a witness recorded by that operation. On Linux and macOS the
   witness is the device and inode. On Windows it is an identifier of the
   retained object, checked through a newly opened handle that also passes the
   DACL verification.

Today the creating operation does not persist that witness, and the receipt
does not record the stage name. A later process therefore cannot make the
proof in step 4. Until a versioned witness exists, recovery must not remove a
directory. In particular, it must not recursively delete a filename pattern.

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
| Stage name no longer identifies the retained inode | `materialize.commit` on Linux and macOS. Abort removes the retained object and leaves the substitute directory. |
| Windows rename while the stage handle is open | Sharing violation. Publication writes the retained tree, not a substitute planted beside it. |
| Both cleanup attempts fail | The stage remains. A later materialization of a different destination in the same parent leaves that stage, a same-shaped directory, a link to an outside directory, an unrelated file, and a pre-existing directory in place. |
| Process killed during the operation | Drop does not run. This is the same leftover class as exhausted cleanup and is not given a separate kill test. |

The preservation test is
`later_materialization_preserves_abandoned_stage_lookalike_and_neighbor`.
The identity test is `commit_rejects_stage_name_substitution_after_audit`.
The native lifecycle oracle covers publication, setup collision, verification
abort, and a destination that appears before publication. Those tests are the
fault evidence for this contract. They do not qualify crash recovery or
power-loss durability.

## Non-claims

This contract does not make `FlushOnly` or `MemberSync` durable across power
loss. It does not sync parent directories. It does not authenticate a receipt.
It does not contain a same-user attacker. It does not authorize a sweeper,
a startup scan, or a hidden retry that deletes matching names.

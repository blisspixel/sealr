# Repository instructions

The only permitted author and public attribution identity is Nick Seal
<32712898+blisspixel@users.noreply.github.com>, GitHub username blisspixel.
Do not add Codex, Claude, Anthropic, OpenAI, ChatGPT, Copilot, other assistant,
model, vendor, tool, or coauthor credits anywhere in public repository content.
This includes commit messages, PR titles and bodies, release notes, annotated tag
messages, documentation, README files, images, and UI text. Do not add attribution
trailers, signatures, footers, badges, or negative disclaimers such as "not by"
that name these tools. Do not add Co-Authored-By or similar trailers.
Do not use emojis or em dashes. Keep documentation current and tidy.
Preserve third-party copyright, license, NOTICE, and other legal attribution.
These rules never authorize removing or rewriting required legal notices.
Instruction files may name the prohibited credits to define this policy.

Enable the local commit guard in both sealr and sealr-validation checkouts with
`git config core.hooksPath .githooks`. The hook must have its executable Git mode.
Run `python scripts/verify_attribution.py --ci` before publication. Check prepared
PR, release, or tag text with
`python scripts/verify_attribution.py --text-file <path>`.
Apply these checks automatically without waiting for human approval.

## Start tidy, stop tidy

Work in this repository may come from several agent tools, and sessions can end partway through a task.

- **Check first.** Before starting new work, run `git fetch --prune` and check `git worktree list`, local and remote branches, and open PRs. Finish, merge, or park leftover work instead of starting a parallel attempt. Squash merges hide merged work from ancestry, so check PR state, not only `git branch --merged`.
- **Checkpoint and hand off.** Commit and push at meaningful checkpoints. Before stopping, leave a short handoff note (in the PR or commit message) saying what is done and what is next.
- **Keep the tree clean.** Test fixtures, scratch scripts, logs, and generated output go only in the designated test or temp locations or a gitignored scratch directory (for example `.agents/`, added to `.gitignore`). Never leave throwaway test files elsewhere in the tree, and remove scratch artifacts before finishing.
- **Keep branches short-lived.** Merge promptly and delete branches after merge. Keep GitHub current: push finished work, update or close PRs, and close finished issues.
- **Goal state.** One `main` with CI passing. Never leave `main` red or work stranded on side branches.
- **Remove only with evidence.** Remove a worktree or branch only once its work is merged, contained in `main`, or pushed to the remote. Never use `--force` to remove one; report anything uncertain instead of deleting it. Run `git worktree prune` for entries whose directories are gone.
- **Ask when unclear.** If it is unclear whether leftover work should be finished, kept, or removed, or what the intended state is, stop and ask instead of guessing.

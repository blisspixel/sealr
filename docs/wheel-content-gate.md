# A wheel-content release gate

The [`deepr_content_gate` example](../crates/sealr/examples/deepr_content_gate/main.rs)
makes a concrete publisher decision through the public `VerifiedArchive` API.
It verifies the whole wheel, independently checks canonical evidence, removes
its private source copy, evaluates wheel semantics, and checks the admitted
member inventory. It installs no files and uses no second archive parser.

This is an owner-maintained integration example. It is not installed in Deepr's
production release workflow and does not satisfy independent adoption.

## The decision

The example is based on
[Deepr's wheel-content check](https://github.com/blisspixel/deepr/blob/02b5c1187ba18ce05e546e36e2c5eb403fe1aff0/scripts/check_wheel_frontend.py).
That check verifies ZIP member integrity and then decides acceptance from names.
It does not inspect HTML, JavaScript, CSS, JSON, YAML, or prompt contents.

| Requirement | Exact scope |
|---|---|
| Dashboard entry point | `deepr/web/frontend/dist/index.html` |
| Dashboard assets | At least one `.js` and one `.css` file under `deepr/web/frontend/dist/assets/` |
| Runtime configuration | `deepr/config/system_message.json` |
| Recon skill | `deepr/skills/recon/skill.yaml` and `deepr/skills/recon/prompt.md` |
| Research template | `deepr/templates/documentation_research.md` |
| Build debris | Refuse `node_modules` and `__pycache__` path components, `frontend-dist.zip`, and `.pyc` or `.pyo` members |

The business function receives only `&VerifiedArchive`. It cannot reopen a
source path. Required paths and frontend assets must be regular files, and the
main program requires the `deepr-research` distribution after wheel evaluation.

There are deliberate additional requirements compared with the original
Python check: the explicit portable UTF-8 profile, complete member verification,
wheel filename and metadata agreement, RECORD verification, and the wheel
consumer's own exclusions all precede the content decision. The business rule
also catches root-level `node_modules`, `__pycache__`, and `frontend-dist.zip`
and prevents directories from satisfying required files. This is not a claim of
identical acceptance for every possible input.

Deepr's source-distribution check is outside this example. The supported
supervised path remains ZIP32 on x86_64 Linux; there is no TAR worker fallback.

## Run it on Linux

Authenticate the matching [native release](release-verification.md), then build
the example from the same release source. The example uses the ordinary public
crate API and the existing authenticated worker and independent verifier.

```sh
cargo build --locked --release -p sealr --example deepr_content_gate

target/release/examples/deepr_content_gate \
  --wheel /absolute/path/deepr_research-2.50.11-py3-none-any.whl \
  --worker-manifest /absolute/path/native/libexec/sealr/sealr-worker.manifest \
  --verifier /absolute/path/native/sealr-identity-verifier
```

The caller's wheel is preserved. A separate private copy is acquired with a
128 MiB bound. The worker verifies it under the normal archive policy, and the
companion verifier binds the canonical evidence to its observed source bytes.
Only then is that private pathname deleted. Wheel evaluation and the business
decision use the surviving capability. Verified backing storage remains alive
until the capability is dropped; pathname deletion does not erase all bytes.

Exit `0` means the complete example accepted the wheel. Exit `1` reports a
setup, archive, evidence, wheel-semantic, or business-rule failure on stderr.
No installation destination is created. The success JSON includes source,
tree, artifact, plan, and canonical evidence digests, each business-rule count,
retention outcomes, and separate phase times. This example report is a preview
integration surface, not a stable core evidence schema.

## Declare the working set when it is known

Repeat `--retain-member` with exact canonical paths from a trusted, pinned
working-set inventory. For this Deepr wheel, the semantic working set is:

```sh
  --retain-member deepr_research-2.50.11.dist-info/METADATA \
  --retain-member deepr_research-2.50.11.dist-info/WHEEL \
  --retain-member deepr_research-2.50.11.dist-info/RECORD \
  --retain-member deepr_research-2.50.11.dist-info/entry_points.txt
```

These optional flags extend the complete command above. Retention is bounded
to 64 paths, 256 KiB per member, and 1 MiB total, with the public path-size
limits unchanged. It captures requested verified bytes during admission. It
does not skip verification of other members. Missing or oversized requests are
reported through retention status; ordinary bounded capability reads remain
available. The content decision itself needs no member reads.

The [bounded retention experiment](capability-reuse-experiment.md) compares
these choices against complete installations of the same pinned wheels. Phase
times are observations from specific runs, not a stable performance promise.

## Regression evidence

```sh
cargo test --locked -p sealr --example deepr_content_gate
```

The fixtures rebuild valid RECORD entries for business-policy mutations, so a
missing runtime asset or added build artifact reaches the intended decision.
Separate cases cover archive integrity and path refusals, lying RECORDs and
filename disagreement, retained versus unretained identity parity, directory
substitutions, and source removal before evaluation followed by a failed reopen
and a successful capability read.

Admission verifies every member even though the final business decision uses
only names. An unrelated corrupt payload or incomplete Deflate stream therefore
fails before the content gate. The example does not establish that the packaged
application works correctly or is safe to execute.

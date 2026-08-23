#!/usr/bin/env bash
set -euo pipefail

selector="scripts/release_candidate.jq"
tag="v0.1.0-alpha.4"
title="sealr 0.1.0-alpha.4: measured semantic contract preview"
notes=$'# sealr 0.1.0-alpha.4\n'
allowed='[
  "SHA256SUMS",
  "sealr-0.1.0-alpha.4-aarch64-apple-darwin.tar.gz",
  "sealr-0.1.0-alpha.4-x86_64-pc-windows-msvc.zip",
  "sealr-0.1.0-alpha.4-x86_64-unknown-linux-gnu.tar.gz"
]'

mapfile -t workspace_versions < <(
  cargo metadata --locked --no-deps --format-version 1 |
    jq -r '.packages[].version' |
    sort -u
)
if [[ "${#workspace_versions[@]}" -ne 1 || "${workspace_versions[0]}" != "${tag#v}" ]]; then
  echo "release candidate workspace versions do not match ${tag#v}"
  printf 'observed version: %s\n' "${workspace_versions[@]:-none}"
  exit 1
fi

make_release() {
  jq -cn \
    --arg tag_name "${1}" \
    --arg name "${title}" \
    --arg body "${notes}" \
    --argjson allowed "${allowed}" '
      {
        id: 374132103,
        tag_name: $tag_name,
        name: $name,
        body: $body,
        draft: true,
        prerelease: true,
        immutable: false,
        published_at: null,
        author: {login: "github-actions[bot]"},
        assets: [
          range(0; 4) as $index |
          {
            id: (523084826 + $index),
            name: $allowed[$index],
            state: "uploaded",
            size: (100 + $index),
            digest: (
              "sha256:" +
              ([range(0; 64) | "a"] | join(""))
            ),
            uploader: {login: "github-actions[bot]"}
          }
        ]
      }
    '
}

classify() {
  jq -ce \
    --arg tag "${tag}" \
    --arg name "${title}" \
    --arg notes "${notes}" \
    --argjson allowed "${allowed}" \
    -f "${selector}"
}

assert_counts() {
  local input="${1}"
  local expected="${2}"
  local actual
  actual="$(classify <<<"${input}" | jq -c '
    {
      exact: (.exact | length),
      valid_exact: (.valid_exact | length),
      recovery: (.recovery | length),
      suspicious: (.suspicious | length)
    }
  ')"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "release candidate fixture failed"
    echo "expected: ${expected}"
    echo "actual:   ${actual}"
    exit 1
  fi
}

exact="$(make_release "${tag}")"
orphan="$(make_release "untagged-4973ca3a37030f6f9ced")"

assert_counts "[[]]" \
  '{"exact":0,"valid_exact":0,"recovery":0,"suspicious":0}'
assert_counts "[[${exact}]]" \
  '{"exact":1,"valid_exact":1,"recovery":0,"suspicious":0}'
assert_counts "[[${orphan}]]" \
  '{"exact":0,"valid_exact":0,"recovery":1,"suspicious":1}'
assert_counts "[[${exact},${orphan}]]" \
  '{"exact":1,"valid_exact":1,"recovery":1,"suspicious":1}'
assert_counts "[[${orphan},$(jq '.id = 374132104' <<<"${orphan}")]]" \
  '{"exact":0,"valid_exact":0,"recovery":2,"suspicious":2}'

wrong_author="$(jq '.author.login = "octocat"' <<<"${orphan}")"
assert_counts "[[${wrong_author}]]" \
  '{"exact":0,"valid_exact":0,"recovery":0,"suspicious":1}'

wrong_state="$(jq '.draft = false | .published_at = "2026-08-21T00:00:00Z"' <<<"${orphan}")"
assert_counts "[[${wrong_state}]]" \
  '{"exact":0,"valid_exact":0,"recovery":0,"suspicious":1}'

wrong_title="$(jq '.name = "changed"' <<<"${orphan}")"
assert_counts "[[${wrong_title}]]" \
  '{"exact":0,"valid_exact":0,"recovery":0,"suspicious":1}'

unknown_asset="$(jq '.assets[0].name = "unexpected.zip"' <<<"${orphan}")"
assert_counts "[[${unknown_asset}]]" \
  '{"exact":0,"valid_exact":0,"recovery":0,"suspicious":1}'

duplicate_asset="$(jq '.assets[1].id = .assets[0].id' <<<"${orphan}")"
assert_counts "[[${duplicate_asset}]]" \
  '{"exact":0,"valid_exact":0,"recovery":0,"suspicious":1}'

duplicate_name="$(jq '.assets[1].name = .assets[0].name' <<<"${orphan}")"
assert_counts "[[${duplicate_name}]]" \
  '{"exact":0,"valid_exact":0,"recovery":0,"suspicious":1}'

starter="$(jq '
  .assets[0].state = "starter" |
  .assets[0].size = 0 |
  .assets[0].digest = null
' <<<"${orphan}")"
assert_counts "[[${starter}]]" \
  '{"exact":0,"valid_exact":0,"recovery":1,"suspicious":1}'

wrong_body="$(jq '.body = "changed"' <<<"${orphan}")"
assert_counts "[[${wrong_body}]]" \
  '{"exact":0,"valid_exact":0,"recovery":0,"suspicious":1}'

malformed_orphan="$(jq '.tag_name = "untagged-not-a-release-id"' <<<"${orphan}")"
assert_counts "[[${malformed_orphan}]]" \
  '{"exact":0,"valid_exact":0,"recovery":0,"suspicious":1}'

published_exact="$(jq '.draft = false | .published_at = "2026-08-21T00:00:00Z"' <<<"${exact}")"
assert_counts "[[${published_exact}]]" \
  '{"exact":1,"valid_exact":0,"recovery":0,"suspicious":0}'

unrelated="$(jq '
  .id = 1 |
  .name = "unrelated" |
  .body = "unrelated" |
  .assets = []
' <<<"${orphan}")"
assert_counts "[[${unrelated}]]" \
  '{"exact":0,"valid_exact":0,"recovery":0,"suspicious":0}'

prior_release="$(jq '
  .id = 2 |
  .tag_name = "v0.0.1" |
  .name = "prior release" |
  .body = "prior notes" |
  .assets = [.assets[] | select(.name == "SHA256SUMS")]
' <<<"${orphan}")"
assert_counts "[[${prior_release}]]" \
  '{"exact":0,"valid_exact":0,"recovery":0,"suspicious":0}'

related_prior_release="$(jq '
  .id = 3 |
  .tag_name = "v0.0.2" |
  .name = "prior release" |
  .body = "prior notes" |
  .assets = [.assets[] | select(.name | endswith(".zip"))]
' <<<"${orphan}")"
assert_counts "[[${related_prior_release}]]" \
  '{"exact":0,"valid_exact":0,"recovery":0,"suspicious":1}'

if classify <<<'{}' >/dev/null 2>&1; then
  echo "malformed release pages were accepted"
  exit 1
fi

echo "release candidate fixtures passed"

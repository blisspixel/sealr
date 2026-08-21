def positive_id:
  type == "number" and . > 0;

def allowed_name($allowed):
  . as $candidate |
  any($allowed[]; . == $candidate);

def valid_asset($allowed):
  (.id | positive_id) and
  (.name | type == "string") and
  (.name | allowed_name($allowed)) and
  .uploader.login == "github-actions[bot]" and
  (
    (
      .state == "uploaded" and
      .size > 0 and
      (.digest | type == "string" and test("^sha256:[0-9a-f]{64}$"))
    ) or
    .state == "starter"
  );

def valid_assets($allowed):
  (.assets | type == "array") and
  (.assets | length) <= 4 and
  ([.assets[].id] | length) == ([.assets[].id] | unique | length) and
  ([.assets[].name] | length) == ([.assets[].name] | unique | length) and
  all(.assets[]; valid_asset($allowed));

def full_contract($allowed; $name; $notes):
  (.id | positive_id) and
  .draft == true and
  .prerelease == true and
  .immutable == false and
  .published_at == null and
  .author.login == "github-actions[bot]" and
  .name == $name and
  .body == $notes and
  valid_assets($allowed);

def orphan_name:
  .tag_name |
  type == "string" and test("^untagged-[0-9a-f]{20}$");

if (
  type != "array" or
  any(.[]; type != "array") or
  ($allowed | type != "array") or
  ($allowed | length) != 4 or
  ($allowed | length) != ($allowed | unique | length) or
  any($allowed[]; type != "string")
) then
  error("invalid release pages or allowed asset set")
else
  {
    exact: [
      .[][] |
      select(.tag_name == $tag)
    ],
    valid_exact: [
      .[][] |
      select(
        .tag_name == $tag and
        full_contract($allowed; $name; $notes)
      )
    ],
    recovery: [
      .[][] |
      select(
        orphan_name and
        full_contract($allowed; $name; $notes)
      )
    ],
    suspicious: [
      .[][] |
      select(
        .tag_name != $tag and
        (
          .name == $name or
          .body == $notes or
          any(
            .assets[]?;
            .name != "SHA256SUMS" and
            (.name | allowed_name($allowed))
          )
        )
      )
    ]
  }
end

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{
    CoreMetadata, EntryPoint, EvaluationStage, WheelFilename, WheelFinding, WheelHeaders,
    WheelLimits,
};

pub fn normalize_distribution(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut separator = false;
    for character in value.chars() {
        if matches!(character, '-' | '_' | '.') {
            separator = true;
        } else {
            if separator && !out.is_empty() {
                out.push('-');
            }
            separator = false;
            out.extend(character.to_lowercase());
        }
    }
    out
}

pub fn normalize_version(value: &str) -> Result<String, WheelFinding> {
    if value.is_empty()
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"._+!".contains(&byte)))
    {
        return Err(WheelFinding::new(
            EvaluationStage::Filename,
            "wheel.version-unsupported",
            "version is outside the bounded research PEP 440 subset",
        ));
    }
    let lower = value.to_ascii_lowercase().replace('_', ".");
    let lower = lower
        .replace("alpha", "a")
        .replace("beta", "b")
        .replace("preview", "rc")
        .replace("pre", "rc");
    let mut out = String::with_capacity(lower.len());
    let mut numeric = String::new();
    for character in lower.chars() {
        if character.is_ascii_digit() {
            numeric.push(character);
            continue;
        }
        flush_numeric(&mut out, &mut numeric);
        out.push(character);
    }
    flush_numeric(&mut out, &mut numeric);
    Ok(out)
}

fn flush_numeric(out: &mut String, numeric: &mut String) {
    if numeric.is_empty() {
        return;
    }
    let trimmed = numeric.trim_start_matches('0');
    out.push_str(if trimmed.is_empty() { "0" } else { trimmed });
    numeric.clear();
}

pub fn parse_wheel_filename(raw: &str, limits: WheelLimits) -> Result<WheelFilename, WheelFinding> {
    if raw.len() as u64 > limits.max_filename_bytes
        || raw.is_empty()
        || !raw.is_ascii()
        || raw.contains(['/', '\\', '\0'])
    {
        return Err(WheelFinding::new(
            EvaluationStage::Filename,
            "wheel.filename-boundary",
            "outer wheel filename is unsafe, non-ASCII, or exceeds its byte cap",
        ));
    }
    let body = raw.strip_suffix(".whl").ok_or_else(|| {
        WheelFinding::new(
            EvaluationStage::Filename,
            "wheel.filename-suffix",
            "outer filename does not end in .whl",
        )
    })?;
    let parts: Vec<&str> = body.split('-').collect();
    if !matches!(parts.len(), 5 | 6) || parts.iter().any(|part| part.is_empty()) {
        return Err(WheelFinding::new(
            EvaluationStage::Filename,
            "wheel.filename-fields",
            "outer filename must contain five fields plus an optional build field",
        ));
    }
    let distribution = parts[0];
    let version = parts[1];
    let (build, python_tag, abi_tag, platform_tag) = if parts.len() == 6 {
        (Some(parts[2]), parts[3], parts[4], parts[5])
    } else {
        (None, parts[2], parts[3], parts[4])
    };
    validate_filename_component(distribution, "distribution", b"._")?;
    validate_filename_component(version, "version", b"._+!")?;
    if let Some(build) = build {
        if !build.as_bytes()[0].is_ascii_digit() {
            return Err(WheelFinding::new(
                EvaluationStage::Filename,
                "wheel.build-tag",
                "build tag must begin with an ASCII digit",
            ));
        }
        validate_filename_component(build, "build", b"_")?;
    }
    let expanded_tags = expand_tag_triple(python_tag, abi_tag, platform_tag, limits)?;
    let normalized_distribution = normalize_distribution(distribution);
    if normalized_distribution.is_empty() {
        return Err(WheelFinding::new(
            EvaluationStage::Filename,
            "wheel.distribution-empty",
            "normalized distribution is empty",
        ));
    }
    Ok(WheelFilename {
        raw: raw.to_owned(),
        distribution: distribution.to_owned(),
        version: version.to_owned(),
        build: build.map(str::to_owned),
        python_tag: python_tag.to_owned(),
        abi_tag: abi_tag.to_owned(),
        platform_tag: platform_tag.to_owned(),
        normalized_distribution,
        normalized_version: normalize_version(version)?,
        expanded_tags,
    })
}

fn validate_filename_component(
    value: &str,
    label: &str,
    punctuation: &[u8],
) -> Result<(), WheelFinding> {
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || punctuation.contains(&byte))
    {
        Ok(())
    } else {
        Err(WheelFinding::new(
            EvaluationStage::Filename,
            format!("wheel.filename-{label}"),
            format!("{label} contains a character outside the wheel filename grammar"),
        ))
    }
}

fn expand_tag_triple(
    python: &str,
    abi: &str,
    platform: &str,
    limits: WheelLimits,
) -> Result<Vec<String>, WheelFinding> {
    let python = tag_parts(python, "Python")?;
    let abi = tag_parts(abi, "ABI")?;
    let platform = tag_parts(platform, "platform")?;
    let count = python
        .len()
        .checked_mul(abi.len())
        .and_then(|count| count.checked_mul(platform.len()))
        .ok_or_else(|| tag_limit_finding(limits.max_expanded_tags))?;
    if count as u64 > limits.max_expanded_tags {
        return Err(tag_limit_finding(limits.max_expanded_tags));
    }
    let mut tags = Vec::new();
    tags.try_reserve_exact(count).map_err(|error| {
        WheelFinding::new(
            EvaluationStage::Filename,
            "wheel.allocation",
            error.to_string(),
        )
    })?;
    for python in &python {
        for abi in &abi {
            for platform in &platform {
                tags.push(format!("{python}-{abi}-{platform}"));
            }
        }
    }
    Ok(tags)
}

fn tag_parts<'a>(value: &'a str, label: &str) -> Result<Vec<&'a str>, WheelFinding> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.is_empty()
        || parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
    {
        return Err(WheelFinding::new(
            EvaluationStage::Filename,
            "wheel.tag-grammar",
            format!("{label} tag is outside the bounded wheel tag grammar"),
        ));
    }
    Ok(parts)
}

fn tag_limit_finding(limit: u64) -> WheelFinding {
    WheelFinding::new(
        EvaluationStage::Filename,
        "wheel.tag-expansion-limit",
        format!("expanded tag count exceeds {limit}"),
    )
}

pub(crate) fn parse_wheel_headers(
    raw: &[u8],
    limits: WheelLimits,
) -> Result<WheelHeaders, WheelFinding> {
    let fields = parse_headers(raw, EvaluationStage::WheelMetadata, limits)?;
    let wheel_version = exactly_one(&fields, "Wheel-Version", EvaluationStage::WheelMetadata)?;
    if wheel_version != "1.0" {
        let greater_major = wheel_version
            .split_once('.')
            .and_then(|(major, minor)| {
                (!major.is_empty()
                    && !minor.is_empty()
                    && major.bytes().all(|byte| byte.is_ascii_digit())
                    && minor.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| major.parse::<u64>().ok())
                .flatten()
            })
            .is_some_and(|major| major > 1);
        let code = if greater_major {
            "wheel.version-unsupported"
        } else {
            "wheel.version-invalid"
        };
        return Err(WheelFinding::new(
            EvaluationStage::WheelMetadata,
            code,
            format!("Wheel-Version {wheel_version:?} is not supported"),
        ));
    }
    let root = exactly_one(&fields, "Root-Is-Purelib", EvaluationStage::WheelMetadata)?;
    let root_is_purelib = match root.as_str() {
        "true" => true,
        "false" => false,
        _ => {
            return Err(WheelFinding::new(
                EvaluationStage::WheelMetadata,
                "wheel.root-is-purelib",
                "Root-Is-Purelib must be exactly true or false",
            ));
        }
    };
    let tags = fields.get("Tag").cloned().unwrap_or_default();
    if tags.is_empty() {
        return Err(WheelFinding::new(
            EvaluationStage::WheelMetadata,
            "wheel.tag-missing",
            "WHEEL has no Tag field",
        ));
    }
    let mut expanded = BTreeSet::new();
    for tag in tags {
        let components: Vec<&str> = tag.split('-').collect();
        if components.len() != 3 {
            return Err(WheelFinding::new(
                EvaluationStage::WheelMetadata,
                "wheel.tag-invalid",
                "WHEEL Tag must have three components",
            ));
        }
        for value in expand_tag_triple(components[0], components[1], components[2], limits)? {
            if !expanded.insert(value) {
                return Err(WheelFinding::new(
                    EvaluationStage::WheelMetadata,
                    "wheel.tag-duplicate",
                    "WHEEL Tag fields expand to a duplicate tag",
                ));
            }
            if expanded.len() as u64 > limits.max_expanded_tags {
                return Err(tag_limit_finding(limits.max_expanded_tags));
            }
        }
    }
    Ok(WheelHeaders {
        wheel_version,
        generator: optional_one(&fields, "Generator", EvaluationStage::WheelMetadata)?,
        root_is_purelib,
        build: optional_one(&fields, "Build", EvaluationStage::WheelMetadata)?,
        tags: expanded.into_iter().collect(),
    })
}

pub(crate) fn parse_core_metadata(
    raw: &[u8],
    limits: WheelLimits,
) -> Result<CoreMetadata, WheelFinding> {
    let fields = parse_headers(raw, EvaluationStage::CoreMetadata, limits)?;
    let metadata_version = exactly_one(&fields, "Metadata-Version", EvaluationStage::CoreMetadata)?;
    if !matches!(metadata_version.as_str(), "2.1" | "2.2" | "2.3" | "2.4") {
        return Err(WheelFinding::new(
            EvaluationStage::CoreMetadata,
            "wheel.metadata-version-unsupported",
            format!("Core Metadata version {metadata_version:?} is not supported"),
        ));
    }
    let name = exactly_one(&fields, "Name", EvaluationStage::CoreMetadata)?;
    let version = exactly_one(&fields, "Version", EvaluationStage::CoreMetadata)?;
    let normalized_name = normalize_distribution(&name);
    let normalized_version = normalize_version(&version).map_err(|mut finding| {
        finding.stage = EvaluationStage::CoreMetadata;
        finding.code = "wheel.metadata-version-grammar".into();
        finding
    })?;
    Ok(CoreMetadata {
        metadata_version,
        name,
        version,
        normalized_name,
        normalized_version,
    })
}

fn parse_headers(
    raw: &[u8],
    stage: EvaluationStage,
    limits: WheelLimits,
) -> Result<BTreeMap<String, Vec<String>>, WheelFinding> {
    if raw.contains(&0) {
        return Err(WheelFinding::new(
            stage,
            "wheel.header-nul",
            "metadata contains NUL",
        ));
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| WheelFinding::new(stage, "wheel.header-utf8", "metadata is not UTF-8"))?;
    let mut fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut last: Option<(String, usize)> = None;
    let mut line_count = 0_u64;
    for line in split_lines(text, stage)? {
        line_count = line_count.checked_add(1).ok_or_else(|| {
            WheelFinding::new(
                stage,
                "wheel.header-line-overflow",
                "metadata line count overflowed",
            )
        })?;
        if line_count > limits.max_header_lines || line.len() as u64 > limits.max_header_line_bytes
        {
            return Err(WheelFinding::new(
                stage,
                "wheel.header-limit",
                "metadata line count or line length exceeds its cap",
            ));
        }
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            let (name, index) = last.as_ref().ok_or_else(|| {
                WheelFinding::new(
                    stage,
                    "wheel.header-continuation",
                    "orphan header continuation",
                )
            })?;
            let value = fields
                .get_mut(name)
                .and_then(|values| values.get_mut(*index))
                .ok_or_else(|| {
                    WheelFinding::new(
                        stage,
                        "wheel.header-state",
                        "header continuation state is invalid",
                    )
                })?;
            value.push('\n');
            value.push_str(line.trim_start_matches([' ', '\t']));
            continue;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            WheelFinding::new(stage, "wheel.header-syntax", "metadata line lacks a colon")
        })?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(WheelFinding::new(
                stage,
                "wheel.header-name",
                "invalid metadata field name",
            ));
        }
        let value = value.strip_prefix(' ').unwrap_or(value).to_owned();
        let values = fields.entry(name.to_owned()).or_default();
        let index = values.len();
        values.push(value);
        last = Some((name.to_owned(), index));
    }
    Ok(fields)
}

fn split_lines(text: &str, stage: EvaluationStage) -> Result<Vec<&str>, WheelFinding> {
    let bytes = text.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\n' => {
                lines.push(&text[start..index]);
                start = index + 1;
            }
            b'\r' => {
                if bytes.get(index + 1) != Some(&b'\n') {
                    return Err(WheelFinding::new(
                        stage,
                        "wheel.header-bare-cr",
                        "metadata contains a bare carriage return",
                    ));
                }
                lines.push(&text[start..index]);
                index += 1;
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    Ok(lines)
}

fn exactly_one(
    fields: &BTreeMap<String, Vec<String>>,
    name: &str,
    stage: EvaluationStage,
) -> Result<String, WheelFinding> {
    match fields.get(name).map(Vec::as_slice) {
        Some([value]) => Ok(value.clone()),
        Some(_) => Err(WheelFinding::new(
            stage,
            "wheel.header-duplicate",
            format!("metadata field {name} is duplicated"),
        )),
        None => Err(WheelFinding::new(
            stage,
            "wheel.header-missing",
            format!("metadata field {name} is missing"),
        )),
    }
}

fn optional_one(
    fields: &BTreeMap<String, Vec<String>>,
    name: &str,
    stage: EvaluationStage,
) -> Result<Option<String>, WheelFinding> {
    match fields.get(name).map(Vec::as_slice) {
        Some([value]) => Ok(Some(value.clone())),
        Some(_) => Err(WheelFinding::new(
            stage,
            "wheel.header-duplicate",
            format!("metadata field {name} is duplicated"),
        )),
        None => Ok(None),
    }
}

pub(crate) fn parse_record_rows(
    raw: &[u8],
    limits: WheelLimits,
) -> Result<Vec<[String; 3]>, WheelFinding> {
    if raw.len() as u64 > limits.max_record_bytes {
        return Err(WheelFinding::new(
            EvaluationStage::Record,
            "wheel.record-size-limit",
            "RECORD exceeds its byte cap",
        ));
    }
    let mut rows = Vec::new();
    let mut fields = Vec::new();
    let mut field = Vec::new();
    let mut in_quotes = false;
    let mut quoted = false;
    let mut after_quote = false;
    let mut row_bytes = 0_u64;
    let mut index = 0;
    while index < raw.len() {
        let byte = raw[index];
        row_bytes = row_bytes
            .checked_add(1)
            .ok_or_else(|| record_limit("RECORD row length overflowed"))?;
        if row_bytes > limits.max_record_row_bytes {
            return Err(record_limit("RECORD row exceeds its byte cap"));
        }
        if in_quotes {
            if byte == b'"' {
                if raw.get(index + 1) == Some(&b'"') {
                    field.push(b'"');
                    index += 1;
                    row_bytes += 1;
                } else {
                    in_quotes = false;
                    after_quote = true;
                }
            } else {
                field.push(byte);
            }
            index += 1;
            continue;
        }
        if after_quote && !matches!(byte, b',' | b'\r' | b'\n') {
            return Err(record_syntax("characters follow a closing CSV quote"));
        }
        match byte {
            b'"' if field.is_empty() && !quoted => {
                in_quotes = true;
                quoted = true;
            }
            b'"' => return Err(record_syntax("quote appears inside an unquoted CSV field")),
            b',' => {
                push_record_field(&mut fields, &mut field)?;
                quoted = false;
                after_quote = false;
            }
            b'\n' => {
                push_record_field(&mut fields, &mut field)?;
                push_record_row(&mut rows, &mut fields, limits)?;
                quoted = false;
                after_quote = false;
                row_bytes = 0;
            }
            b'\r' => {
                if raw.get(index + 1) != Some(&b'\n') {
                    return Err(record_syntax("RECORD contains a bare carriage return"));
                }
                push_record_field(&mut fields, &mut field)?;
                push_record_row(&mut rows, &mut fields, limits)?;
                index += 1;
                quoted = false;
                after_quote = false;
                row_bytes = 0;
            }
            _ => field.push(byte),
        }
        index += 1;
    }
    if in_quotes {
        return Err(record_syntax("RECORD ends inside a quoted field"));
    }
    if !field.is_empty() || !fields.is_empty() || quoted {
        push_record_field(&mut fields, &mut field)?;
        push_record_row(&mut rows, &mut fields, limits)?;
    }
    Ok(rows)
}

fn push_record_field(fields: &mut Vec<String>, field: &mut Vec<u8>) -> Result<(), WheelFinding> {
    let bytes = std::mem::take(field);
    let value =
        String::from_utf8(bytes).map_err(|_| record_syntax("RECORD field is not valid UTF-8"))?;
    fields.push(value);
    Ok(())
}

fn push_record_row(
    rows: &mut Vec<[String; 3]>,
    fields: &mut Vec<String>,
    limits: WheelLimits,
) -> Result<(), WheelFinding> {
    if fields.len() != 3 {
        return Err(record_syntax(
            "RECORD row must contain exactly three fields",
        ));
    }
    if rows.len() as u64 >= limits.max_record_rows {
        return Err(record_limit("RECORD row count exceeds its cap"));
    }
    let mut taken = std::mem::take(fields).into_iter();
    rows.push([
        taken.next().unwrap(),
        taken.next().unwrap(),
        taken.next().unwrap(),
    ]);
    Ok(())
}

fn record_syntax(detail: &str) -> WheelFinding {
    WheelFinding::new(EvaluationStage::Record, "wheel.record-csv", detail)
}

fn record_limit(detail: &str) -> WheelFinding {
    WheelFinding::new(EvaluationStage::Record, "wheel.record-limit", detail)
}

pub(crate) fn decode_sha256_record(value: &str) -> Result<String, WheelFinding> {
    let encoded = value.strip_prefix("sha256=").ok_or_else(|| {
        WheelFinding::new(
            EvaluationStage::Record,
            "wheel.record-hash-unsupported",
            "research profile supports only sha256 RECORD hashes",
        )
    })?;
    if encoded.contains('=') {
        return Err(record_syntax(
            "RECORD hash must use unpadded URL-safe base64",
        ));
    }
    let mut decoded = Vec::new();
    let mut bits = 0_u32;
    let mut bit_count = 0_u8;
    for byte in encoded.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(record_syntax("RECORD hash is not URL-safe base64")),
        };
        bits = (bits << 6) | u32::from(value);
        bit_count += 6;
        while bit_count >= 8 {
            bit_count -= 8;
            decoded.push(((bits >> bit_count) & 0xff) as u8);
        }
    }
    if decoded.len() != 32 || (bit_count != 0 && bits & ((1 << bit_count) - 1) != 0) {
        return Err(record_syntax(
            "RECORD sha256 hash has a non-canonical length",
        ));
    }
    Ok(decoded.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(crate) fn parse_entry_points(
    raw: &[u8],
    limits: WheelLimits,
) -> Result<Vec<EntryPoint>, WheelFinding> {
    if raw.len() as u64 > limits.max_entry_points_bytes {
        return Err(WheelFinding::new(
            EvaluationStage::EntryPoints,
            "wheel.entry-points-size-limit",
            "entry_points.txt exceeds its byte cap",
        ));
    }
    let text = std::str::from_utf8(raw).map_err(|_| {
        WheelFinding::new(
            EvaluationStage::EntryPoints,
            "wheel.entry-points-utf8",
            "entry_points.txt is not UTF-8",
        )
    })?;
    let mut group: Option<String> = None;
    let mut points = Vec::new();
    let mut seen = BTreeSet::new();
    for line in split_lines(text, EvaluationStage::EntryPoints)? {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let name = &line[1..line.len() - 1];
            if !matches!(name, "console_scripts" | "gui_scripts") {
                group = None;
            } else {
                group = Some(name.to_owned());
            }
            continue;
        }
        let Some(group) = group.as_ref() else {
            continue;
        };
        let (name, object) = line.split_once('=').ok_or_else(|| {
            WheelFinding::new(
                EvaluationStage::EntryPoints,
                "wheel.entry-point-syntax",
                "entry point line lacks =",
            )
        })?;
        let name = name.trim();
        let object = object.trim();
        validate_command_name(name)?;
        if object.is_empty() || object.contains(['\0', '\r', '\n', '=']) || !object.contains(':') {
            return Err(WheelFinding::new(
                EvaluationStage::EntryPoints,
                "wheel.entry-point-object",
                "entry point object reference is outside the bounded grammar",
            ));
        }
        if !seen.insert((group.clone(), name.to_owned())) {
            return Err(WheelFinding::new(
                EvaluationStage::EntryPoints,
                "wheel.entry-point-duplicate",
                "entry point name is duplicated within its group",
            ));
        }
        points.push(EntryPoint {
            group: group.clone(),
            name: name.to_owned(),
            object: object.to_owned(),
        });
    }
    points.sort_by(|left, right| {
        (&left.group, &left.name, &left.object).cmp(&(&right.group, &right.name, &right.object))
    });
    Ok(points)
}

fn validate_command_name(name: &str) -> Result<(), WheelFinding> {
    let upper = name.to_ascii_uppercase();
    let reserved = matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4
            && matches!(&upper[..3], "COM" | "LPT")
            && matches!(upper.as_bytes()[3], b'1'..=b'9'));
    if name.is_empty()
        || matches!(name, "." | "..")
        || name.ends_with(['.', ' '])
        || reserved
        || name.chars().any(|character| {
            character.is_control() || character.is_whitespace() || "<>:\"/\\|?*".contains(character)
        })
    {
        return Err(WheelFinding::new(
            EvaluationStage::EntryPoints,
            "wheel.generated-target-name",
            "entry point would generate an unsafe portable command name",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_tags_expand_with_a_checked_product() {
        let parsed =
            parse_wheel_filename("demo-1.0-py2.py3-none-any.whl", WheelLimits::default()).unwrap();
        assert_eq!(parsed.expanded_tags, ["py2-none-any", "py3-none-any"]);
    }

    #[test]
    fn csv_supports_quotes_and_rejects_noncanonical_rows() {
        let rows = parse_record_rows(b"\"a,b\",sha256=AA,3\r\n", WheelLimits::default()).unwrap();
        assert_eq!(rows[0][0], "a,b");
        assert!(parse_record_rows(b"a,b\n", WheelLimits::default()).is_err());
        assert!(parse_record_rows(b"a,\"b\"x,3\n", WheelLimits::default()).is_err());
    }
}

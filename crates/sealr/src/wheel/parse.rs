use std::collections::{BTreeMap, BTreeSet};

use crate::jail::{jail_name_fallible_for_profile, portable_name_violation, JailNameError};
use crate::wheel::model::{
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

/// Normalize the consumer profile's complete supported PEP 440 subset.
///
/// The accepted syntax is the canonical public-version structure, matched
/// case-insensitively: `[N!]N(.N)*[{a|b|rc}N][.postN][.devN][+L(.L)*]`.
/// Numeric components are normalized as integers, an epoch of zero is omitted,
/// and local segments are lowercased. Local segments contain only ASCII letters
/// and digits. PEP 440's legacy spellings, alternate separators, leading `v`,
/// and implicit pre/post/dev numerals are well-formed but intentionally outside
/// this bounded subset.
pub fn normalize_version(value: &str) -> Result<String, WheelFinding> {
    if let Some(normalized) = canonicalize_supported_version(value) {
        return Ok(normalized);
    }
    if is_well_formed_legacy_pep440(value) {
        return Err(WheelFinding::new(
            EvaluationStage::Filename,
            "wheel.version-unsupported",
            "version is valid PEP 440 but outside the supported canonical-syntax subset",
        ));
    }
    Err(WheelFinding::new(
        EvaluationStage::Filename,
        "wheel.version-invalid",
        "version is not well-formed PEP 440",
    ))
}

fn canonicalize_supported_version(value: &str) -> Option<String> {
    if value.is_empty() || !value.is_ascii() {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut position = 0;
    let mut normalized = String::with_capacity(value.len());

    if let Some(epoch_end) = bytes.iter().position(|byte| *byte == b'!') {
        let epoch = bytes.get(..epoch_end)?;
        if epoch.is_empty()
            || !epoch.iter().all(u8::is_ascii_digit)
            || bytes[epoch_end + 1..].contains(&b'!')
        {
            return None;
        }
        let epoch = normalized_digits(epoch);
        if epoch != "0" {
            normalized.push_str(epoch);
            normalized.push('!');
        }
        position = epoch_end + 1;
    }

    let release = take_digits(bytes, &mut position)?;
    normalized.push_str(normalized_digits(release));
    while bytes.get(position) == Some(&b'.')
        && bytes.get(position + 1).is_some_and(u8::is_ascii_digit)
    {
        position += 1;
        let component = take_digits(bytes, &mut position)?;
        normalized.push('.');
        normalized.push_str(normalized_digits(component));
    }

    let pre_label = ["rc", "a", "b"]
        .into_iter()
        .find(|label| lower[position..].starts_with(label));
    if let Some(label) = pre_label {
        position += label.len();
        let number = take_digits(bytes, &mut position)?;
        normalized.push_str(label);
        normalized.push_str(normalized_digits(number));
    }

    if lower[position..].starts_with(".post") {
        position += ".post".len();
        let number = take_digits(bytes, &mut position)?;
        normalized.push_str(".post");
        normalized.push_str(normalized_digits(number));
    }
    if lower[position..].starts_with(".dev") {
        position += ".dev".len();
        let number = take_digits(bytes, &mut position)?;
        normalized.push_str(".dev");
        normalized.push_str(normalized_digits(number));
    }

    if bytes.get(position) == Some(&b'+') {
        position += 1;
        normalized.push('+');
        let mut first = true;
        loop {
            let start = position;
            while bytes.get(position).is_some_and(u8::is_ascii_alphanumeric) {
                position += 1;
            }
            let segment = bytes.get(start..position)?;
            if segment.is_empty() {
                return None;
            }
            if !first {
                normalized.push('.');
            }
            if segment.iter().all(u8::is_ascii_digit) {
                normalized.push_str(normalized_digits(segment));
            } else {
                normalized.push_str(std::str::from_utf8(segment).ok()?);
            }
            first = false;
            if bytes.get(position) != Some(&b'.') {
                break;
            }
            position += 1;
        }
    }

    (position == bytes.len()).then_some(normalized)
}

fn take_digits<'a>(bytes: &'a [u8], position: &mut usize) -> Option<&'a [u8]> {
    let start = *position;
    while bytes.get(*position).is_some_and(u8::is_ascii_digit) {
        *position += 1;
    }
    (*position > start).then(|| &bytes[start..*position])
}

fn normalized_digits(digits: &[u8]) -> &str {
    let first_nonzero = digits
        .iter()
        .position(|byte| *byte != b'0')
        .unwrap_or(digits.len().saturating_sub(1));
    std::str::from_utf8(&digits[first_nonzero..]).expect("ASCII digits are valid UTF-8")
}

fn is_well_formed_legacy_pep440(value: &str) -> bool {
    value.parse::<pep440_rs::Version>().is_ok()
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
    if !valid_project_name(distribution) {
        return Err(WheelFinding::new(
            EvaluationStage::Filename,
            "wheel.distribution-grammar",
            "filename distribution must satisfy the ASCII project-name grammar",
        ));
    }
    validate_filename_component(version, "version", b"._+!")?;
    if let Some(build) = build {
        if !build.as_bytes()[0].is_ascii_digit()
            || !build.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(WheelFinding::new(
                EvaluationStage::Filename,
                "wheel.build-tag",
                "build tag must match [0-9][0-9A-Za-z]*",
            ));
        }
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
        let well_formed = wheel_version
            .split_once('.')
            .and_then(|(major, minor)| {
                (!major.is_empty()
                    && !minor.is_empty()
                    && major.bytes().all(|byte| byte.is_ascii_digit())
                    && minor.bytes().all(|byte| byte.is_ascii_digit()))
                .then_some(())
            })
            .is_some();
        let code = if well_formed {
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
    let tags = fields.get("tag").cloned().unwrap_or_default();
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
    if !valid_project_name(&name) {
        return Err(WheelFinding::new(
            EvaluationStage::CoreMetadata,
            "wheel.metadata-name-grammar",
            "Core Metadata Name is outside the required ASCII project-name grammar",
        ));
    }
    let normalized_name = normalize_distribution(&name);
    let normalized_version = normalize_version(&version).map_err(|mut finding| {
        finding.stage = EvaluationStage::CoreMetadata;
        finding.code = if finding.code == "wheel.version-unsupported" {
            "wheel.metadata-version-unsupported"
        } else {
            "wheel.metadata-version-grammar"
        }
        .into();
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

fn valid_project_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn parse_headers(
    raw: &[u8],
    stage: EvaluationStage,
    limits: WheelLimits,
) -> Result<BTreeMap<String, Vec<String>>, WheelFinding> {
    let byte_limit = match stage {
        EvaluationStage::WheelMetadata => limits.max_wheel_bytes,
        EvaluationStage::CoreMetadata => limits.max_metadata_bytes,
        _ => limits.max_metadata_bytes,
    };
    if raw.len() as u64 > byte_limit {
        return Err(WheelFinding::new(
            stage,
            "wheel.header-limit",
            "metadata byte length exceeds its cap",
        ));
    }
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
    for (line_count, line) in split_lines(text, stage)?.enumerate() {
        let line = line?;
        let line_count = u64::try_from(line_count).map_err(|_| {
            WheelFinding::new(
                stage,
                "wheel.header-limit",
                "metadata line count exceeds its cap",
            )
        })?;
        if line_count >= limits.max_header_lines || line.len() as u64 > limits.max_header_line_bytes
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
        let name = name.to_ascii_lowercase();
        let value = value.strip_prefix(' ').unwrap_or(value).to_owned();
        let values = fields.entry(name.clone()).or_default();
        let index = values.len();
        values.push(value);
        last = Some((name, index));
    }
    Ok(fields)
}

fn split_lines(text: &str, stage: EvaluationStage) -> Result<BoundedLines<'_>, WheelFinding> {
    Ok(BoundedLines {
        text,
        position: 0,
        stage,
    })
}

struct BoundedLines<'a> {
    text: &'a str,
    position: usize,
    stage: EvaluationStage,
}

impl<'a> Iterator for BoundedLines<'a> {
    type Item = Result<&'a str, WheelFinding>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.text.len() {
            return None;
        }
        let bytes = self.text.as_bytes();
        let start = self.position;
        while self.position < bytes.len() {
            match bytes[self.position] {
                b'\n' => {
                    let end = self.position;
                    self.position += 1;
                    return Some(Ok(&self.text[start..end]));
                }
                b'\r' if bytes.get(self.position + 1) == Some(&b'\n') => {
                    let end = self.position;
                    self.position += 2;
                    return Some(Ok(&self.text[start..end]));
                }
                b'\r' => {
                    self.position = bytes.len();
                    return Some(Err(WheelFinding::new(
                        self.stage,
                        "wheel.header-bare-cr",
                        "metadata contains a bare carriage return",
                    )));
                }
                _ => self.position += 1,
            }
        }
        Some(Ok(&self.text[start..]))
    }
}

fn exactly_one(
    fields: &BTreeMap<String, Vec<String>>,
    name: &str,
    stage: EvaluationStage,
) -> Result<String, WheelFinding> {
    match fields
        .get(name.to_ascii_lowercase().as_str())
        .map(Vec::as_slice)
    {
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
    match fields
        .get(name.to_ascii_lowercase().as_str())
        .map(Vec::as_slice)
    {
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
                let crlf_row_bytes = row_bytes
                    .checked_add(1)
                    .ok_or_else(|| record_limit("RECORD row length overflowed"))?;
                if crlf_row_bytes > limits.max_record_row_bytes {
                    return Err(record_limit("RECORD row exceeds its byte cap"));
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
            "consumer profile supports only sha256 RECORD hashes",
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
        let line = line?;
        let line = line.trim_ascii();
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
        let name = name.trim_ascii();
        let object = object.trim_ascii();
        validate_command_name(name)?;
        validate_entry_point_object(object)?;
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

fn validate_entry_point_object(object: &str) -> Result<(), WheelFinding> {
    let invalid = || {
        WheelFinding::new(
            EvaluationStage::EntryPoints,
            "wheel.entry-point-object",
            "entry point object must be module:attribute with optional legacy extras",
        )
    };
    if object.is_empty() || object.contains(['\0', '\r', '\n', '=']) {
        return Err(invalid());
    }

    let (reference, extras) = if object.ends_with(']') {
        let open = object.rfind('[').ok_or_else(&invalid)?;
        let reference = object[..open].trim_ascii_end();
        let extras = &object[open + 1..object.len() - 1];
        if reference.contains(['[', ']']) || extras.contains(['[', ']']) {
            return Err(invalid());
        }
        (reference, Some(extras))
    } else {
        if object.contains(['[', ']']) {
            return Err(invalid());
        }
        (object, None)
    };

    let (module, attribute) = reference.split_once(':').ok_or_else(&invalid)?;
    if attribute.contains(':')
        || !valid_dotted_python_reference(module.trim_ascii())
        || !valid_dotted_python_reference(attribute.trim_ascii())
    {
        return Err(invalid());
    }

    if let Some(extras) = extras {
        let mut seen = BTreeSet::new();
        let mut count = 0_u64;
        for extra in extras.split(',') {
            let extra = extra.trim_ascii();
            count += 1;
            if !valid_project_name(extra) || !seen.insert(normalize_distribution(extra)) {
                return Err(invalid());
            }
        }
        if count == 0 || extras.trim_ascii().is_empty() {
            return Err(invalid());
        }
    }
    Ok(())
}

fn valid_dotted_python_reference(value: &str) -> bool {
    !value.is_empty() && value.split('.').all(valid_python_identifier)
}

fn valid_python_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn validate_command_name(name: &str) -> Result<(), WheelFinding> {
    let portable = match jail_name_fallible_for_profile(
        name,
        1,
        crate::ZipInterpretationProfile::PortableUtf8V1,
    ) {
        Ok(jailed) => Some(jailed),
        Err(JailNameError::Invalid { .. }) => None,
        Err(JailNameError::AllocationFailed) => {
            return Err(WheelFinding::new(
                EvaluationStage::EntryPoints,
                "wheel.allocation",
                "entry-point target validation allocation failed",
            ));
        }
    };
    let unsafe_name = portable.as_ref().is_none_or(|jailed| {
        jailed.components.len() != 1 || portable_name_violation(jailed).is_some()
    }) || name.bytes().any(|byte| byte.is_ascii_whitespace());
    if unsafe_name {
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
    fn build_tags_are_an_initial_digit_followed_by_ascii_alphanumerics() {
        for valid in ["1", "1abc", "9Z"] {
            parse_wheel_filename(
                &format!("demo-1.0-{valid}-py3-none-any.whl"),
                WheelLimits::default(),
            )
            .unwrap();
        }
        for invalid in ["a1", "1_bad", "1.bad", "1+bad", "1!bad"] {
            assert_eq!(
                parse_wheel_filename(
                    &format!("demo-1.0-{invalid}-py3-none-any.whl"),
                    WheelLimits::default(),
                )
                .unwrap_err()
                .code,
                "wheel.build-tag"
            );
        }
    }

    #[test]
    fn filename_distribution_requires_the_ascii_project_name_grammar() {
        for valid in ["demo", "Demo.Package", "demo_package"] {
            parse_wheel_filename(
                &format!("{valid}-1.0-py3-none-any.whl"),
                WheelLimits::default(),
            )
            .unwrap();
        }
        for invalid in [".demo", "demo.", "_demo", "demo_", "caf\u{e9}"] {
            assert!(parse_wheel_filename(
                &format!("{invalid}-1.0-py3-none-any.whl"),
                WheelLimits::default(),
            )
            .is_err());
        }
    }

    #[test]
    fn versions_enforce_the_documented_subset_and_classify_other_inputs() {
        for (raw, normalized) in [
            ("1.0", "1.0"),
            (
                "01.002RC03.post04.dev05+LOCAL.006",
                "1.2rc3.post4.dev5+local.6",
            ),
            ("0!1.0", "1.0"),
            ("2!01.0", "2!1.0"),
        ] {
            assert_eq!(normalize_version(raw).unwrap(), normalized);
        }
        for unsupported in ["v1.0", "1.0-alpha1", "1.0_post1", "1.0post", "1.0+local_1"] {
            assert_eq!(
                normalize_version(unsupported).unwrap_err().code,
                "wheel.version-unsupported"
            );
        }
        for malformed in ["", "release", "1..0", "1.0+", "1.0???", "1.0!"] {
            assert_eq!(
                normalize_version(malformed).unwrap_err().code,
                "wheel.version-invalid"
            );
        }
    }

    #[test]
    fn headers_are_streamed_under_limits_and_names_are_ascii_case_insensitive() {
        let metadata = b"mEtAdAtA-vErSiOn: 2.4\nnAmE: Demo._-Package\nvErSiOn: 1.0\n";
        let parsed = parse_core_metadata(metadata, WheelLimits::default()).unwrap();
        assert_eq!(parsed.name, "Demo._-Package");
        assert_eq!(parsed.normalized_name, "demo-package");

        let duplicate = b"Metadata-Version: 2.4\nName: demo\nnAmE: other\nVersion: 1.0\n";
        assert_eq!(
            parse_core_metadata(duplicate, WheelLimits::default())
                .unwrap_err()
                .code,
            "wheel.header-duplicate"
        );

        let line_limited = WheelLimits {
            max_header_lines: 2,
            ..WheelLimits::default()
        };
        assert_eq!(
            parse_core_metadata(metadata, line_limited)
                .unwrap_err()
                .code,
            "wheel.header-limit"
        );
        let length_limited = WheelLimits {
            max_header_line_bytes: 10,
            ..WheelLimits::default()
        };
        assert_eq!(
            parse_core_metadata(metadata, length_limited)
                .unwrap_err()
                .code,
            "wheel.header-limit"
        );
        let byte_limited = WheelLimits {
            max_metadata_bytes: metadata.len() as u64 - 1,
            ..WheelLimits::default()
        };
        assert_eq!(
            parse_core_metadata(metadata, byte_limited)
                .unwrap_err()
                .code,
            "wheel.header-limit"
        );
    }

    #[test]
    fn core_metadata_names_require_the_ascii_project_name_grammar() {
        for invalid in ["-demo", "demo-", ".", "two words", "demo/name", "caf\u{e9}"] {
            let metadata = format!("Metadata-Version: 2.4\nName: {invalid}\nVersion: 1.0\n");
            assert_eq!(
                parse_core_metadata(metadata.as_bytes(), WheelLimits::default())
                    .unwrap_err()
                    .code,
                "wheel.metadata-name-grammar"
            );
        }
    }

    #[test]
    fn metadata_versions_preserve_invalid_and_unsupported_classification() {
        let unsupported = b"Metadata-Version: 2.4\nName: demo\nVersion: v1.0\n";
        let finding = parse_core_metadata(unsupported, WheelLimits::default()).unwrap_err();
        assert_eq!(finding.stage, EvaluationStage::CoreMetadata);
        assert_eq!(finding.code, "wheel.metadata-version-unsupported");

        let malformed = b"Metadata-Version: 2.4\nName: demo\nVersion: 1..0\n";
        let finding = parse_core_metadata(malformed, WheelLimits::default()).unwrap_err();
        assert_eq!(finding.stage, EvaluationStage::CoreMetadata);
        assert_eq!(finding.code, "wheel.metadata-version-grammar");
    }

    #[test]
    fn future_wheel_versions_are_unsupported_not_malformed() {
        for version in ["1.1", "2.0", "12.34"] {
            let wheel =
                format!("Wheel-Version: {version}\nRoot-Is-Purelib: true\nTag: py3-none-any\n");
            assert_eq!(
                parse_wheel_headers(wheel.as_bytes(), WheelLimits::default())
                    .unwrap_err()
                    .code,
                "wheel.version-unsupported"
            );
        }
        for version in ["1", "1.", ".1", "v1.1"] {
            let wheel =
                format!("Wheel-Version: {version}\nRoot-Is-Purelib: true\nTag: py3-none-any\n");
            assert_eq!(
                parse_wheel_headers(wheel.as_bytes(), WheelLimits::default())
                    .unwrap_err()
                    .code,
                "wheel.version-invalid"
            );
        }
    }

    #[test]
    fn entry_point_objects_are_parsed_with_explicit_legacy_extras() {
        let parsed = parse_entry_points(
            b"[console_scripts]\ndemo = demo.cli:main.run\nlegacy = demo:main [fast, py_3]\n",
            WheelLimits::default(),
        )
        .unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].object, "demo:main [fast, py_3]");

        for invalid in [
            "demo",
            "demo:",
            ":main",
            "demo::main",
            "demo-main:main",
            "demo:main()",
            "demo:main garbage",
            "demo:main []",
            "demo:main [bad extra]",
            "demo:main [fast, FAST]",
            "demo:main [fast",
        ] {
            let contents = format!("[console_scripts]\ndemo = {invalid}\n");
            assert_eq!(
                parse_entry_points(contents.as_bytes(), WheelLimits::default())
                    .unwrap_err()
                    .code,
                "wheel.entry-point-object",
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn csv_supports_quotes_and_rejects_noncanonical_rows() {
        let rows = parse_record_rows(b"\"a,b\",sha256=AA,3\r\n", WheelLimits::default()).unwrap();
        assert_eq!(rows[0][0], "a,b");
        assert!(parse_record_rows(b"a,b\n", WheelLimits::default()).is_err());
        assert!(parse_record_rows(b"a,\"b\"x,3\n", WheelLimits::default()).is_err());

        let mut limits = WheelLimits {
            max_record_row_bytes: 7,
            ..WheelLimits::default()
        };
        assert!(parse_record_rows(b"a,b,c\r\n", limits).is_ok());
        limits.max_record_row_bytes = 6;
        assert!(parse_record_rows(b"a,b,c\r\n", limits).is_err());
    }

    #[test]
    fn generated_targets_share_the_portable_component_contract() {
        for unsafe_name in [
            "CON",
            "COM1",
            "COM\u{b9}",
            "LPT\u{b2}",
            "two words",
            "cafe\u{301}",
            &"x".repeat(256),
        ] {
            assert_eq!(
                validate_command_name(unsafe_name).unwrap_err().code,
                "wheel.generated-target-name"
            );
        }
        validate_command_name("caf\u{e9}").expect("NFC portable target");
    }
}

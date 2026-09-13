use sha2::{Digest, Sha256};

use crate::wheel::model::{
    CoreMetadata, EntryPoint, ExecutableDisposition, InstallEntry, InstallScheme, InstallTransform,
    RealizedOutput, RecordBinding, WheelArtifactIR, WheelHeaders, WheelInstallPlan, WheelLimits,
    ARTIFACT_ENCODING_ID, CONSUMER_PROFILE_ID, CONSUMER_PROFILE_SCHEMA, PLAN_ENCODING_ID,
    REALIZATION_ENCODING_ID, SPEC_SNAPSHOT_ID,
};
use crate::{zip_portable_utf8_v1_digest, ZIP_PORTABLE_UTF8_V1};

pub(crate) fn consumer_profile_digest(limits: WheelLimits) -> String {
    let mut encoder = Encoder::new(b"sealr.wheel.consumer-profile.v1\0");
    encoder.string(CONSUMER_PROFILE_SCHEMA);
    encoder.string(CONSUMER_PROFILE_ID);
    encoder.string(SPEC_SNAPSHOT_ID);
    encoder.string(ZIP_PORTABLE_UTF8_V1);
    encoder.string(&zip_portable_utf8_v1_digest());
    encoder.string(ARTIFACT_ENCODING_ID);
    encoder.string(PLAN_ENCODING_ID);
    encoder.string(REALIZATION_ENCODING_ID);
    encoder.string("pep440-rs-0.7.3-exact-classifier");
    encoder.string("filename-canonical-pep440-subset.v1");
    encoder.string("ascii-case-insensitive-headers.v1");
    encoder.string("record-selected-signatures.v2");
    encoder.string("portable-relocation-topology.v2");
    encoder.string("python-object-entry-points.v2");
    encoder.string("complete-output-realization.v1");
    encoder.string("script-prefix-classification.v1");
    for value in [
        limits.max_filename_bytes,
        limits.max_wheel_bytes,
        limits.max_metadata_bytes,
        limits.max_record_bytes,
        limits.max_entry_points_bytes,
        limits.max_semantic_bytes,
        limits.max_script_bytes,
        limits.max_plan_inspection_bytes,
        limits.max_header_lines,
        limits.max_header_line_bytes,
        limits.max_record_rows,
        limits.max_record_row_bytes,
        limits.max_expanded_tags,
    ] {
        encoder.u64(value);
    }
    encoder.finish()
}

pub(crate) fn artifact_identity(artifact: &WheelArtifactIR) -> String {
    let mut encoder = Encoder::new(b"sealr.wheel.artifact.v1\0");
    encoder.string(ARTIFACT_ENCODING_ID);
    encoder.string(&artifact.consumer_profile);
    encoder.string(&artifact.consumer_profile_digest);
    encoder.string(&artifact.spec_snapshot);
    encoder.string(&artifact.source_sha256);
    encoder.string(&artifact.archive_tree_sha256);
    encoder.string(&artifact.interpretation_profile);
    encoder.string(&artifact.interpretation_profile_sha256);
    let filename = &artifact.filename;
    encoder.string(&filename.raw);
    encoder.string(&filename.distribution);
    encoder.string(&filename.version);
    encoder.optional_string(filename.build.as_deref());
    encoder.string(&filename.python_tag);
    encoder.string(&filename.abi_tag);
    encoder.string(&filename.platform_tag);
    encoder.string(&filename.normalized_distribution);
    encoder.string(&filename.normalized_version);
    encoder.strings(&filename.expanded_tags);
    encoder.string(&artifact.dist_info_root);
    encoder.optional_string(artifact.data_root.as_deref());
    encode_wheel(&mut encoder, &artifact.wheel);
    encode_metadata(&mut encoder, &artifact.metadata);
    encoder.len(artifact.record.len());
    for binding in &artifact.record {
        encode_record(&mut encoder, binding);
    }
    encoder.len(artifact.entry_points.len());
    for entry_point in &artifact.entry_points {
        encode_entry_point(&mut encoder, entry_point);
    }
    encoder.len(artifact.member_facts.len());
    for facts in &artifact.member_facts {
        encoder.u64(facts.member_index as u64);
        encoder.string(&facts.path);
        encoder.u8(facts.creator_system);
        encoder.u64(u64::from(facts.external_attributes));
        encoder.u8(u8::from(facts.source_executable));
    }
    encoder.finish()
}

pub(crate) fn plan_identity(plan: &WheelInstallPlan) -> String {
    let mut encoder = Encoder::new(b"sealr.wheel.install-plan.v1\0");
    encoder.string(PLAN_ENCODING_ID);
    encoder.string(&plan.model);
    encoder.string(&plan.artifact_sha256);
    encoder.len(plan.entries.len());
    for entry in &plan.entries {
        encode_install_entry(&mut encoder, entry);
    }
    encoder.finish()
}

pub(crate) fn realization_identity(
    plan: &WheelInstallPlan,
    target_model: &str,
    installer_policy: &str,
    outputs: &[RealizedOutput],
) -> String {
    let mut outputs = outputs.to_vec();
    outputs.sort_by(|left, right| {
        (
            scheme_tag(&left.scheme),
            &left.relative_path,
            &left.sha256,
            left.size,
        )
            .cmp(&(
                scheme_tag(&right.scheme),
                &right.relative_path,
                &right.sha256,
                right.size,
            ))
    });
    let mut encoder = Encoder::new(b"sealr.wheel.realization.v1\0");
    encoder.string(REALIZATION_ENCODING_ID);
    encoder.string(&plan_identity(plan));
    encoder.string(target_model);
    encoder.string(installer_policy);
    encoder.len(outputs.len());
    for output in &outputs {
        encoder.u8(scheme_tag(&output.scheme));
        encoder.string(&output.relative_path);
        encoder.string(&output.sha256);
        encoder.u64(output.size);
    }
    encoder.finish()
}

fn encode_wheel(encoder: &mut Encoder, wheel: &WheelHeaders) {
    encoder.string(&wheel.wheel_version);
    encoder.optional_string(wheel.generator.as_deref());
    encoder.u8(u8::from(wheel.root_is_purelib));
    encoder.optional_string(wheel.build.as_deref());
    encoder.strings(&wheel.tags);
}

fn encode_metadata(encoder: &mut Encoder, metadata: &CoreMetadata) {
    encoder.string(&metadata.metadata_version);
    encoder.string(&metadata.name);
    encoder.string(&metadata.version);
    encoder.string(&metadata.normalized_name);
    encoder.string(&metadata.normalized_version);
}

fn encode_record(encoder: &mut Encoder, binding: &RecordBinding) {
    encoder.string(&binding.path);
    encoder.u64(binding.member_index as u64);
    encoder.optional_string(binding.sha256.as_deref());
    match binding.size {
        Some(size) => {
            encoder.u8(1);
            encoder.u64(size);
        }
        None => encoder.u8(0),
    }
    encoder.u8(u8::from(binding.is_record));
}

fn encode_entry_point(encoder: &mut Encoder, point: &EntryPoint) {
    encoder.string(&point.group);
    encoder.string(&point.name);
    encoder.string(&point.object);
}

fn encode_install_entry(encoder: &mut Encoder, entry: &InstallEntry) {
    match entry.source_member_index {
        Some(index) => {
            encoder.u8(1);
            encoder.u64(index as u64);
        }
        None => encoder.u8(0),
    }
    encoder.optional_string(entry.source_path.as_deref());
    encoder.u8(scheme_tag(&entry.scheme));
    encoder.string(&entry.relative_path);
    encoder.optional_string(entry.sha256.as_deref());
    match entry.size {
        Some(size) => {
            encoder.u8(1);
            encoder.u64(size);
        }
        None => encoder.u8(0),
    }
    encoder.u8(match entry.executable {
        ExecutableDisposition::NotExecutable => 0,
        ExecutableDisposition::SourceExecutable => 1,
        ExecutableDisposition::GeneratedWrapper => 2,
    });
    encoder.u8(match entry.transform {
        InstallTransform::Copy => 0,
        InstallTransform::RewritePythonShebang => 1,
        InstallTransform::GenerateConsoleWrapper => 2,
        InstallTransform::GenerateGuiWrapper => 3,
    });
    match &entry.entry_point {
        Some(point) => {
            encoder.u8(1);
            encode_entry_point(encoder, point);
        }
        None => encoder.u8(0),
    }
}

fn scheme_tag(scheme: &InstallScheme) -> u8 {
    match scheme {
        InstallScheme::Purelib => 0,
        InstallScheme::Platlib => 1,
        InstallScheme::Scripts => 2,
        InstallScheme::Headers => 3,
        InstallScheme::Data => 4,
    }
}

struct Encoder {
    hasher: Sha256,
}

impl Encoder {
    fn new(domain: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        Self { hasher }
    }

    fn u8(&mut self, value: u8) {
        self.hasher.update([value]);
    }

    fn u64(&mut self, value: u64) {
        self.hasher.update(value.to_le_bytes());
    }

    fn len(&mut self, value: usize) {
        self.u64(u64::try_from(value).expect("bounded collection length fits u64"));
    }

    fn string(&mut self, value: &str) {
        self.len(value.len());
        self.hasher.update(value.as_bytes());
    }

    fn optional_string(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.string(value);
            }
            None => self.u8(0),
        }
    }

    fn strings(&mut self, values: &[String]) {
        self.len(values.len());
        for value in values {
            self.string(value);
        }
    }

    fn finish(self) -> String {
        self.hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

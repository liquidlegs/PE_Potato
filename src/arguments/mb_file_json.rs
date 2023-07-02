use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MbQuery {
  pub query_status: Option<String>,
  pub data:         Option<Vec<MbData>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MbData {
  pub sha256_hash:        Option<String>,
  pub sha3_384_hash:      Option<String>,
  pub sha1_hash:          Option<String>,
  pub md5_hash:           Option<String>,
  pub first_seen:         Option<String>,
  pub last_seen:          Option<String>,
  pub file_name:          Option<String>,
  pub file_size:          Option<usize>,
  pub file_type_mime:     Option<String>,
  pub file_type:          Option<String>,
  pub reporter:           Option<String>,
  pub origin_country:     Option<String>,
  pub anonymous:          Option<usize>,
  pub signature:          Option<String>,
  pub imphash:            Option<String>,
  pub tlsh:               Option<String>,
  pub telfhash:           Option<String>,
  pub gimphash:           Option<String>,
  pub ssdeep:             Option<String>,
  pub dhash_icon:         Option<String>,
  pub comment:            Option<String>,
  pub tags:               Option<Vec<String>>,
  pub code_sign:          Option<Vec<CodeSign>>,
  pub intelligence:       Option<MbIntelligence>,
  pub delivery_method:    Option<String>,

  pub file_information:   Option<Vec<FileInfo>>,
  #[serde(flatten)]
  pub ole_information:    Option<Ole>,
  pub yara_rules:         Option<Vec<MbYaraRule>>,
  pub vendor_intel:       Option<Vendor>,
  pub comments:           Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CodeSign {
  pub subject_cn:             Option<String>,
  pub issuer_cn:              Option<String>,
  pub algorithm:              Option<String>,
  pub valid_from:             Option<String>,
  pub valid_to:               Option<String>,
  pub serial_number:          Option<String>,
  pub thumbprint_algorithm:   Option<String>,
  pub thumbprint:             Option<String>,
  pub cscb_listed:            Option<bool>,
  pub cscb_reason:            Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Ole {
  pub oleva: Option<Vec<MbOlevba>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MbOlevba {
  #[serde(rename = "type")]
  pub _type:          Option<String>,
  pub keyword:        Option<String>,
  pub description:    Option<String>, 
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FileInfo {
  pub context: Option<String>,
  pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MbYaraRule {
  pub rule_name:    Option<String>,
  pub author:       Option<String>,
  pub description:  Option<String>,
  pub reference:    Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MbIntelligence {
  pub clamav:             Option<Vec<String>>,
  pub uploads:            Option<String>,
  pub downloads:          Option<String>,
  pub mail:               Option<String>,
}

// Structure is yet to be filled out.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Vendor {
  #[serde(rename = "ANY.RUN")]
  pub any_dot_run: Option<Vec<AnyDotRun>>,

  #[serde(rename = "CERT-PL_MWDB")]
  pub cert_pl_mwdb: Option<CertPl>,

  #[serde(rename = "YOROI_YOMI")]
  pub yoroi_yomi: Option<YoroiYomi>,

  #[serde(rename = "vxCube")]
  pub vxcube: Option<VxCube>,

  #[serde(rename = "InQuest")]
  pub inquest: Option<InQuest>,

  #[serde(rename = "DocGuard")]
  pub docguard: Option<DocGuard>,

  #[serde(rename = "Triage")]
  pub triage: Option<Triage>,

  #[serde(rename = "ReversingLabs")]
  pub reversinglabs: Option<ReversingLabs>,

  #[serde(rename = "Spamhaus_HBL")]
  pub spamhaus_hbl: Option<Vec<Spamhaus>>,

  #[serde(rename = "FileScan-IO")]
  pub filescan_io: Option<FileScanIo>,

  #[serde(rename = "Intezer")]
  pub intezer: Option<Intezer>,

  #[serde(rename = "UnpacMe")]
  pub unpack_me: Option<Vec<UnpacMe>>,

  #[serde(rename = "VMRay")]
  pub vm_ray: Option<VMRay>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct VMRay {
  pub verdict:            Option<String>,
  pub malware_family:     Option<String>,
  pub report_link:        Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UnpacMe {
  pub sha256_hash:    Option<String>,
  pub md5_hash:       Option<String>,
  pub sha1_hash:      Option<String>,
  #[serde(flatten)]
  pub detections:     Option<Vec<String>>,
  pub link:           Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Intezer {
  pub verdict:      Option<String>,
  pub family_name:  Option<String>,
  pub analysis_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AnyDotRun {
  pub malware_family: Option<String>,
  pub verdict:        Option<String>,
  pub file_name:      Option<String>,
  pub date:           Option<String>,
  pub analysis_url:   Option<String>,
  pub tags:           Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CertPl {
  pub detection:  Option<String>,
  pub link:       Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct YoroiYomi {
  pub detection:  Option<String>,
  pub score:      Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct VxCube {
  pub verdict:        Option<String>,
  pub maliciousness:  Option<String>,
  pub behaviour:      Option<Vec<Behaviour>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Behaviour {
  pub threat_level: Option<String>,
  pub rule:         Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct InQuest {
  pub verdict:  Option<String>,
  pub url:      Option<String>,
  pub details:  Option<Vec<InQuestDetails>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct InQuestDetails {
  pub category:     Option<String>,
  pub title:        Option<String>,
  pub description:  Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DocGuard {
  pub verdict:        Option<String>,
  pub filetype:       Option<String>,
  pub alertlevel:     Option<String>,
  pub urls:           Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Triage {
  pub malware_family:   Option<String>,
  pub score:            Option<String>,
  pub link:             Option<String>,
  pub tags:             Option<Vec<String>>,
  pub signatures:       Option<Vec<TriageSignature>>,
  #[serde(flatten)]
  pub malware_config:   Option<Vec<MalwareConfig>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MalwareConfig {
  pub extraction:   Option<String>,
  pub family:       Option<String>,
  pub c2:           Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TriageSignature {
  pub signature:        Option<String>,
  pub score:            Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ReversingLabs {
  pub threat_name:          Option<String>,
  pub status:               Option<String>,
  pub first_seen:           Option<String>,
  pub scanner_count:        Option<String>,
  pub scanner_mount:        Option<String>,
  pub scanner_percent:      Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Spamhaus {
  pub detection:  Option<String>,
  pub link:       Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FileScanIo {
  pub verdict:        Option<String>,
  pub threatlevel:    Option<String>,
  pub confidence:     Option<String>,
  pub report_link:    Option<String>,
}
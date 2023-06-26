#[derive(Debug, Clone, Deserialize, Default)]
pub struct MbQueryRecentResp {
  query_status: String,
  data: Vec<MbData>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MbData {
  sha256_hash:        Option<String>,
  sha3_384_hash:      Option<String>,
  sha1_hash:          Option<String>,
  md5_hash:           Option<String>,
  first_seen:         Option<String>,
  last_seen:          Option<String>,
  file_name:          Option<String>,
  file_size:          Option<usize>,
  file_type_mime:     Option<String>,
  file_type:          Option<String>,
  reporter:           Option<String>,
  origin_country:     Option<String>,
  anonymous:          Option<String>,
  signature:          Option<String>,
  imphash:            Option<String>,
  tlsh:               Option<String>,
  telfhash:           Option<String>,
  gimphash:           Option<String>,
  ssdeep:             Option<String>,
  dhash_icon:         Option<String>,
  tags:               Option<Vec<String>>,
  code_sign:          Option<Vec<String>>,
  intelligence:       Option<MbIntelligence>,

  file_information:   Option<String>,
  ole_information:    Option<Vec<String>>,
  yara_rules:         Option<Vec<MbYaraRule>>,
  vendor_intel:       Option<Vendor>,
  comments:           Option<String>,
}

// Structure is yet to be filled out.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Vendor {
  #[serde(rename = "ANY.RUN")]
  any_dot_run: None,

  #[serde(rename = "CERT-PL_MWDB")]
  cert_pl_mwdb: None,

  #[serde(rename = "YOROI_YOMI")]
  yoroi_yomi: None,

  #[serde(rename = "vxCube")]
  vxcube: None,

  #[serde(rename = "InQuest")]
  inquest: None,

  #[serde(rename = "DocGuard")]
  docguard: None,

  #[serde(rename = "Triage")]
  triage: None,

  #[serde(rename = "ReversingLabs")]
  reversinglabs: None,

  #[serde(rename = "Spamhaus_HBL")]
  spamhaus_hbl: None,

  #[serde(rename = "FileScan-IO")]
  filescan_io: None,
}

pub struct AnyDotRun {

}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MbYaraRule {
  rule_name:    String,
  author:       String,
  description:  String,
  reference:    String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MbIntelligence {
  clamav:           Option<String>,
  uploads:          Option<String>,
  download:         Option<String>,
  mail:             Option<String>,
}
use serde::Deserialize;
use super::vt_file_json::{Links, AlertContext, SigmaAnalysisResults};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MetaData {
  pub count: usize,
  pub cursor: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct BehaviourData {
  pub attributes:         Option<BehaviourAttributes>,
  #[serde(rename = "type")]
  pub _type:              Option<String>,
  pub id:                 Option<String>,
  pub links:              Option<Links>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct BehaviourAttributes {
  pub analysis_date:                Option<usize>,
  pub behash:                       Option<String>,
  pub calls_highlighted:            Option<Vec<String>>,
  pub command_execution:            Option<Vec<String>>,
  pub files_opened:                 Option<Vec<String>>,
  pub files_written:                Option<Vec<String>>,
  pub files_deleted:                Option<Vec<String>>,
  pub files_attribute_changed:      Option<Vec<String>>,
  pub has_html_report:              Option<bool>,
  pub has_evtx:                     Option<bool>,
  pub has_pcap:                     Option<bool>,
  pub has_memdump:                  Option<bool>,
  pub hosts_file:                   Option<String>,
  pub ids_alerts:                   Option<Vec<Keys>>,
  pub processes_terminated:         Option<Vec<String>>,
  pub processes_killed:             Option<Vec<String>>,
  pub processes_injected:           Option<Vec<String>>,
  pub services_opened:              Option<Vec<String>>,
  pub services_created:             Option<Vec<String>>,
  pub services_started:             Option<Vec<String>>,
  pub services_stopped:             Option<Vec<String>>,
  pub services_deleted:             Option<Vec<String>>,
  pub services_bound:               Option<Vec<String>>,
  pub windows_searched:             Option<Vec<String>>,
  pub windows_hidden:               Option<Vec<String>>,
  pub mutexes_opened:               Option<Vec<String>>,
  pub mutexes_created:              Option<Vec<String>>,
  pub signals_observed:             Option<Vec<String>>,
  pub invokes:                      Option<Vec<String>>,
  pub crypto_algorithims_observed:  Option<Vec<String>>,
  pub crypto_keys:                  Option<Vec<String>>,
  pub crypto_plain_text:            Option<Vec<String>>,
  pub text_decoded:                 Option<Vec<String>>,
  pub text_highlighted:             Option<Vec<String>>,
  pub verdict_confidence:           Option<usize>,
  pub ja3_digest:                   Option<Vec<String>>,
  pub tls:                          Option<Vec<Tls>>,
  pub sni:                          Option<String>,
  pub subject:                      Option<Issuer>,
  pub thumbprint:                   Option<String>,
  pub version:                      Option<String>,
  pub modules_loaded:               Option<Vec<String>>,
  pub registry_keys_opened:         Option<Vec<String>>,
  pub registry_keys_set:            Option<Vec<RegistryKeys>>,
  pub registry_keys_deleted:        Option<Vec<String>>,
  pub mitre_attack_techniques:      Option<Vec<MitreAttackTechniques>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Ref {
  #[serde(rename = "ref")]
  pub _ref: String,
  pub values: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MitreAttackTechniques {
  pub signature_description:    Option<String>,
  pub id:                       Option<String>,
  pub severity:                 Option<String>,
  pub refs:                     Option<Vec<Ref>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RegistryKeys {
  pub key: String,
  pub value: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Issuer {
  #[serde(rename = "C")]
  pub c:            Option<String>,
  #[serde(rename = "CN")]
  pub cn:           Option<String>,
  #[serde(rename = "O")]
  pub o:            Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Tls {
  pub issuer:                 Option<Issuer>,
  pub ja3:                    Option<String>,
  pub ja3s:                   Option<String>,
  pub serial_number:          Option<String>,
  pub sigma_analysis_results: Option<Vec<SigmaAnalysisResults>> 
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Keys {
  pub alert_context:        Option<AlertContext>,
  pub alert_severity:       Option<String>,
  pub alert_category:       Option<String>,
  pub rule_id:              Option<String>,
  pub rule_msg:             Option<String>,
  pub rule_source:          Option<String>,
  pub rule_references:      Option<Vec<String>>,
}
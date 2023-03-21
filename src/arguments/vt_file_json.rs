use serde::Deserialize;
use self::elf::ElfInfo;

pub mod elf {
  use serde::Deserialize;

  #[derive(Debug, Clone, Deserialize, Default)]
  pub struct ElfInfo {
    pub export_list:      Option<Vec<ExportList>>,
    pub header:           Option<Header>,
    pub import_list:      Option<Vec<ImportList>>,
    pub packers:          Option<Vec<String>>,
    pub section_list:     Option<Vec<ElfSections>>,
    pub segment_list:     Option<Vec<SegmentList>>,
    pub shared_libraries: Option<Vec<String>>,
  }

  #[derive(Debug, Clone, Deserialize, Default)]
  pub struct ElfSections {
    pub name:             Option<String>,
    pub virtual_address:  Option<usize>,
    pub flags:            Option<String>,
    pub physical_offset:  Option<usize>,
    pub section_type:     Option<String>,
    pub size:             Option<usize>,
  }

  #[derive(Debug, Clone, Deserialize, Default)]
  pub struct SegmentList {
    pub segment_type:   Option<String>,
    pub resources:      Option<Vec<String>>,
  }

  #[derive(Debug, Clone, Deserialize, Default)]
  pub struct ExportList {
    pub name:   Option<String>,
    #[serde(rename = "type")]
    pub _type:  Option<String>,
  }

  #[derive(Debug, Clone, Deserialize, Default)]
  pub struct ImportList {
    pub name:   Option<String>,
    #[serde(rename = "type")]
    pub _type:  Option<String>,
  }

  #[derive(Debug, Clone, Deserialize, Default)]
  pub struct Header {
    #[serde(rename = "type")]
    pub _type:                Option<String>,
    pub hdr_version:          Option<String>,
    pub num_prog_headers:     Option<usize>,
    pub os_abi:               Option<String>,
    pub obj_version:          Option<String>,
    pub machine:              Option<String>,
    pub entry_point:          Option<usize>,
    pub num_section_headers:  Option<String>,
    pub abi_version:          Option<usize>,
    pub data:                 Option<String>,
    pub class:                Option<String>,
  }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SigmaAnalysisResults {         // Type is Option<Vec<T>>
  pub rule_title:               Option<String>,
  pub rule_source:              Option<String>,
  pub match_context:            Option<Vec<SigmaMatchContext>>,
  pub rule_level:               Option<String>,
  pub rule_description:         Option<String>,
  pub rule_author:              Option<String>,
  pub rule_id:                  Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SigmaMatchContext {
  pub values: SigmaMatchContextValues,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SigmaMatchContextValues {
  #[serde(rename = "TerminalSessionId")]
  pub terminal_session_id:        Option<String>,
  #[serde(rename = "ProcessGuid")]
  pub process_guid:               Option<String>,
  #[serde(rename = "ProcessId")]
  pub process_id:                 Option<String>,
  #[serde(rename = "Product")]
  pub product:                    Option<String>,
  #[serde(rename = "Description")]
  pub desription:                 Option<String>,
  #[serde(rename = "Company")]
  pub company:                    Option<String>,
  #[serde(rename = "ParentProcessGuid")]
  pub parent_process_guid:        Option<String>,
  #[serde(rename = "User")]
  pub user:                       Option<String>,
  #[serde(rename = "Hashes")]
  pub hashes:                     Option<String>,
  #[serde(rename = "OriginalFileName")]
  pub original_file_name:         Option<String>,
  #[serde(rename = "ParentImage")]
  pub parent_image:               Option<String>,
  #[serde(rename = "FileVersion")]
  pub file_version:               Option<String>,
  #[serde(rename = "ParentProcessId")]
  pub parent_process_id:          Option<String>,
  #[serde(rename = "CurrentDirectory")]
  pub current_directory:          Option<String>,
  #[serde(rename = "CommandLine")]
  pub command_line:               Option<String>,
  #[serde(rename = "EventId")]
  pub event_id:                   Option<String>,
  #[serde(rename = "LoginGuid")]
  pub login_guid:                 Option<String>,
  #[serde(rename = "LoginId")]
  pub login_id:                   Option<String>,
  #[serde(rename = "Image")]
  pub image:                      Option<String>,
  #[serde(rename = "IntegrityLevel")]
  pub integrity_level:            Option<String>,
  #[serde(rename = "ParentCommandLine")]
  pub parent_command_line:        Option<String>,
  #[serde(rename = "UtcTime")]
  pub utc_time:                   Option<String>,
  #[serde(rename = "RuleName")]
  pub rule_name:                  Option<String>,
  #[serde(rename = "ScriptBlockId")]
  pub script_block_id:            Option<String>,
  #[serde(rename = "ScriptBlockText")]
  pub script_block_text:          Option<String>,
  #[serde(rename = "MessageNumber")]
  pub message_number:             Option<String>,
  #[serde(rename = "MessageTotal")]
  pub message_total:              Option<String>,
  #[serde(rename = "Path")]
  pub path:                       Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[allow(dead_code)]
pub struct FileJsonOutput {
  pub data: Option<FileData>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[allow(dead_code)]
pub struct FileData {
  pub attributes: Option<FileAttributes>,
  pub _type:      Option<String>,
  pub id:         Option<String>,
  pub links:      Option<Links>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DotNetGuids {
  pub mvid:       Option<String>,
  pub typelib_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AsmData {
  pub buildnumber:    Option<usize>,
  pub culture:        Option<String>,
  pub flags:          Option<usize>,
  pub flags_text:     Option<String>,
  pub hashalgid:      Option<usize>,
  pub majorversion:   Option<usize>,
  pub minorversion:   Option<usize>,
  pub name:           Option<String>,
  pub pubkey:         Option<String>,
  pub revisionnumber: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ExternalAssemblies {

}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ExportedTypes {
  pub name:       Option<String>,
  pub namespace:  Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Streams {
  pub chi2:     Option<f64>,
  pub entropy:  Option<f32>,
  pub md5:      Option<String>,
  pub size:     Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct UnmanagedMethodList {
  pub methods:  Option<Vec<String>>,
  pub name:     Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TypeDefinitionList {
  pub namespace:        Option<String>,
  pub type_definitions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DotNetAsm {
  pub assembly_data:            Option<AsmData>,
  pub assembly_flags:           Option<usize>,
  pub assembly_flags_txt:       Option<String>,
  pub assembly_name:            Option<String>,
  pub clr_meta_version:         Option<String>,
  pub clr_version:              Option<String>,
  pub entry_point_rva:          Option<usize>,
  pub entry_point_token:        Option<usize>,
  pub external_assemblies:      Option<ExternalAssemblies>,
  pub exported_types:           Option<ExportedTypes>,
  pub external_files:           Option<Vec<String>>,
  pub external_modules:         Option<Vec<String>>,
  pub manifest_resource:        Option<Vec<String>>,
  pub metadata_header_rva:      Option<usize>,
  pub resources_va:             Option<usize>,
  pub streams:                  Option<Streams>,
  pub strongname_va:            Option<usize>,
  pub tables_present_map:       Option<String>,
  pub tables_present:           Option<usize>,
  pub tables_rows_map:          Option<String>,
  pub tables_rows_map_log:      Option<String>,
  pub type_defintion_list:      Option<Vec<TypeDefinitionList>>,
  pub unamanaged_method_list:   Option<Vec<UnmanagedMethodList>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[allow(dead_code)]
pub struct FileAttributes {
  pub elf_info:                       Option<ElfInfo>,
  pub dot_net_assembly:               Option<DotNetAsm>,
  pub type_description:               Option<String>,
  pub tlsh:                           Option<String>,
  pub vhash:                          Option<String>,
  pub trid:                           Option<Vec<Trid>>,
  pub crowdsourced_yara_results:      Option<Vec<CrowdSrcYara>>,
  pub creation_date:                  Option<f64>,
  pub names:                          Option<Vec<String>>,
  pub last_modification_date:         Option<f64>,
  pub type_tag:                       Option<String>,
  pub times_submitted:                Option<usize>,
  pub total_votes:                    Option<TotalVotes>,
  pub size:                           Option<usize>,
  pub popular_threat_classification:  Option<PopularThreatClassfication>,
  pub authentihash:                   Option<String>,
  pub detectiteasy:                   Option<DetectItEasy>,
  pub last_submission_date:           Option<usize>,
  pub sigma_analysis_results:         Option<Vec<SigmaAnalysisResults>>,
  pub meaningful_name:                Option<String>,
  pub crowdsourced_ids_stats:         Option<CrowdSrcStats>,
  pub sandbox_verdicts:               Option<SandboxVerdict>,
  pub sha256:                         Option<String>,
  pub type_extension:                 Option<String>,
  pub tags:                           Option<Vec<String>>,
  pub crowdsourced_ids_results:       Option<Vec<CrowdSrcIdResults>>,
  pub last_analysis_date:             Option<usize>,
  pub unique_sources:                 Option<usize>,
  pub first_submission_date:          Option<usize>,
  pub sha1:                           Option<String>,
  pub ssdeep:                         Option<String>,
  pub md5:                            Option<String>,
  pub pe_info:                        Option<PeInfo>,
  pub magic:                          Option<String>,
  pub last_analysis_stats:            Option<LastAnalysisStats>,
  pub last_analysis_results:          Option<LastAnalysisResults>,
  pub reputation:                     Option<i32>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[allow(dead_code, non_snake_case)]
pub struct LastAnalysisResults {
  pub Bkav:                       Option<AVProvider>,
  pub Lionic:                     Option<AVProvider>,
  pub Elastic:                    Option<AVProvider>,
  pub DrWeb:                      Option<AVProvider>,
  #[serde(rename = "MicroWorld-eScan")]
  pub MicroWorld_eScan:           Option<AVProvider>,
  pub CMC:                        Option<AVProvider>,
  #[serde(rename = "CAT-QuickHeal")]
  pub CAT_QuickHeal:              Option<AVProvider>,
  pub McAfee:                     Option<AVProvider>,
  pub Cylance:                    Option<AVProvider>,
  pub VIPRE:                      Option<AVProvider>,
  pub Sangfor:                    Option<AVProvider>,
  pub K7AntiVirus:                Option<AVProvider>,
  pub Alibaba:                    Option<AVProvider>,
  pub K7GW:                       Option<AVProvider>,
  pub CrowdStrike:                Option<AVProvider>,
  pub Arcabit:                    Option<AVProvider>,
  pub BitDefenderTheta:           Option<AVProvider>,
  pub VirIT:                      Option<AVProvider>,
  pub Cyren:                      Option<AVProvider>,
  pub SymantecMobileInsight:      Option<AVProvider>,
  pub Symantec:                   Option<AVProvider>,
  pub tehtris:                    Option<AVProvider>,
  #[serde(rename = "ESET-NOD32")]
  pub ESET_NOD32:                 Option<AVProvider>,
  pub APEX:                       Option<AVProvider>,
  pub Paloalto:                   Option<AVProvider>,
  pub ClamAV:                     Option<AVProvider>,
  pub Kaspersky:                  Option<AVProvider>,
  pub BitDefender:                Option<AVProvider>,
  #[serde(rename = "NANO-Antivirus")]
  pub NANO_Antivirus:             Option<AVProvider>,
  pub SUPERAntiSpyware:           Option<AVProvider>,
  pub Tencent:                    Option<AVProvider>,
  pub Trustlook:                  Option<AVProvider>,
  pub TACHYON:                    Option<AVProvider>,
  #[serde(rename = "F-Secure")]
  pub F_Secure:                   Option<AVProvider>,
  pub Baidu:                      Option<AVProvider>,
  pub Zillya:                     Option<AVProvider>,
  pub TrendMicro:                 Option<AVProvider>,
  #[serde(rename = "McAfee-GW-Edition")]
  pub McAfee_GW_Edition:          Option<AVProvider>,
  pub Trapmine:                   Option<AVProvider>,
  pub FireEye:                    Option<AVProvider>,
  pub Sophos:                     Option<AVProvider>,
  pub SentinelOne:                Option<AVProvider>,
  #[serde(rename = "Avast-Mobile")]
  pub Avast_Mobile:               Option<AVProvider>,
  pub Jiangmin:                   Option<AVProvider>,
  pub Webroot:                    Option<AVProvider>,
  pub Avira:                      Option<AVProvider>,
  #[serde(rename = "Antiy-AVL")]
  pub Antiy_AVL:                  Option<AVProvider>,
  pub Kingsoft:                   Option<AVProvider>,
  pub Gridinsoft:                 Option<AVProvider>,
  pub Xcitium:                    Option<AVProvider>,
  pub Microsoft:                  Option<AVProvider>,
  pub ViRobot:                    Option<AVProvider>,
  pub ZoneAlarm:                  Option<AVProvider>,
  pub GData:                      Option<AVProvider>,
  pub Google:                     Option<AVProvider>,
  pub BitDefenderFalx:            Option<AVProvider>,
  #[serde(rename = "AhnLab-V3")]
  pub AhnLab_V3:                  Option<AVProvider>,
  pub Acronis:                    Option<AVProvider>,
  pub VBA32:                      Option<AVProvider>,
  pub ALYac:                      Option<AVProvider>,
  pub MAX:                        Option<AVProvider>,
  pub Panda:                      Option<AVProvider>,
  pub Zoner:                      Option<AVProvider>,
  #[serde(rename = "TrendMicro-HouseCall")]
  pub TrendMicro_HouseCall:       Option<AVProvider>,
  pub Rising:                     Option<AVProvider>,
  pub Yandex:                     Option<AVProvider>,
  pub Ikarus:                     Option<AVProvider>,
  pub MaxSecure:                  Option<AVProvider>,
  pub Fortinet:                   Option<AVProvider>,
  pub AVG:                        Option<AVProvider>,
  pub Cybereason:                 Option<AVProvider>,
  pub Avast:                      Option<AVProvider>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub struct AVProvider {
  pub category:       Option<String>,
  pub engine_name:    Option<String>,
  pub engine_version: Option<String>,
  pub result:         Option<String>,
  pub method:         Option<String>,
  pub engine_update:  Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VtSection {
  pub name:            Option<String>,
  pub chi2:            Option<f64>,
  pub virtual_address: Option<usize>,
  pub entropy:         Option<f32>,
  pub raw_size:        Option<usize>,
  pub flags:           Option<String>,
  pub virtual_size:    Option<usize>,
  pub md5:             Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Trid {
  pub file_type:    String,
  pub probability:  Option<f32>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TotalVotes {
  pub harmless:   Option<usize>,
  pub malicious:  Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CrowdSrcYara {
  pub description:          Option<String>,
  pub source:               Option<String>,
  pub author:               Option<String>,
  pub match_in_subfile:     Option<bool>,
  pub ruleset_name:         Option<String>,
  pub rule_name:            Option<String>,
  pub ruleset_id:           Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PopularThreatClassfication {
  pub suggested_threat_label:   Option<String>,
  pub popular_threat_category:  Option<Vec<PopularThreat>>,
  pub popular_threat_name:      Option<Vec<PopularThreat>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PopularThreat {
  pub count: Option<usize>,
  pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DetectItEasy {
  pub filetype: Option<String>,
  pub values:   Option<Vec<DetectItEasyValues>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DetectItEasyValues {
  pub info:     Option<String>,
  pub version:  Option<String>,
  #[serde(rename = "type")]
  pub _type:    Option<String>,
  pub name:     Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CrowdSrcStats {
  pub info:   Option<usize>,
  pub low:    Option<usize>,
  pub medium: Option<usize>,
  pub high:   Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SandboxVerdict {
  #[serde(rename = "C2AE")]
  pub c2ae: Option<AVSandbox>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AVSandbox {
  pub category:               Option<String>,
  pub confidence:             Option<usize>,
  pub sandbox_name:           Option<String>,
  pub malware_names:          Option<Vec<String>>,
  pub malware_classification: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AlertContext {
  pub url:          Option<String>,
  pub hostname:     Option<String>,
  pub protocol:     Option<String>,
  pub dest_port:    Option<i32>,
  pub dest_ip:      Option<String>,
  pub src_ip:       Option<String>,
  pub src_port:     Option<i32>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CrowdSrcIdResults {
  pub rule_category:   Option<String>,
  pub alert_severity:  Option<String>,
  pub rule_msg:        Option<String>,
  pub rule_raw:        Option<String>,
  pub alert_context:   Option<Vec<AlertContext>>,
  pub rule_url:        Option<String>,
  pub rule_source:     Option<String>,
  pub rule_id:         Option<String>,
  pub rule_references: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PeInfo {
  pub debug:                      Option<PeDebugInfo>,
  pub resource_details:           Option<Vec<ResourceDetails>>,
  pub rich_pe_header_hash:        Option<String>,
  pub imphash:                    Option<String>,
  pub overlay:                    Option<Overlay>,
  pub compiler_product_versions:  Option<Vec<String>>,
  pub resource_langs:             Option<ResourceLangs>,
  pub machine_type:               Option<usize>,
  pub timestamp:                  Option<usize>,
  pub resource_types:             Option<ResourceTypes>,
  pub sections:                   Option<Vec<VtSection>>,
  pub import_list:                Option<Vec<ImportList>>,
  pub entry_point:                Option<usize>,
  pub exports:                    Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PeDebugInfo {
  pub codeview:       Option<CodeView>,
  pub fpo:            Option<Fpo>,
  pub misc:           Option<Misc>,
  pub reserved10:     Option<Reserved10>,
  pub size:           Option<usize>,
  pub timestamp:      Option<String>,
  #[serde(rename = "type")]
  _type:          Option<usize>,
  pub type_str:       Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Reserved10 {
  pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CodeView {
  pub age:        Option<i32>,
  pub guid:       Option<String>,
  pub name:       Option<String>,
  pub offset:     Option<i32>,
  pub signature:  Option<String>,
  pub timestamp:  Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Fpo {
  pub functions: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Misc {
  pub datatype:   Option<i32>,
  pub length:     Option<usize>,
  pub unicode:    Option<usize>,
  pub data:       Option<String>,
  pub reserved:   Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ImportList {
  pub library_name:       Option<String>,
  pub imported_functions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ResourceTypes {
  #[serde(rename = "RT_ICON")]
  pub rt_icon:          Option<usize>,

  #[serde(rename = "RT_DIALOG")]
  pub rt_dialog:        Option<usize>,
  
  #[serde(rename = "RT_CURSOR")]
  pub rt_cursor:        Option<usize>,
  
  #[serde(rename = "RT_ACCELERATOR")]
  pub rt_accelerator:   Option<usize>,

  #[serde(rename = "RT_BITMAP")]
  pub rt_bitmap:        Option<usize>,
  
  #[serde(rename = "RT_MANIFEST")]
  pub rt_manifest:      Option<usize>,
  
  #[serde(rename = "RT_GROUP_ICON")]
  pub rt_group_icon:    Option<usize>,
  
  #[serde(rename = "RT_GROUP_CURSOR")]
  pub rt_group_cursor:  Option<usize>,

  #[serde(rename = "RT_STRING")]
  pub rt_string:        Option<usize>,
  
  #[serde(rename = "RT_VERSION")]
  pub rt_version:       Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ResourceLangs {
  #[serde(rename = "NEUTRAL")]
  pub neutral: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Overlay {
  pub entropy:    Option<f32>,
  pub offset:     Option<usize>,
  pub chi2:       Option<f64>,
  pub filetype:   Option<String>,
  pub md5:        Option<String>,
  pub size:       Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ResourceDetails {
  pub lang:         Option<String>,
  pub entropy:      Option<f32>,
  pub chi2:         Option<f64>,
  pub filetype:     Option<String>,
  pub sha256:       Option<String>,
  #[serde(rename = "type")]
  pub _type:        Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct LastAnalysisStats {
  pub harmless:           Option<usize>,
  #[serde(rename = "type-unsupported")]
  pub type_unsupported:   Option<usize>,
  pub suspicious:         Option<usize>,
  #[serde(rename = "confirmed-timeout")]
  pub confirmed_timeout:  Option<usize>,
  pub timeout:            Option<usize>,
  pub failure:            Option<usize>,
  pub malicious:          Option<usize>,
  pub undetected:         Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Links {
  #[serde(rename = "self")]
  pub _self: Option<String>, 
}
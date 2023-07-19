mod virus_total;
use serde::Deserialize;
use virus_total::*;
mod function_backlist;
use function_backlist::*;
mod malware_bazaar;
use malware_bazaar::*;

use clap::{Parser, Args};
use console::style;
use goblin::Object;
use goblin::pe::data_directories::DataDirectories;
use goblin::pe::header::{DosHeader, CoffHeader};
use goblin::pe::optional_header::OptionalHeader;
use goblin::pe::section_table::SectionTable;
use goblin::pe::{
  export::Export,
  import::Import,
};

use std::fs::OpenOptions;
use std::{
  fs::read,
  io::Write,
  path::Path,
};
use comfy_table::{Table, Cell, Row, Color};
use reqwest::{
  blocking::ClientBuilder, Method
};
use custom_error::custom_error;

use self::vt_behaviour_json::BehaviorJsonOutput;
use self::vt_file_json::FileJsonOutput;

mod vt_file_json;
mod vt_behaviour_json;
mod mb_file_json;

custom_error! {pub GeneralError
  VtFlag{flag: std::io::Error}                = "Unable to parse flag - {flag}",
  Config{src: std::io::Error}                 = "Config file error - {src}",
  Io{source: std::io::Error}                  = "Unable to read file - {source}",
  Request{source: reqwest::Error}             = "Unable to make request - {source}",
  Goblin{source: goblin::error::Error}        = "Unable to parse binary - {source}",
}

pub const CONFIG_JSON: &str = "config.json";
pub const W_DBG_REL_PATH: &str = "..\\..\\config.json";
pub const L_DBG_REL_PATH: &str = "../../config.json";
pub const DF_CONFIG_D: &str = "{\n  \"vt_enable_search\": false,\n  \"vt_api_key\": \"\",\n  \"mb_enable_search\": false,\n  \"mb_enable_download\": false,\n  \"mb_api_key\": \"\"\n}";

#[derive(Debug, Clone, Default)]
pub struct CmdSettings {
  pub vt_api_key:         String,
  pub vt_enable_search:   bool,
  pub mb_enable_search:   bool,
  pub mb_enable_download: bool,
  pub mb_api_key:         String,
  pub file_hash:          String,
  pub file_bytes:         Vec<u8>,
}

impl CmdSettings {
  pub fn new(file_hash: String, file_bytes: Vec<u8>) -> Self {
    Self {
      vt_api_key: String::new(),
      mb_api_key: String::new(),
      vt_enable_search: false,
      mb_enable_search: false,
      mb_enable_download: false,
      file_hash: file_hash,
      file_bytes: file_bytes,
    }
  }
}

#[derive(Debug, Default)]
pub struct CombinedTable {
  pub title:    Table,
  pub contents: Table,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CmdSettingsJson {
  pub vt_api_key:   Option<String>,
  pub vt_enable_search:    Option<bool>,
  pub mb_enable_search:    Option<bool>,
  pub mb_enable_download:  Option<bool>,
  pub mb_api_key:   Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DataDirectoryInfo {
  pub name: String,
  pub size: u32,
  pub virtual_address: u32,
}

#[derive(Debug, Clone, Parser)]
#[clap(author, about, version)]
pub struct Arguments {
  #[clap(subcommand)]
  pub command: Option<Action>,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum Action {
  /// Parse local PE files similar to PEstudio and CFF Explorer
  Bin(BinArgs),
  
  /// Query the Virus Total API.
  VirusTotal(VtArgs),
  
  /// Query the Malware Bazaar API.
  MalwareBazaar(MbArgs),
  
  /// Query the YARAify API. [Not Implemented]
  Yaraify(YrArgs),
  
  /// Query the ThreatFox API. [Not Implemented]
  ThreatFox(TfArgs),
}

#[derive(Debug, Clone, Default, clap::ValueEnum, PartialEq)]
pub enum MbQueryType {
  #[default]
  Time,
  Amount,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConfigPath {
  Release,
  Debug,
  Root,
  Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CTerm {
  Fg,
  Bg,
}

// Yaraify arguments.
#[derive(Debug, Clone, Default, Args)]
pub struct YrArgs {}
impl YrArgs {}

// ThreatFox arguments.
#[derive(Debug, Clone, Default, Args)]
pub struct TfArgs {}
impl TfArgs {}

#[derive(Args, Debug, Clone, Default)]
pub struct MbArgs {
  #[clap(short, long)]
  /// Provide a file and generate a hash. [TODO]
  pub file: Option<String>,

  #[clap(long)]
  /// Query a general hash such as md5, sha1 or sha256.
  pub query_hash: Option<String>,
  
  #[clap(value_enum, short, long)]
  /// Query the most recent 100 samples or all samples added in the last hour.
  pub query_recent: Option<MbQueryType>,

  #[clap(short, long)]
  /// Download malware sample. [TODO]
  pub download: Option<String>,

  #[clap(long)]
  /// Query malware sample by tag. [tag:n_results] - Eg: rootkit:15
  pub query_tag: Option<String>,

  #[clap(long)]
  /// Query malware sample by signature. [signature:results] - Eg: AgentTesla:100
  pub query_signature: Option<String>,
  
  #[clap(long)]
  /// Query malware sample by file type [filetype:n_results] - Eg: docx:30 
  pub query_filetype: Option<String>,
  
  #[clap(long)]
  /// Query a yara rule. [TODO]
  pub query_yara: Option<String>,

  #[clap(long)]
  /// Query by clamAv signature
  pub query_clamv: Option<String>,

  #[clap(long)]
  /// Query by gimphash
  pub query_gimphash: Option<String>,

  #[clap(long)]
  /// Query by dhash
  pub query_dhash: Option<String>,

  #[clap(long)]
  /// Query bu imphash
  pub query_imphash: Option<String>,

  #[clap(long)]
  /// Query by telfhash
  pub query_telfhash: Option<String>,

  #[clap(long)]
  /// Query by tlsh
  pub query_tlsh: Option<String>,

  #[clap(long, default_value_if("debug", Some("false"), Some("true")), min_values(0))]
  /// Display debug messages [TODO]
  pub debug: bool,

  #[clap(short, long, default_value_if("raw_json", Some("false"), Some("true")), min_values(0))]
  /// Display the raw json response instead of a table.
  pub raw_json: bool,
}

#[allow(dead_code)]
impl MbArgs {
  pub fn check_valid_flags(&self) -> usize {
    let mut count: usize = 0;
    
    if let Some(_) = self.query_yara.clone() {
      count += 1;
    }

    if let Some(_) = self.query_clamv.clone() {
      count += 1;
    }

    if let Some(_) = self.query_dhash.clone() {
      count += 1;
    }

    if let Some(_) = self.query_gimphash.clone() {
      count += 1;
    }

    if let Some(_) = self.query_imphash.clone() {
      count += 1;
    }

    if let Some(_) = self.query_telfhash.clone() {
      count += 1;
    }

    if let Some(_) = self.query_tlsh.clone() {
      count += 1;
    }

    if self.debug.clone() == true {
      count += 1;
    }

    if let Some(_) = self.query_tag.clone() {
      count += 1;
    }
    
    if let Some(_) = self.query_filetype.clone() {
      count += 1;
    }

    if let Some(_) = self.file.clone() {
      count += 1;
    }

    if let Some(_) = self.query_hash.clone() {
      count += 1;
    }

    if let Some(_) = self.download.clone() {
      count += 1;
    }

    if let Some(_) = self.query_recent.clone() {
      count += 1;
    }

    count
  }
}

#[derive(Args, Debug, Clone, Default)]
pub struct VtArgs {
  #[clap(short, long)]
  /// The file name or path
  pub filename: Option<String>,
  
  #[clap(long)]
  /// Manually query virus total with a hash.
  pub vt_hash: Option<String>,
  
  #[clap(long, default_value_if("vt", Some("false"), Some("true")), min_values(0))]
  /// Shows a query on virus total. Must be enabled in the config file.
  pub av: bool,

  #[clap(short, long, default_value_if("general-info", Some("false"), Some("true")), min_values(0))]
  /// Combines results from virus total and resulting from parsing the binary
  pub general_info: bool,

  #[clap(short, long, default_value_if("sections", Some("false"), Some("true")), min_values(0))]
  /// Get sections
  pub sections: bool,

  #[clap(short, long, default_value_if("resource-details", Some("false"), Some("true")), min_values(0))]
  /// Display resource details
  pub resource_details: bool,

  #[clap(short = 'R', long, default_value_if("resource-by-type", Some("false"), Some("true")), min_values(0))]
  /// Display resources by type
  pub resources_by_type: bool,

  #[clap(short, long, default_value_if("yara-rules", Some("false"), Some("true")), min_values(0))]
  /// Display suggested yara rules
  pub yara_rules: bool,

  #[clap(short = 'S', long, default_value_if("sigma-rules", Some("false"), Some("true")), min_values(0))]
  /// Display suggested sigma rules [TODO]
  pub sigma_rules: bool,

  #[clap(short, long, default_value_if("names", Some("false"), Some("true")), min_values(0))]
  /// Display the history of names
  pub names: bool,

  #[clap(short, long, default_value_if("compiler-products", Some("false"), Some("true")), min_values(0))]
  /// Display compiler products
  pub compiler_products: bool,

  #[clap(short, long, default_value_if("imports", Some("false"), Some("true")), min_values(0))]
  /// Display imported functions
  pub imports: bool,

  #[clap(short, long, default_value_if("exports", Some("false"), Some("true")), min_values(0))]
  /// Display exported functions.
  pub exports: bool,

  #[clap(short, long, default_value_if("tags", Some("false"), Some("true")), min_values(0))]
  /// Display tags.
  pub tags: bool,

  #[clap(long, default_value_if("dns", Some("false"), Some("true")), min_values(0))]
  /// Display Dns lookups
  pub dns: bool,
  
  #[clap(short = 'm', long = "tech", default_value_if("mtech", Some("false"), Some("true")), min_values(0))]
  /// Display mitre attack techniques relating to a file.
  pub mitre_techniques: bool,

  #[clap(long, default_value_if("ipt", Some("false"), Some("true")), min_values(0))]
  /// Displays ip traffic.
  pub ip: bool,

  #[clap(long, default_value_if("http", Some("false"), Some("true")), min_values(0))]
  /// Display HTTP conversations.
  pub http: bool,

  #[clap(long = "ss", default_value_if("ss", Some("false"), Some("true")), min_values(0))]
  /// Get a lis of json structures that were returned by the query.
  pub structure_stats: bool,

  #[clap(short, long, default_value_if("upload", Some("false"), Some("true")), min_values(0))]
  /// Upload a file to virus total.
  pub upload: bool,

  #[clap(long, default_value_if("debug", Some("false"), Some("true")), min_values(0))]
  /// Display debug messages. [TODO]
  pub debug: bool,

  #[clap(short, long)]
  /// Send API requests to an ipaddress:port of your choice.
  pub web_debug: Option<String>,

  #[clap(long, default_value_if("raw_json", Some("false"), Some("true")), min_values(0))]
  /// Display the raw json response.
  pub raw_json: bool,

  #[clap(long, default_value_if("reg_open", Some("false"), Some("true")), min_values(0))]
  /// Registry keys that a malware sample has opened [TODO]
  pub reg_open: bool,

  #[clap(long, default_value_if("reg_set", Some("false"), Some("true")), min_values(0))]
  /// Registry keys that a malware sample has closed [TODO]
  pub reg_set: bool,

  #[clap(short, long, default_value_if("process_tree", Some("false"), Some("true")), min_values(0))]
  /// The process tree [TODO]
  pub process_tree: bool,

  #[clap(long, default_value_if("files_opened", Some("false"), Some("true")), min_values(0))]
  /// Displays files that were opened
  pub files_opened: bool,
  
  #[clap(long, default_value_if("files_deleted", Some("false"), Some("true")), min_values(0))]
  /// Displays files hat were deleted
  pub files_deleted: bool,
  
  #[clap(long, default_value_if("files_written", Some("false"), Some("true")), min_values(0))]
  /// Displays files that were written to the disk
  pub files_written: bool,
  
  #[clap(long, default_value_if("files_changed", Some("false"), Some("true")), min_values(0))]
  /// Displays files that has their attributes modified
  pub files_changed: bool,

  #[clap(long, default_value_if("reg_set", Some("false"), Some("true")), min_values(0))]
  /// Displays files that were dropped on disk [TODO]
  pub files_dropped: bool
}

impl VtArgs {

  /**Function checks if the provided flags or options have been set to true.
   * This is to prevent the executable from running if a file on the disk or file hash has
   * been specified, but no options have been provided.
   * Params:
   *  &self
   * Returns usize
   */
  pub fn count_valid_flags(&self) -> usize {
    let mut count: usize = 0;
    
    if self.av == true                      { count += 1; }
    if self.general_info == true            { count += 1; }
    if self.sections == true                { count += 1; }
    if self.resource_details == true        { count += 1; }
    if self.resources_by_type == true       { count += 1; }
    if self.yara_rules == true              { count += 1; }
    if self.sigma_rules == true             { count += 1; }
    if self.names == true                   { count += 1; }
    if self.compiler_products == true       { count += 1; }
    if self.imports == true                 { count += 1; }
    if self.exports == true                 { count += 1; }
    if self.tags == true                    { count += 1; }
    if self.mitre_techniques  == true       { count += 1; }
    if self.ip  == true                     { count += 1; }
    if self.http == true                    { count += 1; }
    if self.structure_stats == true         { count += 1; }
    if self.upload == true                  { count += 1; }
    if self.debug == true                   { count += 1; }
    if self.dns == true                     { count += 1; }
    if self.reg_open == true                { count += 1; }
    if self.reg_set == true                 { count += 1; }
    if self.files_changed == true           { count += 1; }
    if self.files_deleted == true           { count += 1; }
    if self.files_dropped == true           { count += 1; }
    if self.files_opened == true            { count += 1; }
    if self.files_written == true           { count += 1; }
    
    if let Some(_) = self.filename.clone() {
      count += 1;
    }

    if let Some(_) = self.vt_hash.clone() {
      count += 1;
    }

    count
  }

  /**Function checks what kinds of options that have been provided to it can determines what api
   * calls need to be made and what json responses from the Virus Total api need to be parsed.
   * Params:
   *  &self
   * Returns Result<VtArgType, GeneralError>
   */
  pub fn check_arg_types(&self) -> std::result::Result<VtArgType, GeneralError> {
    let mut _type = VtArgType::default();
    let mut att_count: usize = 0;
    let mut beh_count: usize = 0;

    if self.av == true                      { att_count += 1; }
    if self.general_info == true            { att_count += 1; }
    if self.sections == true                { att_count += 1; }
    if self.resource_details == true        { att_count += 1; }
    if self.resources_by_type == true       { att_count += 1; }
    if self.yara_rules == true              { att_count += 1; }
    if self.names == true                   { att_count += 1; }
    if self.compiler_products == true       { att_count += 1; }
    if self.imports == true                 { att_count += 1; }
    if self.exports == true                 { att_count += 1; }
    if self.tags == true                    { att_count += 1; }
    if self.sigma_rules == true             { beh_count += 1; }
    if self.mitre_techniques  == true       { beh_count += 1; }
    if self.ip  == true                     { beh_count += 1; }
    if self.http == true                    { beh_count += 1; }
    if self.dns == true                     { beh_count += 1; }
    if self.reg_open == true                { beh_count += 1; }
    if self.reg_set == true                 { beh_count += 1; }
    if self.files_changed == true           { beh_count += 1; }
    if self.files_deleted == true           { beh_count += 1; }
    if self.files_dropped == true           { beh_count += 1; }
    if self.files_opened == true            { beh_count += 1; }
    if self.files_written == true           { beh_count += 1; }

    if self.structure_stats == true         {
      att_count += 1;
      beh_count += 1;
    }

    if att_count > 0 {
      _type.attributes = true;
    }

    if beh_count > 0 {
      _type.behaviour = true;
    }

    Ok(_type)
  }
}

#[derive(Args, Debug, Clone, Default)]
pub struct BinArgs {
  #[clap(value_parser)]
  /// The file name or path
  pub filename: String,
  
  #[clap(short, long, default_value_if("exports", Some("false"), Some("true")), min_values(0))]
  /// Exported functions.
  pub exports: bool,

  #[clap(long, default_value_if("ex_libs", Some("false"), Some("true")), min_values(0))]
  /// Shows libraies used by exported function.
  pub ex_libs: bool,
  
  #[clap(short, long, default_value_if("imports", Some("false"), Some("true")), min_values(0))]
  /// imported functions.
  pub imports: bool,

  #[clap(short, long, default_value_if("sections", Some("false"), Some("true")), min_values(0))]
  /// Display info about the section headers
  pub sections: bool,

  #[clap(long = "Dh", default_value_if("Dh", Some("false"), Some("true")), min_values(0))]
  /// Display info about the DOS header
  pub dos_header: bool,

  #[clap(long = "Oh", default_value_if("Oh", Some("false"), Some("true")), min_values(0))]
  /// Display info about the optional header
  pub optional_header: bool,
  
  #[clap(long = "Ch", default_value_if("Ch", Some("false"), Some("true")), min_values(0))]
  /// Display info about the COFF header
  pub coff_header: bool,

  #[clap(short, long, default_value_if("directories", Some("false"), Some("true")), min_values(0))]
  /// Display info about directories and tables
  pub directories: bool,

  #[clap(long = "debug", default_value_if("debug", Some("false"), Some("true")), min_values(0))]
  /// Display debug messages [TODO]
  pub debug: bool,
}

impl Arguments {

  /**Function parses and displays information about a query from virus total and determines
   * what information will be displayed to the screen.
   * Params:
   *  &self,
   *  settings:      &mut CmdSettings {Contains the file hash and the api key}
   *  sh_everything: bool             {When true, will display all information returned from virus total}
   * Returns std::io::Result<()>
   */
  pub fn vt_enable_search(&self, settings: &mut CmdSettings, _sh_everything: bool) -> std::result::Result<(), GeneralError> {
    // Create a default struct and then update it.
    let mut av = VtArgs::default();
    if let Some(v) = self.command.clone() {

      match v {
        Action::VirusTotal(args) => { av = args; }
        _ => {}
      }
    }

    // debugging flags.
    let mut wdbg = String::new();
    if let Some(w) = av.web_debug.clone() {
      wdbg.push_str(w.as_str());
    }

    let debug = av.debug.clone();
    
    // Get the apu key from the config file.
    Self::load_config_file(settings)?;

    if settings.vt_enable_search.clone() == false {
      return Err(GeneralError::Config {
        src: std::io::Error::new(
          std::io::ErrorKind::Other, "Virus Total search must be enabled in the config file"
        )
      });
    }

    if settings.vt_api_key.clone().len() < 1 {
      return Err(GeneralError::Config {
        src: std::io::Error::new(
          std::io::ErrorKind::Other, "An api key must be supplied in the config file to use the Virus Total api"
        )
      });
    }


    if settings.file_hash.len() > 0 {
      
      // This will only execute a file or a file hash has been specified, but no options have been provided.
      if av.count_valid_flags() < 1 {
        println!("{}: \n\t-f <Path> [OPTIONS]\n\t--vt-hash <Hash> [OPTIONS]", style("Syntax Error").red().bright());
        return Ok(());  
      }

      else {
        // Uploads the file to virus total.
        // Uploads must be 32MB or less.
        if av.upload.clone() == true {
        
          if let Some(filename) = av.filename.clone() {
            VirusTotal::upload_file(
              filename.as_str(), &settings.vt_api_key, debug.clone(), wdbg.clone()
            )?;
          }
  
          else {
            return Err(GeneralError::VtFlag {
              flag: std::io::Error::new(
                std::io::ErrorKind::Other, "You can not upload a sample to Virus Total without specifying the file path"
              )
            }); 
          }
        }

        println!("Querying [{}] on Virus Total", style(settings.file_hash.clone()).cyan());
      }

      let mut file_request = String::new();
      let mut behaviour_request = String::new();
      let mut file_att = FileJsonOutput::default();
      // let mut file_att_test = FileJsonOutput::default();
      let mut beh_att = BehaviorJsonOutput::default();
      let arg_types = av.check_arg_types()?;
      let _file_bytes = settings.file_bytes.clone();
      let raw_json = av.raw_json.clone();

      let display_table = |title: Table, contents: Table| {
        let lines = contents.lines().count();
  
        if lines > 4 {
          println!("{}\n{}", title, contents);
        }
      };

      if arg_types.attributes == true {
        file_request.push_str(VirusTotal::query_file_attributes(&settings.file_hash, &settings.vt_api_key).as_str());
        file_att = VirusTotal::parse_response(raw_json, file_request.clone());
      }

      if arg_types.behaviour == true {
        behaviour_request.push_str(VirusTotal::query_file_behaviour(&settings.file_hash, 10, &settings.vt_api_key)?.as_str());
        beh_att = VirusTotal::parse_behavior_response(raw_json, behaviour_request);
      }

      if av.av == true {
        if let Some(t) = VirusTotal::search_detections(file_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.general_info == true {
        if let Some(t) = VirusTotal::get_general_info(file_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.sections == true {
        if let Some(t) = VirusTotal::get_sections(file_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.resource_details == true {
        if let Some(t) = VirusTotal::get_resource_details(file_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.resources_by_type == true {
        if let Some(t) = VirusTotal::get_resource_by_type(file_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.yara_rules  == true {
        if let Some(t) = VirusTotal::get_yara_rules(file_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.sigma_rules == true {
        if let Some(t) = VirusTotal::get_sigma_rules(beh_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.names == true {
        if let Some(t) = VirusTotal::get_file_names(file_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.compiler_products == true {
        if let Some(t) = VirusTotal::get_compiler_products(file_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.imports  == true {
        if let Some(t) = VirusTotal::get_imports(file_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.exports == true {
        if let Some(t) = VirusTotal::get_exports(file_att.clone()) {
          display_table(t.title, t.contents);
        }
      } 

      if av.tags == true {
        if let Some(t) = VirusTotal::get_tags(file_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.ip == true {
        if let Some(t) = VirusTotal::get_ip_traffic(beh_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.http == true {
        if let Some(t) = VirusTotal::get_http_conv(beh_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.dns == true {
        if let Some(t) = VirusTotal::get_dns_requests(beh_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.reg_open == true {
        if let Some(t) = VirusTotal::get_registry_keys_open(beh_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.reg_set == true {
        if let Some(t) = VirusTotal::get_registry_keys_set(beh_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.mitre_techniques == true {
        if let Some(t) = VirusTotal::get_mitre_attack_techniques(beh_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.structure_stats == true {
        if let Some(t) = VirusTotal::get_structure_stats(file_att.clone(), beh_att.clone()) {
          display_table(t.title, t.contents);
        }
      }

      if av.files_changed == true {
        if let Some(t) = VirusTotal::get_files(beh_att.clone(), FileAction::Changed) {
          display_table(t.title, t.contents);
        }
      }

      if av.files_deleted == true {
        if let Some(t) = VirusTotal::get_files(beh_att.clone(), FileAction::Deleted) {
          display_table(t.title, t.contents);
        }
      }

      if av.files_dropped == true {
        todo!("Files dropped will be implemented in the next update")
        // if let Some(t) = VirusTotal::get_files(beh_att.clone(), FileAction::) {
        //   display_table(t.title, t.contents);
        // }
      }

      if av.files_opened == true {
        if let Some(t) = VirusTotal::get_files(beh_att.clone(), FileAction::Opened) {
          display_table(t.title, t.contents);
        }
      }

      if av.files_written == true {
        if let Some(t) = VirusTotal::get_files(beh_att.clone(), FileAction::Written) {
          display_table(t.title, t.contents);
        }
      }
    }

    else {
      println!("{}: \n\t-f <Path> [OPTIONS]\n\t--vt-hash <Hash> [OPTIONS]", style("Syntax Error").red().bright());
    }

    Ok(())
  }

  /**Function takes options from the MbArgs struct as sepcified by the user and determines what information
   * is displayed to the screen.
   * Params:
   *  &self
   *  settings: &mut CmdSettings {Contains the file hash and the api key}
   * Returns nothing
   */
  #[allow(dead_code)]
  pub fn mb_enable_search(&self, settings: &mut CmdSettings) -> std::result::Result<(), GeneralError> {
    Self::load_config_file(settings)?;
    let mut mb_args = MbArgs::default();

    if let Some(m) = self.command.clone() {
      match m {
        Action::MalwareBazaar(args) => { mb_args = args; }
        _ => {}
      }
    }

    let display_table = |title: Table, contents: Table| {
      let lines = contents.lines().count();

      if lines > 4 {
        println!("{}\n{}", title, contents);
      }
    };

    let mb = MalwareBazaar {
      debug: mb_args.debug.clone(), 
      raw_json: mb_args.raw_json.clone(), 
      api_key: settings.mb_api_key.clone(),
    };

    if let Some(q) = mb_args.query_recent.clone() {
      MalwareBazaar::query_recent_samples(&settings.mb_api_key, q)?;
    }

    if let Some(q) = mb_args.query_filetype {
      if let Some(t) = mb.get_query_items(q, SearchType::FileType) {
        display_table(t.title, t.contents);
      }
    }

    if let Some(q) = mb_args.query_tag {
      if let Some(t) = mb.get_query_items(q, SearchType::Tag) {
        display_table(t.title, t.contents);
      }
    }

    if let Some(q) = mb_args.query_signature {
      if let Some(t) = mb.get_query_items(q, SearchType::Signature) {
        display_table(t.title, t.contents);
      }
    }

    if let Some(q) = mb_args.query_clamv {
      if let Some(t) = mb.get_query_items(q, SearchType::ClamAv) {
        display_table(t.title, t.contents);
      }
    }

    if let Some(q) = mb_args.query_dhash {
      if let Some(t) = mb.get_query_items(q, SearchType::Dhash) {
        display_table(t.title, t.contents);
      }
    }

    if let Some(q) = mb_args.query_gimphash {
      if let Some(t) = mb.get_query_items(q, SearchType::GimpHash) {
        display_table(t.title, t.contents);
      }
    }

    if let Some(q) = mb_args.query_imphash {
      if let Some(t) = mb.get_query_items(q, SearchType::ImpHash) {
        display_table(t.title, t.contents);
      }
    }

    if let Some(q) = mb_args.query_telfhash {
      if let Some(t) = mb.get_query_items(q, SearchType::TelfHash) {
        display_table(t.title, t.contents);
      }
    }

    if let Some(q) = mb_args.query_tlsh {
      if let Some(t) = mb.get_query_items(q, SearchType::Tlsh) {
        display_table(t.title, t.contents);
      }
    }

    // shows more detailed information about a single sample.
    // would like to also show yara rules and vendor intel with this same command.
    if let Some(q) = mb_args.query_hash {
      if let Some(s_table) = mb.get_query_hash(q) {
        let f_info = s_table.0;    // File Information
        let y_rules = s_table.1;    // Yara Rules
        let intel = s_table.2;    // Sandbox Intel

        display_table(f_info.title, f_info.contents);
        display_table(y_rules.title, y_rules.contents);
        display_table(intel.title, intel.contents);
      }
    }

    Ok(())
  }

  /**Function displays all data contained in the load file or just some of it in a table as specified by the user.
   * Params:
   *  &self
   *  bytes:         Vec<u8>          {The raw bytes of the loaded binary}
   *  settings:      &mut CmdSettings {The file hash and virus total search information}
   *  sh_everything: bool             {When true displays all information in the binary}
   * Returns Result<()>
   */
  pub fn display_data(&self, bytes: Vec<u8>, settings: &mut CmdSettings, sh_everything: bool) -> goblin::error::Result<()> {
    Self::load_config_file(settings).unwrap();
    let mut bin = BinArgs::default();

    if let Some(b) = self.command.clone() {

      match b {
        Action::Bin(args) => { bin = args; }
        _ => {}
      }
    }

    match Object::parse(&bytes)? {
      Object::Elf(_) => {
        // TODO
      },
      
      Object::PE(pe) => {
        let imports = pe.imports;
        let exports = pe.exports;
        let sections = pe.sections;      
        let dos_header = pe.header.dos_header;
        let coff_header = pe.header.coff_header;
        let optional_header = pe.header.optional_header;

        Self::load_config_file(settings).unwrap();
        if sh_everything == true {
          let export_table = Self::get_exports(&exports);
          println!("{export_table}");
          
          let export_lib_table = Self::get_exported_lib(exports);
          println!("{export_lib_table}");

          let import_table = Self::get_imports(&imports);
          println!("{import_table}");
        }

        else {
          if bin.exports == true {
            let export_table = Self::get_exports(&exports);
            println!("{export_table}");
          }

          if bin.ex_libs == true {
            let export_lib_table = Self::get_exported_lib(exports);
            println!("{export_lib_table}");
          }

          if bin.imports == true {
            let import_table = Self::get_imports(&imports);
            println!("{import_table}");
          }

          if bin.sections == true {
            Self::get_section_data(sections);
          }

          if bin.dos_header == true {
            let dos_header_tb = Self::get_dos_header(dos_header);
            println!("{dos_header_tb}");
          }

          if bin.coff_header == true {
            let coff_header_tb = Self::get_coff_header(coff_header);
            println!("{coff_header_tb}");
          }

          if bin.optional_header == true {
            match Self::get_optional_header(optional_header) {
              Some(table) => {
                println!("{table}");
              }
              None => {
                println!("Could not read header");
              }
            }
          }

          if bin.directories == true {
            match optional_header.clone() {
              Some(h) => {
                let table = Self::get_data_directories(h.data_directories);
                println!("{table}");
              }
              None => {
                println!("Could not read data directories");
              }
            }
          }
        }
      },

      Object::Mach(_) => {},      // TODO
      Object::Archive(_) => {},   // TODO
      Object::Unknown(_) => {}    // TODO
    }

    Ok(())
  }

  /**Function returns information stored in the dos header.
   * Params:
   *  header: DosHeader {The dos header}
   * Returns Table
   */
  pub fn get_dos_header(header: DosHeader) -> Table {
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("Header_Name").fg(Color::Green),
      Cell::from("Header_Offset").fg(Color::DarkCyan),
      Cell::from("Signature").fg(Color::DarkYellow),
    ]);

    table.add_row(vec![
      Cell::from("DOS_Header").fg(Color::Green),
      Cell::from(format!("0x{:x}", header.pe_pointer)).fg(Color::DarkCyan),
      Cell::from(format!("0x{:x}", header.signature)).fg(Color::DarkYellow),
    ]);

    table
  }

  /**Function returns information about the coff_header.
   * Params:
   *  header: CoffHeader {The CoffHeader}
   * Returns Table
   */
  pub fn get_coff_header(header: CoffHeader) -> Table {
    let mut table = Table::new();
    table.add_row(vec![
      Cell::from("Header_Name"),
      Cell::from("Characteristics").fg(Color::Blue),
      Cell::from("Machine Type").fg(Color::Green),
      Cell::from("Number_Of_Sections").fg(Color::DarkYellow),
      Cell::from("Number_Of_Symbols").fg(Color::DarkCyan),
      Cell::from("Symbol_Address_Table").fg(Color::Red),
      Cell::from("Optional_Header_Size").fg(Color::Cyan),
      Cell::from("Timestamp").fg(Color::Yellow),
    ]);

    table.add_row(vec![
      Cell::from("COFF_Header"),
      Cell::from(format!("0x{:x}", header.characteristics)).fg(Color::Blue),
      Cell::from(format!("0x{:x}", header.machine)).fg(Color::Green),
      Cell::from(header.number_of_sections).fg(Color::DarkYellow),
      Cell::from(header.number_of_symbol_table).fg(Color::DarkCyan),
      Cell::from(format!("0x{:x}", header.pointer_to_symbol_table)).fg(Color::Red),
      Cell::from(format!("0x{:x} ({} bytes)", header.size_of_optional_header, header.size_of_optional_header)).fg(Color::Cyan),
      Cell::from(header.time_date_stamp).fg(Color::Yellow),
    ]);

    table
  }

  /**Function creates vec of data directories with their names, sizes and virtual addresses.
   * Params:
   *  dir: DataDirectories {The data directories to check}
   * Returns Vec<DataDirectoryInfo>
   */
  pub fn get_data_directories(dir: DataDirectories) -> Table {
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("Name").fg(Color::Yellow),
      Cell::from("Size").fg(Color::Yellow),
      Cell::from("Virtual_Address").fg(Color::Yellow),
    ]);

    let mut label_string = String::new();
    let mut size_string = String::new();
    let mut rva_string = String::new();

    let mut directories: Vec<DataDirectoryInfo> = Default::default();
    let mut arch = DataDirectoryInfo::default();
    let mut realloc = DataDirectoryInfo::default();
    let mut bound_import = DataDirectoryInfo::default();
    let mut certificate = DataDirectoryInfo::default();
    let mut clr_runtime_header = DataDirectoryInfo::default();
    let mut debug = DataDirectoryInfo::default();
    let mut delay_import_desc = DataDirectoryInfo::default();
    let mut except = DataDirectoryInfo::default();
    let mut export = DataDirectoryInfo::default();
    let mut global_ptr = DataDirectoryInfo::default();
    let mut import_addr = DataDirectoryInfo::default();
    let mut import = DataDirectoryInfo::default();
    let mut load_config = DataDirectoryInfo::default();
    let mut resource = DataDirectoryInfo::default();
    let mut tls = DataDirectoryInfo::default();

    if let Some(d) = dir.get_architecture() {
      arch.name.push_str("architecture");
      arch.size = d.size;
      arch.virtual_address =d.virtual_address;
      directories.push(arch);
    }

    if let Some(d) = dir.get_base_relocation_table() {
      realloc.name.push_str("relocation");
      realloc.size = d.size;
      realloc.virtual_address =d.virtual_address;
      directories.push(realloc);
    }

    if let Some(d) = dir.get_bound_import_table() {
      bound_import.name.push_str("bound_import");
      bound_import.size = d.size;
      bound_import.virtual_address =d.virtual_address;
      directories.push(bound_import);
    }

    if let Some(d) = dir.get_certificate_table() {
      certificate.name.push_str("certificate");
      certificate.size = d.size;
      certificate.virtual_address =d.virtual_address;
      directories.push(certificate);
    }

    if let Some(d) = dir.get_clr_runtime_header() {
      clr_runtime_header.name.push_str("clr_runtime_header");
      clr_runtime_header.size = d.size;
      clr_runtime_header.virtual_address =d.virtual_address;
      directories.push(clr_runtime_header);
    }

    if let Some(d) = dir.get_debug_table() {
      debug.name.push_str("debug");
      debug.size = d.size;
      debug.virtual_address =d.virtual_address;
      directories.push(debug);
    }

    if let Some(d) = dir.get_delay_import_descriptor() {
      delay_import_desc.name.push_str("delay_import");
      delay_import_desc.size = d.size;
      delay_import_desc.virtual_address =d.virtual_address;
      directories.push(delay_import_desc);
    }

    if let Some(d) = dir.get_exception_table() {
      except.name.push_str("exception");
      except.size = d.size;
      except.virtual_address =d.virtual_address;
      directories.push(except);
    }

    if let Some(d) = dir.get_export_table() {
      export.name.push_str("export");
      export.size = d.size;
      export.virtual_address =d.virtual_address;
      directories.push(export);
    }

    if let Some(d) = dir.get_global_ptr() {
      global_ptr.name.push_str("global_ptr");
      global_ptr.size = d.size;
      global_ptr.virtual_address =d.virtual_address;
      directories.push(global_ptr);
    }

    if let Some(d) = dir.get_import_address_table() {
      import_addr.name.push_str("import_address");
      import_addr.size = d.size;
      import_addr.virtual_address =d.virtual_address;
      directories.push(import_addr);
    }

    if let Some(d) = dir.get_import_table() {
      import.name.push_str("import");
      import.size = d.size;
      import.virtual_address =d.virtual_address;
      directories.push(import);
    }

    if let Some(d) = dir.get_load_config_table() {
      load_config.name.push_str("load_config");
      load_config.size = d.size;
      load_config.virtual_address =d.virtual_address;
      directories.push(load_config);
    }

    if let Some(d) = dir.get_resource_table() {
      resource.name.push_str("resource");
      resource.size = d.size;
      resource.virtual_address =d.virtual_address;
      directories.push(resource);
    }

    if let Some(d) = dir.get_tls_table() {
      tls.name.push_str("tls");
      tls.size = d.size;
      tls.virtual_address =d.virtual_address;
      directories.push(tls);
    }

    for i in directories.clone() {
      label_string.push_str(format!("{}\n", i.name).as_str());
      size_string.push_str(format!("0x{:x} ({} bytes)\n", i.size, i.size).as_str());
      rva_string.push_str(format!("0x{:x}\n", i.virtual_address).as_str());
    }

    label_string.pop();
    size_string.pop();
    rva_string.pop();

    table.add_row(vec![
      Cell::from(label_string).fg(Color::Yellow),
      Cell::from(size_string).fg(Color::DarkCyan),
      Cell::from(rva_string).fg(Color::DarkCyan),
    ]);

    table
  }

  /**Function returns information about the optional_header.
   * Params:
   *  header: Option<OptionalHeader> {The optional header}
   * Returns Option<Table>
   */
  pub fn get_optional_header(header: Option<OptionalHeader>) -> Option<Table> {
    if let Some(h) = header {

      let mut labels: Vec<&str> = Default::default();
      labels.push("magic");
      labels.push("major_linker_version");
      labels.push("minor_linker_version");
      labels.push("size_of_code");
      labels.push("size_of_initialized_data");
      labels.push("size_of_uninitialized_data");
      labels.push("address_of_entry_point");
      labels.push("base_of_code");
      labels.push("base_of_data");

      labels.push("check_sum");
      labels.push("dll_characteristics");
      labels.push("file_alignment");
      labels.push("image_base");
      labels.push("loader_flags");
      labels.push("major_image_version");
      labels.push("major_operating_system_version");
      labels.push("major_subsystem_version");
      labels.push("minor_image_version");
      labels.push("minor_operating_system_version");
      labels.push("minor_subsystem_version");
      labels.push("number_of_rva_and_sizes");
      labels.push("section_alignment");
      labels.push("size_of_headers");
      labels.push("size_of_heap_commit");
      labels.push("size_of_heap_reserve");
      labels.push("size_of_image");
      labels.push("size_of_stack_commit");
      labels.push("size_of_stack_reserve");
      labels.push("subsystem");
      labels.push("win32_version_value");

      let mut table = Table::new();
      let mut label_string = String::new();
      let mut value_string = String::new();

      for i in labels.clone() {
        label_string.push_str(format!("{}\n", i).as_str());
      }

      label_string.pop();

      let mut values: Vec<String> = Default::default();
      values.push(format!("{}\n", h.standard_fields.magic));
      values.push(format!("{}\n", h.standard_fields.major_linker_version));
      values.push(format!("{}\n", h.standard_fields.minor_linker_version));
      values.push(format!("{} bytes\n", h.standard_fields.size_of_code));
      values.push(format!("{} bytes\n", h.standard_fields.size_of_initialized_data));
      values.push(format!("{} bytes\n", h.standard_fields.size_of_uninitialized_data));
      values.push(format!("0x{:x}\n", h.standard_fields.address_of_entry_point));
      values.push(format!("0x{:x}\n", h.standard_fields.base_of_code));
      values.push(format!("0x{:x}\n", h.standard_fields.base_of_data));
      values.push(format!("0x{:x}\n", h.windows_fields.check_sum));
      values.push(format!("0x{:x}\n", h.windows_fields.dll_characteristics));
      values.push(format!("0x{:x}\n", h.windows_fields.file_alignment));
      values.push(format!("0x{:x}\n", h.windows_fields.image_base));
      values.push(format!("0x{:x}\n", h.windows_fields.loader_flags));
      values.push(format!("{}\n", h.windows_fields.major_image_version));
      values.push(format!("{}\n", h.windows_fields.major_operating_system_version));
      values.push(format!("{}\n", h.windows_fields.major_subsystem_version));
      values.push(format!("{}\n", h.windows_fields.minor_image_version));
      values.push(format!("{}\n", h.windows_fields.minor_operating_system_version));
      values.push(format!("{}\n", h.windows_fields.minor_subsystem_version));
      values.push(format!("{}\n", h.windows_fields.number_of_rva_and_sizes));
      values.push(format!("{}\n", h.windows_fields.section_alignment));
      values.push(format!("{} bytes\n", h.windows_fields.size_of_headers));
      values.push(format!("{} bytes\n", h.windows_fields.size_of_heap_commit));
      values.push(format!("{} bytes\n", h.windows_fields.size_of_heap_reserve));
      values.push(format!("{} bytes\n", h.windows_fields.size_of_image));
      values.push(format!("{} bytes\n", h.windows_fields.size_of_stack_commit));
      values.push(format!("{} bytes\n", h.windows_fields.size_of_stack_reserve));
      values.push(format!("{}\n", h.windows_fields.subsystem));
      values.push(format!("0x{:x}", h.windows_fields.win32_version_value));

      for i in values.clone() {
        value_string.push_str(i.as_str());
      }

      let row = Row::from(vec![
        Cell::from(label_string).fg(Color::Yellow),
        Cell::from(value_string).fg(Color::DarkCyan),
      ]);

      table.add_row(row);
      return Some(table);
    }

    None
  }

  /**Function displays information about each section header in the form of a table.
   * Params:
   *  sections: Vec<SectionTable> {The headers and information to be displayed}
   * Returns Table
   */
  pub fn get_section_data(sections: Vec<SectionTable>) -> Table {
    let mut table = Table::new();

    table.set_header(vec![
      Cell::from("Name"), 
      Cell::from("Characteristics").fg(Color::Green), 
      Cell::from("Virtual_Address").fg(Color::DarkCyan),
      Cell::from("Virtual_Size").fg(Color::DarkYellow), 
      Cell::from("Raw_Address").fg(Color::Cyan),
      Cell::from("Raw_Size").fg(Color::Red),
    ]);

    for i in sections.clone() {
      let mut section_name = "";
      
      match i.name() {
        Ok(s) => {
          section_name = s;
        },
        Err(_) => {}
      }

      let mut ptr_rw_data = String::new();
      match i.pointer_to_raw_data {
        0 => { ptr_rw_data.push_str("None"); }
        _ => { ptr_rw_data.push_str(format!("{:?}", i.pointer_to_raw_data as *const u32).as_str()); }
      }

      table.add_row(vec![
        Cell::from(section_name), 
        Cell::from(format!("0x{:x}", i.characteristics)).fg(Color::Green), 
        Cell::from(format!("0x{:x}", i.virtual_address)).fg(Color::DarkCyan),
        Cell::from(format!("{:x} ({} bytes)", i.virtual_size, i.virtual_size)).fg(Color::DarkYellow), 
        Cell::from(ptr_rw_data).fg(Color::Cyan),
        Cell::from(format!("{:x} ({} bytes)",i.size_of_raw_data, i.size_of_raw_data)).fg(Color::Red), 
      ]);
    }

    println!("{table}");
    table
  }

  /**Function returns the library name from re_export debug string.
   * Params:
   *  buffer: &str {The data to filter}
   * Returns String.
   */
  pub fn filter_export_lib(buffer: &str) -> String {
    let filter: Vec<&str> = buffer.split("lib: ").collect();
    let mut last_chunk = filter[1]
                                .replace("\"", "")
                                .replace(",", "")
                                .replace(" ", "")
                                .replace("}", "");

    last_chunk.pop();
    last_chunk
  }

  /**Function returns a list of library names that were found in the export table.
   * Params:
   *  exports: Vec<Export> {The exported functions}
   * Returns Table.
   */
  pub fn get_exported_lib(exports: Vec<Export>) -> Table {
    let mut table = Table::new();
    let mut lib_names: Vec<String> = Default::default();

    table.set_header(vec![
      Cell::from("Library Name").fg(Color::Green),
    ]);

    for i in exports {
      if let Some(re) = i.reexport {
        let re_debug = Self::filter_export_lib(format!("{:#?}", re).as_str());
        lib_names.push(re_debug);
      }
    }

    lib_names.sort();
    lib_names.dedup();

    let mut lib_name_string = String::new();
    for i in lib_names {
      lib_name_string.push_str(format!("{}\n", i).as_str());
    }

    lib_name_string.pop();
    let row = Row::from(vec![
      Cell::from(lib_name_string).fg(Color::DarkCyan),
    ]);

    table.add_row(row);
    table
  }

  /**Function returns a list exported function found in the binary in a table like format.
   * Params:
   *  exports: &Vec<Export>
   * Returns Table
   */
  pub fn get_exports(exports: &Vec<Export>) -> Table {
    let mut table = Table::new();
  
    println!("{}: {}", style("Exports").cyan(), style(exports.len()).yellow().bright());
    table.set_header(
      vec![
        Cell::from("Export_Name").fg(Color::Green), 
        Cell::from("Offset").fg(Color::DarkCyan), 
        Cell::from("RVA").fg(Color::DarkYellow),
      ]
    );
  
    let mut export_names = String::new();
    let mut lib_name = String::new();
    let mut offsets = String::new();
    let mut rvas = String::new();
  
    for i in exports {
      if let Some(n) = i.name {
        export_names.push_str(format!("{n}\n").as_str());
      }
      
      if let Some(off) = i.offset {
        offsets.push_str(format!("0x{:x}\n", off).as_str());
      }
  
      rvas.push_str(format!("0x{:x}\n", i.rva).as_str());
    }
  
    export_names.pop();
    lib_name.pop();
    offsets.pop();
    rvas.pop();
  
    let row = Row::from(vec![
      Cell::from(export_names).fg(Color::Green),
      Cell::from(offsets).fg(Color::DarkCyan),
      Cell::from(rvas).fg(Color::DarkYellow),
    ]);
  
    table.add_row(row);
    table
  }

  /**Function returns a list of imported function found in the binary in a table like format.
   * Params:
   *  imports: &Vec<Import>
   * Returns Table
   */
  pub fn get_imports(imports: &Vec<Import>) -> Table {
    let mut table = Table::new();

    table.set_header(
      vec![
        Cell::from("Import_Name").fg(Color::Green),
        Cell::from("DLL").fg(Color::DarkCyan),
        Cell::from("Offset").fg(Color::DarkYellow),
        Cell::from("RVA").fg(Color::Red),
        Cell::from("Ordinal").fg(Color::Yellow),
      ]
    );

    let mut names = String::new();
    let mut dll_names = String::new();
    let mut offsets = String::new();
    let mut rvas = String::new();
    let mut ord = String::new();

    for i in imports {
      names.push_str(format!("{}\n", i.name).as_str());
      dll_names.push_str(format!("{}\n", i.dll).as_str());
      offsets.push_str(format!("0x{:x}\n", i.offset).as_str());
      rvas.push_str(format!("0x{:x}\n", i.rva).as_str());
      ord.push_str(format!("0x{:x}\n", i.ordinal).as_str());
    }

    names.pop();
    dll_names.pop();
    offsets.pop();
    rvas.pop();
    ord.pop();

    table.add_row(
      Row::from(vec![
        Cell::from(names).fg(Color::Green),
        Cell::from(dll_names).fg(Color::DarkCyan),
        Cell::from(offsets).fg(Color::DarkYellow),
        Cell::from(rvas).fg(Color::Red),
        Cell::from(ord).fg(Color::Yellow),
      ])
    );

    table
  }

  /**Funtion creates the config file if not already created.
   * Params:
   *  config_path: &str {The path to where the config file will be created}
   * Returns bool
   */
  pub fn create_config_file(config_path: &str) -> bool {
    let data = DF_CONFIG_D;

    match OpenOptions::new().read(true).write(true).create(true).open(config_path) {
      Ok(mut s) => {
        if let Ok(f) = s.write(data.as_bytes()) {
          println!("Config.json generated with {f} bytes");
          true
        }
        else {
          println!("{}: Failed to create config", style("Error").red().bright()); 
          return false;
        }
      },
      Err(e) => {
        println!("{}: failed to create config file - {}", style("Error").red().bright(), style(e).cyan());
        false
      }
    }
  }

  /**Function is wrapper for current_dir()
   * Params:
   *  None
   * Returns Option<String>
   */
  pub fn get_pwd() -> Option<String> {
    let mut out = String::from("");
    
    match std::env::current_dir() {
      Ok(mut s) => {
        if let Ok(o) = s.as_mut_os_string().clone().into_string() {
          out.push_str(o.as_str());
        }
        else {
          println!("{}: Unable to get present working diretory", style("Error").red().bright());
          return None;
        }
      }
      Err(e) => {
        println!("{}: Unable to get present working diretory - {}", style("Error").red().bright(), style(e).cyan());
        return None;
      }
    }
    
    Some(out)
  }

  /**function expands environment variables as specified by the user.
   * Params:
   *  input: &str {The environment variable}
   * Returns Option<String>
   */
  pub fn expand_env_var(input: &str) -> Option<String> {

    if let Some(e) = std::env::var_os(input) {
      if let Ok(temp) = e.into_string() {
        Some(temp)
      }
      
      else { return None; }
    }

    else {
      return None;
    }
  }

  /**Function checks if the config file exists
   * Params:
   *  path: &str {The path to the config file}
   * Returns Result<(), GeneralError>
   */
  pub fn check_config_exists(path: &str) -> Result<(), GeneralError> {
    match std::fs::File::open(path) {
      Ok(s) => {
        return Ok(());
      }
      Err(e) => {
        return Err(GeneralError::Io { source: e });
      }
    }
  }

  /**Functio checks if the current working directory is in the project root, release and debug directories.
   * Params:
   *  None,
   * Returns Result<Option<ConfigPath>, GeneralError>
   */
  pub fn check_current_path() -> std::result::Result<Option<ConfigPath>, GeneralError> {
    let mut path = String::new();

    if let Some(s) = Self::get_pwd() {
      path.push_str(s.as_str());
    }

    let mut _delim = "";
    match std::env::consts::OS {
      "windows" =>  { _delim = "\\"; }
      _ =>          { _delim = "/"; }
    }

    let split_path: Vec<&str> = path.split(_delim).collect();
    match split_path[split_path.len()-1].to_lowercase().as_str() {
      "release" =>    { return Ok(Some(ConfigPath::Release)); }
      "debug" =>      { return Ok(Some(ConfigPath::Debug)); }
      "pe_potato" =>  { return Ok(Some(ConfigPath::Root)); }
      _ =>            { return Ok(None); }
    }
  }

  /**Function loads the config file into memory and reads the value for each key.
   * Params:
   *  settings: &mut CmdSettings {The config settings}
   * Returns Result<()>
   */
  pub fn load_config_file(settings: &mut CmdSettings) -> std::io::Result<()> {
    let mut output = String::new();
    let mut pwd = ConfigPath::Unknown;
    let mut _path_str = "";

    // Get the current directory.
    // Checks if the user is in the project, root, release, or debug directory.
    if let Ok(p) = Self::check_current_path() {
      if let Some(pth) = p {
        pwd = pth;
      }
    }

    if pwd == ConfigPath::Debug || pwd == ConfigPath::Release {
      match std::env::consts::OS {
        "windows" =>  { _path_str = W_DBG_REL_PATH; }
        _ =>          { _path_str = L_DBG_REL_PATH; }
      }
    }

    else if pwd == ConfigPath::Root {
      _path_str = CONFIG_JSON;
    }

    else if pwd == ConfigPath::Unknown {
      println!("{}: Unable to find config.json.\nThis is likely because you are not executing the binary from the projects root directory.",
      style("Error").red().bright());
    }

    // Create the config if it does not exist.
    if let Err(_) = Self::check_config_exists(_path_str) {
      Self::create_config_file(_path_str);
    }

    // Read the config file into a buffer.
    let path = Path::new(_path_str);
    let mut buffer: Vec<u8> = Default::default();

    if let Ok(r) = read(path) {
      buffer = r;
    }

    match String::from_utf8(buffer) {
      Ok(s) => {
        output.push_str(s.as_str());
      },
      Err(_) => {}
    }

    // Parse the buffer as json.
    let mut json_object = CmdSettingsJson::default();
    match serde_json::from_str::<CmdSettingsJson>(&output.clone()) {
      Ok(s) => {
        json_object = s;
      },
      Err(e) => {
        println!("{}: Unable to parse config file {}", style("Error").red().bright(), style(format!("{:?}", e)));
      }
    };

    Self::parse_config_file(settings, &json_object)?;
    Ok(())
  }

  /**Function parses each option in the config file and verifies if the provided values are correct.
   * Params:
   *  settings: &mut CmdSettings            {The config settings}
   *  json_obj: &mut CmdSettingsJson        {The content of the json config file}
   * Returns Result<()>
   */
  pub fn parse_config_file(settings: &mut CmdSettings, json_object: &CmdSettingsJson) -> std::io::Result<()> {
    let get_env = |input: String| -> Option<String> {
      let f_char: Vec<char> = input.clone().chars().collect();
      if f_char.len() == 0 { return None; }

      match f_char[0] {
        '$' => {
          let temp_string = String::from(&input[1..]);

          if let Some(s) = Self::expand_env_var(temp_string.as_str()) {
            Some(s)
          }

          else { None }
        }

        _ => {
          None
        }
      }
    };
    
    if let Some(vt_api) = json_object.vt_api_key.clone() {  
      if let Some(s) = get_env(vt_api.clone()) {
        settings.vt_api_key.push_str(s.as_str());
      }
      
      else if vt_api.len() >= 32 {
        settings.vt_api_key.push_str(vt_api.as_str());
      }
    }

    if let Some(vt_enable_search) = json_object.vt_enable_search.clone() {
      settings.vt_enable_search = vt_enable_search;
    }

    if let Some(mb_api) = json_object.mb_api_key.clone() {
      if let Some(s) = get_env(mb_api.clone()) {
        settings.mb_api_key.push_str(s.as_str());
      }

      else { settings.mb_api_key.push_str(mb_api.as_str()); }
    }

    if let Some(mb_enable_download) = json_object.mb_enable_download.clone() {
      settings.mb_enable_download = mb_enable_download;
    }

    if let Some(mb_enable_search) = json_object.mb_enable_search.clone() {
      settings.mb_enable_search = mb_enable_search;
    }

    Ok(())
  }
}
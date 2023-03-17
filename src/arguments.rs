use clap::{Parser, Subcommand, Args};
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
use std::path::Path;
use std::str::Split;
use std::{
  fs::read,
};
use comfy_table::{Table, Cell, Row, Color};
use reqwest::{
  blocking::ClientBuilder, Method
};

mod av_json;
use av_json::*;

mod config_options {
  pub const CONFIG_FILE: &str = "config.conf";
  pub const ENABLE_VT_SEARCH: &str = "enable_virustotal_search";
  pub const API_KEY: &str = "apikey";
}

#[derive(Debug, Clone, Default)]
pub struct CmdSettings {
  pub api_key: String,
  pub auto_search_vt: bool,
  pub file_hash: String,
}

impl CmdSettings {
  pub fn new(file_hash: String) -> Self {
    Self {
      api_key: String::new(),
      auto_search_vt: false,
      file_hash: file_hash,
    }
  }
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
  VirusTotal(VtArgs),
  Bin(BinArgs),
}

#[derive(Args, Debug, Clone, Default)]
pub struct VtArgs {
  #[clap(short, long)]
  /// The file name or path
  pub filename: Option<String>,
  
  #[clap(long, default_value_if("vt", Some("false"), Some("true")), min_values(0))]
  /// Shows a query on virus total. Must be enabled in the config file.
  pub vt: bool,

  #[clap(long)]
  /// Manually query virus total with a hash.
  pub vt_hash: Option<String>,

  #[clap(short, long, default_value_if("general-info", Some("false"), Some("true")), min_values(0))]
  /// Combines results from virus total and resulting from parsing the binary
  pub general_info: bool,
}

impl VtArgs {
  pub fn count_valid_flags(&self) -> usize {
    let mut count: usize = 0;
    
    if self.vt == true              { count += 1 }
    if self.general_info == true    { count += 1 }

    count
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
}

impl Arguments {

  /**Function unpacks the AnalysisResults struct into a vec so user does not have to manually extract data from 82 fields.
   * Params:
   *  d: AnalysisResult {The struct to unpack}
   * Returns Vec<AVProvider>
   */
  pub fn get_av_provider_data(d: AnalysisResults) -> Vec<AVProvider> {
    let mut out: Vec<AVProvider> = Default::default();
    if let Some(d) = d.Bkav                   { out.push(d); }
    if let Some(d) = d.Lionic                 { out.push(d); }
    if let Some(d) = d.Elastic                { out.push(d); }
    if let Some(d) = d.DrWeb                  { out.push(d); }
    if let Some(d) = d.MicroWorld_eScan       { out.push(d); }
    if let Some(d) = d.CMC                    { out.push(d); }
    if let Some(d) = d.CAT_QuickHeal          { out.push(d); }
    if let Some(d) = d.McAfee                 { out.push(d); }
    if let Some(d) = d.Cylance                { out.push(d); }
    if let Some(d) = d.VIPRE                  { out.push(d); }
    if let Some(d) = d.Sangfor                { out.push(d); }
    if let Some(d) = d.K7AntiVirus            { out.push(d); }
    if let Some(d) = d.Alibaba                { out.push(d); }
    if let Some(d) = d.K7GW                   { out.push(d); }
    if let Some(d) = d.CrowdStrike            { out.push(d); }
    if let Some(d) = d.Arcabit                { out.push(d); }
    if let Some(d) = d.BitDefenderTheta       { out.push(d); }
    if let Some(d) = d.VirIT                  { out.push(d); }
    if let Some(d) = d.Cyren                  { out.push(d); }
    if let Some(d) = d.SymantecMobileInsight  { out.push(d); }
    if let Some(d) = d.Symantec               { out.push(d); }
    if let Some(d) = d.tehtris                { out.push(d); }
    if let Some(d) = d.ESET_NOD32             { out.push(d); }
    if let Some(d) = d.APEX                   { out.push(d); }
    if let Some(d) = d.Paloalto               { out.push(d); }
    if let Some(d) = d.ClamAV                 { out.push(d); }
    if let Some(d) = d.Kaspersky              { out.push(d); }
    if let Some(d) = d.BitDefender            { out.push(d); }
    if let Some(d) = d.NANO_Antivirus         { out.push(d); }
    if let Some(d) = d.SUPERAntiSpyware       { out.push(d); }
    if let Some(d) = d.Tencent                { out.push(d); }
    if let Some(d) = d.Trustlook              { out.push(d); }
    if let Some(d) = d.TACHYON                { out.push(d); }
    if let Some(d) = d.F_Secure               { out.push(d); }
    if let Some(d) = d.Baidu                  { out.push(d); }
    if let Some(d) = d.Zillya                 { out.push(d); }
    if let Some(d) = d.TrendMicro             { out.push(d); }
    if let Some(d) = d.McAfee_GW_Edition      { out.push(d); }
    if let Some(d) = d.Trapmine               { out.push(d); }
    if let Some(d) = d.FireEye                { out.push(d); }
    if let Some(d) = d.Sophos                 { out.push(d); }
    if let Some(d) = d.SentinelOne            { out.push(d); }
    if let Some(d) = d.Avast_Mobile           { out.push(d); }
    if let Some(d) = d.Jiangmin               { out.push(d); }
    if let Some(d) = d.Webroot                { out.push(d); }
    if let Some(d) = d.Avira                  { out.push(d); }
    if let Some(d) = d.Antiy_AVL              { out.push(d); }
    if let Some(d) = d.Kingsoft               { out.push(d); }
    if let Some(d) = d.Gridinsoft             { out.push(d); }
    if let Some(d) = d.Xcitium                { out.push(d); }
    if let Some(d) = d.Microsoft              { out.push(d); }
    if let Some(d) = d.ViRobot                { out.push(d); }
    if let Some(d) = d.ZoneAlarm              { out.push(d); }
    if let Some(d) = d.GData                  { out.push(d); }
    if let Some(d) = d.Google                 { out.push(d); }
    if let Some(d) = d.BitDefenderFalx        { out.push(d); }
    if let Some(d) = d.AhnLab_V3              { out.push(d); }
    if let Some(d) = d.Acronis                { out.push(d); }
    if let Some(d) = d.VBA32                  { out.push(d); }
    if let Some(d) = d.ALYac                  { out.push(d); }
    if let Some(d) = d.MAX                    { out.push(d); }
    if let Some(d) = d.Panda                  { out.push(d); }
    if let Some(d) = d.Zoner                  { out.push(d); }
    if let Some(d) = d.TrendMicro_HouseCall   { out.push(d); }
    if let Some(d) = d.Rising                 { out.push(d); }
    if let Some(d) = d.Yandex                 { out.push(d); }
    if let Some(d) = d.Ikarus                 { out.push(d); }
    if let Some(d) = d.MaxSecure              { out.push(d); }
    if let Some(d) = d.Fortinet               { out.push(d); }
    if let Some(d) = d.AVG                    { out.push(d); }
    if let Some(d) = d.Cybereason             { out.push(d); } 
    if let Some(d) = d.Avast                  { out.push(d); }

    out
  }

  /**Function queries virus total for general info about the sample.
   * Params:
   *  hash_id:  &str {The hash of the sample}
   *  apikey:   &str {The virus total api key}
   *  cpu:      bool {Tells us whether the cpu is 64 or 32}
   * Returns nothing
   */
  pub fn get_general_info(hash_id: &str, apikey: &str) -> () {
    let mut table = Table::new();
    let mut section_table = Table::new();
    let text = Self::query_virus_total(hash_id, apikey);

    // Deserialize the json object in another thread.
    let (tx, rx) = std::sync::mpsc::channel::<VtJsonOutput>();
    std::thread::spawn(Box::new(move || {
      match serde_json::from_str::<VtJsonOutput>(&text) {
        Ok(s) => {

          // Send the results back to the main thread.
          match tx.send(s) {
            Ok(_) => {},
            Err(e) => {
              println!("{e}");
            }
          }
        },
        Err(e) => {
          println!("{e}");
        }
      }
    }));

    // Receives the data.
    let mut output_data = VtJsonOutput::default();
    match rx.recv() {
      Ok(s) => {
        output_data = s;
      },
      Err(_) => {}
    }

    // Prepares the strings to hold the information to be displayed in the table.
    let mut names = String::new();
    let mut bin_size: usize = 0;
    let mut filetype = String::new();
    let mut arch = String::new();
    let mut subsys = String::new();
    let mut comp = String::new();
    let mut pack = String::new();
    let mut entropy: f32 = 0.0;
    let mut number_of_sections: usize = 0;
    let mut family = String::new();
    let mut md5_hash = String::new();
    let mut sha256 = String::new();
    let mut detections: usize = 0;
    let mut no_detections: usize = 0;

    let mut detect_it_easy = DetectItEasy::default();
    let mut pe_info = PeInfo::default();
    let mut stats = LastAnalysisStats::default();
    let mut sections: Vec<VtSection> = Default::default();
    
    // Updates each string and structure with data.
    if let Some(data) = output_data.data {
      if let Some(att) = data.attributes {
        if let Some(name) = att.names {
          names.push_str(name[0].as_str());
        }

        if let Some(size) = att.size {
          bin_size = size;
        }

        if let Some(md5) = att.md5 {
          md5_hash.push_str(md5.as_str());
        }

        if let Some(sha) = att.sha256 {
          sha256.push_str(sha.as_str());
        }

        if let Some(detect) = att.detectiteasy {
          detect_it_easy = detect;
        }

        if let Some(pe) = att.pe_info {
          pe_info = pe;
          
          if let Some(s) = pe_info.sections {
            sections = s;
            number_of_sections = sections.len().clone();
          }
        }

        if let Some(av) = att.last_analysis_stats {
          stats = av;
        }

        if let Some(threat) = att.popular_threat_classification {
          if let Some(label) = threat.suggested_threat_label {
            family.push_str(label.as_str());
          }
        }
      }
    }

    if let Some(ovr) = pe_info.overlay {
      if let Some(e) = ovr.entropy {
        entropy = e;
      }
    }

    if let Some(file) = detect_it_easy.filetype {
      filetype.push_str(file.as_str());

      match filetype.as_str() {
        "PE64" => { arch.push_str("64-bit") }
        "PE32" => { arch.push_str("32-bit") }
        _ => {}
      }
    }

    if let Some(values) = detect_it_easy.values {
      for i in values {
        
        if let Some(t) = i._type {
          match t.as_str() {
            "Compiler" => {

              if let Some(n) = i.name {
                comp.push_str(n.as_str());
              }
            }

            "Packer" => {
              
              if let Some(n) = i.name {
                pack.push_str(n.as_str());
              }
            }

            _ => {}
          }
        }

        if let Some(inf) = i.info {
          subsys.push_str(inf.as_str());
          subsys.push(' ');
        }
      }
    }

    if let Some(av) = stats.malicious {
      detections = av;
    }

    if let Some(av) = stats.undetected {
      no_detections = av;
    }

    let mut label_col = String::new();      // Will store all labels.
    let mut value_col = String::new();      // Will store all values.

    label_col.push_str(
      format!("FileName\nFileSize\nFileType\nCpu\nSubsystem\nCompiler\nPacker\nSections\nEntropy\nFamily\nDetected\nUndetected\nMD5\nSHA256").as_str()
    );

    value_col.push_str(
      format!("{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}", 
      names, bin_size, filetype, arch, subsys, comp, pack, number_of_sections, entropy, family, detections, no_detections, md5_hash, sha256).as_str()
    );

    table.add_row(vec![
      Cell::from(label_col).fg(Color::Yellow),
      Cell::from(value_col).fg(Color::DarkCyan),
    ]);

    // Sets the header for the table.
    section_table.set_header(vec![
      Cell::from("Name").fg(Color::Yellow),
      Cell::from("Virtual Address").fg(Color::Yellow),
      Cell::from("Virtual Size").fg(Color::Yellow),
      Cell::from("Raw Size").fg(Color::Yellow),
      Cell::from("Entropy").fg(Color::Yellow),
      Cell::from("MD5").fg(Color::Yellow),
    ]);

    let mut s_names = String::new();
    let mut s_va = String::new();
    let mut s_vs = String::new();
    let mut s_size = String::new();
    let mut s_entropy = String::new();
    let mut s_md5 = String::new();

    // Adds the data to each row.
    for i in sections {
      if let Some(n) = i.name {
        s_names.push_str(format!("{n}\n").as_str());
      }

      if let Some(virt_a) = i.virtual_address {
        s_va.push_str(format!("0x{:X}\n", virt_a).as_str());
      }

      if let Some(vsize) = i.virtual_size {
        s_vs.push_str(format!("0x{:X}\n", vsize).as_str());
      }

      if let Some(rs) = i.raw_size {
        s_size.push_str(format!("{rs}\n").as_str());
      }

      if let Some(e) = i.entropy {
        s_entropy.push_str(format!("{e}\n").as_str());
      }

      if let Some(m) = i.md5 {
        s_md5.push_str(format!("{m}\n").as_str());
      }
      
    }

    // Remove the new line character at the end of every string.
    s_names.pop();
    s_va.pop();
    s_vs.pop();
    s_size.pop();
    s_entropy.pop();
    s_md5.pop();

    // Adds each row to the table.
    section_table.add_row(vec![
      Cell::from(s_names).fg(Color::Red),
      Cell::from(s_va).fg(Color::Red),
      Cell::from(s_vs).fg(Color::Red),
      Cell::from(s_size).fg(Color::Red),
      Cell::from(s_entropy).fg(Color::Red),
      Cell::from(s_md5).fg(Color::Red),
    ]);

    println!("{table}");
    println!("{section_table}");
  }


  /**Function parses and displays information about a query from virus total and determines
   * what information will be displayed to the screen.
   * Params:
   *  &self,
   *  settings:      &mut CmdSettings {Contains the file hash and the api key}
   *  sh_everything: bool             {When true, will display all information returned from virus total}
   * Returns std::io::Result<()>
   */
  pub fn vt_search(&self, settings: &mut CmdSettings, sh_everything: bool) -> std::io::Result<()> {
    // Create a default struct and then update it.
    let mut av = VtArgs::default();
    if let Some(v) = self.command.clone() {

      match v {
        Action::VirusTotal(args) => { av = args; }
        _ => {}
      }
    }
    
    // Get the apu key from the config file.
    Self::load_config_file(settings).unwrap();

    if settings.auto_search_vt.clone() == true {
      if settings.file_hash.len() > 0 {
        
        // This will only execute if the specifies a file or a hash with no arguments.
        if av.count_valid_flags() < 1 {
          println!("{}: \n\t-f <Path> [OPTIONS]\n\t--vt-hash <Hash> [OPTIONS]", style("Syntax Error").red().bright());
          return Ok(());  
        }

        else {
          println!("Querying [{}] on Virus Total", style(settings.file_hash.clone()).cyan());
        }

        if av.vt == true {
          Self::search_virus_total(&settings.file_hash, &settings.api_key)?;
        }
  
        if av.general_info == true {
          Self::get_general_info(&settings.file_hash, &settings.api_key);
        }
      }

      else {
        println!("{}: \n\t-f <Path> [OPTIONS]\n\t--vt-hash <Hash> [OPTIONS]", style("Syntax Error").red().bright());
      }
    }

    else {
      println!("{}: Virus Total search must be enabled in the config file", style("Error").red().bright());
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
      Cell::from("Name").fg(Color::DarkCyan),
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
      Cell::from(label_string).fg(Color::DarkCyan),
      Cell::from(size_string).fg(Color::Yellow),
      Cell::from(rva_string).fg(Color::Yellow),
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
        Cell::from(label_string).fg(Color::DarkCyan),
        Cell::from(value_string).fg(Color::Yellow),
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
        Err(e) => {}
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

  /**Function queries the virus total api and returns a string with the json response.
   * Params:
   *  hash_id: &str {The hash to query}
   *  apikey: &str  {The users api key}
   * Returns String
   */
  pub fn query_virus_total(hash_id: &str, apikey: &str) -> String {
    let base_url = format!("https://www.virustotal.com/api/v3/files/{hash_id}");
  
    let builder = ClientBuilder::new()
                                  .build().unwrap().request(Method::GET, base_url)
                                  .header("x-apikey", apikey);
    
    let request = builder.send().unwrap();
    let text = request.text().unwrap();

    text
  }

  /**Function makes a GET reuqest to the virus total api query a hash for the input file.
   * Params:
   *  hash_id: &str {The file hash}
   *  apikey: &str  {The Virus Total api key}
   * Returns nothing
   */
  pub fn search_virus_total(hash_id: &str, apikey: &str) -> std::io::Result<()> {
    let text = Self::query_virus_total(hash_id, apikey);

    // Deserialize the json object in another thread.
    let (tx, rx) = std::sync::mpsc::channel::<VtJsonOutput>();
    std::thread::spawn(Box::new(move || {
      match serde_json::from_str::<VtJsonOutput>(&text) {
        Ok(s) => {

          // Send the results back to the main thread.
          match tx.send(s) {
            Ok(_) => {},
            Err(e) => {
              println!("{e}");
            }
          }
        },
        Err(e) => {
          println!("{e}");
        }
      }
    }));

    // receive the data.
    let mut output_data = VtJsonOutput::default();
    match rx.recv() {
      Ok(s) => {
        output_data = s;
      },
      Err(e) => {}
    }
    
    // Setup a table.
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("Av_Engine").fg(Color::Yellow),
      Cell::from("Category").fg(Color::Green),
      Cell::from("Result").fg(Color::Red),
      Cell::from("Version").fg(Color::DarkCyan),
      Cell::from("Method").fg(Color::DarkYellow),
      Cell::from("Engine_Update").fg(Color::Magenta),
    ]);

    // Unpack the AnalysisResult struct and construct the table.
    let mut av: Vec<AVProvider> = Default::default();
    let mut matches = false;

    if let Some(o) = output_data.data {
      if let Some(att) = o.attributes {
        if let Some(results) = att.last_analysis_results {
          av = Self::get_av_provider_data(results);
          matches = true;
        }
      }
    }

    for i in av {
      
      let mut av = String::from("None");
      let mut method = String::from("None");
      let mut update = String::from("None");
      let mut category = String::from("None");
      let mut result = String::from("None");
      let mut version = String::from("None");

      if let Some(a) = i.engine_name {
        av.clear();
        av.push_str(a.as_str());
      }

      if let Some(m) = i.method {
        method.clear();
        method.push_str(m.as_str());
      }

      if let Some(u) = i.engine_update {
        update.clear();
        update.push_str(u.as_str());
      }

      if let Some(c) = i.category {
        category.clear();
        category.push_str(c.as_str());
      }

      if let Some(r) = i.result {
        result.clear();
        result.push_str(r.as_str());
      }

      if let Some(v) = i.engine_version {
        version.clear();
        version.push_str(v.as_str());
      }

      let mut c_av = Cell::from(av.clone());
      let mut c_method = Cell::from(method.clone());
      let mut c_update = Cell::from(update.clone());
      let mut c_category = Cell::from(category.clone());
      let mut c_result = Cell::from(result.clone());
      let mut c_version = Cell::from(version.clone());

      match av.as_str() {
        "None" => {}
        _ => { c_av = Cell::from(av.clone()).fg(Color::Yellow); }
      }

      match method.as_str() {
        "None" => {}
        _ => { c_method = Cell::from(method.clone()).fg(Color::DarkYellow); }
      }

      match update.as_str() {
        "None" => {}
        _ => { c_update = Cell::from(update.clone()).fg(Color::Magenta); }
      }
      
      match category.as_str() {
        "type-unsupported" => { c_category = Cell::from(category).fg(Color::Blue); }
        "undetected" =>       { c_category = Cell::from(category).fg(Color::Green); }
        "malicious" =>        { c_category = Cell::from(category).fg(Color::Red); }
        _ => {}
      }

      match result.as_str() {
        "None" => {}
        _ => { c_result = Cell::from(result).fg(Color::Red); }
      }

      match version.as_str() {
        "None" => {}
        _ => { c_version = Cell::from(version).fg(Color::DarkCyan); }
      }

      let row = Row::from(vec![
        c_av,
        c_category,
        c_result,
        c_version,
        c_method,
        c_update,
      ]);

      table.add_row(row);
    }

    if matches == true {
      println!("{table}");
    }

    else {
      println!("No matches found");
    }

    Ok(())
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

  /**Function loads the config file into memory and reads the value for each key.
   * Params:
   *  settings: &mut CmdSettings {The config settings}
   * Returns Result<()>
   */
  pub fn load_config_file(settings: &mut CmdSettings) -> std::io::Result<()> {
    let mut string_buf = String::new();
    let path = Path::new(config_options::CONFIG_FILE);
    let buffer = read(path)?;

    match String::from_utf8(buffer) {
      Ok(s) => {
        string_buf.push_str(s.as_str());
      },
      Err(_) => {}
    }

    let mut split_buffer: Vec<&str> = Default::default();
    let pattern = Self::is_split_valid(string_buf.clone());
    match pattern {
      SplitType::CarriageNewLine => {
        split_buffer = string_buf.split("\r\n").collect();
      }

      SplitType::NewLine =>         {
        split_buffer = string_buf.split("\n").collect();
      }

      SplitType::Unknown =>         {
        
      }
    }

    for i in split_buffer.clone() {
      let line = String::from(i);

      let split_keys: Vec<&str> = line.split('=').collect();
      if split_keys.len() > 1 {
        Self::parse_config_file(split_keys, settings);
      }  
    }

    // println!("{:#?}", settings);
    Ok(())
  }

  /**Function parses each option in the config file and verifies if the provided values are correct.
   * Params:
   *  pair:     Vec<&str>        {The key and the value}
   *  settings: &mut CmdSettings {The config settings}
   * Returns nothing
   */
  pub fn parse_config_file(pair: Vec<&str>, settings: &mut CmdSettings) -> () {
    match pair[0] {
      config_options::ENABLE_VT_SEARCH => {
        match pair[1] {
          "true" =>   { settings.auto_search_vt = true; }
          "false" =>  { settings.auto_search_vt = false; }
          _ =>        {}
        }
      }

      config_options::API_KEY =>                    {
        if pair[1].len() >= 64 {
          settings.api_key.push_str(pair[1]);
        }
      }

      _ => {
        println!("{}? unknown configuration option", style(pair[1]).yellow().bright());
      }
    }
  }

  pub fn is_split_valid(buffer: String) -> SplitType {
    let mut test_split: Vec<&str> = buffer.split("\r\n").collect();
    if test_split.len() > 1 {
      return SplitType::CarriageNewLine;
    }

    test_split = buffer.split("\n").collect();
    if test_split.len() > 1 {
      return SplitType::NewLine;
    }

    return SplitType::Unknown;
  }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SplitType {
  NewLine,
  CarriageNewLine,
  Unknown,
}
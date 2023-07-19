use console::style;
use comfy_table::{Table, Cell, Row, Color, ContentArrangement};
use reqwest::{blocking::multipart::{Form, Part}, header::{USER_AGENT, HOST, ACCEPT, CONTENT_LENGTH}};
use serde::Deserialize;
use super::{
  vt_file_json::*,
  ClientBuilder, Method, 
  GeneralError, vt_behaviour_json::{
    BehaviorJsonOutput, IpTraffic, HttpConversations, MitreAttackTechniques, RegistryKeys, SigmaAnalysisResults, SigmaMatchContext
  },
  CombinedTable, CTerm,
};

#[derive(Debug, Clone, PartialEq)]
pub enum FileAction {
  Deleted,
  Changed,
  Opened,
  Written,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct VtErrors {
  pub error: VhttpError,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct VhttpError {
  pub message: String,
  pub code: String,
}

#[derive(Debug, Clone, Default)]
pub struct VtArgType {
  pub attributes: bool,
  pub behaviour: bool,
}
pub struct VirusTotal {}
impl VirusTotal {

  pub fn get_preset_cell(value: bool) -> Cell {
    // match "" {
    //   "true" => {}
    //   "false" => {}
    //   _ => {}
    // }
    if value == false {
      return Cell::from("false")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Red);
    }
    else {
      return Cell::from("true")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Green);
    }
  }

  pub fn get_preset_row(name: &str, value: bool) -> Row {
    Row::from(vec![
      Cell::from(name)
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow),
      Self::get_preset_cell(value)
    ])
  }

  #[allow(dead_code, unused_assignments)]
  pub fn get_structure_stats(file_data: FileJsonOutput, behaviour_data: BehaviorJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("Structure Statistics\n(File Attributes)")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));
    
    let mut table = Table::new();
    table.set_header(Row::from(vec![
      Cell::from("Key").bg(Color::DarkBlue).fg(Color::White).set_alignment(comfy_table::CellAlignment::Center),
      Cell::from("Information Available").bg(Color::DarkBlue).fg(Color::White).set_alignment(comfy_table::CellAlignment::Center),
    ]));

    let f_data = file_data.data?.attributes?;
    let b_data = behaviour_data.data?;
    let mut rows: Vec<Row> = Default::default();

    if let Some(_) = f_data.elf_info                         {
      rows.push(Self::get_preset_row("ELF Info", true));
    }
    else {
      rows.push(Self::get_preset_row("ELF Info", false));
    }

    if let Some(_) = f_data.dot_net_assembly                 {
      rows.push(Self::get_preset_row(".Net-Assembly", true));
    }
    else {
      rows.push(Self::get_preset_row(".Net-Assembly", false));
    }

    if let Some(_) = f_data.type_description                 {
      rows.push(Self::get_preset_row("Type Description", true))
    }
    else {
      rows.push(Self::get_preset_row("Type Description", false))
    }

    if let Some(_) = f_data.tlsh                             {
      rows.push(Self::get_preset_row("Tlsh", true));
    }
    else {
      rows.push(Self::get_preset_row("Tlsh", false));
    }

    if let Some(_) = f_data.vhash                            {
      rows.push(Self::get_preset_row("Vhash", true))
    }
    else {
      rows.push(Self::get_preset_row("Vhash", false))
    }

    if let Some(_) = f_data.trid                             {
      rows.push(Self::get_preset_row("Trid", true));
    }
    else {
      rows.push(Self::get_preset_row("Trid", false));
    }

    if let Some(_) = f_data.crowdsourced_yara_results        {
      rows.push(Self::get_preset_row("Crowdsourced Yara Results", true));
    }
    else {
      rows.push(Self::get_preset_row("Crowdsourced Yara Results", false));
    }

    if let Some(_) = f_data.creation_date                    {
      rows.push(Self::get_preset_row("Creation Date", true));
    }
    else {
      rows.push(Self::get_preset_row("Creation Date", false));
    }

    if let Some(_) = f_data.names                            {
      rows.push(Self::get_preset_row("Names", true));
    }
    else {
      rows.push(Self::get_preset_row("Names", false));
    }

    if let Some(_) = f_data.last_modification_date           {
      rows.push(Self::get_preset_row("Last Modification Date", true));
    }
    else {
      rows.push(Self::get_preset_row("Last Modification Date", false));
    }

    if let Some(_) = f_data.type_tag                         {
      rows.push(Self::get_preset_row("Type Tag", true));
    }
    else {
      rows.push(Self::get_preset_row("Type Tag", false));
    }

    if let Some(_) = f_data.times_submitted                  {
      rows.push(Self::get_preset_row("Times Submitted", true));
    }
    else {
      rows.push(Self::get_preset_row("Times Submitted", false));
    }

    if let Some(_) = f_data.total_votes                      {
      rows.push(Self::get_preset_row("Total Votes", true));
    }
    else {
      rows.push(Self::get_preset_row("Total Votes", false));
    }

    if let Some(_) = f_data.size                             {
      rows.push(Self::get_preset_row("Size", true));
    }
    else {
      rows.push(Self::get_preset_row("Size", false));
    }

    if let Some(_) = f_data.popular_threat_classification    {
      rows.push(Self::get_preset_row("Popular Threat Classification", true));
    }
    else {
      rows.push(Self::get_preset_row("Popular Threat Classification", false));
    }

    if let Some(_) = f_data.authentihash                     {
      rows.push(Self::get_preset_row("Authentihash", true));
    }
    else {
      rows.push(Self::get_preset_row("Authentihash", false));
    }

    if let Some(_) = f_data.detectiteasy                     {
      rows.push(Self::get_preset_row("Detect It Easy", true));
    }
    else {
      rows.push(Self::get_preset_row("Detect It Easy", false));
    }

    if let Some(_) = f_data.last_submission_date             {
      rows.push(Self::get_preset_row("Last Submission Date", true));
    }
    else {
      rows.push(Self::get_preset_row("Last Submission Date", false));
    }

    // if let Some(_) = f_data.sigma_analysis_results           {
    //   rows.push(Self::get_preset_row("Sigma Analysis Results", true));
    // }
    // else {
    //   rows.push(Self::get_preset_row("Sigma Analysis Results", false));
    // }

    if let Some(_) = f_data.meaningful_name                  {
      rows.push(Self::get_preset_row("Meaningful Name", true));
    }
    else {
      rows.push(Self::get_preset_row("Meaningful Name", false));
    }

    if let Some(_) = f_data.crowdsourced_ids_stats           {
      rows.push(Self::get_preset_row("Crowdsourced Ids Stats", true));
    }
    else {
      rows.push(Self::get_preset_row("Crowdsourced Ids Stats", false));
    }

    if let Some(_) = f_data.sandbox_verdicts                 {
      rows.push(Self::get_preset_row("Sandbox Verdicts", true));
    }
    else {
      rows.push(Self::get_preset_row("Sandbox Verdicts", false));
    }

    if let Some(_) = f_data.sha256                           {
      rows.push(Self::get_preset_row("SHA256", true));
    }
    else {
      rows.push(Self::get_preset_row("SHA256", false));
    }

    if let Some(_) = f_data.type_extension                   {
      rows.push(Self::get_preset_row("Type Extension", true));
    }
    else {
      rows.push(Self::get_preset_row("Type Extension", false));
    }

    if let Some(_) = f_data.tags                             {
      rows.push(Self::get_preset_row("Tags", true));
    }
    else {
      rows.push(Self::get_preset_row("Tags", false));
    }

    if let Some(_) = f_data.crowdsourced_ids_results         {
      rows.push(Self::get_preset_row("Crowdsourced Ids Results", true));
    }
    else {
      rows.push(Self::get_preset_row("Crowdsourced Ids Results", false));
    }

    if let Some(_) = f_data.last_analysis_date               {
      rows.push(Self::get_preset_row("Last Analysis Date", true));
    }
    else {
      rows.push(Self::get_preset_row("Last Analysis Date", false));
    }

    if let Some(_) = f_data.unique_sources                   {
      rows.push(Self::get_preset_row("Unique Sources", true));
    }

    else {
      rows.push(Self::get_preset_row("Unique Sources", false));
    }

    if let Some(_) = f_data.first_submission_date            {
      rows.push(Self::get_preset_row("First Submission Date", true));
    }

    else {
      rows.push(Self::get_preset_row("First Submission Date", false));
    }

    if let Some(_) = f_data.sha1                             {
      rows.push(Self::get_preset_row("SHA1", true));
    }

    else {
      rows.push(Self::get_preset_row("SHA1", false));
    }

    if let Some(_) = f_data.ssdeep                           {
      rows.push(Self::get_preset_row("SSdeep", true));
    }

    else {
      rows.push(Self::get_preset_row("SSdeep", false));
    }

    if let Some(_) = f_data.md5                              {
      rows.push(Self::get_preset_row("MD5", true));
    }

    else {
      rows.push(Self::get_preset_row("MD5", false));
    }

    if let Some(_) = f_data.pe_info                          {
      rows.push(Self::get_preset_row("PE Info", true));
    }

    else {
      rows.push(Self::get_preset_row("PE Info", false));
    }

    if let Some(_) = f_data.magic                            {
      rows.push(Self::get_preset_row("Magic", true));
    }

    else {
      rows.push(Self::get_preset_row("Magic", false));
    }

    if let Some(_) = f_data.last_analysis_stats              {
      rows.push(Self::get_preset_row("Last Analysis Stats", true));
    }

    else {
      rows.push(Self::get_preset_row("Last Analysis Stats", false));
    }

    if let Some(_) = f_data.last_analysis_results            {
      rows.push(Self::get_preset_row("Last Analysis Results", true));
    }

    else {
      rows.push(Self::get_preset_row("Last Analysis Results", false));
    }

    if let Some(_) = f_data.reputation                       {
      rows.push(Self::get_preset_row("Reputation", true));
    }

    else {
      rows.push(Self::get_preset_row("Reputation", false));
    }

    // Values stores the number of structures returned from the API query.
    let mut _meta: usize = 0;
    let mut _analysis_date: usize = 0;
    let mut _behash: usize = 0;
    let mut _calls_highlighted: usize = 0;
    let mut _command_execution: usize = 0;
    let mut _files_opened: usize = 0;
    let mut _files_written: usize = 0;
    let mut _files_deleted: usize = 0;
    let mut _files_attribute_changed: usize = 0;
    let mut _has_html_report: usize = 0;
    let mut _has_evtx: usize = 0;
    let mut _has_pcap: usize = 0;
    let mut _has_memdump: usize = 0;
    let mut _hosts_file: usize = 0;
    let mut _ids_alerts: usize = 0;
    let mut _processes_terminated: usize = 0;
    let mut _processes_killed: usize = 0;
    let mut _processes_injected: usize = 0;
    let mut _services_opened: usize = 0;
    let mut _services_created: usize = 0;
    let mut _services_started: usize = 0;
    let mut _services_stopped: usize = 0;
    let mut _services_deleted: usize = 0;
    let mut _services_bound: usize = 0;
    let mut _windows_searched: usize = 0;
    let mut _windows_hidden: usize = 0;
    let mut _mutexes_opened: usize = 0;
    let mut _mutexes_created: usize = 0;
    let mut _signals_observed: usize = 0;
    let mut _invokes: usize = 0;
    let mut _crypto_algorithims_observed: usize = 0;
    let mut _crypto: usize = 0;
    let mut _crypto_plain_text: usize = 0;
    let mut _text_decoded: usize = 0;
    let mut _text_highlighted: usize = 0;
    let mut _verdict_confidence: usize = 0;
    let mut _ja3_digest: usize = 0;
    let mut _tls: usize = 0;
    let mut _sni: usize = 0;
    let mut _subject: usize = 0;
    let mut _thumbprint: usize = 0;
    let mut _version: usize = 0;
    let mut _modules_loaded: usize = 0;
    let mut _registry_opened: usize = 0;
    let mut _registry_set: usize = 0;
    let mut _registry_deleted: usize = 0;
    let mut _mitre_attack_techniques: usize = 0;
    let mut _ip_traffic: usize = 0;
    let mut _http_conversations: usize = 0;

    // The code below will the behaviour stats
    for i in b_data {
      let att = i.attributes?;
    }

    // Place title and contents here.....

    table.add_rows(rows);
    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }

  /**Function displayed detailed information about each resource in the file.
   * Params:
   *  output_data: FileJsonOutput {The parsed json response}
   * Returns Option<CombinedTable>
   */
  pub fn get_resource_details(output_data: FileJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("Resources")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));
    
    let mut table = Table::new();

    // Set the table header.
    table.set_header(vec![
      Cell::from("Lang").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Entropy").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Chi2").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Filetype").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("SHA256").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Type").bg(Color::DarkBlue).fg(Color::White),
    ]);

    // Prepare each column.
    let mut lang = String::new();
    let mut entropy = String::new();
    let mut chi = String::new();
    let mut filetype = String::new();
    let mut sha = String::new();
    let mut _type = String::new();

    let resources = output_data.data?.attributes?.pe_info?.resource_details?;

    // For each column with data.
    for i in resources {
      if let Some(l) = i.lang {
        lang.push_str(format!("{l}\n").as_str());
      }

      if let Some(e) = i.entropy {
        entropy.push_str(format!("{e}\n").as_str());
      }

      if let Some(ch) = i.chi2 {
        chi.push_str(format!("{ch}\n").as_str());
      }

      if let Some(ft) = i.filetype {
        filetype.push_str(format!("{ft}\n").as_str());
      }

      if let Some(sh) = i.sha256 {
        sha.push_str(format!("{sh}\n").as_str());
      }

      if let Some(t) =i._type {
        _type.push_str(format!("{t}\n").as_str());
      }
    }

    lang.pop();
    entropy.pop();
    chi.pop();
    filetype.pop();
    sha.pop();
    _type.pop();

    // Add rows to the table.
    table.add_row(vec![
      Cell::from(lang).fg(Color::Red),
      Cell::from(entropy).fg(Color::Red),
      Cell::from(chi).fg(Color::Red),
      Cell::from(filetype).fg(Color::Red),
      Cell::from(sha).fg(Color::Red),
      Cell::from(_type).fg(Color::Red),
    ]);

    title.set_content_arrangement(comfy_table::ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(comfy_table::ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }

  /**Function displays detailed information about the section headers.
   * Params:
   *  output_data: FileJsonOutput {The parsed json response}
   * Returns Option<CombinedTable>
   */
  pub fn get_sections(output_data: FileJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("Section Headers")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));
    
    let mut section_table = Table::new();

    // Sets the header for the table.
    section_table.set_header(vec![
      Cell::from("Name").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Virtual Address").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Virtual Size").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Raw Size").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Entropy").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("MD5").bg(Color::DarkBlue).fg(Color::White),
    ]);

    let pe = output_data.data?.attributes?.pe_info?;
    let sections = pe.sections?;
    let mut rows: Vec<Row> = Default::default();

    // Adds the data to each row.
    for i in sections {
      let mut cells: Vec<Cell> = Default::default();

      if let Some(n) = i.name {
        cells.push(Cell::from(n).fg(Color::Green));
      }

      if let Some(virt_a) = i.virtual_address {
        cells.push(Cell::from(format!("0x{:X}", virt_a)).fg(Color::Yellow));
      }

      if let Some(vsize) = i.virtual_size {
        cells.push(Cell::from(format!("0x{:X}", vsize)).fg(Color::Yellow));
      }

      if let Some(rs) = i.raw_size {
        cells.push(Cell::from(rs).fg(Color::Yellow));
      }

      if let Some(e) = i.entropy {
        
        if e < 3.0 {
          cells.push(Cell::from(format!("{e}")).fg(Color::Blue));
        }

        else if e >= 3.0 && e < 4.5 {
          cells.push(Cell::from(format!("{e}")).fg(Color::Green));
        }
    
        else if e >= 4.5 && e < 7.0 {
          cells.push(Cell::from(format!("{e}")).fg(Color::Yellow));
        }
    
        else if e >= 7.0 {
          cells.push(Cell::from(format!("{e}")).bg(Color::DarkRed).fg(Color::White));
        }
      }

      if let Some(m) = i.md5 {
        cells.push(Cell::from(m).fg(Color::DarkCyan));
      }
      
      rows.push(Row::from(cells.clone()));
    }

    section_table.add_rows(rows);
    title.set_content_arrangement(comfy_table::ContentArrangement::DynamicFullWidth);
    section_table.set_content_arrangement(comfy_table::ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = section_table;
    Some(out)
  }


  pub fn handle_api_error(response: String) -> () {
    if let Ok(s) = serde_json::from_str::<VtErrors>(&response.clone()) {
      let msg = s.error.message;
      let code = s.error.code;

      println!(
        "{}: ({}) {} - {}", style("Error").red().bright(), 
        style("Virus Total").blue().bright(), style(msg).yellow(), style(code).cyan()
      );

      std::process::exit(0);
    }
  }


  pub fn parse_response(raw_json: bool, response: String) -> FileJsonOutput {
    if raw_json == true {
      println!("{response}");
      std::process::exit(0);
    }

    if response.len() <= 500 {
      Self::handle_api_error(response.clone());
    }
    
    // Deserialize the json object in another thread.
    let (tx, rx) = std::sync::mpsc::channel::<FileJsonOutput>();
    std::thread::spawn(Box::new(move || {
      match serde_json::from_str::<FileJsonOutput>(&response) {
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
    let mut output_data = FileJsonOutput::default();
    match rx.recv() {
      Ok(s) => {
        output_data = s;
      },
      Err(_) => {}
    }

    output_data
  }

  
  pub fn parse_behavior_response(raw_json: bool, response: String) -> BehaviorJsonOutput {
    if raw_json == true {
      println!("{response}");
      std::process::exit(0);
    }

    if response.len() <= 500 {
      Self::handle_api_error(response.clone());
    }
    
    // Deserialize the json object in another thread.
    let (tx, rx) = std::sync::mpsc::channel::<BehaviorJsonOutput>();
    std::thread::spawn(Box::new(move || {
      match serde_json::from_str::<BehaviorJsonOutput>(&response) {
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
    let mut output_data = BehaviorJsonOutput::default();
    match rx.recv() {
      Ok(s) => {
        output_data = s;
      },
      Err(_) => {}
    }

    output_data
  }

  /**Function queries virus total for general info about the sample.
   * Params:
   *  output_data: FileJsonOutput {The parsed json response}
   * Returns Option<CombinedTable>
   */
  pub fn get_general_info(output_data: FileJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("[General Information]")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));

    let mut table = Table::new();
    table.set_header(Row::from(vec![
      Cell::from("Key").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Value").bg(Color::DarkBlue).fg(Color::White),
    ]));

    // Prepares the strings to hold the information to be displayed in the table.
    let mut names = String::new();
    let mut bin_size: usize = 0;
    let mut filetype = String::new();
    let mut arch = String::new();
    let mut subsys = String::new();
    let mut comp = String::new();
    let mut pack = String::new();
    let mut entropy: f32 = 0.0;
    let mut entropy_c = Color::Blue;
    let mut number_of_sections: usize = 0;
    let mut family = String::new();
    let mut md5_hash = String::new();
    let mut sha256 = String::new();
    let mut detections: usize = 0;
    let mut no_detections: usize = 0;

    let mut detect_it_easy = DetectItEasy::default();
    let mut pe_info = PeInfo::default();
    let mut stats = LastAnalysisStats::default();
    
    let att = output_data.data?.attributes?;
    
    // Updates each string and structure with data.
    if let Some(name) = att.names {
      if name.len() > 0 {
        names.push_str(name[0].as_str());
      }
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
        number_of_sections = s.len().clone();
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

    if entropy > 3.0 && entropy < 4.5 {
      entropy_c = Color::Green;
    }

    else if entropy > 4.5 && entropy < 7.5 {
      entropy_c = Color::Yellow;
    }

    else if entropy > 7.5 {
      entropy_c = Color::Red;
    }

    let rows = vec![
      Row::from(vec![
        Cell::from("FileName").fg(Color::White), Cell::from(names).fg(Color::Green)
      ]),

      Row::from(vec![
        Cell::from("FileSize").bg(Color::DarkGrey).fg(Color::White), Cell::from(format!("{bin_size} (Bytes)")).fg(Color::Yellow)
      ]),

      Row::from(vec![
        Cell::from("FileType").fg(Color::White), Cell::from(filetype).fg(Color::Green)
      ]),

      Row::from(vec![
        Cell::from("CPU").bg(Color::DarkGrey).fg(Color::White), Cell::from(arch).fg(Color::DarkCyan)
      ]),

      Row::from(vec![
        Cell::from("SubSystem").fg(Color::White), Cell::from(subsys).fg(Color::DarkCyan)
      ]),

      Row::from(vec![
        Cell::from("Compiler").bg(Color::DarkGrey).fg(Color::White), Cell::from(comp).fg(Color::Blue)
      ]),

      Row::from(vec![
        Cell::from("Packer").fg(Color::White), Cell::from(pack).fg(Color::Green)
      ]),

      Row::from(vec![
        Cell::from("Sections").bg(Color::DarkGrey).fg(Color::White), Cell::from(number_of_sections).fg(Color::Yellow)
      ]),

      Row::from(vec![
        Cell::from("Entropy").fg(Color::White), Cell::from(entropy).fg(entropy_c)
      ]),

      Row::from(vec![
        Cell::from("Family").bg(Color::DarkGrey).fg(Color::White), Cell::from(family).fg(Color::Red)
      ]),

      Row::from(vec![
        Cell::from("Detected").fg(Color::White), Cell::from(detections).fg(Color::Yellow)
      ]),

      Row::from(vec![
        Cell::from("Undetected").bg(Color::DarkGrey).fg(Color::White), Cell::from(no_detections).fg(Color::Yellow)
      ]),

      Row::from(vec![
        Cell::from("MD5").fg(Color::White), Cell::from(md5_hash).fg(Color::DarkCyan)
      ]),

      Row::from(vec![
        Cell::from("SHA256").bg(Color::DarkGrey).fg(Color::White), Cell::from(sha256).fg(Color::DarkCyan)
      ]),
    ];

    table.add_rows(rows);
    title.set_content_arrangement(comfy_table::ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(comfy_table::ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }

  /**Function displays all the compiler products for a said binary by parse the response from the virus total api.
   * Params:
   *  output_data: FileJsonOutput {The json repsonse from virus total api}
   * Returns Option<CombinedTable>
   */
  pub fn get_compiler_products(output_data: FileJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("[Compiler Products]")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));
    
    let mut table = Table::new();

    table.set_header(vec![
      Cell::from("ID").fg(Color::Yellow),
      Cell::from("Version").fg(Color::Yellow),
      Cell::from("Count").fg(Color::Yellow),
    ]);

    let mut ids = String::new();
    let mut versions = String::new();
    let mut counts = String::new();
    
    let data = output_data.data?.attributes?.pe_info?.compiler_product_versions?;
    for i in data {

      // Correctly filter out string so split with " " works as expected.
      let filter = i.replace(",", "").replace("=", ": ");
      let split: Vec<&str> = filter.split(" ").collect();

      for idx in 0..split.len() {
        match split[idx] {
          "id:" =>        { ids.push_str(format!("{}\n", split[idx+1]).as_str()); }
          "[---]" =>      { ids.push_str("None\n"); }
          "version:" =>   { versions.push_str(format!("{}\n", split[idx+1]).as_str()); }
          "count:" =>     { counts.push_str(format!("{}\n", split[idx+1]).as_str()); }
          _ => {  }
        }
      }
    }

    ids.pop();
    versions.pop();
    counts.pop();

    table.add_row(vec![
      Cell::from(ids).fg(Color::Red),
      Cell::from(versions).fg(Color::Red),
      Cell::from(counts).fg(Color::Red),
    ]);

    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    
    out.title = title;
    out.contents = table;
    Some(out)
  }

  /**Function displays all files names from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: FileJsonOutput {The virus total api response}
   * Returns Option<CombinedTable>
   */
  pub fn get_file_names(output_data: FileJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("File Names")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));
    
    let mut table = Table::new();

    table.set_header(vec![
      Cell::from("Name").bg(Color::DarkBlue).fg(Color::White),
    ]);

    let mut rows: Vec<Row> = Default::default();
    let data = output_data.data?.attributes?.names?;
    
    for i in data {
      rows.push(Row::from(vec![
        Cell::from(i).fg(Color::Green)
      ]));
    }

    table.add_rows(rows);
    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }

  /**Function displays all tags from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: FileJsonOutput {The virus total api response}
   * Returns Option<CombinedTable>
   */
  pub fn get_tags(output_data: FileJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("[Tags]")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));
    
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("Tag Names").bg(Color::DarkBlue).fg(Color::White),
    ]);

    let data = output_data.data?.attributes?.tags?;
    let mut tags = String::new();

    for i in data {
      tags.push_str(format!("{i}\n").as_str());
    }

    tags.pop();
    table.add_row(vec![
      Cell::from(tags).fg(Color::Red),
    ]);

    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }

  /**Function displays all resource types from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: FileJsonOutput {The virus total api response}
   * Returns Option<CombinedTable>
   */
  pub fn get_resource_by_type(output_data: FileJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("[Resource by type]")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));
    
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("Resource Type").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Count").bg(Color::DarkBlue).fg(Color::White),
    ]);

    let mut rows: Vec<Row> = Default::default();
    let data = output_data.data?.attributes?.pe_info?.resource_types?;

    if let Some(icon) = data.rt_icon {
      rows.push(Row::from(vec![
        Cell::from("RT_ICON").fg(Color::Green),
        Cell::from(format!("{icon}")).fg(Color::Yellow),
      ]));
    }

    if let Some(dialog) = data.rt_dialog {
      rows.push(Row::from(vec![
        Cell::from("RT_DIALOG").fg(Color::Green),
        Cell::from(format!("{dialog}")).fg(Color::Yellow),
      ]));
    };

    if let Some(cursor) = data.rt_cursor {
      rows.push(Row::from(vec![
        Cell::from("RT_CURSOR").fg(Color::Green),
        Cell::from(format!("{cursor}")).fg(Color::Yellow),
      ]));
    }

    if let Some(acc) = data.rt_accelerator {
      rows.push(Row::from(vec![
        Cell::from("RT_ACCELERATOR").fg(Color::Green),
        Cell::from(format!("{acc}")).fg(Color::Yellow),
      ]));
    }

    if let Some(bit) = data.rt_bitmap {
      rows.push(Row::from(vec![
        Cell::from("RT_BITMAP").fg(Color::Green),
        Cell::from(format!("{bit}")).fg(Color::Yellow),
      ]));
    }

    if let Some(mani) = data.rt_manifest {
      rows.push(Row::from(vec![
        Cell::from("RT_MANIFEST").fg(Color::Green),
        Cell::from(format!("{mani}")).fg(Color::Yellow),
      ]));
    }

    if let Some(g_icon) = data.rt_group_icon {
      rows.push(Row::from(vec![
        Cell::from("RT_GROUP_ICON").fg(Color::Green),
        Cell::from(format!("{g_icon}")).fg(Color::Yellow),
      ]));
    }

    if let Some(g_cursor) = data.rt_group_cursor {
      rows.push(Row::from(vec![
        Cell::from("RT_GROUP_CURSOR").fg(Color::Green),
        Cell::from(format!("{g_cursor}")).fg(Color::Yellow),
      ]));
    }

    if let Some(_str) = data.rt_string {
      rows.push(Row::from(vec![
        Cell::from("RT_STRING").fg(Color::Green),
        Cell::from(format!("{_str}")).fg(Color::Yellow),
      ]));
    }

    if let Some(ver) = data.rt_version {
      rows.push(Row::from(vec![
        Cell::from("RT_VERSION").fg(Color::Green),
        Cell::from(format!("{ver}")).fg(Color::Yellow),
      ]));
    }

    table.add_rows(rows);
    title.set_content_arrangement(comfy_table::ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(comfy_table::ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }

  /**Function displays ip traffic from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: BehaviorJsonOutput {The virus total api file behavior response}
   * Returns Option<CombinedTable>
   */
  pub fn get_ip_traffic(output_data: BehaviorJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("[IP Traffic]")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));
    
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("IP").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Port").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Protocol").bg(Color::DarkBlue).fg(Color::White),
    ]);

    let mut rows: Vec<Row> = Default::default();
    let data = output_data.data?;
    
    for i in data {
      let mut traffic: Vec<IpTraffic> = Default::default();
      if let Some(t) = i.attributes?.ip_traffic {
        traffic = t;
      }

      for idx in traffic {
        let mut cells: Vec<Cell> = Default::default();

        if let Some(ipp) = idx.destination_ip {
          cells.push(Cell::from(ipp).fg(Color::Green));
        }

        if let Some(p) = idx.destination_port {
          cells.push(Cell::from(format!("{p}")).fg(Color::Yellow));
        }

        if let Some(pro) = idx.transport_layer_protocol {
          cells.push(Cell::from(pro).fg(Color::Red));
        }

        rows.push(Row::from(cells.clone()));
      }
    }

    table.add_rows(rows);
    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }

  /**Function displays http coversations from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: BehaviorJsonOutput {The virus total api file behavior response}
   * Returns Option<CombinedTable>
   */
  pub fn get_http_conv(output_data: BehaviorJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("[HTTP Requests]")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));
    
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("Method").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Url").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Status_code").bg(Color::DarkBlue).fg(Color::White),
    ]);

    let get_method_colour = |method: &str| {
      match method {
        "GET" =>      { return Color::Green; }
        "POST" =>     { return Color::DarkYellow; }
        "PUT" =>      { return Color::DarkCyan; }
        "UPDATE" =>   { return Color::Blue; }
        "DELETE" =>   { return Color::Red; }
        "HEAD" =>     { return Color::Cyan; }
        _ =>          { return Color::White; }
      }
    };

    let mut rows: Vec<Row> = Default::default();
    let data = output_data.data?;
    let empty_cell = Cell::from("");
    
    for i in data {
      
      let mut conv: Vec<HttpConversations> = Default::default();
      if let Some(h) = i.attributes?.http_conversations {
        conv = h;
      }

      for idx in conv {
        let mut cells: Vec<Cell> = Default::default();
        
        if let Some(m) = idx.request_method {
          cells.push(Cell::from(m.clone()).fg(get_method_colour(m.as_str())));
        }
        else {
          cells.push(empty_cell.clone());
        }

        if let Some(u) = idx.url {
          cells.push(Cell::from(u).fg(Color::DarkCyan));
        }
        else {
          cells.push(empty_cell.clone());
        }

        if let Some(s) = idx.response_status_code {
          cells.push(Cell::from(s).fg(Color::Yellow));
        }
        else {
          cells.push(empty_cell.clone());
        }

        rows.push(Row::from(cells));
      }
    }

    table.add_rows(rows);
    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }

  /**Function displays set registry keys from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: FileJsonOutput {The virus total api response}
   * Returns Option<CombinedTable>
   */
  #[allow(dead_code)]
  pub fn get_registry_keys_set(output_data: BehaviorJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();
    
    title.add_row(Row::from(vec![
      Cell::from("Registry Keys Set").fg(Color::Yellow)
    ]));
    
    let mut table = Table::new();
    table.set_header(Row::from(vec![
      Cell::from("Key").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Value").bg(Color::DarkBlue).fg(Color::White),
    ]));

    let data = output_data.data?;
    let mut d_keys: Vec<RegistryKeys> = Default::default();

    for i in data {
      let att = i.attributes?;
      
      if let Some(keys) = att.registry_keys_set {
        for idx in keys {
          d_keys.push(idx);
        }
      }
    }

    let mut rows: Vec<Row> = Default::default();
    for i in d_keys {
      let mut add_empty = false;

      if let Some(k) = i.key {
        rows.push(Row::from(vec![
          Cell::from("Key").fg(Color::White), Cell::from(k).fg(Color::Green)
        ]));

        add_empty = true;
      }

      if let Some(v) = i.value {
        rows.push(Row::from(vec![
          Cell::from("Value").fg(Color::White), Cell::from(v).fg(Color::Yellow)
        ]));
        
        add_empty = true;
      }

      if add_empty == true {
        rows.push(Row::from(vec![
          Cell::from("").bg(Color::DarkGrey)
        ]));
      }
    }

    rows.pop();
    table.add_rows(rows);
    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)  
  }


  #[allow(dead_code)]
  pub fn get_registry_keys_open(output_data: BehaviorJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();
    
    title.add_row(Row::from(vec![
      Cell::from("Registry Keys Open").fg(Color::Yellow).set_alignment(comfy_table::CellAlignment::Center)
    ]));
    
    let mut table = Table::new();
    table.set_header(Row::from(vec![
      Cell::from("Key").bg(Color::DarkBlue).fg(Color::White),
    ]));

    let data = output_data.data?;
    let mut rows: Vec<Row> = Default::default();

    for i in data {
      let att = i.attributes?;
      if let Some(keys) = att.registry_keys_opened {
        
        for idx in keys {
          rows.push(Row::from(vec![
            Cell::from(idx).fg(Color::Green)
          ]));
        }
      }

    }
  
    table.add_rows(rows);
    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)  
  }


  pub fn nth_row(colour: CTerm, counter: usize) -> Color {
    match counter {
      0 => {
        if colour == CTerm::Fg {
          return Color::White
        }

        else {
          return Color::Reset
        }
      }

      1 => {
        if colour == CTerm::Bg {
          return Color::DarkGrey;
        }

        else {
          return Color::Reset;
        }
      }

      _ => { return Color::White; }
    }
  }


  /**Function creates a simple table with column
   * Params:
   *  name:     &str {The name of the table}
   *  col_name: &str {The name of the column}
   *  data:     &str {The data to be stored in the column}
   * Returns Option<CombinedTable>
   */
  pub fn create_simple_table(name: &str, col_name: &str, data: Vec<String>) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut col_data = String::new();

    let mut title = Table::new();
    title.add_row(Row::from(vec![
      Cell::from(name).fg(Color::Yellow)
    ]));

    let mut table = Table::new();
    table.set_header(Row::from(vec![
      Cell::from(col_name).bg(Color::DarkBlue).fg(Color::White)
    ]));

    if data.len() < 1 {
      return None;
    }

    for i in data {
      col_data.push_str(i.as_str());
      col_data.push('\n');
    }

    col_data.pop();
    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    
    out.title = title;
    out.contents = table;
    Some(out)
  }


  /** */
  #[allow(dead_code)]
  pub fn get_sigma_rules(output_data: BehaviorJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    
    let mut title = Table::new();
    title.add_row(Row::from(vec![
      Cell::from("Sigma Rules")
      .fg(Color::Yellow)
      .set_alignment(comfy_table::CellAlignment::Center)
    ]));
    
    let mut table = Table::new();
    table.set_header(Row::from(vec![
      Cell::from("Key").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Value").bg(Color::DarkBlue).fg(Color::White)
    ]));
    
    let data = output_data.data?;
    let mut sigma_rules: Vec<SigmaAnalysisResults> = Default::default();
    let mut rows: Vec<Row> = Default::default();

    for i in data {
      let att = i.attributes?;
      
      if let Some(rules) = att.sigma_analysis_results {
        for idx in rules {
          sigma_rules.push(idx);
        }
      }
    }

    let extract_sigma_context = |context: SigmaMatchContext| -> Vec<Row> {
      let mut rows: Vec<Row> = Default::default();
      let mut grey_counter: usize = 0;

      if let Some(t) = context.values {

        if let Some(t) = t.terminal_session_id {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Terminal Session ID").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Yellow),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.process_guid {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Process Guid").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Yellow),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.process_id {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Process ID").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Yellow),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.product {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Product").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Green),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.desription {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Description").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Green),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.company {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Company").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::DarkCyan),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.parent_process_guid {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Parent Process Guid").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Yellow),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.user {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("User").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Green),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.hashes {
          let hashes: Vec<&str> = t.split(",").collect();
          let mut hash_str = String::new();
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          for i in hashes {
            hash_str.push_str(i);
            hash_str.push('\n');
          }
          
          hash_str.pop();

          rows.push(Row::from(vec![
            Cell::from("Hashes").bg(ln_bg).fg(ln_fg),
            Cell::from(hash_str).fg(Color::DarkCyan),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.original_file_name {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Original File Name").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Cyan),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.parent_image {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Parent Image").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Cyan),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.file_version {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("File Version").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Yellow),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.parent_process_id {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Parent Process ID").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Yellow),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.current_directory {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Parent Directory").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Cyan),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.command_line {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Command Line").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Red),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.event_id {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Event ID").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Yellow),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.logon_guid {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Logon Guid").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Yellow),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.logon_id {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Logon ID").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Yellow),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.image {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Image").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Green),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.integrity_level {
          let fg = Self::generate_alert_colour(CTerm::Fg, t.clone().as_str());
          let bg = Self::generate_alert_colour(CTerm::Bg, t.clone().as_str());
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Integrity Level").bg(ln_bg).fg(ln_fg),
            Cell::from(t.clone()).fg(fg).bg(bg)
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.parent_command_line {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Parent Command Line").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Cyan),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.utc_time {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("UTC Time").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::Magenta),
          ]));
          
          grey_counter += 1;
        }

        if let Some(t) = t.rule_name {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
            Cell::from("Rule Name").bg(ln_bg).fg(ln_fg),
            Cell::from(t).fg(Color::DarkCyan),
          ]));
        }
      }

      rows
    };

    let mut grey_counter: usize = 0;
    for i in sigma_rules {
      
      if let Some(t) = i.rule_title {
          let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
          let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
          rows.push(Row::from(vec![
          Cell::from("Rule Title").bg(ln_bg).fg(ln_fg),
          Cell::from(t).fg(Color::Green),
        ]));

        grey_counter += 1;
      }

      if let Some(t) = i.rule_level {
        let fg = Self::generate_alert_colour(CTerm::Fg, t.clone().as_str());
        let bg = Self::generate_alert_colour(CTerm::Bg, t.clone().as_str());
        let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
        let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
        rows.push(Row::from(vec![
          Cell::from("Rule Level").bg(ln_bg).fg(ln_fg),
          Cell::from(t).fg(fg).bg(bg)
        ]));
        
        grey_counter += 1;
      }

      if let Some(t) = i.rule_description {
        let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
        let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
        rows.push(Row::from(vec![
          Cell::from("Rule Description").bg(ln_bg).fg(ln_fg),
          Cell::from(t).fg(Color::Green),
        ]));
        
        grey_counter += 1;
      }

      if let Some(t) = i.rule_author {
        let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
        let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
        rows.push(Row::from(vec![
          Cell::from("Rule Author").bg(ln_bg).fg(ln_fg),
          Cell::from(t).fg(Color::Cyan),
        ]));
        
        grey_counter += 1;
      }

      if let Some(t) = i.rule_id {
        let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
        let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
        rows.push(Row::from(vec![
          Cell::from("Rule ID").bg(ln_bg).fg(ln_fg),
          Cell::from(t).fg(Color::Yellow),
        ]));
        
        grey_counter += 1;
      }

      if let Some(t) = i.rule_source {
        let ln_fg = Self::nth_row(CTerm::Fg, grey_counter % 2);
        let ln_bg = Self::nth_row(CTerm::Bg, grey_counter % 2);
          
        rows.push(Row::from(vec![
          Cell::from("Rule Source").bg(ln_bg).fg(ln_fg),
          Cell::from(t).fg(Color::DarkCyan),
        ]));
        
        grey_counter += 1;
      }

      if let Some(_context) = i.match_context {
        for idx in _context {
          let sigma_rows = extract_sigma_context(idx);

          if sigma_rows.len() > 0 {
            for rws in sigma_rows {
              rows.push(rws);
            }
          }
        }
      }

      rows.push(Row::from(vec![
        Cell::from("")
      ]));
    }

    rows.pop();
    table.add_rows(rows);
    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }

  #[allow(dead_code)]
  pub fn get_files(output_data: BehaviorJsonOutput, action: FileAction) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut table_name = String::new();

    let get_paths = |files: Vec<String>| -> String {
      let mut out = String::new();
      
      for idx in files {
        out.push_str(idx.as_str());
        out.push('\n');
      }

      out.pop();
      out
    };

    match action {
      FileAction::Changed =>  { table_name.push_str("Files Changed") }
      FileAction::Opened =>   { table_name.push_str("Files Opened") }
      FileAction::Deleted =>  { table_name.push_str("Files Deleted") }
      FileAction::Written =>  { table_name.push_str("Files Written") }
    }

    let data = output_data.data?;
    let mut files = String::new();

    for i in data {
      let att = i.attributes?;

      if action == FileAction::Opened {
        if let Some(t) = att.files_opened {
          let paths = get_paths(t);

          files.push_str(paths.as_str());
        }
      }

      else if action == FileAction::Deleted {
        if let Some(t) = att.files_deleted {
          let paths = get_paths(t);

          files.push_str(paths.as_str());
        }
      }

      else if action == FileAction::Changed {
        if let Some(t) = att.files_attribute_changed {
          let paths = get_paths(t);
          
          files.push_str(paths.as_str());
        }
      }

      else if action == FileAction::Written {
        if let Some(t) = att.files_written {
          let paths = get_paths(t);
          
          files.push_str(paths.as_str());
        }
      }
    }
    
    files.pop();

    let mut title = Table::new();
    title.add_row(Row::from(vec![
      Cell::from(table_name).fg(Color::Yellow).set_alignment(comfy_table::CellAlignment::Center)
    ]));

    let mut table = Table::new();
    table.set_header(Row::from(vec![
      Cell::from("Path").bg(Color::DarkBlue).fg(Color::White)
    ]));

    if files.len() > 0 {
      table.add_row(Row::from(vec![
        Cell::from(files).fg(Color::Green)
      ]));
    }

    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }


  #[allow(dead_code)]
  pub fn get_command_executions(_output_data: BehaviorJsonOutput) -> () {
    
  }


  #[allow(dead_code)]
  pub fn get_dropped_files(output_data: BehaviorJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();
    
    title.add_row(Row::from(vec![
      Cell::from("Dropped Files").fg(Color::Yellow)
    ]));
    
    let mut table = Table::new();
    table.set_header(Row::from(vec![
      Cell::from("Key").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Value").bg(Color::DarkBlue).fg(Color::White),
    ]));

    // Path
    // Sha256
    // Type

    let data = output_data.data?;
    for i in data {
      let _att = i.attributes?;

      // Files dropped havent been defined in vt_json...
    }
    // Place code below.....
  
    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)  
  }


  /** */
  pub fn get_dns_requests(output_data: BehaviorJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("DNS Requests").fg(Color::Yellow)
    ]));

    let mut table = Table::new();
    table.set_header(Row::from(vec![
      Cell::from("Resolved IPs").fg(Color::White).bg(Color::DarkBlue),
      Cell::from("Hostname").fg(Color::White).bg(Color::DarkBlue),
    ]));

    let get_ips = |ip: Vec<String>| -> String {
      let mut out = String::new();

      for i in ip {
        out.push_str(i.as_str());
        out.push('\n');
      }

      out.pop();
      out
    };

    let data = output_data.data?;
    let mut rows: Vec<Row> = Default::default();

    for i in data {
      let att = i.attributes?;

      if let Some(dns) = att.dns_lookups {

        for idx in dns {
          let mut ips = String::new();
          let mut cells: Vec<Cell> = Default::default();
  
          if let Some(ip) = idx.resolved_ips {
            ips.push_str(get_ips(ip).as_str());
            cells.push(Cell::from(ips).fg(Color::Green));
          }
          
          else {
            cells.push(Cell::from(""));
          }
  
          if let Some(h) = idx.hostname {
            cells.push(Cell::from(h).fg(Color::DarkCyan));
          }
  
          else {
            cells.push(Cell::from(""));
          }
  
          rows.push(Row::from(cells));
        }
      }

    }

    table.add_rows(rows);
    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }


  /** */
  pub fn generate_alert_colour(colour: CTerm, keyword: &str) -> Color {
    match keyword.to_lowercase().as_str() {
      
      "info" =>     {
        if colour == CTerm::Fg {
          return Color::White
        }
        else {
          return Color::Reset
        }

      }
      
      "low" => {
        if colour == CTerm::Fg {
          return Color::Blue
        }
        else {
          Color::Reset
        }
      }
      
      "medium" =>   {
        if colour == CTerm::Fg {
          return Color::DarkYellow
        }
        else {
          return Color::Reset;
        }
      }
      
      "high" =>     {
        if colour == CTerm::Fg {
          return Color::White
        }
        else {
          return Color::DarkRed
        }
      }

      _ => {
        if colour == CTerm::Fg {
          return Color::White;
        }
        else {
          return Color::Reset;
        }
      }
    }
  }

  /**Function displays mitre attack techniques and sub techniques from the virus total 
   * api response in regards to a file hash.
   * Params:
   *  output_data: BehaviorJsonOutput {The virus total api file behavior response}
   * Returns Option<CombinedTable>
   */
  pub fn get_mitre_attack_techniques(output_data: BehaviorJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("Mitre Attack Techniques")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));
    
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("id").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("description").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("severity").bg(Color::DarkBlue).fg(Color::White),
    ]);

    let data = output_data.data?;
    let mut rows: Vec<Row> = vec![];
    let mut counter: usize = 0;

    for i in data {
      let mut mitre: Vec<MitreAttackTechniques> = Default::default();
      if let Some(m) = i.attributes?.mitre_attack_techniques {
        mitre = m;
      }

      for idx in mitre {
        let mut cells: Vec<Cell> = Default::default();

        if let Some(i) = idx.id {
          if counter % 2 == 0 {
            cells.push(Cell::from(i).bg(Color::DarkGrey).fg(Color::White));
            counter += 1;
          }

          else {
            cells.push(Cell::from(i).fg(Color::White));
            counter += 1;
          }
        }

        if let Some(d) = idx.signature_description {
          cells.push(Cell::from(d).fg(Color::Green));
        }

        if let Some(s) = idx.severity {
          let alert = s.replace("IMPACT_SEVERITY_", "");
          cells.push(Cell::from(alert.clone())
          .bg(Self::generate_alert_colour(CTerm::Bg, alert.as_str()))
          .fg(Self::generate_alert_colour(CTerm::Fg, alert.as_str())));
        }

        rows.push(Row::from(cells));
      }
    }

    table.add_rows(rows);
    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }

  /**Function displays function imports from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: FileJsonOutput {The virus total api response}
   * Returns Option<CombinedTable>
   */
  pub fn get_imports(output_data: FileJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("[Imported Functions]")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));
    
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("Symbol Name").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Library").bg(Color::DarkBlue).fg(Color::White),
    ]);

    let mut libs = String::new();
    let mut names = String::new();

    let imports = output_data.data?.attributes?.pe_info?.import_list?;
    for i in imports {
      let lib_name = i.library_name?;
      let funcs = i.imported_functions?;

      for idx in funcs {
        libs.push_str(format!("{}\n", lib_name).as_str());
        names.push_str(format!("{}\n", idx).as_str());
      }
    }

    libs.pop();
    names.pop();

    table.add_row(vec![
      Cell::from(libs).fg(Color::Red),
      Cell::from(names).fg(Color::Red),
    ]);

    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }

  /**Function displays function imports from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: FileJsonOutput {The virus total api response}
   * Returns Option<CombinedTable>
   */
  pub fn get_exports(output_data: FileJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("[Exported Functions]")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));
    
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("Symbol Name").fg(Color::Yellow),
    ]);

    let mut names = String::new();
    let exports = output_data.data?.attributes?.pe_info?.exports?;
    
    for i in exports {
      names.push_str(format!("{i}\n").as_str());
    }

    names.pop();
    table.add_row(vec![
      Cell::from(names).fg(Color::Red),
    ]);

    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }
  
  /**Function queries the virus total api and returns a string with the json response.
   * Params:
   *  hash_id:  &str  {The hash to query}
   *  apikey:   &str  {The users api key}
   * Returns String
   */
  pub fn query_file_attributes(hash_id: &str, apikey: &str) -> std::result::Result<String, GeneralError> {
    let base_url = format!("https://www.virustotal.com/api/v3/files/{hash_id}");
  
    let builder = ClientBuilder::new()
                                  .build().unwrap().request(Method::GET, base_url)
                                  .header("x-apikey", apikey);
    
    let request = builder.send()?;
    let text = request.text()?;

    Ok(text)
  }

  /**Function queries the virus total api for file behaviour and returns a json response.
   * Params:
   *  hash_id:       &str       {The hash of the file}
   *  releationship: &str       {The type of behaviour to query}
   *  n_results:     &str       {The number of json objects to return}
   * Returns Result<Response>.
   */
  pub fn query_file_behaviour(hash_id: &str, n_results: usize, apikey: &str) -> std::result::Result<String, GeneralError> {
    let url = format!("https://www.virustotal.com/api/v3/files/{hash_id}/behaviours?limit={n_results}");
    
    let builder = ClientBuilder::new()
                  .build()?.request(Method::GET, url)
                  .header("accept", "application/json")
                  .header("x-apikey", apikey);

    let request = builder.send()?;
    let text = request.text()?;

    Ok(text)
  }

  /**
   * Function splits the path up into chunks for forward or back slashes
   * and returns of the last chunk in the array.
   * Params:
   *  input: &str {The path}
   * Returns String
   */
  pub fn get_filename_from_path(input: String) -> String {
    #[allow(unused_assignments)]
    let mut delim = "";
    
    match std::env::consts::OS {
      "windows" => {
        delim = "\\";
      }
      
      _ => {
        delim = "/";
      }
    }

    let split_input: Vec<&str> = input.split(delim).collect();
    String::from(split_input[split_input.len()-1])
  }

  /**Function uploads a file to virus total with the api and returns a response when complete.
   * Params:
   *  path:     &str    { The file path }
   *  byte_len: usize   { Length of the file in bytes }
   *  apikey:   &str    { The virustotal api key }
   *  debug:    bool    { Display debug messages }
   *  wdbg:     bool    { Modify the sending address and port }
   * Returns Result<String, GeneralError>
   */
  pub fn upload_file(path: &str, apikey: &str, debug: bool, wdbg: String) -> std::result::Result<(), GeneralError> {    
    let mut url = String::new();
    let mut host = String::new();
    let filename = Self::get_filename_from_path(String::from(path));

    if wdbg.len() > 1 {
      // Redirect api request to debug server.
      url.push_str(format!("http://{wdbg}/").as_str());
      host.push_str(&url[7..url.len()-1]);
    }
    else {
      url.push_str("https://www.virustotal.com/api/v3/files");
      host.push_str("www.virustotal.com");
    }

    // Read file into a buffer.
    println!("{}: Reading file into buffer", style("Info").yellow().bright());
    let contents = std::fs::read(path.clone())?;
    let content_len = contents.len().clone();
    
    // Add filename and bytes to a multiform in the request.
    let test = Part::bytes(contents.clone()).file_name(filename.clone());
    let form = Form::new().part("file", test);

    // Build the request to upload a file under 32MB.
    println!("{}: Building request", style("Info").yellow().bright());
    let builder = ClientBuilder::new()
    .build()?
    .request(Method::POST, url)
    .header(ACCEPT, "application/json")
    .header(HOST, host)
    .header(USER_AGENT, "PE Potato 0.1.0")
    .header("X-Apikey", apikey)
    .header(CONTENT_LENGTH, content_len)
    .multipart(form);

    // // Send the request and get the response.
    println!("{}: Sending request", style("Info").yellow().bright());
    let response = builder.send()?;
    let status = response.status();
    
    if status.is_success() {
      println!(
        "{}: {} uploaded {} to {}", 
        style("OK").yellow().bright(), style("Successfully").green().bright(), style(filename).red().bright(), 
        style("Virus Total").blue().bright()
      )
    }

    else if status.is_server_error() {
      println!(
        "{}: Unable to upload {} to virus total - Server Error", style("Error").red().bright(), style(filename).red().bright()
      )
    }

    else if status.is_client_error() {
      println!(
        "{}: Unable to upload {} to virus total - Client Error", style("Error").red().bright(), style(filename).red().bright()
      )
    }

    if debug == true {
      println!("{} status code: {}", style("Debug =>").red().bright(), style(status.as_str()).cyan());
    }

    Ok(())
  }

  /**Function displays crowd sources yara rules from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: FileJsonOutput {The virus total api response}
   * Returns Option<Table>
   */
  pub fn get_yara_rules(output_data: FileJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("[Yara Rules]")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));
    
    let mut table = Table::new();
    let mut rows: Vec<Row> = Default::default();
    let rules = output_data.data?.attributes?.crowdsourced_yara_results?;

    for i in rules {
      let mut description = String::new();
      let mut source = String::new();
      let mut author = String::new();
      let mut ruleset_id = String::new();
      let mut ruleset_name = String::new();
      let mut rule_name = String::new();
      
      if let Some(d) = i.description {
        description.push_str(d.as_str());
      }

      if let Some(s) = i.source {
        source.push_str(s.as_str());
      }

      if let Some(a) = i.author {
        author.push_str(a.as_str());
      }

      if let Some(rn) = i.ruleset_name {
        ruleset_id.push_str(rn.as_str());
      }

      if let Some(ri) = i.ruleset_id {
        ruleset_name.push_str(ri.as_str());
      }

      if let Some(name) = i.rule_name {
        rule_name.push_str(name.as_str());
      }

      rows.push(Row::from(vec![
        Cell::from("Description").bg(Color::DarkGrey).fg(Color::White), Cell::from(description).fg(Color::Green)
      ]));

      rows.push(Row::from(vec![
        Cell::from("Source").fg(Color::Yellow), Cell::from(source).fg(Color::DarkCyan)
      ]));

      rows.push(Row::from(vec![
        Cell::from("Author").bg(Color::DarkGrey).fg(Color::White), Cell::from(author).fg(Color::Green)
      ]));

      rows.push(Row::from(vec![
        Cell::from("Ruleset_ID").fg(Color::Yellow), Cell::from(ruleset_id).fg(Color::Red)
      ]));

      rows.push(Row::from(vec![
        Cell::from("Ruleset_Name").bg(Color::DarkGrey).fg(Color::White), Cell::from(ruleset_name).fg(Color::DarkYellow)
      ]));

      rows.push(Row::from(vec![
        Cell::from("Rule_Name").fg(Color::Yellow), Cell::from(rule_name).fg(Color::Red)
      ]));

      rows.push(Row::from(vec![
        Cell::from("").fg(Color::Yellow), Cell::from("").fg(Color::DarkCyan)
      ]));
    }

    rows.pop();
    table.add_rows(rows);

    title.set_content_arrangement(ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }

  /**Function makes a GET reuqest to the virus total api query a hash for the input file.
   * Params:
   *  hash_id: &str {The file hash}
   *  apikey: &str  {The Virus Total api key}
   * Returns nothing
   */
  pub fn search_detections(output_data: FileJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("Antivirus Detections")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));

    // Setup a table.
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("Av_Engine").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Category").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Result").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Version").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Method").bg(Color::DarkBlue).fg(Color::White),
      Cell::from("Engine_Update").bg(Color::DarkBlue).fg(Color::White),
    ]);

    // Unpack the AnalysisResult struct and construct the table.
    let mut av: Vec<AVProvider> = Self::get_engine_data(output_data.data?.attributes?.last_analysis_results?);

    av.sort();
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
        "type-unsupported" => { c_category = Cell::from(category).fg(Color::Blue);                     }
        "undetected" =>       { c_category = Cell::from(category).fg(Color::Green);                    }
        "malicious" =>        { c_category = Cell::from(category).bg(Color::DarkRed).fg(Color::White); }
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

    title.set_content_arrangement(comfy_table::ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(comfy_table::ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }

  /**Function unpacks the LastAnalysisResults struct into a vec so user does not have to manually extract data from 82 fields.
   * Params:
   *  d: AnalysisResult {The struct to unpack}
   * Returns Vec<AVProvider>
   */
  pub fn get_engine_data(d: LastAnalysisResults) -> Vec<AVProvider> {
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
}
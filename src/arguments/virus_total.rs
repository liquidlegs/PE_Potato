use console::style;
use comfy_table::{Table, Cell, Row, Color, ContentArrangement};
use reqwest::{blocking::multipart::{Form, Part}, header::{USER_AGENT, HOST, ACCEPT, CONTENT_LENGTH}};
use super::{
  vt_file_json::*,
  ClientBuilder, Method, 
  GeneralError, vt_behaviour_json::{BehaviorJsonOutput, IpTraffic, HttpConversations, MitreAttackTechniques},
  CombinedTable,
};

#[derive(Debug, Clone, Default)]
pub struct VtArgType {
  pub attributes: bool,
  pub behaviour: bool,
}

pub struct VirusTotal {}
impl VirusTotal {

  #[allow(dead_code, unused_variables, unused_assignments)]
  pub fn get_structure_stats(file_data: FileJsonOutput, behaviour_data: BehaviorJsonOutput) -> Option<Table> {
    let mut table = Table::new();

    let mut b_elf_info = false;
    let mut b_dot_net_assembly = false;
    let mut b_type_description = false;
    let mut b_tlsh = false;
    let mut b_vhash = false;
    let mut b_trid = false;
    let mut b_crowdsourced_yara_results = false;
    let mut b_creation_date = false;
    let mut b_names = false;
    let mut b_last_modification_date = false;
    let mut b_type_tag = false;
    let mut b_times_submitted = false;
    let mut b_total_votes = false;
    let mut b_size = false;
    let mut b_popular_threat_classification = false;
    let mut b_authentihash = false;
    let mut b_detectiteasy = false;
    let mut b_last_submission_date = false;
    let mut b_sigma_analysis_results = false;
    let mut b_meaningful_name = false;
    let mut b_crowdsourced_ids_stats = false;
    let mut b_sandbox_verdicts = false;
    let mut b_sha256 = false;
    let mut b_type_extension = false;
    let mut b_tags = false;
    let mut b_crowdsourced_ids_results = false;
    let mut b_last_analysis_date = false;
    let mut b_unique_sources = false;
    let mut b_first_submission_date = false;
    let mut b_sha1 = false;
    let mut b_ssdeep = false;
    let mut b_md5 = false;
    let mut b_pe_info = false;
    let mut b_magic = false;
    let mut b_last_analysis_stats = false;
    let mut b_last_analysis_results = false;
    let mut b_reputation = false;

    let mut labels = String::new();
    labels.push_str("elf_info\ndot_net_assembly\ntype_description\ntlsh\nvhash\ntrid\ncrowdsourced_yara_results\ncreation_date\nnames");
    labels.push_str("\nlast_modification_date\ntype_tag\ntimes_submitted\ntotal_votes\nsize\npopular_threat_classification\nauthentihash\ndetectiteasy");
    labels.push_str("\nlast_submission_date\nsigma_analysis_results\nmeaningful_name\ncrowdsourced_ids_stats\nsandbox_verdicts\nsha256\ntype_extension\ntags\ncrowdsourced_ids_results");
    labels.push_str("\nlast_analysis_date\nunique_sources\nfirst_submission_date\nsha1\nssdeep\nmd5\npe_info\nmagic\nlast_analysis_stats\nlast_analysis_results\nreputation");

    let f_data = file_data.data?.attributes?;
    let b_data = behaviour_data.data?;


    if let Some(_) = f_data.elf_info                         {
      b_elf_info = true;
    }

    if let Some(_) = f_data.dot_net_assembly                 {
      b_dot_net_assembly = true;
    }

    if let Some(_) = f_data.type_description                 {
      b_type_description = true;
    }

    if let Some(_) = f_data.tlsh                             {
      b_tlsh = true;
    }

    if let Some(_) = f_data.vhash                            {
      b_vhash = true;
    }

    if let Some(_) = f_data.trid                             {
      b_trid = true;
    }

    if let Some(_) = f_data.crowdsourced_yara_results        {
      b_crowdsourced_yara_results = true;
    }

    if let Some(_) = f_data.creation_date                    {
      b_creation_date = true;
    }

    if let Some(_) = f_data.names                            {
      b_names = true;
    }

    if let Some(_) = f_data.last_modification_date           {
      b_last_modification_date = true;
    }

    if let Some(_) = f_data.type_tag                         {
      b_type_tag = true;
    }

    if let Some(_) = f_data.times_submitted                  {
      b_times_submitted = true;
    }

    if let Some(_) = f_data.total_votes                      {
      b_total_votes = true;
    }

    if let Some(_) = f_data.size                             {
      b_size = true;
    }

    if let Some(_) = f_data.popular_threat_classification    {
      b_popular_threat_classification = true;
    }

    if let Some(_) = f_data.authentihash                     {
      b_authentihash = true;
    }

    if let Some(_) = f_data.detectiteasy                     {
      b_detectiteasy = true;
    }

    if let Some(_) = f_data.last_submission_date             {
      b_last_submission_date = true;
    }

    if let Some(_) = f_data.sigma_analysis_results           {
      b_sigma_analysis_results = true;
    }

    if let Some(_) = f_data.meaningful_name                  {
      b_meaningful_name = true;
    }

    if let Some(_) = f_data.crowdsourced_ids_stats           {
      b_crowdsourced_ids_stats = true;
    }

    if let Some(_) = f_data.sandbox_verdicts                 {
      b_sandbox_verdicts = true;
    }

    if let Some(_) = f_data.sha256                           {
      b_sha256 = true;
    }

    if let Some(_) = f_data.type_extension                   {
      b_type_extension = true;
    }

    if let Some(_) = f_data.tags                             {
      b_tags = true;
    }

    if let Some(_) = f_data.crowdsourced_ids_results         {
      b_crowdsourced_ids_results = true;
    }

    if let Some(_) = f_data.last_analysis_date               {
      b_last_analysis_date = true;
    }

    if let Some(_) = f_data.unique_sources                   {
      b_unique_sources = true;
    }

    if let Some(_) = f_data.first_submission_date            {
      b_first_submission_date = true;
    }

    if let Some(_) = f_data.sha1                             {
      b_sha1 = true;
    }

    if let Some(_) = f_data.ssdeep                           {
      b_ssdeep = true;
    }

    if let Some(_) = f_data.md5                              {
      b_md5 = true;
    }

    if let Some(_) = f_data.pe_info                          {
      b_pe_info = true;
    }

    if let Some(_) = f_data.magic                            {
      b_magic = true;
    }

    if let Some(_) = f_data.last_analysis_stats              {
      b_last_analysis_stats = true;
    }

    if let Some(_) = f_data.last_analysis_results            {
      b_last_analysis_results = true;
    }

    if let Some(_) = f_data.reputation                       {
      b_reputation = true;
    }

    Some(table)
  }

  #[allow(dead_code)]
  pub fn get_sigma_rules(output_data: FileJsonOutput) -> Option<Table> {
    let table = Table::new();

    let data = output_data.data?;
    let sigma = data.attributes?.sigma_analysis_results?;

    for i in sigma {
      let mut _context = SigmaMatchContextValues::default();
      
      for idx in i.match_context? {
        if let Some(v) = idx.values {
          _context = v;
        }
      }
    }

    Some(table)
  }

  /**Function displayed detailed information about each resource in the file.
   * Params:
   *  output_data: FileJsonOutput {The parsed json response}
   * Returns nothing.
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
      Cell::from("lang").fg(Color::Yellow),
      Cell::from("entropy").fg(Color::Yellow),
      Cell::from("chi2").fg(Color::Yellow),
      Cell::from("filetype").fg(Color::Yellow),
      Cell::from("sha256").fg(Color::Yellow),
      Cell::from("type").fg(Color::Yellow),
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
      Cell::from("Name").fg(Color::Yellow),
      Cell::from("Virtual Address").fg(Color::Yellow),
      Cell::from("Virtual Size").fg(Color::Yellow),
      Cell::from("Raw Size").fg(Color::Yellow),
      Cell::from("Entropy").fg(Color::Yellow),
      Cell::from("MD5").fg(Color::Yellow),
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
        cells.push(Cell::from(format!("0x{:X}", virt_a)).fg(Color::DarkYellow));
      }

      if let Some(vsize) = i.virtual_size {
        cells.push(Cell::from(format!("0x{:X}", vsize)).fg(Color::DarkYellow));
      }

      if let Some(rs) = i.raw_size {
        cells.push(Cell::from(rs).fg(Color::DarkYellow));
      }

      if let Some(e) = i.entropy {
        
        if e < 3.0 {
          cells.push(Cell::from(format!("{e}")).fg(Color::Blue));
        }

        else if e > 3.0 && e < 4.5 {
          cells.push(Cell::from(format!("{e}")).fg(Color::Green));
        }
    
        else if e > 4.5 && e < 7.5 {
          cells.push(Cell::from(format!("{e}")).fg(Color::DarkYellow));
        }
    
        else if e > 7.5 {
          cells.push(Cell::from(format!("{e}")).fg(Color::Red));
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

  pub fn parse_response(response: String) -> FileJsonOutput {
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

  
  pub fn parse_behavior_response(response: String) -> BehaviorJsonOutput {
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
   *  hash_id:  &str {The hash of the sample}
   *  apikey:   &str {The virus total api key}
   *  cpu:      bool {Tells us whether the cpu is 64 or 32}
   * Returns nothing
   */
  pub fn get_general_info(output_data: FileJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("General Information")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));

    let mut table = Table::new();

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
      entropy_c = Color::DarkYellow;
    }

    else if entropy > 7.5 {
      entropy_c = Color::Red;
    }

    let rows = vec![
      Row::from(vec![
        Cell::from("FileName").fg(Color::Yellow), Cell::from(names).fg(Color::Green)
      ]),

      Row::from(vec![
        Cell::from("FileSize").fg(Color::Yellow), Cell::from(format!("{bin_size} (Bytes)")).fg(Color::DarkYellow)
      ]),

      Row::from(vec![
        Cell::from("FileType").fg(Color::Yellow), Cell::from(filetype).fg(Color::Green)
      ]),

      Row::from(vec![
        Cell::from("CPU").fg(Color::Yellow), Cell::from(arch).fg(Color::DarkCyan)
      ]),

      Row::from(vec![
        Cell::from("SubSystem").fg(Color::Yellow), Cell::from(subsys).fg(Color::DarkCyan)
      ]),

      Row::from(vec![
        Cell::from("Compiler").fg(Color::Yellow), Cell::from(comp).fg(Color::Blue)
      ]),

      Row::from(vec![
        Cell::from("Packer").fg(Color::Yellow), Cell::from(pack).fg(Color::Green)
      ]),

      Row::from(vec![
        Cell::from("Sections").fg(Color::Yellow), Cell::from(number_of_sections).fg(Color::DarkYellow)
      ]),

      Row::from(vec![
        Cell::from("Entropy").fg(Color::Yellow), Cell::from(entropy).fg(entropy_c)
      ]),

      Row::from(vec![
        Cell::from("Family").fg(Color::Yellow), Cell::from(family).fg(Color::Red)
      ]),

      Row::from(vec![
        Cell::from("Detected").fg(Color::Yellow), Cell::from(detections).fg(Color::DarkYellow)
      ]),

      Row::from(vec![
        Cell::from("Undetected").fg(Color::Yellow), Cell::from(no_detections).fg(Color::DarkYellow)
      ]),

      Row::from(vec![
        Cell::from("MD5").fg(Color::Yellow), Cell::from(md5_hash).fg(Color::DarkCyan)
      ]),

      Row::from(vec![
        Cell::from("SHA256").fg(Color::Yellow), Cell::from(sha256).fg(Color::DarkCyan)
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
   * Returns Option<Table>
   */
  pub fn get_compiler_products(output_data: FileJsonOutput) -> Option<Table> {
    let mut table = Table::new();

    table.set_header(vec![
      Cell::from("id").fg(Color::Yellow),
      Cell::from("version").fg(Color::Yellow),
      Cell::from("count").fg(Color::Yellow),
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
          _ => {}
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
    
    Some(table)
  }

  /**Function displays all files names from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: FileJsonOutput {The virus total api response}
   * Returns Option<Table>
   */
  pub fn get_file_names(output_data: FileJsonOutput) -> Option<Table> {
    let mut table = Table::new();

    table.set_header(vec![
      Cell::from("Name").fg(Color::Yellow),
    ]);

    let mut row = String::from("");
    let data = output_data.data?.attributes?.names?;
    
    for i in data {
      row.push_str(format!("{}\n", i).as_str());
    }

    row.pop();

    table.add_row(vec![
      Cell::from(row).fg(Color::Red),
    ]);

    Some(table)
  }

  /**Function displays all tags from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: FileJsonOutput {The virus total api response}
   * Returns Option<Table>
   */
  pub fn get_tags(output_data: FileJsonOutput) -> Option<Table> {
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("Tags").fg(Color::Yellow),
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

    Some(table)
  }

  /**Function displays all resource types from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: FileJsonOutput {The virus total api response}
   * Returns Option<Table>
   */
  pub fn get_resource_by_type(output_data: FileJsonOutput) -> Option<CombinedTable> {
    let mut out = CombinedTable::default();
    let mut title = Table::new();

    title.add_row(Row::from(vec![
      Cell::from("Resource by type")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));
    
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("Resource_Type").fg(Color::Yellow),
      Cell::from("count").fg(Color::Yellow),
    ]);

    let mut resource = String::new();
    let mut count = String::new();
    let data = output_data.data?.attributes?.pe_info?.resource_types?;

    if let Some(icon) = data.rt_icon {
      resource.push_str("RT_ICON\n");
      count.push_str(format!("{icon}\n").as_str());
    }

    if let Some(dialog) = data.rt_dialog {
      resource.push_str("RT_DIALOG\n");
      count.push_str(format!("{dialog}\n").as_str());
    };

    if let Some(cursor) = data.rt_cursor {
      resource.push_str("RT_CURSOR\n");
      count.push_str(format!("{cursor}\n").as_str());
    }

    if let Some(acc) = data.rt_accelerator {
      resource.push_str("RT_ACCELERATOR\n");
      count.push_str(format!("{acc}\n").as_str());
    }

    if let Some(bit) = data.rt_bitmap {
      resource.push_str("RT_BITMAP\n");
      count.push_str(format!("{bit}\n").as_str());
    }

    if let Some(mani) = data.rt_manifest {
      resource.push_str("RT_MANIFEST\n");
      count.push_str(format!("{mani}\n").as_str());
    }

    if let Some(g_icon) = data.rt_group_icon {
      resource.push_str("RT_GROUP_ICON\n");
      count.push_str(format!("{g_icon}\n").as_str());
    }

    if let Some(g_cursor) = data.rt_group_cursor {
      resource.push_str("RT_GROUP_CURSOR\n");
      count.push_str(format!("{g_cursor}\n").as_str());
    }

    if let Some(_str) = data.rt_string {
      resource.push_str("RT_STRING\n");
      count.push_str(format!("{_str}\n").as_str());
    }

    if let Some(ver) = data.rt_version {
      resource.push_str("RT_VERSION\n");
      count.push_str(format!("{ver}\n").as_str());
    }
    
    resource.pop();
    count.pop();

    table.add_row(vec![
      Cell::from(resource).fg(Color::Red),
      Cell::from(count).fg(Color::Red),
    ]);

    title.set_content_arrangement(comfy_table::ContentArrangement::DynamicFullWidth);
    table.set_content_arrangement(comfy_table::ContentArrangement::DynamicFullWidth);

    out.title = title;
    out.contents = table;
    Some(out)
  }

  /**Function displays ip traffic from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: BehaviorJsonOutput {The virus total api file behavior response}
   * Returns Option<Table>
   */
  pub fn get_ip_traffic(output_data: BehaviorJsonOutput) -> Option<Table> {
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("IP").fg(Color::Yellow),
      Cell::from("Port").fg(Color::Yellow),
      Cell::from("Protocol").fg(Color::Yellow),
    ]);

    let mut ip = String::new();
    let mut port = String::new();
    let mut proto = String::new();

    let data = output_data.data?;
    for i in data {
      let mut traffic: Vec<IpTraffic> = Default::default();
      if let Some(t) = i.attributes?.ip_traffic {
        traffic = t;
      }

      for idx in traffic {
        if let Some(ipp) = idx.destination_ip {
          ip.push_str(format!("{ipp}\n").as_str());
        }

        if let Some(p) = idx.destination_port {
          port.push_str(format!("{}\n", p).as_str());
        }

        if let Some(pro) = idx.transport_layer_protocol {
          proto.push_str(format!("{}\n", pro).as_str());
        }
      }
    }

    if ip.len() < 1 && port.len() < 1 && proto.len() < 1 {
      return None;
    }

    ip.pop();
    port.pop();
    proto.pop();

    table.add_row(vec![
      Cell::from(ip).fg(Color::Red),
      Cell::from(port).fg(Color::Red),
      Cell::from(proto).fg(Color::Red),
    ]);

    Some(table)
  }

  /**Function displays http coversations from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: BehaviorJsonOutput {The virus total api file behavior response}
   * Returns Option<Table>
   */
  pub fn get_http_conv(output_data: BehaviorJsonOutput) -> Option<Table> {
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("Method").fg(Color::Yellow),
      Cell::from("Url").fg(Color::Yellow),
      Cell::from("Status_code").fg(Color::Yellow),
    ]);

    let mut method = String::new();
    let mut urls = String::new();
    let mut status = String::new();

    let data = output_data.data?;
    for i in data {
      
      let mut conv: Vec<HttpConversations> = Default::default();
      if let Some(h) = i.attributes?.http_conversations {
        conv = h;
      }

      for idx in conv {
        if let Some(m) = idx.request_method {
          method.push_str(format!("{m}\n").as_str());
        }

        if let Some(u) = idx.url {
          urls.push_str(format!("{u}\n").as_str());
        }

        if let Some(s) = idx.response_status_code {
          status.push_str(format!("{s}\n").as_str());
        }
      }
    }

    if method.len() < 1 && urls.len() < 1 && status.len() < 1 {
      return None;
    }

    method.pop();
    urls.pop();
    status.pop();

    table.add_row(vec![
      Cell::from(method).fg(Color::Red),
      Cell::from(urls).fg(Color::Red),
      Cell::from(status).fg(Color::Red),
    ]);

    Some(table)
  }

  /**Function displays set registry keys from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: FileJsonOutput {The virus total api response}
   * Returns Option<Table>
   */
  #[allow(dead_code)]
  pub fn get_registry_keys_set(_output_data: BehaviorJsonOutput) -> Option<Table> {
    let table = Table::new();
  
    Some(table)  
  }

  /**Function displays mitre attack techniques and sub techniques from the virus total 
   * api response in regards to a file hash.
   * Params:
   *  output_data: BehaviorJsonOutput {The virus total api file behavior response}
   * Returns Option<Table>
   */
  pub fn get_mitre_attack_techniques(output_data: BehaviorJsonOutput) -> Option<Table> {
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("id").fg(Color::Yellow),
      Cell::from("description").fg(Color::Yellow),
      Cell::from("severity").fg(Color::Yellow),
    ]);

    let mut ids = String::new();
    let mut desc = String::new();
    let mut severity = String::new();
    let data = output_data.data?;

    for i in data {
      let mut mitre: Vec<MitreAttackTechniques> = Default::default();
      if let Some(m) = i.attributes?.mitre_attack_techniques {
        mitre = m;
      }

      for idx in mitre {
        if let Some(i) = idx.id {
          ids.push_str(format!("{i}\n").as_str());
        }

        if let Some(d) = idx.signature_description {
          desc.push_str(format!("{d}\n").as_str());
        }

        if let Some(s) = idx.severity {
          severity.push_str(format!("{}\n", s.replace("IMPACT_SEVERITY_", "")).as_str());
        }
      }
    }

    ids.pop();
    desc.pop();
    severity.pop();

    table.add_row(vec![
      Cell::from(ids).fg(Color::Red),
      Cell::from(desc).fg(Color::Red),
      Cell::from(severity).fg(Color::Red),
    ]);

    Some(table)
  }

  /**Function displays function imports from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: FileJsonOutput {The virus total api response}
   * Returns Option<Table>
   */
  pub fn get_imports(output_data: FileJsonOutput) -> Option<Table> {
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("Name").fg(Color::Yellow),
      Cell::from("Library").fg(Color::Yellow),
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

    Some(table)
  }

  /**Function displays function imports from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: FileJsonOutput {The virus total api response}
   * Returns Option<Table>
   */
  pub fn get_exports(output_data: FileJsonOutput) -> Option<Table> {
    let mut table = Table::new();
    table.set_header(vec![
      Cell::from("").fg(Color::Yellow),
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

    Some(table)
  }
  
  /**Function queries the virus total api and returns a string with the json response.
   * Params:
   *  hash_id:  &str  {The hash to query}
   *  apikey:   &str  {The users api key}
   * Returns String
   */
  pub fn query_file_attributes(hash_id: &str, apikey: &str) -> String {
    let base_url = format!("https://www.virustotal.com/api/v3/files/{hash_id}");
  
    let builder = ClientBuilder::new()
                                  .build().unwrap().request(Method::GET, base_url)
                                  .header("x-apikey", apikey);
    
    let request = builder.send().unwrap();
    let text = request.text().unwrap();

    text
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
      Cell::from("Yara Rules")
      .set_alignment(comfy_table::CellAlignment::Center)
      .fg(Color::Yellow)
    ]));
    
    let mut table = Table::new();
    // let labels = String::from(
    //   "Description\nSource\nAuthor\nRuleset_ID\nRuleset_Name\nRule_Name"
    // );

    let mut rows: Vec<Row> = Default::default();
    let rules = output_data.data?.attributes?.crowdsourced_yara_results?;
    
    for i in rules {
      // let mut input = String::new();
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
        Cell::from("Description").fg(Color::Yellow), Cell::from(description).fg(Color::Green)
      ]));

      rows.push(Row::from(vec![
        Cell::from("Source").fg(Color::Yellow), Cell::from(source).fg(Color::DarkCyan)
      ]));

      rows.push(Row::from(vec![
        Cell::from("Author").fg(Color::Yellow), Cell::from(author).fg(Color::Green)
      ]));

      rows.push(Row::from(vec![
        Cell::from("Ruleset_ID").fg(Color::Yellow), Cell::from(ruleset_id).fg(Color::Red)
      ]));

      rows.push(Row::from(vec![
        Cell::from("Ruleset_Name").fg(Color::Yellow), Cell::from(ruleset_name).fg(Color::DarkYellow)
      ]));

      rows.push(Row::from(vec![
        Cell::from("Rule_Name").fg(Color::Yellow), Cell::from(rule_name).fg(Color::Red)
      ]));

      rows.push(Row::from(vec![
        Cell::from("").fg(Color::Yellow), Cell::from("").fg(Color::DarkCyan)
      ]));
      
      // rows.push(Row::from(vec![
      //   Cell::from(labels.as_str()).fg(Color::Yellow),
      //   Cell::from(input.as_str()).fg(Color::DarkCyan),
      // ]));
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
      Cell::from("Av_Engine").fg(Color::Yellow),
      Cell::from("Category").fg(Color::Yellow),
      Cell::from("Result").fg(Color::Yellow),
      Cell::from("Version").fg(Color::Yellow),
      Cell::from("Method").fg(Color::Yellow),
      Cell::from("Engine_Update").fg(Color::Yellow),
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
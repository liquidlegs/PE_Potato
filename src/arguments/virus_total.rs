use comfy_table::{Table, Cell, Row, Color};
use super::{
  vt_file_json::*,
  ClientBuilder, Method, Response, 
  GeneralError, vt_behaviour_json::{BehaviorJsonOutput, IpTraffic, HttpConversations, MitreAttackTechniques},
};

#[derive(Debug, Clone, Default)]
pub struct VtArgType {
  pub attributes: bool,
  pub behaviour: bool,
}

pub struct VirusTotal {}
impl VirusTotal {

  /**Function displayed detailed information about each resource in the file.
   * Params:
   *  output_data: FileJsonOutput {The parsed json response}
   * Returns nothing.
   */
  pub fn get_resource_details(output_data: FileJsonOutput) -> Option<Table> {
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

    Some(table)
  }

  /**Function displays detailed information about the section header.
   * Params:
   *  output_data: FileJsonOutput {The parsed json response}
   * Returns nothing.
   */
  pub fn get_sections(output_data: FileJsonOutput) -> Option<Table> {
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

    let mut s_names = String::new();
    let mut s_va = String::new();
    let mut s_vs = String::new();
    let mut s_size = String::new();
    let mut s_entropy = String::new();
    let mut s_md5 = String::new();

    let mut pe = output_data.data?.attributes?.pe_info?;
    let mut sections = pe.sections?;

    // if let Some(sec) = pe.sections {
    //   sections = sec;
    // }

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

    Some(section_table)
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
  pub fn get_general_info(output_data: FileJsonOutput) -> Option<Table> {
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

    Some(table)
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
  pub fn get_resource_by_type(output_data: FileJsonOutput) -> Option<Table> {
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

    Some(table)
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
  pub fn get_registry_keys_set(output_data: BehaviorJsonOutput) -> Option<Table> {
    let mut table = Table::new();
  
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
   *  hash_id: &str {The hash to query}
   *  apikey: &str  {The users api key}
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

  /**Function uploads a file to virus total with the api and returns a response when complete.
   * Params:
   *  filename: &str        {The name of the file to upload}
   *  bytes:    Vec<u8>     {The raw bytes of the file}
   *  apikey:    &str        {The virus total api key}
   * Returns Result<Repsonse>
   */
  pub fn upload_file(filename: &str, bytes: Vec<u8>, apikey: &str) -> reqwest::Result<Response> {
    let url = format!("https://www.virustotal.com/api/v3/files");
    let file_param = format!("file=@{filename}");

    // Build the request to upload a file under 32MB.
    let builder = ClientBuilder::new()
    .build()?
    .request(Method::POST, url)
    .header("accept", "application/json")
    .header("content-type", "multipart/form-data")
    .header("x-apikey", apikey)
    .form(&file_param)
    .body(bytes);

    // Send the request and get the response.
    let response = builder.send()?;
    Ok(response)
  }

  /**Function displays crowd sources yara rules from the virus total api response in regards to a file hash.
   * Params:
   *  output_data: FileJsonOutput {The virus total api response}
   * Returns Option<Table>
   */
  pub fn get_yara_rules(output_data: FileJsonOutput) -> Option<Table> {
    let mut table = Table::new();
    let labels = String::from(
      "Description\nSource\nAuthor\nRuleset_ID\nRuleset_Name\nRule_Name"
    );

    let mut rows: Vec<Row> = Default::default();
    let rules = output_data.data?.attributes?.crowdsourced_yara_results?;
    
    for i in rules {
      let mut input = String::new();
      
      if let Some(d) = i.description {
        input.push_str(format!("{}\n", d).as_str());
      }

      if let Some(s) = i.source {
        input.push_str(format!("{}\n", s).as_str());
      }

      if let Some(a) = i.author {
        input.push_str(format!("{}\n", a).as_str());
      }

      if let Some(rn) = i.ruleset_name {
        input.push_str(format!("{}\n", rn).as_str());
      }

      if let Some(ri) = i.ruleset_id {
        input.push_str(format!("{}\n", ri).as_str());
      }

      if let Some(name) = i.rule_name {
        input.push_str(format!("{}", name).as_str());
      }

      rows.push(Row::from(vec![
        Cell::from(labels.as_str()).fg(Color::Yellow),
        Cell::from(input.as_str()).fg(Color::DarkCyan),
      ]));
    }

    table.add_rows(rows);

    Some(table)
  }

  /**Function makes a GET reuqest to the virus total api query a hash for the input file.
   * Params:
   *  hash_id: &str {The file hash}
   *  apikey: &str  {The Virus Total api key}
   * Returns nothing
   */
  pub fn search_detections(output_data: FileJsonOutput) -> Option<Table> {
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

    Some(table)
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
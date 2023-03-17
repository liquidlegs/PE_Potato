use comfy_table::{Table, Cell, Row, Color};
use super::{
  av_json::*,
  ClientBuilder, Method,
};

pub struct VirusTotal {}
impl VirusTotal {

  /**Function displayed detailed information about each resource in the file.
   * Params:
   *  output_data: VtJsonOutput {The parsed json response}
   * Returns nothing.
   */
  pub fn get_resource_details(output_data: VtJsonOutput) -> () {
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

    let mut peinfo = PeInfo::default();
    let mut resources: Vec<ResourceDetails> = Default::default();

    if let Some(data) = output_data.data {
      if let Some(att) = data.attributes {
        if let Some(pe) = att.pe_info {
          peinfo = pe;
        }
      }
    }

    if let Some(r) = peinfo.resource_details {
      resources = r.clone();
    }

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

    println!("{table}");
  }

  /**Function displays detailed information about the section header.
   * Params:
   *  output_data: VtJsonOutput {The parsed json response}
   * Returns nothing.
   */
  pub fn get_sections(output_data: VtJsonOutput) -> () {
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

    let mut sections: Vec<VtSection> = Default::default();
    let mut pe = PeInfo::default();

    if let Some(data) = output_data.data {
      if let Some(att) = data.attributes {
        if let Some(s) = att.pe_info {
          pe = s;
        }
      }
    }

    if let Some(sec) = pe.sections {
      sections = sec;
    }

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

    println!("{section_table}");
  }

  pub fn parse_response(response: String) -> VtJsonOutput {
    // Deserialize the json object in another thread.
    let (tx, rx) = std::sync::mpsc::channel::<VtJsonOutput>();
    std::thread::spawn(Box::new(move || {
      match serde_json::from_str::<VtJsonOutput>(&response) {
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

    output_data
  }
  
  /**Function queries virus total for general info about the sample.
   * Params:
   *  hash_id:  &str {The hash of the sample}
   *  apikey:   &str {The virus total api key}
   *  cpu:      bool {Tells us whether the cpu is 64 or 32}
   * Returns nothing
   */
  pub fn get_general_info(output_data: VtJsonOutput) -> () {
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

    println!("{table}");
  }

  /**Function queries the virus total api and returns a string with the json response.
   * Params:
   *  hash_id: &str {The hash to query}
   *  apikey: &str  {The users api key}
   * Returns String
   */
  pub fn query_api(hash_id: &str, apikey: &str) -> String {
    let base_url = format!("https://www.virustotal.com/api/v3/files/{hash_id}");
  
    let builder = ClientBuilder::new()
                                  .build().unwrap().request(Method::GET, base_url)
                                  .header("x-apikey", apikey);
    
    let request = builder.send().unwrap();
    let text = request.text().unwrap();

    text
  }

  /**Function uploads a file to virus total with the api and returns a response when complete.
   * Params:
   *  filename: &str        {The name of the file to upload}
   *  bytes:    Vec<u8>     {The raw bytes of the file}
   *  apikey:    &str        {The virus total api key}
   * Returns Result<()>
   */
  pub fn upload_file(filename: &str, bytes: Vec<u8>, apikey: &str) -> reqwest::Result<()> {
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
    let text = response.text()?;

    Ok(())
  }

  /**Function makes a GET reuqest to the virus total api query a hash for the input file.
   * Params:
   *  hash_id: &str {The file hash}
   *  apikey: &str  {The Virus Total api key}
   * Returns nothing
   */
  pub fn search_detections(output_data: VtJsonOutput) -> std::io::Result<()> {
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
          av = Self::get_engine_data(results);
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
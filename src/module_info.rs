use winapi;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum AV {
  VirusTotal,
  AVG,
  Avira,
  Defender,
  Nortan,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ModuleInfo {
  functions: Vec<String>,
  strings: Vec<String>,
  sections: Vec<String>,
  entropy: u32,
  arch: u32,
  detected: Vec<(AV, bool)>,
  md5: String,
  sha_256: String,
  sha_512: String,
}

impl ModuleInfo {
  pub fn load_functions(&self) {

  }

  pub fn load_strings(&self) {

  }

  pub fn load_sections(&self) {

  }

  pub fn get_detections(&self) {

  }

  pub fn get_general_info(&self) {
    
  }
}
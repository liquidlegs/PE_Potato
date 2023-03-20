use serde::Deserialize;
use std::thread;
use std::sync::mpsc;

#[derive(Debug, Clone)]
pub enum FunctionType {
  Enumeration,
  Execution,
  Collection,
  DefenseEvasion,
  Networking,
  AntiDebugging,
  Crypto,
  Helper
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct MaliciousCategories {
  enumeration:        Vec<String>,
  execution:          Vec<String>,
  collection:         Vec<String>,
  defense_evasion:    Vec<String>,
  networking:         Vec<String>,
  anti_debugging:     Vec<String>,
  crypto:             Vec<String>,
  helper:             Vec<String>,  
}

const BLACK_LIST: &str = "src/arguments/text_files/blacklist.json";
impl MaliciousCategories {

  /**Function loads the function blacklist and then deserializes the json object into a structure.
   * Params:
   *  None
   * Returns Result<MaliciousCategories>
   */
  pub fn read_blacklist(&self) -> std::io::Result<(MaliciousCategories)> {
    let path = std::path::Path::new(BLACK_LIST);
    let bytes = std::fs::read(path)?;

    let mut utf8_string = String::new();
    if let Ok(s) = String::from_utf8(bytes) {
      utf8_string.push_str(s.as_str());
    }

    let (tx, rx) = mpsc::channel::<MaliciousCategories>();
    thread::spawn(Box::new(move || {
      match serde_json::from_str::<MaliciousCategories>(&utf8_string) {
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
    let mut data = MaliciousCategories::default();
    match rx.recv() {
      Ok(s) => {
        data = s;
      },
      Err(_) => {}
    }

    Ok(data)
  }
}






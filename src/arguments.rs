use clap::Parser;
use console::style;
use goblin::Object;
use goblin::pe::{
  export::Export,
  import::Import,
};
use std::path::Path;
use std::{
  fs::read,
};
use comfy_table::{Table, Cell, Row, Color};
use reqwest::{
  blocking::ClientBuilder, Method
};

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

#[derive(Debug, Clone, Parser)]
#[clap(author, about, version)]
pub struct Arguments {
  #[clap(value_parser)]
  /// The file name or path
  pub filename: String,

  #[clap(short, long)]
  /// Manuallt enter apikey and query binary on virus total.
  pub api_key: Option<String>,

  #[clap(long, default_value_if("vt", Some("false"), Some("true")), min_values(0))]
  /// Shows a query on virus total. Must be enabled in the config file.
  pub vt: bool,
  
  #[clap(short, long, default_value_if("exports", Some("false"), Some("true")), min_values(0))]
  /// Exported functions.
  pub exports: bool,

  #[clap(long, default_value_if("ex_libs", Some("false"), Some("true")), min_values(0))]
  /// Shows libraies used by exported function.
  pub ex_libs: bool,
  
  #[clap(short, long, default_value_if("imports", Some("false"), Some("true")), min_values(0))]
  /// imported functions.
  pub imports: bool,
}

impl Arguments {
  pub fn display_data(&self, bytes: Vec<u8>, settings: &mut CmdSettings, sh_everything: bool) -> goblin::error::Result<()> {
    match Object::parse(&bytes)? {
      Object::Elf(_) => {},
      
      Object::PE(pe) => {
        let imports = pe.imports;
        let exports = pe.exports;
        
        Self::load_config_file(settings).unwrap();
        if sh_everything == true {
          let export_table = Self::get_exports(&exports);
          println!("{export_table}");
          
          let export_lib_table = Self::get_exported_lib(exports);
          println!("{export_lib_table}");

          let import_table = Self::get_imports(&imports);
          println!("{import_table}");

          if self.vt == true {
            if settings.auto_search_vt.clone() == false {
              println!("{}: Virus Total search must be enabled in the config file", style("Error").red().bright());
            }

            else {
              println!("Querying [{}] on Virus Total", style(settings.file_hash.clone()).cyan());
              Self::search_virus_total(&settings.file_hash, &settings.api_key.as_str());
            }
          }
        }

        else {

          if self.vt == true {
            if settings.auto_search_vt.clone() == false {
              println!("{}: Virus Total search must be enabled in the config file", style("Error").red().bright());
            }

            else {
              println!("Querying [{}] on Virus Total", style(settings.file_hash.clone()).cyan());
              Self::search_virus_total(&settings.file_hash, &settings.api_key.as_str());
            }
          }

          if self.exports == true {
            let export_table = Self::get_exports(&exports);
            println!("{export_table}");
          }

          if self.ex_libs == true {
            let export_lib_table = Self::get_exported_lib(exports);
            println!("{export_lib_table}");
          }

          if self.imports == true {
            let import_table = Self::get_imports(&imports);
            println!("{import_table}");
          }

          // virus_total_search(hash.as_str());
        }

      },

      Object::Mach(_) => {},
      Object::Archive(_) => {},
      Object::Unknown(magic) => { println!("unknown magic: {:#x}", magic) }
    }

    Ok(())
  }

  pub fn search_virus_total(hash_id: &str, apikey: &str) -> () {
    let base_url = format!("https://www.virustotal.com/api/v3/files/{hash_id}");
  
    let builder = ClientBuilder::new()
                                  .build().unwrap().request(Method::GET, base_url)
                                  .header("x-apikey", apikey);
    
    // println!("{:#?}", builder);
    let request = builder.send().unwrap();
    let text = request.text().unwrap();
    println!("{text}");
  }

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

  pub fn get_exports(exports: &Vec<Export>) -> Table {
    let mut table = Table::new();
  
    println!("{}: {}", style("Exports").cyan(), style(exports.len()).yellow().bright());
    table.set_header(
      vec![
        Cell::from("Name").fg(Color::Green), 
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
        offsets.push_str(format!("0x{off}\n").as_str());
      }
  
      rvas.push_str(format!("0x{}\n", i.rva).as_str());
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

  pub fn get_imports(imports: &Vec<Import>) -> Table {
    let mut table = Table::new();

    table.set_header(
      vec![
        Cell::from("Name").fg(Color::Green),
        Cell::from("DLL").fg(Color::DarkCyan),
        Cell::from("Offset").fg(Color::DarkYellow),
        Cell::from("RVA").fg(Color::Red),
      ]
    );

    let mut names = String::new();
    let mut dll_names = String::new();
    let mut offsets = String::new();
    let mut rvas = String::new();

    for i in imports {
      names.push_str(format!("{}\n", i.name).as_str());
      dll_names.push_str(format!("{}\n", i.dll).as_str());
      offsets.push_str(format!("{}\n", i.offset).as_str());
      rvas.push_str(format!("{}\n", i.offset).as_str());
    }

    names.pop();
    dll_names.pop();
    offsets.pop();
    rvas.pop();

    table.add_row(
      Row::from(vec![
        Cell::from(names).fg(Color::Green),
        Cell::from(dll_names).fg(Color::DarkCyan),
        Cell::from(offsets).fg(Color::DarkYellow),
        Cell::from(rvas).fg(Color::Red),
      ])
    );

    table
  }

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
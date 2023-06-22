mod arguments;
use arguments::*;

use clap::Parser;
use console::style;
use std::path::Path;
use sha256::try_digest;

#[derive(Debug, PartialEq)]
enum AppState {
  AvSearch,
  BinSearch,
  Waiting,
}

/**Function handles how to add the file hash to the CmdSettings when manually speicified or generated with a file path.
 * Params:
 *  filename_exists: bool       {If true the hash is generated with a file path}
 *  hash_exists:     bool       {If true hash is received from stdin}
 *  input:           bool       {Input can be either a filepath or a hash received from stdin}
 *  argc:            String     {The number of arguments}
 *  args:            Arguments  {Used to query virus total}
 * Returns error::Result<()>
 */
fn run_av_search(filename_exists: bool, hash_exists: bool, input: String, argc: usize, args: Arguments) -> std::result::Result<(), GeneralError> {    
  if filename_exists == true {
    let path = Path::new(&input);
    let bytes = std::fs::read(&input)?;
    let hash = try_digest(path)?;
    let mut settings = CmdSettings::new(hash, bytes);

    if argc == 4 {
      match args.vt_search(&mut settings, true) {
        Ok(_) => {},
        Err(e) => { println!("{}: {e}", style("Error").red().bright()); }
      }
    }

    else if argc > 4 {
      match args.vt_search(&mut settings, false) {
        Ok(_) => {},
        Err(e) => { println!("{}: {e}", style("Error").red().bright()); }
      }
    }
  }

  else if hash_exists == true {
    let mut settings = CmdSettings::new(input, Default::default());

    if argc == 4 {
      match args.vt_search(&mut settings, true) {
        Ok(_) => {},
        Err(e) => { println!("{}: {e}", style("Error").red().bright()); }
      }
    }

    else if argc > 4 {
      match args.vt_search(&mut settings, false) {
        Ok(_) => {},
        Err(e) => { println!("{}: {e}", style("Error").red().bright()); }
      }
    }
  }

  Ok(())
}

fn main() -> std::result::Result<(), GeneralError> {
  let cmdline: Vec<String> = std::env::args().collect();
  let args = Arguments::parse();
  let mut state = AppState::Waiting;
  let mut filename = String::new();
  let mut opt_hash = String::new();
  let mut bin_debug = false;

  let mut av_filename_exists = false;
  let mut av_hash_exists = false;

  if let Some(a) = args.command.clone() {
    
    // Workout which subcommand was executed.
    match a {
      Action::VirusTotal(f) => {
        if let Some(h) = f.filename {
          filename.push_str(h.as_str());
          av_filename_exists = true;
          state = AppState::AvSearch;
        }

        else if let Some(h) = f.vt_hash {
          opt_hash.push_str(h.as_str());
          av_hash_exists = true;
          state = AppState::AvSearch;
        }
      }

      Action::Bin(b) => {
        filename.clear();
        filename.push_str(b.filename.clone().as_str());
        state = AppState::BinSearch;

        if b.debug.clone() == true {
          bin_debug = true;
        }
      }

      _ => {}
    }
  }

  // Virus total commands will execute this branch.
  if state == AppState::AvSearch {
    if av_filename_exists == true {
      run_av_search(true, false, filename, cmdline.len(), args.clone())?;
    }

    else if av_hash_exists == true {
      run_av_search(false, true, opt_hash, cmdline.len(), args.clone())?;
    }
  }

  // Local pe parsing with execute this branch.
  else if state == AppState::BinSearch {

    if bin_debug == true {
      println!("{}: filepath: {}", style("Debug =>").red().bright(), style(filename.clone()).cyan());
    }

    let path = Path::new(&filename);
    let hash = try_digest(path)?;
    
    let mut settings = CmdSettings::new(hash, Default::default());
    let bytes = std::fs::read(path)?;
    
    if cmdline.len() == 3 {
      println!("Showing everything");
      args.display_data(bytes, &mut settings, true)?;
    }

    else if cmdline.len() > 3 {
      args.display_data(bytes, &mut settings, false)?;
    }
  }

  Ok(())
}
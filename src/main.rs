mod arguments;
use arguments::*;

use clap::Parser;
use goblin::error;
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
fn run_av_search(filename_exists: bool, hash_exists: bool, input: String, argc: usize, args: Arguments) -> error::Result<()> {    
  if filename_exists == true {
    let path = Path::new(&input);
    let hash = try_digest(path)?;
    let mut settings = CmdSettings::new(hash);

    if argc == 4 {
      args.vt_search(&mut settings, true)?;
    }

    else if argc > 4 {
      args.vt_search(&mut settings, false)?;
    }
  }

  else if hash_exists == true {
    let mut settings = CmdSettings::new(input);

    if argc == 4 {
      args.vt_search(&mut settings, true)?;
    }

    else if argc > 4 {
      args.vt_search(&mut settings, false)?;
    }
  }

  Ok(())
}

fn main() -> error::Result<()> {
  let cmdline: Vec<String> = std::env::args().collect();
  let args = Arguments::parse();
  let mut state = AppState::Waiting;
  let mut filename = String::new();
  let mut opt_hash = String::new();

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

    let path = Path::new(&filename);
    let hash = try_digest(path)?;
    
    let mut settings = CmdSettings::new(hash);
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
mod arguments;
use arguments::*;

use clap::Parser;
use console::style;
use std::path::Path;
use sha256::try_digest;

#[derive(Debug, PartialEq)]
enum AppState {
  AvSearch,
  MbSearch,
  BinSearch,
  Waiting,
}

/**Intergrate the following tools & apis
  Malware Bazaar:  A resource for sharing malware samples.
  Feodo Tracker:   A resource used to track botnet command and control (C2) infrastructure linked with Emotet, Dridex and TrickBot.
  SSL Blacklist:   A resource for collecting and providing a blocklist for malicious SSL certificates and JA3/JA3s fingerprints.
  URL Haus:        A resource for sharing malware distribution sites.
  Threat Fox:      A resource for sharing indicators of compromise (IOCs).
  YARAify:         A database for storing and sharing YARA rules.
 */

/**Function handles how to add the file hash to the CmdSettings when manually speicified or generated with a file path.
 * Params:
 *  filename_exists: bool       {If true the hash is generated with a file path}
 *  hash_exists:     bool       {If true hash has been received from stdin}
 *  upload:          bool       {Set to true if uploading to virus total, fIlename should always exist.}
 *  input:           bool       {Input can be either a filepath or a hash received from stdin}
 *  argc:            String     {The number of arguments}
 *  args:            Arguments  {Used to query virus total}
 * Returns error::Result<()>
 */
fn run_av_search(filename_exists: bool, hash_exists: bool, input: String, argc: usize, args: Arguments) 
-> std::result::Result<(), GeneralError> {

  if filename_exists == true {
    let path = Path::new(&input);
    let bytes = std::fs::read(&input)?;
    let hash = try_digest(path)?;
    let mut settings = CmdSettings::new(hash, bytes);

    if argc == 4 {
      match args.vt_enable_search(&mut settings, true) {
        Ok(_) => {},
        Err(e) => { println!("{}: {e}", style("Error").red().bright()); }
      }
    }

    else if argc > 4 {
      match args.vt_enable_search(&mut settings, false) {
        Ok(_) => {},
        Err(e) => { println!("{}: {e}", style("Error").red().bright()); }
      }
    }
  }

  else if hash_exists == true {
    let mut settings = CmdSettings::new(input, Default::default());

    if argc == 4 {
      match args.vt_enable_search(&mut settings, true) {
        Ok(_) => {},
        Err(e) => { println!("{}: {e}", style("Error").red().bright()); }
      }
    }

    else if argc > 4 {
      match args.vt_enable_search(&mut settings, false) {
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
        let c_f = f.clone();

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

        else if av_filename_exists == false && av_hash_exists == false {
          println!(
            "\n{}: Please note that search requires a hash/file to be supplied by specifying [{}], [{}] or by uploading a file with [{}]", 
            style("Info").yellow().bright(), style("--vt-hash").cyan(), style("-f").cyan(), style("-u").cyan()
          );
          
          std::process::exit(0);
        }

        // Code block prevents users from providing -f or --vt-hash without suppliying arguments to display the data.
        if av_filename_exists == true || av_hash_exists == true {
          let flags = c_f.count_valid_flags();

          if flags < 2 {
            println!(
              "\n{}: The {} or {} flags are must be supplied to query the Virus Total API, however, addtional flags must be supplied to display the data", 
              style("Error").red().bright(), style("-f").cyan(), style("--vt-hash").cyan()
            );

            println!("{}: PE_Potato virus-total {} <{}> {} will display some basic properties, sections, resources and yara rules (if any)",
            style("For example").yellow().bright(), style("--vt-hash").cyan(), style("hash").green().bright(), style("-g -s -r -y").cyan());

            std::process::exit(0);
          }
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

      Action::MalwareBazaar(_) => {
        state = AppState::MbSearch;
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

  else if state == AppState::MbSearch {
    let mut settings = CmdSettings::new(String::new(), Default::default());
    args.mb_enable_search(&mut settings)?;
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
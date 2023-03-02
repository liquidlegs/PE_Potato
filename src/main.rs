mod arguments;
use arguments::*;

use clap::Parser;
use goblin::error;
use std::path::Path;
use std::env;
use sha256::try_digest;

fn main() -> error::Result<()> {
  
  let args = Arguments::parse();
  let cmdline: Vec<String> = env::args().collect();
  let path = Path::new(cmdline[1].as_str());
  println!("{:?}", path);
  let hash = try_digest(path)?;

  let mut settings = CmdSettings::new(hash);
  let bytes = std::fs::read(path)?;
  
  if cmdline.len() == 2 {
    println!("Showing everything");
    args.display_data(bytes, &mut settings, true)?;
  }

  else if cmdline.len() > 2 {
    args.display_data(bytes, &mut settings, false)?;
  }

  Ok(())
}
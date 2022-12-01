extern crate native_windows_gui as nwg;
extern crate native_windows_derive as nwd;

// mod about;
// mod module_info;

use nwd::NwgUi;
use nwg::{NativeUi, FlexboxLayout};
use nwg::{Button, Window, FileDialog, GridLayout};
use std::env;

#[derive(Default, NwgUi)]
pub struct MainWindow {
  #[nwg_control(size: (800, 600), position: (50, 50), title: "PE Potato")]
  #[nwg_events(OnWindowClose: [MainWindow::exit])]
  window: Window,

  #[nwg_layout(parent: window, spacing: 1, max_size: [310, 35])]
  toolbar_layout: GridLayout,

  #[nwg_layout_item(layout: toolbar_layout, row: 0, col: 0)]
  #[nwg_control(text: "Open")]
  #[nwg_events(OnButtonClick: [MainWindow::open_file])]
  open_file_btn: Button,

  #[nwg_resource(title: "Open File", action: nwg::FileDialogAction::Open)]
  open_file_dg: FileDialog,

  #[nwg_layout_item(layout: toolbar_layout, row: 0, col: 1)]
  #[nwg_control(text: "Close File")]
  close_file: Button,

  #[nwg_layout_item(layout: toolbar_layout, row: 0, col: 2)]
  #[nwg_control(text: "About")]
  about: Button,

  #[nwg_layout_item(layout: toolbar_layout, row: 0, col: 3)]
  #[nwg_control(text: "Exit")]
  #[nwg_events(OnButtonClick: [MainWindow::exit])]
  close_app: Button,
}

impl MainWindow {
  pub fn exit(&self) {
    nwg::stop_thread_dispatch();
  }

  // Function opens the file dialog and sets the path of the file as the window title.
  pub fn open_file(&self) {

    // Gets the current directory path.
    match env::current_dir() {
      Ok(s) => {

        match s.to_str() {
          // Attempts to convert the string to a slice.
          Some(s) => {
            println!("Setting current directory [{}]", s);

            // Sets the directory path to be used as the default folder location.
            match self.open_file_dg.set_default_folder(s) {
              Ok(_) => {},
              Err(e) => { println!("{}", e); }
            }
          }

          None => {
            // Sets the default folder location as the root of the C drive anything goes wrong.
            match self.open_file_dg.set_default_folder("C:\\") {
              Ok(_) => {},
              Err(e) => { println!("{}", e); }
            }
          }
        }
      },

      Err(e) => { println!("Unable to get current directory {}", e); }
    }

    // Opens the file dialog.
    let result = self.open_file_dg.run(Some(&self.window));
    if result == true {

      if let Ok(directory) = self.open_file_dg.get_selected_item() {
        // Gets the path of the selected item by the user and sets the string as the title of the window.
        match directory.into_string() {
          Ok(s) => {
            self.window.set_text(s.as_str());
          },

          Err(e) => {
            drop(e);
            println!("Unable to set current executable as window title");
          }
        }
      }
    }
  }

  pub fn read_file(&self) {

  }
}

fn main() {
  nwg::init().expect("Failed to initalize the PE Potato GUI");

  let app = MainWindow::build_ui(Default::default()).expect("Failed to build GUI");

  nwg::dispatch_thread_events();
}

mod about;
mod module_info;

use fltk::{app, button::Button, frame::Frame, prelude::*, window::Window, enums::{Color, FrameType}, group::{HGrid}, menu::MenuButton};
use fltk::{menu::{MenuFlag, MenuBar, MenuButtonType}, enums::Shortcut};

fn main() {
  // The UI is created with a window size of 800X600 pixcels.
  let app = app::App::default().with_scheme(app::Scheme::Gtk);
  let mut m_window = Window::default().with_size(800, 600).center_screen();
  
  let mut menu = MenuBar::default()
      .with_size(m_window.pixel_w(), 25)
      .with_type(MenuButtonType::Popup123);
  menu.add_choice("Open|Close-File|About");
  menu.set_color(Color::from_u32(0x424242));
  menu.set_text_color(Color::White);

  // Displays the position of the window in terms of Width X Height
  let mut dbg_frame = Frame::default().with_size(200, 25).with_label("W:  H:  X:  Y: ").center_of(&menu);
  dbg_frame.set_frame(FrameType::GleamUpFrame);
  dbg_frame.set_label_color(Color::White);
  
  menu.end();       // All objects created after the menubar is initiated will be added to the object as children.
  menu.show();      // Displays the menubar.

  // Callback events for each button.
  menu.add("Open", Shortcut::None, MenuFlag::Normal, Box::new(|callback: &mut MenuBar| {
    println!("Open clicked");
  }));

  menu.add("Close-File", Shortcut::None, MenuFlag::Normal, Box::new(|callback: &mut MenuBar| {
    println!("Close-File clicked");
  }));

  menu.add("About", Shortcut::None, MenuFlag::Normal, Box::new(|callback: &mut MenuBar| {
    println!("About clicked");
  }));

  m_window.make_resizable(true);
  m_window.set_color(Color::from_u32(0xE9E9E9));

  // The position of windows pixels are retrived whenever the window is resized.
  m_window.resize_callback(Box::new(move |window: &mut Window, x: i32, y: i32, w: i32, h: i32| {
    let w = window.pixel_w().to_string();
    let h = window.pixel_h().to_string();
    dbg_frame.set_label(format!("D\t[W: {}, H: {}]", w.as_str(), h.as_str()).as_str());
  }));

  m_window.end();
  m_window.show();

  app.run().unwrap();
}
// Prevents an extra console window on Windows in release builds of the
// desktop check build. The phone builds start from `run` in lib.rs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    deskvnc_mobile_lib::run()
}

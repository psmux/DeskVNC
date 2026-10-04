//! Check capture size and pointer mapping on this machine.
//! cargo run -p boundary-platform --example probe
use boundary_session::Input;
fn main() -> anyhow::Result<()> {
    for d in boundary_platform::displays()? {
        println!("display {} {}", d.id, d.name);
    }
    let first = boundary_platform::displays()?[0].id;
    let mut desktop = boundary_platform::open(first)?;
    let frame = desktop.capture()?;
    println!("frame {}x{}", frame.width, frame.height);
    for (x, y) in [(0.25f32, 0.25f32), (0.75, 0.5)] {
        desktop.input(Input::Move { x, y })?;
        std::thread::sleep(std::time::Duration::from_millis(200));
        println!("moved to fraction {x},{y}");
        let out = std::process::Command::new("powershell").args(["-NoProfile","-Command","Add-Type -AssemblyName System.Windows.Forms; $p=[System.Windows.Forms.Cursor]::Position; $b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds; \"cursor $($p.X),$($p.Y) of $($b.Width)x$($b.Height)\""]).output()?;
        print!("{}", String::from_utf8_lossy(&out.stdout));
    }
    Ok(())
}

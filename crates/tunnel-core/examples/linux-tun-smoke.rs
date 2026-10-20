#[cfg(target_os = "linux")]
use std::io::{self, Write};
#[cfg(target_os = "linux")]
use std::{path::Path, thread, time::Duration};

#[cfg(target_os = "linux")]
use tunnel_core::{LinuxTunDevice, TunnelDevice};

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut device = LinuxTunDevice::create(Some("gsmtest0"), 1_500)?;
    println!("ready name={} mtu={}", device.name(), device.mtu());
    io::stdout().flush()?;

    if let Some(start_file) = std::env::var_os("GSM_TUN_START_FILE") {
        while !Path::new(&start_file).exists() {
            thread::sleep(Duration::from_millis(10));
        }
    }

    let mut packet = [0; 1_500];
    let read = device.read_packet(&mut packet)?;
    println!("read bytes={read}");
    io::stdout().flush()?;

    let written = device.write_packet(&packet[..read])?;
    println!("written bytes={written}");
    io::stdout().flush()?;

    device.close()?;
    println!("closed");
    io::stdout().flush()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("linux-tun-smoke requires Linux");
}

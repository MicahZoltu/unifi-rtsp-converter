//! Command-line entry point. Parses `--install`, `--uninstall`, and
//! `--console` arguments. The Windows Service Control Manager FFI lifecycle
//! lands in a later step; for now these branches print a banner only.
//!
//! The logic modules live in the `flvproxy` library crate (`src/lib.rs`);
//! the binary imports them as needed in later steps.

/// Prints the startup banner identifying the proxy and its supported modes.
fn print_banner() {
    println!("flvproxy — UniFi Camera FLV-to-RTSP/ONVIF proxy");
    println!("usage: flvproxy [--install | --uninstall | --console]");
}

/// Handles a recognized CLI flag by printing the matching stub message.
///
/// Returns the process exit code to report to the operating system.
fn handle_flag(flag: &str) -> i32 {
    match flag {
        "--install" => {
            println!("--install: service installation not implemented yet");
            0
        }
        "--uninstall" => {
            println!("--uninstall: service removal not implemented yet");
            0
        }
        "--console" => {
            println!("--console: foreground run not implemented yet");
            0
        }
        other => {
            eprintln!("flvproxy: unknown argument '{other}'");
            eprintln!("valid arguments: --install, --uninstall, --console");
            1
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_banner();
        return;
    }
    let code = handle_flag(&args[0]);
    std::process::exit(code);
}

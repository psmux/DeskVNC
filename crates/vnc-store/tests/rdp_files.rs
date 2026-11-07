//! Importing `.rdp` files as they are found on disk (issue #20).
//!
//! The unit tests in `rdpfile.rs` build their input in code. These read files:
//! one as `mstsc` saves it (UTF-16 LE with a BOM, CRLF, every key it writes,
//! a saved password and an RD Gateway), and one a person wrote by hand in
//! UTF-8. Each draft is saved through the store and read back, because a
//! draft that does not survive `save_host` is not an import.

use remote_core::{AudioMode, RdpColorDepth, RdpResolution};
use vnc_store::{parse_rdp_file, RdpImport, RdpSettings, Store};

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn import(name: &str) -> RdpImport {
    parse_rdp_file(&fixture(name), Some(name)).expect("the file imports")
}

fn saved_and_read_back(import: &RdpImport) -> (vnc_store::HostProfile, RdpSettings) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(Some(dir.path().to_path_buf())).unwrap();
    store.save_host(&import.profile).unwrap();
    let back = store
        .get_host(&import.profile.id)
        .unwrap()
        .expect("the saved host");
    let settings = RdpSettings::parse(back.rdp_settings.as_deref())
        .unwrap()
        .expect("the RDP settings were saved");
    (back, settings)
}

#[test]
fn the_mstsc_file_is_utf16_with_a_bom() {
    let bytes = fixture("mstsc-gateway-utf16le.rdp");
    assert_eq!(
        &bytes[..2],
        &[0xff, 0xfe],
        "the fixture is what mstsc writes"
    );
    assert!(bytes.windows(4).any(|w| w == [b'\r', 0, b'\n', 0]));
}

#[test]
fn a_file_saved_by_mstsc_becomes_a_host() {
    let import = import("mstsc-gateway-utf16le.rdp");
    assert_eq!(import.unparseable, 0);
    let (host, settings) = saved_and_read_back(&import);

    assert_eq!(host.protocol, "rdp");
    assert_eq!(host.friendly_name, "mstsc-gateway-utf16le");
    assert_eq!(host.address, "192.0.2.10");
    assert_eq!(host.port, 3390);
    assert_eq!(import.username.as_deref(), Some("EXAMPLE\\operator"));
    assert_eq!(settings.options.domain.as_deref(), Some("EXAMPLE"));

    // Screen mode and size.
    assert!(settings.fullscreen, "screen mode id:i:2 is full screen");
    assert_eq!(import.desktop_size, Some((1920, 1080)));
    assert_eq!(
        settings.options.resolution,
        RdpResolution::Fixed {
            width: 1920,
            height: 1080
        }
    );
    // Smart sizing, audio, clipboard, colour depth.
    assert_eq!(host.scaling_mode, "aspect-fit");
    assert_eq!(settings.options.audio, AudioMode::PlayLocally);
    assert!(settings.clipboard);
    assert_eq!(settings.options.color_depth, RdpColorDepth::Bpp32);
    for key in [
        "full address",
        "screen mode id",
        "desktopwidth",
        "smart sizing",
        "audiomode",
        "redirectclipboard",
    ] {
        assert!(import.mapped.iter().any(|k| k == key), "{key} was mapped");
    }
}

#[test]
fn a_gateway_is_kept_and_survives_a_save() {
    let import = import("mstsc-gateway-utf16le.rdp");
    let (_, settings) = saved_and_read_back(&import);
    let gateway = settings.options.gateway.expect("the gateway is recorded");
    assert_eq!(gateway.host, "gw.example.net");
    assert_eq!(gateway.port, 443);
    // The connection now goes through it, so there is nothing to warn about.
    assert!(
        !import.warnings.iter().any(|w| w.contains("RD Gateway")),
        "{:?}",
        import.warnings
    );
}

#[test]
fn the_saved_password_is_never_imported() {
    let import = import("mstsc-gateway-utf16le.rdp");
    let (host, _) = saved_and_read_back(&import);
    assert!(!host.has_password);
    let everything = serde_json::to_string(&import).unwrap();
    assert!(
        !everything.contains("D08C9DDF"),
        "no byte of the password blob is anywhere in the import"
    );
    assert!(import.ignored.iter().any(|k| k == "password 51"));
    assert!(import.warnings.iter().any(|w| w.contains("saved password")));
}

#[test]
fn a_hand_written_utf8_file_becomes_a_host() {
    let import = import("plain-utf8.rdp");
    assert_eq!(import.unparseable, 0);
    let (host, settings) = saved_and_read_back(&import);

    assert_eq!(host.address, "198.51.100.20");
    assert_eq!(host.port, 3389, "no port in the file is the RDP default");
    assert_eq!(host.friendly_name, "plain-utf8");
    assert_eq!(import.username.as_deref(), Some("operator"));
    assert_eq!(settings.options.domain.as_deref(), Some("LAB"));
    assert!(!settings.fullscreen, "screen mode id:i:1 is a window");
    assert_eq!(
        settings.options.resolution,
        RdpResolution::Fixed {
            width: 1280,
            height: 720
        }
    );
    assert_eq!(host.scaling_mode, "actual", "smart sizing off is 1:1");
    assert_eq!(settings.options.audio, AudioMode::Off);
    assert!(!settings.clipboard);
    assert_eq!(settings.options.color_depth, RdpColorDepth::Bpp16);
    assert!(settings.options.gateway.is_none());
    assert!(
        import.warnings.is_empty(),
        "nothing to warn about: {:?}",
        import.warnings
    );
}

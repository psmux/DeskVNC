//! The store's side of RDP support, through the public API only.
//!
//! These are the tests that stand between a schema change and a user losing
//! their saved hosts, so they assert what a profile *is* after a round trip
//! rather than which SQL ran. The migration itself is tested inside the crate,
//! where `MIGRATIONS` can be applied by hand to build an old database
//! (`migrating_a_v2_database_gives_every_host_the_vnc_protocol`).

use vnc_store::{CertPin, HostProfile, ProtocolKind, RdpSettings, Store};

fn temp_store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(Some(dir.path().to_path_buf())).unwrap();
    (dir, store)
}

fn rdp_host(name: &str, address: &str) -> HostProfile {
    let mut settings = RdpSettings::default();
    settings.options.domain = Some("CORP".into());
    settings.options.legacy_tls = true;
    HostProfile {
        friendly_name: name.to_string(),
        address: address.to_string(),
        rdp_settings: Some(settings.to_json().unwrap()),
        ..HostProfile::for_protocol(ProtocolKind::Rdp)
    }
}

#[test]
fn an_rdp_profile_round_trips() {
    let (_dir, store) = temp_store();
    let host = rdp_host("Office PC", "10.0.0.5");
    let blob = host.rdp_settings.clone().unwrap();
    store.save_host(&host).unwrap();

    for got in [
        store.get_host(&host.id).unwrap().unwrap(),
        store.list_hosts().unwrap().pop().unwrap(),
    ] {
        assert_eq!(got.protocol, "rdp");
        assert_eq!(got.protocol_kind(), Some(ProtocolKind::Rdp));
        assert_eq!(got.port, 3389);
        assert_eq!(
            got.rdp_settings.as_deref(),
            Some(blob.as_str()),
            "the blob comes back byte for byte"
        );
        let parsed = RdpSettings::parse(got.rdp_settings.as_deref())
            .unwrap()
            .unwrap();
        assert_eq!(parsed.options.domain.as_deref(), Some("CORP"));
        assert!(parsed.options.legacy_tls);
    }

    // An update keeps the created date, the same promise `host_crud_round_trip`
    // makes for a VNC profile.
    let mut edited = store.get_host(&host.id).unwrap().unwrap();
    edited.friendly_name = "Office".into();
    edited.rdp_settings = Some(RdpSettings::default().to_json().unwrap());
    store.save_host(&edited).unwrap();
    let again = store.get_host(&host.id).unwrap().unwrap();
    assert_eq!(again.friendly_name, "Office");
    assert_eq!(again.created_at, host.created_at);
    assert!(
        !RdpSettings::parse(again.rdp_settings.as_deref())
            .unwrap()
            .unwrap()
            .options
            .legacy_tls
    );
}

/// The store never parses the blob, so one bad blob cannot hide a tile. This
/// is the test that pins that decision (PRDRDP/08 §2.4).
#[test]
fn a_profile_with_an_unreadable_rdp_blob_is_still_usable() {
    let (_dir, store) = temp_store();
    let mut host = rdp_host("Broken", "10.0.0.6");
    host.rdp_settings = Some("{not json".into());
    store.save_host(&host).unwrap();

    let listed = store.list_hosts().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].rdp_settings.as_deref(), Some("{not json"));
    let got = store.get_host(&host.id).unwrap().unwrap();
    assert_eq!(got.rdp_settings.as_deref(), Some("{not json"));

    // It is the typed reader that refuses it, where a failure is a refusal to
    // connect rather than a profile that vanished.
    assert!(RdpSettings::parse(got.rdp_settings.as_deref()).is_err());

    // And it can still be repaired and deleted.
    let mut fixed = got;
    fixed.rdp_settings = Some(RdpSettings::default().to_json().unwrap());
    store.save_host(&fixed).unwrap();
    assert!(RdpSettings::parse(
        store
            .get_host(&host.id)
            .unwrap()
            .unwrap()
            .rdp_settings
            .as_deref()
    )
    .unwrap()
    .is_some());
    store.delete_host(&host.id).unwrap();
    assert!(store.get_host(&host.id).unwrap().is_none());
}

/// A profile written by a newer build is refused, never misread. The whole
/// point of the `v` field: a field whose *meaning* changed would otherwise be
/// read under the old meaning and act on it.
#[test]
fn a_profile_from_a_newer_schema_is_refused_rather_than_misread() {
    let (_dir, store) = temp_store();
    let mut host = rdp_host("From The Future", "10.0.0.7");
    // A blob a later build wrote: a higher `v`, and a value for `nla` that a
    // future version might well spell differently.
    host.rdp_settings = Some(r#"{"v":2,"domain":"CORP","nla":"required"}"#.into());
    store.save_host(&host).unwrap();

    let got = store.get_host(&host.id).unwrap().unwrap();
    assert!(
        got.rdp_settings.as_deref().unwrap().contains("\"v\":2"),
        "the store stores it verbatim, it does not police the blob"
    );
    let err = RdpSettings::parse(got.rdp_settings.as_deref()).unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("newer version"),
        "the message must say the app is old, not that the profile is corrupt: {text}"
    );
}

/// An unrecognised protocol string reads back verbatim and matches nothing,
/// rather than aliasing onto a protocol we do implement. Mirrors
/// `a_pin_never_satisfies_a_different_scheme`.
#[test]
fn an_unknown_protocol_string_is_readable_and_never_aliases() {
    let (_dir, store) = temp_store();
    let host = HostProfile {
        friendly_name: "Something else".into(),
        address: "10.0.0.8".into(),
        port: 5900,
        protocol: "spice".into(),
        ..Default::default()
    };
    store.save_host(&host).unwrap();

    let got = store.get_host(&host.id).unwrap().unwrap();
    assert_eq!(got.protocol, "spice");
    assert_eq!(got.protocol_kind(), None);
    assert!(store
        .find_host_by_address(ProtocolKind::Vnc, "10.0.0.8", 5900)
        .unwrap()
        .is_none());
    assert!(store
        .find_host_by_address(ProtocolKind::Rdp, "10.0.0.8", 5900)
        .unwrap()
        .is_none());
    assert_eq!(store.list_hosts().unwrap().len(), 1, "still listable");
}

/// One endpoint under two protocols is two profiles. One TCP port carries one
/// service, so in practice only one of them works, and refusing to store the
/// pair would mean a user who mistyped a port once cannot fix it.
#[test]
fn the_same_endpoint_under_two_protocols_is_two_hosts() {
    let (_dir, store) = temp_store();
    let rdp = store
        .adopt_endpoint_for(ProtocolKind::Rdp, "10.0.0.5", 3389)
        .unwrap();
    let vnc = store
        .adopt_endpoint_for(ProtocolKind::Vnc, "10.0.0.5", 3389)
        .unwrap();

    assert_ne!(rdp.id, vnc.id);
    assert_eq!(store.list_hosts().unwrap().len(), 2);
    assert_eq!(
        store
            .find_host_by_address(ProtocolKind::Rdp, "10.0.0.5", 3389)
            .unwrap()
            .unwrap()
            .id,
        rdp.id
    );
    assert_eq!(
        store
            .find_host_by_address(ProtocolKind::Vnc, "10.0.0.5", 3389)
            .unwrap()
            .unwrap()
            .id,
        vnc.id
    );
}

/// The regression test for the bug §2.6 names: adopting an RDP endpoint under
/// the old two argument call minted a VNC profile pointing at 3389, which
/// failed on every later connect from the tile.
#[test]
fn adopting_an_rdp_endpoint_produces_an_rdp_profile() {
    let (_dir, store) = temp_store();
    let adopted = store
        .adopt_endpoint_for(ProtocolKind::Rdp, "10.0.0.5", 3389)
        .unwrap();
    assert_eq!(adopted.protocol, "rdp");
    assert_eq!(adopted.port, 3389);
    assert_eq!(adopted.friendly_name, "10.0.0.5");

    // Adopting the same endpoint again returns the same profile.
    let again = store
        .adopt_endpoint_for(ProtocolKind::Rdp, "10.0.0.5", 3389)
        .unwrap();
    assert_eq!(again.id, adopted.id);
    assert_eq!(store.list_hosts().unwrap().len(), 1);

    // The two argument spelling the shell still calls adopts VNC, which is
    // what a VNC-only build could only have meant.
    let vnc = store.adopt_endpoint("10.0.0.9", 5900).unwrap();
    assert_eq!(vnc.protocol, "vnc");
}

/// An RDP pin and a VNC pin for one machine are two rows that never shadow
/// each other, and forgetting one endpoint leaves the other alone. Modelled on
/// `tls_and_ra2_pins_coexist_without_shadowing`.
#[test]
fn an_rdp_pin_coexists_with_a_vnc_pin_for_one_machine() {
    let (_dir, store) = temp_store();
    let pin = |port: u16, scheme: &str, spki: &str| CertPin {
        host: "pi.local".into(),
        port,
        scheme: scheme.into(),
        sha256_spki: spki.into(),
        subject: "CN=pi".into(),
        first_trusted_at: 1,
        last_seen_at: 2,
        security_type: None,
    };
    store
        .save_cert_pin(&pin(5900, "tls", &"aa".repeat(32)))
        .unwrap();
    store
        .save_cert_pin(&pin(3389, "rdp-tls", &"bb".repeat(32)))
        .unwrap();

    assert_eq!(
        store
            .get_cert_pin("pi.local", 3389, "rdp-tls")
            .unwrap()
            .unwrap()
            .sha256_spki,
        "bb".repeat(32)
    );
    assert_eq!(store.list_cert_pins("pi.local", 5900).unwrap().len(), 1);
    assert!(
        store
            .get_cert_pin("pi.local", 3389, "tls")
            .unwrap()
            .is_none(),
        "an RDP pin must never satisfy a TLS lookup"
    );

    // Forgetting one endpoint clears every scheme at that endpoint and
    // nothing at the other.
    assert_eq!(store.delete_cert_pins("pi.local", 3389).unwrap(), 1);
    assert_eq!(store.list_cert_pins("pi.local", 5900).unwrap().len(), 1);
}

/// A build that does not know `"rdp-tls"` reads such a row without error and
/// never matches it against another scheme. The store treats the scheme as an
/// opaque string, which is what makes that true.
#[test]
fn an_unknown_pin_scheme_is_readable_and_never_matches() {
    let (_dir, store) = temp_store();
    store
        .save_cert_pin(&CertPin {
            host: "gw.example".into(),
            port: 443,
            scheme: "rdp-gateway-tls".into(),
            sha256_spki: "cc".repeat(32),
            subject: "CN=gw".into(),
            first_trusted_at: 1,
            last_seen_at: 2,
            security_type: None,
        })
        .unwrap();
    let pins = store.list_cert_pins("gw.example", 443).unwrap();
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].scheme, "rdp-gateway-tls");
    assert!(store
        .get_cert_pin("gw.example", 443, "rdp-tls")
        .unwrap()
        .is_none());
}

//! Unattended access end to end, over real encrypted connections on this
//! machine: pairing during an attended session, then a paired helper, an
//! unknown one, the password, the lockout and the off switch.

use boundary_session::{
    Approval, Desktop, Event, Frame, HostOptions, Input, Session,
    unattended::{self, Access, Notice},
};
use std::{path::PathBuf, time::Duration};
use tokio::time::timeout;

struct Fake;
impl Desktop for Fake {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        Ok(Frame {
            width: 2,
            height: 2,
            rgba: vec![200; 16],
        })
    }
    fn input(&mut self, _: Input) -> anyhow::Result<()> {
        Ok(())
    }
    fn release(&mut self) {}
}

fn local() -> HostOptions {
    HostOptions {
        relay: false,
        relay_url: None,
        bind_ip: None,
    }
}
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "boundary-unattended-{name}-{}-{}",
        std::process::id(),
        unattended_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
fn unattended_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// Wait for a helper session to end, and say how.
async fn outcome(mut session: Session) -> Result<bool, String> {
    loop {
        match session.events.recv().await {
            Some(Event::Connected { control, .. }) => return Ok(control),
            Some(Event::Finished(Err(error))) => return Err(format!("{error:#}")),
            Some(Event::Finished(Ok(()))) | None => return Err("ended without a word".into()),
            _ => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_helper_paired_in_person_comes_back_unattended_and_others_are_refused() {
    timeout(Duration::from_secs(60), async {
        let dir = scratch("flow");
        let machine_key = unattended::load_or_create_key(&dir.join("machine.key")).unwrap();
        let again = unattended::load_or_create_key(&dir.join("machine.key")).unwrap();
        assert_eq!(
            unattended::machine_id(&machine_key),
            unattended::machine_id(&again),
            "the identity lasts"
        );
        let helper_key = unattended::load_or_create_key(&dir.join("helper.key")).unwrap();
        let access_path = dir.join("access.json");

        // 1. An ordinary attended session, where the person pairs the helper.
        let mut host = boundary_session::host(local(), || Ok(Box::new(Fake)));
        let ticket = loop {
            if let Some(Event::Invitation(t)) = host.events.recv().await {
                break t;
            }
        };
        let mut helper =
            boundary_session::viewer_as(ticket, "Godwin".into(), local(), Some(helper_key.clone()));
        let peer = loop {
            match host.events.recv().await {
                Some(Event::Approval { answer, .. }) => {
                    let _ = answer.send(Approval::Control);
                }
                Some(Event::Connected { peer, .. }) => break peer,
                _ => {}
            }
        };
        assert_eq!(
            peer,
            helper_key.public().to_string(),
            "the host sees the helper's lasting key"
        );
        let mut access = Access::default();
        access.enabled = true;
        access.trust(&peer, "Godwin", true).unwrap();
        access.save(&access_path).unwrap();
        let machine = unattended::machine_id(&machine_key);
        host.offer_pairing(machine.clone(), "Office PC".into())
            .unwrap();
        let (paired_id, paired_name) = loop {
            if let Some(Event::Paired { machine, name }) = helper.events.recv().await {
                break (machine, name);
            }
        };
        assert_eq!(
            (paired_id.as_str(), paired_name.as_str()),
            (machine.as_str(), "Office PC")
        );
        host.stop();
        helper.stop();

        // 2. The machine listens unattended.
        let mut listener = unattended::listen(local(), machine_key, access_path.clone(), || {
            Ok(Box::new(Fake))
        });
        let address = loop {
            match listener.notices.recv().await {
                Some(Notice::Ready {
                    address,
                    machine: id,
                }) => {
                    assert_eq!(id, machine);
                    break address;
                }
                Some(Notice::Finished(result)) => panic!("listener ended: {result:?}"),
                _ => {}
            }
        };

        // 3. The paired helper gets in with no password and sees the screen.
        let mut paired = unattended::connect_to(
            Ok(address.clone()),
            "Godwin".into(),
            None,
            helper_key.clone(),
            local(),
        );
        let held = loop {
            match listener.notices.recv().await {
                Some(Notice::Connected {
                    name,
                    control,
                    session,
                    ..
                }) => {
                    assert_eq!(name, "Godwin");
                    assert!(control, "paired with control");
                    break session;
                }
                Some(Notice::Refused { reason, .. }) => panic!("paired helper refused: {reason}"),
                _ => {}
            }
        };
        loop {
            if paired.frames.has_changed().unwrap_or(false)
                && let Some(frame) = paired.frames.borrow_and_update().as_ref()
            {
                assert_eq!(frame.rgba, vec![200; 16]);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        drop(held);
        paired.stop();

        // 4. A stranger with no password is refused, with a reason.
        let stranger = unattended::load_or_create_key(&dir.join("stranger.key")).unwrap();
        let refused = outcome(unattended::connect_to(
            Ok(address.clone()),
            "Stranger".into(),
            None,
            stranger.clone(),
            local(),
        ))
        .await;
        assert!(
            refused.as_ref().is_err_and(|e| e.contains("not allowed")),
            "{refused:?}"
        );

        // 5. With a password set, the right one gets in and wrong ones lock it.
        let mut access = Access::load(&access_path).unwrap();
        assert!(access.set_password(Some("short")).is_err(), "too short");
        access.set_password(Some("correct horse battery")).unwrap();
        access.save(&access_path).unwrap();
        let let_in = unattended::connect_to(
            Ok(address.clone()),
            "Stranger".into(),
            Some("correct horse battery".into()),
            stranger.clone(),
            local(),
        );
        let held = loop {
            if let Some(Notice::Connected { session, .. }) = listener.notices.recv().await {
                break session;
            }
        };
        assert!(outcome(let_in).await.is_ok());
        drop(held);
        for _ in 0..5 {
            let wrong = outcome(unattended::connect_to(
                Ok(address.clone()),
                "Guesser".into(),
                Some("wrong password!!".into()),
                stranger.clone(),
                local(),
            ))
            .await;
            assert!(
                wrong.as_ref().is_err_and(|e| e.contains("Wrong password")),
                "{wrong:?}"
            );
        }
        let locked = outcome(unattended::connect_to(
            Ok(address.clone()),
            "Guesser".into(),
            Some("correct horse battery".into()),
            stranger.clone(),
            local(),
        ))
        .await;
        assert!(
            locked.as_ref().is_err_and(|e| e.contains("paused")),
            "{locked:?}"
        );

        // 6. Switched off, even the paired helper is refused, at once.
        let mut access = Access::load(&access_path).unwrap();
        access.enabled = false;
        access.save(&access_path).unwrap();
        let off = outcome(unattended::connect_to(
            Ok(address.clone()),
            "Godwin".into(),
            None,
            helper_key,
            local(),
        ))
        .await;
        assert!(
            off.as_ref().is_err_and(|e| e.contains("switched off")),
            "{off:?}"
        );

        listener.stop();
        let _ = std::fs::remove_dir_all(dir);
    })
    .await
    .expect("unattended flow timed out");
}

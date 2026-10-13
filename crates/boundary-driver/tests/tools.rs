//! Commands and files from DeskVNC to a Boundary host, over a real
//! connection on this machine, and only while the person there allows them.

use boundary_driver::BoundaryDriver;
use boundary_session::{
    tools::{Reply, Request},
    Approval, Desktop, Event, Frame, HostOptions, Input,
};
use remote_core::{
    intent::{AgentIntent, CommandSpec, ExitTier, IntentId, IntentKind, ServedAnswer},
    ClientCommand, ConnectOptions, ProtocolDriver, ProtocolEvent, SessionEvent, SessionState,
};
use std::time::Duration;
use tokio::{sync::mpsc, time::timeout};

struct Still;
impl Desktop for Still {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        Ok(Frame {
            width: 2,
            height: 2,
            rgba: vec![9; 16],
        })
    }
    fn input(&mut self, _: Input) -> anyhow::Result<()> {
        Ok(())
    }
    fn release(&mut self) {}
}

fn run(id: u64, command: &str) -> ClientCommand {
    ClientCommand::Agent(AgentIntent {
        id: IntentId(id),
        grant: "test-agent".into(),
        deadline: Some(Duration::from_secs(20)),
        fence: None,
        kind: IntentKind::Exec {
            spec: CommandSpec {
                command: command.into(),
                cwd: None,
                env: vec![("BOUNDARY_TOOLS_TEST".into(), "carried".into())],
                timeout: Duration::from_secs(20),
                stdin: None,
                max_output_bytes: None,
            },
        },
    })
}

/// The next answer to an intent, skipping frames and everything else.
async fn answer(rx: &mut mpsc::Receiver<SessionEvent>) -> SessionEvent {
    loop {
        match rx.recv().await.expect("the session ended") {
            event @ (SessionEvent::AgentServed(_) | SessionEvent::AgentRefused(_)) => return event,
            SessionEvent::StateChanged(SessionState::Disconnected { reason, .. }) => {
                panic!("{reason}")
            }
            _ => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_agent_runs_commands_and_moves_files_only_while_the_person_allows_it() {
    timeout(Duration::from_secs(60), async {
        let mut host = boundary_session::host(
            HostOptions {
                relay: false,
                relay_url: None,
                bind_ip: None,
            },
            || Ok(Box::new(Still)),
        );
        let ticket = loop {
            if let Some(Event::Invitation(ticket)) = host.events.recv().await {
                break ticket;
            }
        };
        let driver = BoundaryDriver::default();
        let id = driver.prepare(ticket, "DeskVNC helper".into()).unwrap();
        let (tx, mut rx) = mpsc::channel(64);
        let handle = driver
            .spawn("tools".into(), ConnectOptions::boundary(id), tx)
            .unwrap();

        // DeskVNC said it can send commands, so the person is asked, and says yes.
        loop {
            if let Some(Event::Approval { tools, answer, .. }) = host.events.recv().await {
                assert!(tools, "DeskVNC must declare tools so the person is asked");
                host.set_tools(true);
                answer.send(Approval::View).ok().unwrap();
                break;
            }
        }
        loop {
            if let Some(SessionEvent::Protocol(ProtocolEvent::Boundary { tools, .. })) =
                rx.recv().await
            {
                assert!(tools);
                break;
            }
        }

        // A command, with its own output, its own status and our environment.
        let echo = if cfg!(windows) {
            "echo %BOUNDARY_TOOLS_TEST% && exit 4"
        } else {
            "echo $BOUNDARY_TOOLS_TEST; exit 4"
        };
        handle.send(run(1, echo)).await.unwrap();
        let SessionEvent::AgentServed(served) = answer(&mut rx).await else {
            panic!("the command was refused while allowed");
        };
        let ServedAnswer::Ran(ran) = served.answer else {
            panic!("not a run");
        };
        assert_eq!(ran.status.code, Some(4));
        assert_eq!(ran.status.source, ExitTier::Exec);
        assert_eq!(String::from_utf8_lossy(&ran.stdout).trim(), "carried");

        // Files, through the client the shell's file verbs use.
        let client = driver
            .tools("tools")
            .expect("a tools client while connected");
        let path = std::env::temp_dir()
            .join(format!("boundary-driver-tools-{}.txt", std::process::id()))
            .to_string_lossy()
            .to_string();
        let wait = Duration::from_secs(10);
        let (reply, _) = client
            .call(
                &Request::Put {
                    path: path.clone(),
                    offset: 0,
                    mode: None,
                },
                b"over boundary",
                wait,
            )
            .await
            .unwrap();
        assert!(
            matches!(reply, Reply::Wrote { written: 13, .. }),
            "{reply:?}"
        );
        let (reply, bytes) = client
            .call(
                &Request::Get {
                    path: path.clone(),
                    offset: 0,
                    length: 1024,
                },
                &[],
                wait,
            )
            .await
            .unwrap();
        assert!(matches!(reply, Reply::Window { size: 13, .. }), "{reply:?}");
        assert_eq!(bytes, b"over boundary");

        // The person can see what was done.
        let mut seen = Vec::new();
        while seen.len() < 3 {
            if let Some(Event::Activity(line)) = host.events.recv().await {
                seen.push(line);
            }
        }
        assert!(
            seen.iter().any(|l| l.contains("BOUNDARY_TOOLS_TEST")),
            "{seen:?}"
        );

        // Taken back: the helper is told, and the host refuses even a request
        // that ignores what it was told.
        host.set_tools(false);
        loop {
            if let Some(SessionEvent::Protocol(ProtocolEvent::Boundary { tools: false, .. })) =
                rx.recv().await
            {
                break;
            }
        }
        handle.send(run(2, "echo should not run")).await.unwrap();
        let SessionEvent::AgentRefused(refused) = answer(&mut rx).await else {
            panic!("a command ran after the person took it back");
        };
        assert!(
            refused.reason.contains("has not allowed"),
            "{}",
            refused.reason
        );
        let (reply, _) = client
            .call(
                &Request::Remove {
                    path: path.clone(),
                    recursive: false,
                },
                &[],
                wait,
            )
            .await
            .unwrap();
        assert!(matches!(reply, Reply::Refused(_)), "{reply:?}");
        assert!(std::path::Path::new(&path).exists());
        let _ = std::fs::remove_file(&path);

        handle.shutdown();
        host.stop();
        // The client is taken back with the session.
        for _ in 0..100 {
            if driver.tools("tools").is_none() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the tools client outlived its session");
    })
    .await
    .expect("tools test timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_runs_when_the_person_only_allowed_viewing() {
    timeout(Duration::from_secs(30), async {
        let mut host = boundary_session::host(
            HostOptions {
                relay: false,
                relay_url: None,
                bind_ip: None,
            },
            || Ok(Box::new(Still)),
        );
        let ticket = loop {
            if let Some(Event::Invitation(ticket)) = host.events.recv().await {
                break ticket;
            }
        };
        let driver = BoundaryDriver::default();
        let id = driver.prepare(ticket, "DeskVNC helper".into()).unwrap();
        let (tx, mut rx) = mpsc::channel(64);
        let handle = driver
            .spawn("view-only".into(), ConnectOptions::boundary(id), tx)
            .unwrap();
        loop {
            if let Some(Event::Approval { answer, .. }) = host.events.recv().await {
                answer.send(Approval::Control).ok().unwrap();
                break;
            }
        }
        loop {
            if let Some(SessionEvent::StateChanged(SessionState::Connected)) = rx.recv().await {
                break;
            }
        }
        handle.send(run(1, "echo should not run")).await.unwrap();
        let SessionEvent::AgentRefused(refused) = answer(&mut rx).await else {
            panic!("a command ran without the person's say so");
        };
        assert!(
            refused.reason.contains("has not allowed"),
            "{}",
            refused.reason
        );
        handle.shutdown();
        host.stop();
    })
    .await
    .expect("view only test timed out");
}

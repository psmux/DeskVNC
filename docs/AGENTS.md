# Driving DeskVNC from an AI agent

DeskVNC exposes an optional control plane so an existing AI agent can observe and
act on the machines you connect to, over VNC, RDP or SSH, with nothing installed
on the remote target. This document is the practical entry point. The design
rationale lives in the source comments and the internal specification cited there
as `PRDAgentPlug/NN`.

## The shape of it

The plane follows one loop:

```
observe()  ->  Observation      a screenshot plus geometry and session state
decide()   ->  Action           the agent's business, not ours
act()      ->  ActionResult     one settlement per action, never fire and forget
```

Three properties separate it from the version a person writes in an afternoon:

- **The observation is fenced.** It carries a geometry generation, and an action
  computed against a stale geometry is refused rather than landing in the wrong
  place after a resize.
- **The action is settled, not fired.** Every intent gets an id and exactly one
  result, so an agent never waits forever on something a driver could not serve.
- **The loop can lose the machine mid step.** A person can take the wheel between
  observe and act. Control is leased; on any lease change the plane releases all
  held keys, so a half-finished drag cannot strand the desktop.

## Transports

`dvv` is one server behind two transports:

- **stdio**, for agents that spawn a subprocess. This is the default.
- **HTTP**, for agents that cannot. It is off by default, binds to loopback,
  always requires a bearer token, checks `Origin`, and refuses to start rather
  than start without a token.

Both frame the same dispatch table, so a tool behaves identically regardless of
how the agent reached it.

## Getting connected

1. In DeskVNC, open the **AI Agents** panel and switch the plane on.
2. Use the **Register with Claude Code** button, or copy the shown command for a
   different agent. An installed build ships `dvv` inside the bundle, signed and
   notarized, and reports its real path.
3. The agent can now open a saved machine by name, read the host library
   (protocols and whether a credential is stored, never the credential itself),
   take screenshots, and send input, subject to the capabilities on its grant.

## What an agent can and cannot do

- It **can** open one of your saved machines or an endpoint, and the session
  opens as an ordinary pane with an "agent driving" badge.
- It **can** read the library to know what there is to open.
- It **cannot** supply or read a stored password. The credential is applied on
  the far side of the same call your click goes through, so an agent names a
  machine and never a secret.
- A person **can** take the wheel from any agent-driven pane with one click, and
  hand it back the same way.

## Building this into your own product

If you are building agent automation for legacy or locked-down Windows desktops,
the no-install, protocol-level path DeskVNC takes reaches machines that a
driver-based tool cannot: Citrix, VDI, jump hosts and client-owned PCs. For a
hardened `dvv` tailored to your agent, a commercial integration, or protocol work
on the Rust RDP, VNC and SSH cores, email **godwin@altrosyn.com**.

import { describe, expect, it } from "vitest";
import {
  AGENT_BOUNDARY_WHY,
  AGENT_CAN,
  AGENT_CANNOT,
  DVV_PATH_PLACEHOLDER,
  TOKEN_ENV,
  binaryNote,
  doctorLine,
  httpAddLine,
  knowsBinary,
  mcpAddLine,
  needsManualSetup,
  parseRegisterResult,
  registerLine,
  registerTone,
  shellQuote,
  tokenExportLine,
} from "./agentSetup";

describe("quoting a path so it survives being pasted", () => {
  it("leaves an ordinary path exactly as it is", () => {
    // A person compares this against what `dvv doctor` printed. Quoting a path
    // that needs no quoting makes two identical paths look different.
    expect(shellQuote("/usr/local/bin/dvv")).toBe("/usr/local/bin/dvv");
    expect(shellQuote("/Users/gj/.cargo/bin/dvv")).toBe("/Users/gj/.cargo/bin/dvv");
  });

  it("quotes a path with a space in it", () => {
    expect(shellQuote("/Applications/Desk VNC/dvv")).toBe("'/Applications/Desk VNC/dvv'");
  });

  it("closes and reopens around an apostrophe, which is the only way", () => {
    expect(shellQuote("/Users/gj/o'brien/dvv")).toBe("'/Users/gj/o'\\''brien/dvv'");
  });

  it("uses double quotes for a Windows path, where single ones mean nothing", () => {
    expect(shellQuote("C:\\Program Files\\dvv.exe")).toBe('"C:\\Program Files\\dvv.exe"');
    expect(shellQuote("\\\\server\\tools\\dvv.exe")).toBe('"\\\\server\\tools\\dvv.exe"');
  });
});

describe("the line that registers the server", () => {
  it("is what dvv doctor prints, byte for byte", () => {
    expect(mcpAddLine("/usr/local/bin/dvv")).toBe(
      "claude mcp add --scope user deskvnc -- /usr/local/bin/dvv mcp --stdio",
    );
  });

  it("shows an obvious placeholder rather than a path that is right on one machine", () => {
    for (const nothing of [null, "", "   "]) {
      expect(knowsBinary(nothing)).toBe(false);
      expect(mcpAddLine(nothing)).toContain(DVV_PATH_PLACEHOLDER);
    }
  });

  it("quotes the path it was given, so a space cannot break the command", () => {
    expect(mcpAddLine("/Applications/Desk VNC/dvv")).toBe(
      "claude mcp add --scope user deskvnc -- '/Applications/Desk VNC/dvv' mcp --stdio",
    );
  });
});

describe("the line that checks it", () => {
  it("names the binary when we know where it is", () => {
    expect(doctorLine("/usr/local/bin/dvv")).toBe("/usr/local/bin/dvv doctor");
    expect(doctorLine("/Applications/Desk VNC/dvv")).toBe("'/Applications/Desk VNC/dvv' doctor");
  });

  it("falls back to the name on the path, which is what a person has anyway", () => {
    expect(doctorLine(null)).toBe("dvv doctor");
  });
});

describe("the HTTP form carries no secret", () => {
  it("spells the header with the variable rather than the token", () => {
    const line = httpAddLine("http://127.0.0.1:8787/mcp");
    expect(line).toBe(
      'claude mcp add --transport http deskvnc http://127.0.0.1:8787/mcp --header "Authorization: Bearer $DESKVNC_TOKEN"',
    );
    expect(line).toContain(`$${TOKEN_ENV}`);
  });

  it("reads the token in without echoing it", () => {
    // `read -rs` is the whole point: no echo, and nothing in shell history.
    expect(tokenExportLine()).toBe("read -rs DESKVNC_TOKEN && export DESKVNC_TOKEN");
  });
});

describe("what it says it can do", () => {
  it("is short enough to be read", () => {
    expect(AGENT_CAN.length).toBeLessThanOrEqual(4);
    expect(AGENT_CANNOT.length).toBeLessThanOrEqual(4);
  });

  it("counts opening a machine and running over SSH as things that work", () => {
    // Both were limits and are limits no longer. A list nobody rereads goes on
    // telling people a feature is missing months after it shipped.
    const can = AGENT_CAN.join(" ");
    expect(can).toContain("Open one of your saved machines");
    expect(can).toContain("SSH");
    const cannot = AGENT_CANNOT.join(" ");
    expect(cannot).not.toContain("Open a machine");
    expect(cannot).not.toContain("SSH");
  });

  it("leaves exactly one thing an agent will not do, and says why", () => {
    expect(AGENT_CANNOT).toHaveLength(1);
    expect(AGENT_CANNOT[0]).toContain("password");
    expect(AGENT_CANNOT[0]).toContain("stay yours");
    // A boundary rather than a gap, and the reason is the advertisement.
    expect(AGENT_BOUNDARY_WHY).toContain("deliberate");
  });

  it("promises the credential never reaches the agent", () => {
    expect(AGENT_CAN[0]).toContain("keychain");
    expect(AGENT_CAN[0]).toContain("neither supplies it nor sees it");
  });
});

describe("saying why a line has a hole in it", () => {
  it("says nothing at all when the path is known, which is the normal case", () => {
    expect(binaryNote("/usr/local/bin/dvv")).toBeNull();
    expect(binaryNote("/Applications/Desk VNC.app/Contents/MacOS/dvv")).toBeNull();
  });

  it("explains the placeholder rather than leaving somebody to wonder", () => {
    for (const nothing of [null, "", "   "]) {
      const note = binaryNote(nothing);
      expect(note).not.toBeNull();
      expect(note).toContain("development build");
      expect(note).toContain("dvv doctor");
    }
  });
});

describe("reading what the shell said about registering", () => {
  it("reads every arm the shell actually sends", () => {
    // `RegistrationOutcome` in `src-tauri/src/agent/mod.rs`, serialized
    // internally tagged on `status` with kebab-case arm names. These six
    // payloads are that enum, arm for arm. If one of them stops parsing, the
    // modal has gone quiet about a real answer.
    expect(
      parseRegisterResult({ status: "registered", claude: "/usr/bin/claude", argv: ["mcp", "add"] })
        .outcome,
    ).toBe("registered");
    expect(
      parseRegisterResult({ status: "already-registered", claude: "/usr/bin/claude" }).outcome,
    ).toBe("already");
    expect(
      parseRegisterResult({ status: "claude-not-found", looked: ["/usr/bin", "/opt"] }).outcome,
    ).toBe("no-claude");
    expect(parseRegisterResult({ status: "no-binary" }).outcome).toBe("no-binary");
    expect(
      parseRegisterResult({ status: "timed-out", claude: "/usr/bin/claude", seconds: 20 }).outcome,
    ).toBe("timed-out");
    expect(
      parseRegisterResult({
        status: "failed",
        claude: "/usr/bin/claude",
        code: 2,
        stderr: "config is read only",
      }),
    ).toEqual({ outcome: "failed", detail: "config is read only" });
  });

  it("does not mistake the path to claude for something the shell wanted to say", () => {
    // Every arm carries `claude`, and none of them means it as a message.
    const result = parseRegisterResult({ status: "registered", claude: "/usr/bin/claude" });
    expect(result.detail).toBe("");
  });

  it("takes the plain word, however it is spelled", () => {
    expect(parseRegisterResult("registered").outcome).toBe("registered");
    expect(parseRegisterResult("AlreadyRegistered").outcome).toBe("already");
    expect(parseRegisterResult("already_registered").outcome).toBe("already");
    expect(parseRegisterResult("claude-not-found").outcome).toBe("no-claude");
  });

  it("takes the word out of a field, whichever field it is in", () => {
    expect(parseRegisterResult({ outcome: "registered" }).outcome).toBe("registered");
    expect(parseRegisterResult({ status: "alreadyRegistered" }).outcome).toBe("already");
    expect(parseRegisterResult({ result: "notInstalled" }).outcome).toBe("no-claude");
    expect(parseRegisterResult({ kind: "failed", message: "exit 1" })).toEqual({
      outcome: "failed",
      detail: "exit 1",
    });
  });

  it("takes a serde enum arriving as one key naming its arm", () => {
    expect(parseRegisterResult({ AlreadyRegistered: null }).outcome).toBe("already");
    expect(parseRegisterResult({ Failed: { message: "claude exited 2" } })).toEqual({
      outcome: "failed",
      detail: "claude exited 2",
    });
    expect(parseRegisterResult({ Failed: "no write permission" })).toEqual({
      outcome: "failed",
      detail: "no write permission",
    });
  });

  it("takes a bare boolean, and an ok field", () => {
    expect(parseRegisterResult(true).outcome).toBe("registered");
    expect(parseRegisterResult(false).outcome).toBe("failed");
    expect(parseRegisterResult({ ok: true }).outcome).toBe("registered");
    expect(parseRegisterResult({ ok: false, error: "spawn failed" })).toEqual({
      outcome: "failed",
      detail: "spawn failed",
    });
  });

  it("calls nothing at all unsupported rather than a failure", () => {
    // `safeInvoke` answers its fallback when the command is not in the build.
    // That is a build without the button, not a button that broke.
    for (const nothing of [null, undefined, 42]) {
      expect(parseRegisterResult(nothing)).toEqual({ outcome: "unsupported", detail: "" });
    }
    expect(parseRegisterResult({}).outcome).toBe("unsupported");
  });

  it("treats prose it cannot place as the failure it always is", () => {
    expect(parseRegisterResult("claude: command not found\n")).toEqual({
      outcome: "failed",
      detail: "claude: command not found",
    });
    expect(parseRegisterResult({ error: "config is read only" }).outcome).toBe("failed");
  });

  it("flattens and caps a message, so stderr cannot push the button off screen", () => {
    const noisy = parseRegisterResult({ error: "line one\n\tline two " });
    expect(noisy.detail).toBe("line one line two");
    const long = parseRegisterResult({ error: "x".repeat(600) });
    expect(long.detail.length).toBeLessThanOrEqual(240);
    expect(long.detail.endsWith("…")).toBe(true);
  });
});

describe("what the button says afterwards", () => {
  it("has a sentence for every outcome, and never just says error", () => {
    const outcomes = [
      "registered",
      "already",
      "no-claude",
      "no-binary",
      "timed-out",
      "failed",
      "unsupported",
    ] as const;
    for (const outcome of outcomes) {
      const line = registerLine({ outcome, detail: "" });
      expect(line.length).toBeGreaterThan(20);
      expect(line).not.toMatch(/^error/i);
    }
  });

  it("says the thing that actually gets a fresh registration noticed", () => {
    expect(registerLine({ outcome: "registered", detail: "" })).toContain("restart it");
    expect(registerLine({ outcome: "already", detail: "" })).toContain("nothing left to do");
  });

  it("repeats what the shell said, when the shell said anything", () => {
    expect(registerLine({ outcome: "failed", detail: "claude exited 2" })).toContain(
      "claude exited 2",
    );
    // And admits the silence rather than inventing a reason for it.
    expect(registerLine({ outcome: "failed", detail: "" })).toContain("did not say why");
  });

  it("does not blame this application for Claude Code being absent", () => {
    const line = registerLine({ outcome: "no-claude", detail: "" });
    expect(line).toContain("not on this computer");
    expect(line).toContain("Install it");
  });

  it("colours a success, a shrug and a problem differently", () => {
    expect(registerTone("registered")).toBe("success");
    expect(registerTone("already")).toBe("info");
    // Nothing is broken about running the build you just compiled, and amber
    // over that teaches somebody to ignore amber.
    expect(registerTone("no-binary")).toBe("info");
    expect(registerTone("no-claude")).toBe("warning");
    expect(registerTone("timed-out")).toBe("warning");
    expect(registerTone("failed")).toBe("warning");
    expect(registerTone("unsupported")).toBe("warning");
  });

  it("opens the copyable lines for exactly the outcomes that need them", () => {
    expect(needsManualSetup("registered")).toBe(false);
    expect(needsManualSetup("already")).toBe(false);
    for (const outcome of ["no-claude", "no-binary", "timed-out", "failed", "unsupported"] as const) {
      expect(needsManualSetup(outcome)).toBe(true);
    }
  });
});

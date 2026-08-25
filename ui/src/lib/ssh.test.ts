import { describe, expect, it } from "vitest";
import { blankSshSettings, parseSshSettings, serializeSshSettings } from "./ssh";

describe("parseSshSettings", () => {
  it("reads nothing as nothing", () => {
    expect(parseSshSettings(null)).toBeNull();
    expect(parseSshSettings("")).toBeNull();
    expect(parseSshSettings("null")).toBeNull();
    expect(parseSshSettings("not json")).toBeNull();
    expect(parseSshSettings("[]")).toBeNull();
  });

  it("reads an empty object as the defaults", () => {
    expect(parseSshSettings("{}")).toEqual(blankSshSettings());
  });

  it("falls back to auto on a multiplexer value it does not know", () => {
    expect(parseSshSettings('{"multiplexer":"nonsense"}')?.multiplexer).toBe("auto");
    expect(parseSshSettings('{"multiplexer":"tmux"}')?.multiplexer).toBe("tmux");
  });

  it("falls back to agent on an auth value it does not know, the same tolerant rule as multiplexer", () => {
    expect(parseSshSettings('{"auth":"nonsense"}')?.auth).toBe("agent");
    expect(parseSshSettings('{"auth":"password"}')?.auth).toBe("password");
    expect(parseSshSettings('{"auth":"key-file"}')?.auth).toBe("key-file");
  });

  it("reads a missing wsl as false, the same tolerant rule as every other flag", () => {
    expect(parseSshSettings("{}")?.wsl).toBe(false);
    expect(parseSshSettings('{"sessionName":"work"}')?.wsl).toBe(false);
    expect(parseSshSettings('{"wsl":true}')?.wsl).toBe(true);
  });

  it("reads a v higher than this build understands rather than refusing", () => {
    // Unlike `vnc_store::SshSettings::parse`, which errors on a blob newer
    // than it knows (PRDRDP/08 §2.4 style rule), this reader never guesses at
    // a CONNECT, it only has to give the editor something to show. Refusing
    // here would make a profile written by a newer build uneditable, not
    // just unconnectable.
    const settings = parseSshSettings('{"v":99,"sessionName":"work"}');
    expect(settings?.v).toBe(99);
    expect(settings?.sessionName).toBe("work");
  });
});

describe("serializeSshSettings", () => {
  it("writes null for an untouched object, so the column stays empty", () => {
    expect(serializeSshSettings(null)).toBeNull();
    expect(serializeSshSettings(blankSshSettings())).toBeNull();
  });

  it("round trips a change", () => {
    const s = { ...blankSshSettings(), sessionName: "work", multiplexer: "tmux" as const };
    const text = serializeSshSettings(s);
    expect(text).not.toBeNull();
    expect(parseSshSettings(text)).toEqual(s);
  });

  it("round trips auth and keyPath", () => {
    const s = {
      ...blankSshSettings(),
      auth: "key-file" as const,
      keyPath: "/Users/alice/.ssh/id_ed25519",
    };
    const text = serializeSshSettings(s);
    expect(text).not.toBeNull();
    expect(parseSshSettings(text)).toEqual(s);
  });

  it("round trips wsl and wslDistro", () => {
    const s = { ...blankSshSettings(), wsl: true, wslDistro: "Ubuntu-22.04" };
    const text = serializeSshSettings(s);
    expect(text).not.toBeNull();
    expect(parseSshSettings(text)).toEqual(s);
  });

  it("re-emits a field this build has never heard of", () => {
    // The editor parses into a typed object and writes a fresh one, so
    // without this a UI predating a field drops it on every save.
    const parsed = parseSshSettings('{"v":1,"sessionName":"work","somethingNewer":{"a":1}}');
    const text = serializeSshSettings(parsed);
    expect(text).toContain("somethingNewer");
    expect(JSON.parse(text as string).somethingNewer).toEqual({ a: 1 });
  });

  it("always writes the current version, even when it parsed a newer one", () => {
    const parsed = parseSshSettings('{"v":99,"sessionName":"work"}');
    const text = serializeSshSettings(parsed);
    expect(JSON.parse(text as string).v).toBe(1);
  });
});

describe("blankSshSettings", () => {
  it("matches the Rust defaults", () => {
    const b = blankSshSettings();
    expect(b.auth).toBe("agent");
    expect(b.keyPath).toBeNull();
    expect(b.term).toBe("xterm-256color");
    expect(b.cols).toBe(80);
    expect(b.rows).toBe(24);
    expect(b.multiplexer).toBe("auto");
    expect(b.sessionName).toBe("deskvnc");
    expect(b.customCommand).toBeNull();
    expect(b.fallbackToShell).toBe(true);
    expect(b.startupCommand).toBeNull();
    expect(b.wsl).toBe(false);
    expect(b.wslDistro).toBeNull();
    expect(b.fontSize).toBe(13);
    expect(b.scrollback).toBe(10_000);
  });
});

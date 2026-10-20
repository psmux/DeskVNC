// The test environment has no `localStorage`.
//
// Node 22 and later define a `localStorage` global of their own, which is
// undefined unless the process was started with a local storage file, and
// they shadow the environment's. The environment here is jsdom, whose
// window does not carry a storage of its own either, so a bare
// `localStorage` in a test is undefined and every test that reads or
// writes stored settings fails with "cannot read properties of undefined".
//
// These tests want a storage that keeps things for the length of a test
// run and forgets them afterwards, which is what this is. It is only
// installed when the environment has nothing better.
class MemoryStorage implements Storage {
  private data = new Map<string, string>();

  get length(): number {
    return this.data.size;
  }

  clear(): void {
    this.data.clear();
  }

  getItem(key: string): string | null {
    return this.data.has(key) ? (this.data.get(key) as string) : null;
  }

  key(index: number): string | null {
    return Array.from(this.data.keys())[index] ?? null;
  }

  removeItem(key: string): void {
    this.data.delete(key);
  }

  setItem(key: string, value: string): void {
    this.data.set(key, String(value));
  }
}

function install(target: object, name: "localStorage" | "sessionStorage"): void {
  try {
    if (typeof (target as Record<string, unknown>)[name] === "undefined") {
      Object.defineProperty(target, name, {
        value: new MemoryStorage(),
        configurable: true,
        writable: true,
      });
    }
  } catch {
    // A frozen environment is not worth failing over.
  }
}

install(globalThis, "localStorage");
install(globalThis, "sessionStorage");
const view = (globalThis as { window?: unknown }).window;
if (view) {
  install(view, "localStorage");
  install(view, "sessionStorage");
}

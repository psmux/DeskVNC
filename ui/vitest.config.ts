import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // The input layer talks to real DOM events, so it needs a DOM.
    environment: "jsdom",
    // Node's own localStorage global shadows the environment's; the setup
    // file points it at the right one.
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.ts"],
  },
});

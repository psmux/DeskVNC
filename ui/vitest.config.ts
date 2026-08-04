import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // The input layer talks to real DOM events, so it needs a DOM.
    environment: "jsdom",
    include: ["src/**/*.test.ts"],
  },
});

import { defineConfig } from "vitest/config";

export default defineConfig({
  // passkey-kit depends on sac-sdk, whose entry point is uncompiled TypeScript.
  test: { server: { deps: { inline: [/passkey-kit/, /sac-sdk/] } } },
});

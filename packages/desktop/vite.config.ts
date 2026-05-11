import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;

const __dirname = dirname(fileURLToPath(import.meta.url));

// Build-time metadata injected via `define` so the React app can render
// the version, commit SHA, and build timestamp in a footer. Lets the
// user identify exactly which build is running.
function buildMetadata() {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "package.json"), "utf-8"),
  ) as { version: string };
  let sha = "unknown";
  try {
    sha = execSync("git rev-parse --short HEAD", {
      cwd: __dirname,
      encoding: "utf-8",
    }).trim();
  } catch {
    /* no git, or shallow clone — leave as "unknown" */
  }
  const builtAt = new Date().toISOString();
  return {
    "import.meta.env.VITE_APP_VERSION": JSON.stringify(pkg.version),
    "import.meta.env.VITE_APP_GIT_SHA": JSON.stringify(sha),
    "import.meta.env.VITE_APP_BUILT_AT": JSON.stringify(builtAt),
  };
}

// https://vite.dev/config/
export default defineConfig(async () => ({
  plugins: [react()],
  define: buildMetadata(),

  // Tauri 2 loads bundled HTML through a custom protocol. Absolute asset
  // URLs (`/assets/foo.js`) don't resolve there and the window renders blank;
  // emitting relative paths fixes that.
  base: "./",

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
}));

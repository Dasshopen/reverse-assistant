import { defineConfig } from "vite";
import { sveltekit } from "@sveltejs/kit/vite";

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;

// https://vite.dev/config/
export default defineConfig(async () => ({
  plugins: [sveltekit()],

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
      // 3. watch application sources only. The corpus directories contain
      // large archives and H2 databases that build tools/antivirus may lock
      // temporarily on Windows; they are runtime resources, not frontend
      // source files, so watching them can crash Vite with EBUSY.
      ignored: [
        "**/src-tauri/**",
        "**/bsim-corpus/sources/**",
        "**/bsim-corpus/build/**",
      ],
    },
  },
}));

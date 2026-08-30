import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// base: "./" — the bundle is served from the chain under
// /_/raw/<cid>/, so every asset reference must be relative.
//
// The dev proxy forwards /api to the public gateway so `npm run dev`
// talks to the live network; override with THEBES_GATEWAY.
const gateway = process.env.THEBES_GATEWAY ?? "https://memphis.mercaturaforum.com";

export default defineConfig({
  plugins: [react()],
  base: "./",
  server: {
    proxy: {
      "/api": {
        target: gateway,
        changeOrigin: true,
      },
    },
  },
});

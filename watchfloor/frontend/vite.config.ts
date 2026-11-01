import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// `npm run build:demo` produces the static GitHub Pages build that reads public/demo/*.json.
// `npm run build` produces the live build that the hub serves and that calls /api.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    base: "./",
    plugins: [react(), tailwindcss()],
    // The shared design system is linked from ../../packages; make sure it uses this app's single React copy.
    resolve: { dedupe: ["react", "react-dom", "motion", "cytoscape", "@radix-ui/react-dialog"] },
    define: {
      __DATA_MODE__: JSON.stringify(mode === "demo" ? "replay" : env.VITE_DATA_MODE || "auto"),
    },
    server: {
      proxy: { "/api": { target: env.VITE_HUB_URL || "http://127.0.0.1:8000", changeOrigin: true } },
    },
    build: { outDir: mode === "demo" ? "dist-demo" : "dist", chunkSizeWarningLimit: 1500 },
    test: { environment: "node", include: ["src/**/*.test.ts"] },
  };
});

import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// Vite reads env vars prefixed with VITE_*. Two important ones:
//   VITE_AEGIS_API_BASE  — base path for API calls (default "" → same origin)
//   VITE_USE_MOCKS       — when "true", api client returns mock data
//
// In dev we proxy /admin/* and /metrics to a locally-running aegis so the
// UI can be developed against a real backend without CORS shenanigans.
export default defineConfig(({ mode }) => {
    const env = loadEnv(mode, process.cwd(), "");
    const aegisBackend = env.AEGIS_DEV_BACKEND || "http://localhost:6280";
    return {
        plugins: [react()],
        resolve: {
            alias: {
                "@": path.resolve(__dirname, "./src"),
            },
        },
        // Built assets get embedded into the aegis binary at compile time
        // (see src/admin_ui.rs::include_dir!). Aegis always serves the
        // bundle under /admin/ui/, so hard-code the base — it makes
        // asset URLs absolute (`/admin/ui/assets/…`), which means a
        // bare `GET /` redirect resolves them correctly without any
        // relative-path gymnastics.
        base: "/admin/ui/",
        build: {
            outDir: "dist",
            // One vendor chunk for the heavy bits (monaco, recharts) so
            // first paint stays snappy.
            rollupOptions: {
                output: {
                    manualChunks: {
                        monaco: ["monaco-editor", "@monaco-editor/react"],
                        charts: ["recharts"],
                    },
                },
            },
        },
        server: {
            port: 5173,
            proxy: {
                "/admin": { target: aegisBackend, changeOrigin: true },
                "/metrics": { target: aegisBackend, changeOrigin: true },
            },
        },
    };
});

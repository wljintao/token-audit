import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  //base: "/token-audit/",
  base:"",
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:3000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});

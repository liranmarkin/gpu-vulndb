import type { NextConfig } from "next";

const config: NextConfig = {
  // The database lives outside web/, so the build traces one directory up.
  outputFileTracingRoot: process.cwd() + "/..",
  async redirects() {
    return [{ source: "/vuln/:id.html", destination: "/vuln/:id", permanent: true }];
  },
  async headers() {
    return [
      {
        source: "/:file(data.json|index.json)",
        headers: [
          { key: "Access-Control-Allow-Origin", value: "*" },
          { key: "Cache-Control", value: "public, max-age=0, s-maxage=3600, stale-while-revalidate=86400" },
        ],
      },
    ];
  },
};

export default config;

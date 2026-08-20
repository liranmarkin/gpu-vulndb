import { getAllEntries } from "@/lib/entries";

export const dynamic = "force-static";

/** The whole corpus in one file. Documented in the README as the public data endpoint. */
export function GET() {
  return Response.json(
    { entries: getAllEntries() },
    { headers: { "Access-Control-Allow-Origin": "*" } },
  );
}

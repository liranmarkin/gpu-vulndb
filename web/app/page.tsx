import Browser from "./_components/Browser";
import { getAllEntries } from "@/lib/entries";
import { toIndex } from "@/lib/schema";

export default function Home() {
  const entries = getAllEntries().map(toIndex);

  return (
    <main className="mx-auto max-w-[1200px] px-[22px]">
      <Browser entries={entries} />
    </main>
  );
}

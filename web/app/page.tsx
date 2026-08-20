import Browser from "./_components/Browser";
import { getAllEntries } from "@/lib/entries";
import { toIndex } from "@/lib/schema";

export default function Home() {
  const entries = getAllEntries().map(toIndex);
  const critical = entries.filter((e) => e.severity === "critical").length;
  const exploited = entries.filter((e) => e.kev).length;

  return (
    <main className="mx-auto max-w-[1200px] px-[22px]">
      <section className="pt-6 sm:pt-8">
        <div className="wafer relative overflow-hidden rounded-[28px] px-6 pb-20 pt-12 text-white sm:px-12 sm:pb-24 sm:pt-16">
          {/* a few dies on the map are lit — the flaws. Offsets are 21+44k+9,
              14+44j+9 so each one sits inside a cell of the 44px die grid. */}
          <div aria-hidden className="pointer-events-none absolute inset-0">
            <span className="absolute right-[118px] top-[111px] hidden h-[25px] w-[25px] rounded-[5px] bg-defect/85 sm:block" />
            <span className="absolute right-[110px] top-[103px] hidden h-[41px] w-[41px] rounded-[8px] bg-defect/35 blur-[16px] sm:block" />
            <span className="absolute right-[250px] top-[199px] hidden h-[25px] w-[25px] rounded-[5px] bg-high/65 sm:block" />
            <span className="absolute right-[74px] top-[287px] hidden h-[25px] w-[25px] rounded-[5px] bg-white/18 sm:block" />
            <span className="absolute right-[338px] top-[155px] hidden h-[25px] w-[25px] rounded-[5px] bg-white/10 sm:block" />
            <span className="absolute right-[162px] top-[243px] hidden h-[25px] w-[25px] rounded-[5px] bg-medium/45 sm:block" />
          </div>

          <p className="mb-5 font-mono text-[11.5px] uppercase tracking-[0.18em] text-lavender">
            Open vulnerability database
          </p>
          <h1 className="mb-6 max-w-[13ch] font-display text-[clamp(38px,6vw,68px)] font-extrabold leading-[1.02] tracking-[-0.02em]">
            The stack is the attack surface.
          </h1>
          <p className="mb-8 max-w-[52ch] text-[17px] leading-[1.6] text-white/80 sm:text-[19px]">
            An open project to list all known vulnerabilities in the stack GPU datacenters run on.
          </p>
          <p className="flex flex-wrap gap-x-6 gap-y-2 font-mono text-[13px] text-lavender">
            <span><b className="font-semibold text-white">{entries.length.toLocaleString()}</b> entries</span>
            <span><b className="font-semibold text-white">{critical}</b> critical</span>
            <span><b className="font-semibold text-white">{exploited}</b> known exploited</span>
            <span><b className="font-semibold text-white">6</b> layers of the stack</span>
          </p>
        </div>
      </section>

      <Browser entries={entries} />
    </main>
  );
}

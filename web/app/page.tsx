import Browser from "./_components/Browser";
import { getAllEntries } from "@/lib/entries";
import { toIndex } from "@/lib/schema";

export default function Home() {
  const entries = getAllEntries().map(toIndex);

  return (
    <main className="mx-auto max-w-[1200px] px-[22px]">
      <section className="pt-18">
        <p className="mb-4.5 font-mono text-[11.5px] uppercase tracking-[0.16em] text-dimmer">
          Open vulnerability database
        </p>
        <h1 className="mb-5.5 max-w-[15ch] font-display text-[clamp(36px,6.2vw,64px)] font-extrabold leading-[1.0] tracking-[-0.025em]">
          The stack is the attack surface.
        </h1>
        <p className="mb-11 max-w-[64ch] text-[17.5px] text-dim">
          Running GPUs means running six layers of software and firmware, and an attacker only needs
          one of them. This is an open, community-maintained record of the vulnerabilities that matter
          to anyone operating GPU infrastructure — GPU clouds, colocation datacenters, and enterprises
          with their own fleets. Every entry carries{" "}
          <strong className="font-medium text-ink">what an operator has to do about it</strong>, not
          just a CVSS score.
        </p>
      </section>

      <Browser entries={entries} />
    </main>
  );
}

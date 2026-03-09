import { getServerInfo } from "@/lib/serverInfo";
import {
  OverviewSection,
  NetworkSection,
  CpuSection,
  MemorySection,
  DiskSection,
  ProcessSection,
  UserSection,
  SecuritySection,
  SoftwareSection,
  TimezoneSection,
} from "./components/ServerSections";
import Link from "next/link";

export default async function Home() {
  const data = await getServerInfo() as any;
  const memPct = parseFloat(data.memory.usagePercent);

  return (
    <div className="min-h-screen bg-background py-10 px-4 sm:px-6 lg:px-8">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-end justify-between mb-10">
          <div>
            <div className="flex items-center gap-3 mb-1.5">
              <div className="h-2.5 w-2.5 rounded-full bg-emerald-500 animate-pulse" />
              <h1 className="text-xl font-bold text-foreground tracking-tight">
                Server Dashboard
              </h1>
            </div>
            <p className="text-[13px] text-muted font-mono">
              {data.distro?.PRETTY_NAME || data.os.type} &middot; {data.os.hostname} &middot; {data.buildTime}
            </p>
          </div>
          <Link
            href="/json"
            className="text-[12px] font-mono px-3.5 py-2 rounded-lg bg-surface border border-border text-muted hover:text-foreground hover:border-zinc-600 transition-all"
          >
            {"{ } JSON"}
          </Link>
        </div>

        {/* Hero stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
          <HeroStat
            label="External IP"
            value={data.network.realExternalIP}
            sub={data.network.ipGeo ? `${countryFlag(data.network.ipGeo.countryCode)} ${data.network.ipGeo.country}${data.network.ipGeo.city ? ` · ${data.network.ipGeo.city}` : ""}` : undefined}
            color="text-blue-400"
          />
          <HeroStat
            label="CPU"
            value={`${data.cpu.count} cores`}
            sub={data.cpu.model}
          />
          <HeroStat
            label="Memory"
            value={data.memory.total.gb}
            sub={`${memPct}% used`}
            color={memPct > 80 ? "text-amber-400" : "text-foreground"}
          />
          <HeroStat
            label="Node.js"
            value={data.process.nodeVersion}
            sub={`V8 ${data.process.v8Version}`}
            color="text-emerald-400"
          />
        </div>

        {/* Main grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <OverviewSection data={data} />
          <NetworkSection data={data} />
          <CpuSection data={data} />
          <MemorySection data={data} />
          <DiskSection data={data} />
          <ProcessSection data={data} />
          <div className="grid grid-cols-2 gap-4 lg:col-span-1">
            <UserSection data={data} />
            <SecuritySection data={data} />
          </div>
          <TimezoneSection data={data} />
          <SoftwareSection data={data} />
        </div>

        {/* Footer */}
        <div className="mt-10 pt-6 border-t border-border text-center">
          <p className="text-[11px] text-zinc-600 font-mono">
            Collected at build time &middot; {data.timestamp}
          </p>
        </div>
      </div>
    </div>
  );
}

function HeroStat({
  label,
  value,
  sub,
  color = "text-foreground",
}: {
  label: string;
  value: string;
  sub?: string;
  color?: string;
}) {
  return (
    <div className="rounded-2xl border border-border bg-surface p-4 hover:border-zinc-600 transition-colors">
      <div className="text-[11px] text-muted uppercase tracking-widest mb-2">
        {label}
      </div>
      <div className={`text-[15px] font-mono font-bold truncate ${color}`}>
        {value}
      </div>
      {sub && (
        <div className="text-[11px] text-zinc-600 font-mono mt-1 truncate">
          {sub}
        </div>
      )}
    </div>
  );
}

function countryFlag(code: string): string {
  if (!code || code.length !== 2) return "";
  const offset = 0x1F1E6 - 65; // 'A' is 65
  return String.fromCodePoint(
    code.codePointAt(0)! + offset,
    code.codePointAt(1)! + offset
  );
}

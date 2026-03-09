import { getServerInfo } from "@/lib/serverInfo";
import Link from "next/link";

export default async function JsonPage() {
  const serverInfo = await getServerInfo();

  return (
    <div className="min-h-screen bg-background py-10 px-4 sm:px-6 lg:px-8">
      <div className="max-w-5xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-lg font-bold text-foreground tracking-tight">
            Raw JSON
          </h1>
          <Link
            href="/"
            className="text-[12px] font-mono px-3.5 py-2 rounded-lg bg-surface border border-border text-muted hover:text-foreground hover:border-zinc-600 transition-all"
          >
            &larr; Dashboard
          </Link>
        </div>
        <pre className="rounded-2xl border border-border bg-surface p-6 text-[12px] font-mono text-zinc-300 overflow-x-auto leading-relaxed">
          {JSON.stringify(serverInfo, null, 2)}
        </pre>
      </div>
    </div>
  );
}

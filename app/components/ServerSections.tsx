import { Card, StatRow, Badge, ProgressBar } from "./Card";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type ServerInfoData = any;

function countryFlag(code: string): string {
  if (!code || code.length !== 2) return "";
  const offset = 0x1F1E6 - 65;
  return String.fromCodePoint(
    code.charCodeAt(0) + offset,
    code.charCodeAt(1) + offset
  );
}

export function OverviewSection({ data }: { data: ServerInfoData }) {
  return (
    <Card title="System Overview" icon="⚙️">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8">
        <StatRow label="Operating System" value={data.distro?.PRETTY_NAME || data.os.type} />
        <StatRow label="Kernel" value={data.os.release} mono />
        <StatRow label="Architecture" value={`${data.os.arch} (${data.os.machine || "N/A"})`} mono />
        <StatRow label="Uptime" value={data.os.uptime.formatted} mono />
        <StatRow
          label="Runtime"
          value={
            data.container.isContainer ? (
              <Badge color="cyan">{data.container.runtime}</Badge>
            ) : (
              <Badge color="gray">Bare Metal</Badge>
            )
          }
        />
        <StatRow
          label="Provider"
          value={
            <Badge color={data.hostingProvider.confidence === "high" ? "green" : "yellow"}>
              {data.hostingProvider.provider}
            </Badge>
          }
        />
      </div>
    </Card>
  );
}

export function NetworkSection({ data }: { data: ServerInfoData }) {
  const net = data.network;
  const geo = net.ipGeo;
  const flag = geo?.countryCode ? countryFlag(geo.countryCode) : "";
  const webhook = data.webhook;
  return (
    <Card title="Network" icon="🌐">
      {/* External IP highlight */}
      <div className="mb-4 px-4 py-3 rounded-xl bg-blue-500/5 ring-1 ring-inset ring-blue-500/10">
        <div className="text-[11px] text-blue-400/70 uppercase tracking-widest mb-1">External IP</div>
        <div className="flex items-center gap-3">
          <div className="font-mono text-lg text-blue-400 font-semibold">{net.realExternalIP}</div>
          {flag && <span className="text-2xl">{flag}</span>}
        </div>
        {geo && (
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-2 text-[11px] text-zinc-400">
            {geo.country && <span>{geo.country}</span>}
            {geo.city && <span>&middot; {geo.city}{geo.region ? `, ${geo.region}` : ""}</span>}
            {geo.org && <span>&middot; {geo.org}</span>}
          </div>
        )}
      </div>

      {(webhook?.build || webhook?.runtime) && (
        <div className="mb-4 px-4 py-3 rounded-xl bg-amber-500/5 ring-1 ring-inset ring-amber-500/10">
          <div className="text-[11px] text-amber-400/70 uppercase tracking-widest mb-2">Webhook.site Debug</div>
          <div className="space-y-1 text-[11px] font-mono text-zinc-400">
            {webhook?.build && (
              <div>
                Build ping: {webhook.build.webhook?.sent ? "sent" : webhook.build.webhook?.enabled ? "failed" : "disabled"} &middot; {webhook.build.generatedAt || "N/A"}
              </div>
            )}
            {webhook?.runtime && (
              <div>
                Runtime ping: {webhook.runtime.sent ? "sent" : "failed"} &middot; {webhook.runtime.timestamp}
              </div>
            )}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8">
        {net.privateIPv4.map((ip: string) => (
          <StatRow key={ip} label="Private IPv4" value={ip} mono />
        ))}
        {net.privateIPv6.map((ip: string) => (
          <StatRow key={ip} label="Private IPv6" value={<span className="text-[11px]">{ip}</span>} mono />
        ))}
        <StatRow label="Hostname" value={net.hostname || "—"} mono />
        {net.dns?.resolv?.nameservers?.map((ns: string) => (
          <StatRow key={ns} label="DNS Server" value={ns} mono />
        ))}
      </div>

      {/* Interface cards */}
      <div className="mt-4 space-y-2">
        {Object.entries(net.interfaces).map(([name, addrs]) => (
          <div key={name} className="rounded-lg bg-surface-2 px-3.5 py-2.5">
            <div className="text-[12px] font-mono font-bold text-foreground mb-1.5">{name}</div>
            <div className="space-y-1">
              {(addrs as any[]).map((addr: any, i: number) => (
                <div key={i} className="flex items-center gap-2 text-[12px]">
                  <Badge color={addr.family === "IPv4" ? "blue" : "purple"}>{addr.family}</Badge>
                  <span className="font-mono text-zinc-300">{addr.cidr}</span>
                  <span className="text-zinc-600 ml-auto font-mono text-[11px]">{addr.mac}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

export function CpuSection({ data }: { data: ServerInfoData }) {
  const cpu = data.cpu;
  return (
    <Card title="CPU" icon="⚡">
      <StatRow label="Model" value={cpu.model} />
      <StatRow label="Cores" value={<span className="text-lg font-bold text-foreground">{cpu.count}</span>} />
      <StatRow label="Speed" value={cpu.speed} mono />
      <div className="mt-4 space-y-3">
        <ProgressBar percent={parseFloat(cpu.loadAverage["1min"]) / cpu.count * 100} label={`Load 1m — ${cpu.loadAverage["1min"]}`} />
        <ProgressBar percent={parseFloat(cpu.loadAverage["5min"]) / cpu.count * 100} label={`Load 5m — ${cpu.loadAverage["5min"]}`} />
        <ProgressBar percent={parseFloat(cpu.loadAverage["15min"]) / cpu.count * 100} label={`Load 15m — ${cpu.loadAverage["15min"]}`} />
      </div>
    </Card>
  );
}

export function MemorySection({ data }: { data: ServerInfoData }) {
  const mem = data.memory;
  const usagePercent = parseFloat(mem.usagePercent);
  return (
    <Card title="Memory" icon="🧠">
      <div className="mb-4">
        <ProgressBar percent={usagePercent} label="RAM Usage" />
      </div>
      <div className="grid grid-cols-3 gap-3">
        <MiniStat label="Total" value={mem.total.gb} />
        <MiniStat label="Used" value={mem.used.gb} color="text-amber-400" />
        <MiniStat label="Free" value={mem.free.gb} color="text-emerald-400" />
      </div>
      {mem.swap && mem.swap.total.bytes > 0 && (
        <div className="mt-3 pt-3 border-t border-border-subtle">
          <div className="grid grid-cols-2 gap-3">
            <MiniStat label="Swap Total" value={mem.swap.total.gb} />
            <MiniStat label="Swap Used" value={mem.swap.used.gb} />
          </div>
        </div>
      )}
    </Card>
  );
}

function MiniStat({ label, value, color = "text-foreground" }: { label: string; value: string; color?: string }) {
  return (
    <div className="rounded-lg bg-surface-2 px-3 py-2.5 text-center">
      <div className="text-[11px] text-muted uppercase tracking-wider mb-0.5">{label}</div>
      <div className={`text-sm font-mono font-semibold ${color}`}>{value}</div>
    </div>
  );
}

export function DiskSection({ data }: { data: ServerInfoData }) {
  const filesystems = data.disk?.filesystems;
  if (!filesystems) return null;
  return (
    <Card title="Disk" icon="💾" className="lg:col-span-2">
      <div className="overflow-x-auto -mx-5 px-5">
        <table className="w-full text-[12px]">
          <thead>
            <tr className="text-left text-muted border-b border-border-subtle">
              <th className="pb-2.5 pr-4 font-medium">Filesystem</th>
              <th className="pb-2.5 pr-4 font-medium">Size</th>
              <th className="pb-2.5 pr-4 font-medium">Used</th>
              <th className="pb-2.5 pr-4 font-medium">Avail</th>
              <th className="pb-2.5 pr-4 font-medium">Usage</th>
              <th className="pb-2.5 font-medium">Mount</th>
            </tr>
          </thead>
          <tbody className="font-mono">
            {filesystems.map((f: any, i: number) => {
              const pct = parseInt(f.usePercent) || 0;
              return (
                <tr key={i} className="border-t border-border-subtle">
                  <td className="py-2.5 pr-4 text-foreground">{f.filesystem}</td>
                  <td className="py-2.5 pr-4 text-zinc-400">{f.size}</td>
                  <td className="py-2.5 pr-4 text-zinc-400">{f.used}</td>
                  <td className="py-2.5 pr-4 text-zinc-400">{f.available}</td>
                  <td className="py-2.5 pr-4">
                    <div className="flex items-center gap-2">
                      <div className="w-16">
                        <ProgressBar percent={pct} size="sm" />
                      </div>
                      <span className={`text-[11px] ${pct > 90 ? "text-red-400" : pct > 70 ? "text-amber-400" : "text-zinc-400"}`}>
                        {f.usePercent}
                      </span>
                    </div>
                  </td>
                  <td className="py-2.5 text-zinc-500">{f.mountedOn}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function ProcessSection({ data }: { data: ServerInfoData }) {
  const proc = data.process;
  return (
    <Card title="Node.js" icon="🟢">
      <div className="flex items-center gap-2 mb-4">
        <Badge color="green">{proc.nodeVersion}</Badge>
        <span className="text-[11px] text-muted">PID {proc.pid}</span>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8">
        <StatRow label="V8 Engine" value={proc.v8Version} mono />
        <StatRow label="OpenSSL" value={proc.opensslVersion} mono />
        <StatRow label="Platform" value={`${proc.platform} / ${proc.arch}`} mono />
        <StatRow label="Uptime" value={proc.uptime} mono />
      </div>
      <div className="mt-4 grid grid-cols-3 gap-3">
        <MiniStat label="RSS" value={proc.memoryUsage.rss.mb} />
        <MiniStat label="Heap Total" value={proc.memoryUsage.heapTotal.mb} />
        <MiniStat label="Heap Used" value={proc.memoryUsage.heapUsed.mb} />
      </div>
    </Card>
  );
}

export function UserSection({ data }: { data: ServerInfoData }) {
  const user = data.user;
  return (
    <Card title="User" icon="👤">
      <div className="flex items-center gap-2 mb-3">
        <span className="font-mono text-foreground font-semibold">{user.username}</span>
        {user.uid === 0 && <Badge color="red">root</Badge>}
      </div>
      <StatRow label="UID / GID" value={`${user.uid} / ${user.gid}`} mono />
      <StatRow label="Shell" value={user.shell} mono />
      <StatRow label="Home" value={user.homedir} mono />
    </Card>
  );
}

export function SecuritySection({ data }: { data: ServerInfoData }) {
  const sec = data.security;
  return (
    <Card title="Security" icon="🛡️">
      <div className="grid grid-cols-3 gap-3">
        <SecurityItem label="SELinux" value={sec.selinux} />
        <SecurityItem label="AppArmor" value={sec.apparmor} />
        <SecurityItem label="Seccomp" value={sec.seccomp} />
      </div>
    </Card>
  );
}

function SecurityItem({ label, value }: { label: string; value: string | null }) {
  const isActive = value && value !== "disabled" && value !== "N/A";
  return (
    <div className={`rounded-lg px-3 py-3 text-center ${isActive ? "bg-emerald-500/5 ring-1 ring-inset ring-emerald-500/10" : "bg-surface-2"}`}>
      <div className="text-[11px] text-muted uppercase tracking-wider mb-1">{label}</div>
      <Badge color={isActive ? "green" : value === "disabled" ? "yellow" : "gray"}>
        {value || "N/A"}
      </Badge>
    </div>
  );
}

export function SoftwareSection({ data }: { data: ServerInfoData }) {
  const sw = data.software;
  if (!sw) return null;
  const entries = Object.entries(sw).filter(([k]) => !k.startsWith("_"));
  return (
    <Card title="Software" icon="📦" className="lg:col-span-2">
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
        {entries.map(([name, version]) => (
          <div key={name} className="rounded-lg bg-surface-2 px-3 py-2">
            <div className="text-[11px] text-muted capitalize mb-0.5">{name}</div>
            <div className="font-mono text-[11px] text-zinc-300 truncate" title={String(version)}>
              {String(version).split(" ")[0]}
            </div>
          </div>
        ))}
      </div>
      {sw._installedPackageCount && (
        <div className="mt-3 text-[11px] text-muted">
          {sw._installedPackageCount} system packages installed
        </div>
      )}
    </Card>
  );
}

export function ProxyDetectionSection({ data }: { data: ServerInfoData }) {
  const proxy = data.proxyDetection;
  if (!proxy) return null;

  const statusColor = proxy.isProxied
    ? proxy.confidence === "high" ? "red" : proxy.confidence === "medium" ? "yellow" : "yellow"
    : "green";
  const statusText = proxy.isProxied
    ? `Proxy/CDN likely (${proxy.confidence} confidence)`
    : "Direct connection (no proxy detected)";

  return (
    <Card title="Proxy / CDN Detection" icon="🔍" className="lg:col-span-2">
      <div className={`mb-4 px-4 py-3 rounded-xl ${
        proxy.isProxied
          ? "bg-amber-500/5 ring-1 ring-inset ring-amber-500/10"
          : "bg-emerald-500/5 ring-1 ring-inset ring-emerald-500/10"
      }`}>
        <div className="flex items-center gap-2">
          <Badge color={statusColor}>{statusText}</Badge>
        </div>
        {proxy.indicators.length > 0 && (
          <div className="mt-2 space-y-1">
            {proxy.indicators.map((ind: string, i: number) => (
              <div key={i} className="text-[11px] font-mono text-zinc-400">
                &bull; {ind}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8">
        {proxy.details.reverseDns && (
          <StatRow label="Reverse DNS" value={proxy.details.reverseDns} mono />
        )}
        {proxy.details.knownProxyOrg && (
          <StatRow label="Known Proxy Org" value="Yes" />
        )}
        {proxy.details.locationMismatch && (
          <StatRow
            label="Location Mismatch"
            value={`TZ: ${proxy.details.locationMismatch.serverTimezone} → IP: ${proxy.details.locationMismatch.ipCountry || proxy.details.locationMismatch.ipContinent}`}
            mono
          />
        )}
        {Object.keys(proxy.details.proxyEnvVars).length > 0 && (
          <StatRow
            label="Proxy Env Vars"
            value={Object.keys(proxy.details.proxyEnvVars).join(", ")}
            mono
          />
        )}
        {proxy.details.proxySoftware.length > 0 && (
          <StatRow
            label="Proxy Software"
            value={proxy.details.proxySoftware.join(", ")}
            mono
          />
        )}
      </div>

      {proxy.details.multiServiceIPs.length > 0 && (
        <div className="mt-4">
          <div className="text-[11px] text-muted uppercase tracking-widest mb-2">Multi-Service IP Check</div>
          <div className="space-y-1">
            {proxy.details.multiServiceIPs.map((entry: { service: string; ip: string }, i: number) => (
              <div key={i} className="flex items-center gap-2 text-[11px] font-mono text-zinc-400">
                <span className="text-zinc-600 truncate max-w-[200px]">{entry.service.replace(/https?:\/\//, "")}</span>
                <span className="text-zinc-300">{entry.ip}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
}

export function TimezoneSection({ data }: { data: ServerInfoData }) {
  return (
    <Card title="Timezone" icon="🕐">
      <StatRow label="Timezone" value={data.timezone.timezone} />
      <StatRow label="Locale" value={data.timezone.locale} />
    </Card>
  );
}

export function Card({
  title,
  icon,
  children,
  className = "",
}: {
  title: string;
  icon: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`rounded-2xl border border-border bg-surface overflow-hidden ${className}`}
    >
      <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-border-subtle">
        <span className="text-base">{icon}</span>
        <h2 className="text-[13px] font-semibold text-muted uppercase tracking-widest">
          {title}
        </h2>
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

export function StatRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex justify-between items-baseline py-2 border-b border-border-subtle last:border-b-0 gap-4">
      <span className="text-[13px] text-muted shrink-0">
        {label}
      </span>
      <span
        className={`text-[13px] text-foreground text-right break-all ${mono ? "font-mono" : ""}`}
      >
        {value}
      </span>
    </div>
  );
}

export function Badge({
  children,
  color = "gray",
}: {
  children: React.ReactNode;
  color?: "green" | "red" | "yellow" | "blue" | "gray" | "purple" | "cyan";
}) {
  const colors = {
    green: "bg-emerald-500/10 text-emerald-400 ring-emerald-500/20",
    red: "bg-red-500/10 text-red-400 ring-red-500/20",
    yellow: "bg-amber-500/10 text-amber-400 ring-amber-500/20",
    blue: "bg-blue-500/10 text-blue-400 ring-blue-500/20",
    gray: "bg-zinc-500/10 text-zinc-400 ring-zinc-500/20",
    purple: "bg-violet-500/10 text-violet-400 ring-violet-500/20",
    cyan: "bg-cyan-500/10 text-cyan-400 ring-cyan-500/20",
  };
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium ring-1 ring-inset ${colors[color]}`}
    >
      {children}
    </span>
  );
}

export function ProgressBar({
  percent,
  label,
  size = "md",
}: {
  percent: number;
  label?: string;
  size?: "sm" | "md";
}) {
  const color =
    percent > 90
      ? "bg-red-500"
      : percent > 70
        ? "bg-amber-500"
        : percent > 40
          ? "bg-blue-500"
          : "bg-emerald-500";
  const glowColor =
    percent > 90
      ? "shadow-red-500/30"
      : percent > 70
        ? "shadow-amber-500/30"
        : percent > 40
          ? "shadow-blue-500/30"
          : "shadow-emerald-500/30";
  return (
    <div>
      {label && (
        <div className="flex justify-between text-[12px] mb-1.5">
          <span className="text-muted">{label}</span>
          <span className="font-mono text-foreground">
            {percent.toFixed(1)}%
          </span>
        </div>
      )}
      <div className={`w-full ${size === "sm" ? "h-1.5" : "h-2"} bg-zinc-800 rounded-full overflow-hidden`}>
        <div
          className={`h-full rounded-full transition-all shadow-sm ${color} ${glowColor}`}
          style={{ width: `${Math.min(percent, 100)}%` }}
        />
      </div>
    </div>
  );
}

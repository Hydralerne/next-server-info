// lib/serverInfo.js
import os from "os";
import fs from "fs";
import { execSync } from "child_process";

// ─── Helper Functions ────────────────────────────────────────────────────────

function isPrivateIP(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 127) return true;
  return false;
}

async function fetchExternalIP() {
  const services = [
    "https://api.ipify.org?format=json",
    "https://api.my-ip.io/ip.json",
    "https://ipapi.co/json/",
  ];
  for (const service of services) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      const response = await fetch(service, {
        signal: controller.signal,
        headers: { "User-Agent": "Node.js Server Info" },
      });
      clearTimeout(timeoutId);
      if (response.ok) {
        const data = await response.json();
        return data.ip || data.IP || data.query || null;
      }
    } catch {
      continue;
    }
  }
  return null;
}

function safeExec(command) {
  try {
    return execSync(command, { encoding: "utf8", timeout: 3000, stdio: ["pipe", "pipe", "pipe"] }).trim();
  } catch {
    return null;
  }
}

function safeReadFile(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8").trim();
  } catch {
    return null;
  }
}

function formatBytes(bytes) {
  const gb = (bytes / 1024 / 1024 / 1024).toFixed(2);
  const mb = (bytes / 1024 / 1024).toFixed(2);
  return { bytes, mb: `${mb} MB`, gb: `${gb} GB` };
}

function formatUptime(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  return `${d}d ${h}h ${m}m ${s}s`;
}

// ─── Container Detection ────────────────────────────────────────────────────

function detectContainer() {
  const result = {
    isContainer: false,
    isDocker: false,
    isKubernetes: false,
    containerId: null,
    runtime: null,
    cgroupVersion: null,
    initProcess: null,
  };

  // Method 1: /.dockerenv file (most reliable for Docker)
  if (fs.existsSync("/.dockerenv")) {
    result.isContainer = true;
    result.isDocker = true;
    result.runtime = "Docker";
  }

  // Method 2: Check cgroup files
  for (const cgroupPath of ["/proc/self/cgroup", "/proc/1/cgroup"]) {
    const content = safeReadFile(cgroupPath);
    if (!content) continue;

    if (content.includes("docker")) {
      result.isContainer = true;
      result.isDocker = true;
      result.runtime = "Docker";
      const match =
        content.match(/docker[/-]([0-9a-f]{64})/) ||
        content.match(/docker[/-]([0-9a-f]{12,})/);
      if (match && !result.containerId) {
        result.containerId = match[1].substring(0, 12);
      }
    }

    if (content.includes("kubepods") || content.includes("kube-pod")) {
      result.isContainer = true;
      result.isKubernetes = true;
      result.runtime = result.runtime ? `${result.runtime}/Kubernetes` : "Kubernetes";
    }

    if (content.includes("containerd")) {
      result.isContainer = true;
      result.runtime = result.runtime ? `${result.runtime}/containerd` : "containerd";
    }
    if (content.includes("podman")) {
      result.isContainer = true;
      result.runtime = result.runtime ? `${result.runtime}/Podman` : "Podman";
    }
    if (content.includes("lxc")) {
      result.isContainer = true;
      result.runtime = result.runtime ? `${result.runtime}/LXC` : "LXC";
    }
  }

  // Method 3: cgroup v2 detection
  const mountinfo = safeReadFile("/proc/self/mountinfo");
  if (mountinfo && mountinfo.includes("cgroup2")) {
    result.cgroupVersion = "v2";
  } else {
    result.cgroupVersion = "v1";
  }

  // Method 4: Kubernetes service account
  if (fs.existsSync("/var/run/secrets/kubernetes.io/serviceaccount/token")) {
    result.isContainer = true;
    result.isKubernetes = true;
    if (!result.runtime || !result.runtime.includes("Kubernetes")) {
      result.runtime = result.runtime ? `${result.runtime}/Kubernetes` : "Kubernetes";
    }
  }

  // Method 5: init process (PID 1)
  const initCmdline = safeReadFile("/proc/1/cmdline");
  if (initCmdline) {
    result.initProcess = initCmdline.replace(/\0/g, " ").trim();
  }

  return result;
}

// ─── Hosting Provider Detection ──────────────────────────────────────────────

async function detectHostingProvider() {
  const detection = {
    provider: "Unknown",
    confidence: "low",
    indicators: [],
    metadata: {},
  };

  // Container info
  const containerInfo = detectContainer();
  detection.metadata.container = containerInfo;
  if (containerInfo.runtime) {
    detection.indicators.push(`Container runtime: ${containerInfo.runtime}`);
  }

  // ── Environment variable checks (PaaS) ──
  const env = process.env;

  const paasChecks = [
    { test: () => env.RAILWAY_ENVIRONMENT || env.RAILWAY_PROJECT_ID, name: "Railway", meta: { projectId: env.RAILWAY_PROJECT_ID, environment: env.RAILWAY_ENVIRONMENT } },
    { test: () => env.VERCEL || env.VERCEL_ENV, name: "Vercel", meta: { env: env.VERCEL_ENV, region: env.VERCEL_REGION } },
    { test: () => env.NETLIFY, name: "Netlify", meta: {} },
    { test: () => env.DYNO, name: "Heroku", meta: { dyno: env.DYNO } },
    { test: () => env.RENDER, name: "Render", meta: { serviceId: env.RENDER_SERVICE_ID } },
    { test: () => env.FLY_APP_NAME, name: "Fly.io", meta: { app: env.FLY_APP_NAME, region: env.FLY_REGION } },
    { test: () => env.COOLIFY_URL || env.COOLIFY_FQDN, name: "Coolify", meta: { url: env.COOLIFY_URL || env.COOLIFY_FQDN } },
    { test: () => env.GAE_APPLICATION || env.GOOGLE_CLOUD_PROJECT, name: "Google Cloud", meta: { project: env.GOOGLE_CLOUD_PROJECT } },
    { test: () => env.AWS_LAMBDA_FUNCTION_NAME, name: "AWS Lambda", meta: { function: env.AWS_LAMBDA_FUNCTION_NAME, region: env.AWS_REGION } },
    { test: () => env.ECS_CONTAINER_METADATA_URI, name: "AWS ECS", meta: {} },
    { test: () => env.AZURE_FUNCTIONS_ENVIRONMENT, name: "Azure Functions", meta: {} },
    { test: () => env.WEBSITE_SITE_NAME && env.WEBSITE_INSTANCE_ID, name: "Azure App Service", meta: { siteName: env.WEBSITE_SITE_NAME } },
    { test: () => env.NIXPACKS_METADATA, name: "Nixpacks-based (Railway/Coolify/etc.)", meta: { nixpacksMeta: env.NIXPACKS_METADATA } },
  ];

  for (const check of paasChecks) {
    if (check.test()) {
      detection.provider = check.name;
      detection.confidence = "high";
      detection.indicators.push(`${check.name} environment variable(s) detected`);
      Object.assign(detection.metadata, check.meta);
      break;
    }
  }

  // ── Cloud metadata endpoints ──
  if (detection.provider === "Unknown") {
    const metadataChecks = [
      { name: "AWS", url: "http://169.254.169.254/latest/meta-data/instance-id", headers: {} },
      { name: "Google Cloud", url: "http://metadata.google.internal/computeMetadata/v1/instance/id", headers: { "Metadata-Flavor": "Google" } },
      { name: "Azure", url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", headers: { Metadata: "true" } },
      { name: "DigitalOcean", url: "http://169.254.169.254/metadata/v1/id", headers: {} },
    ];

    for (const check of metadataChecks) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 1500);
        const response = await fetch(check.url, { signal: controller.signal, headers: check.headers });
        clearTimeout(timeoutId);
        if (response.ok) {
          detection.provider = check.name;
          detection.confidence = "high";
          detection.indicators.push(`Metadata endpoint responded: ${check.url}`);
          try { detection.metadata.instanceId = (await response.text()).substring(0, 100); } catch {}
          break;
        }
      } catch {
        // Continue
      }
    }
  }

  // ── DMI/SMBIOS ──
  const dmiFiles = {
    productName: "/sys/class/dmi/id/product_name",
    vendor: "/sys/class/dmi/id/sys_vendor",
    chassisVendor: "/sys/class/dmi/id/chassis_vendor",
    biosVendor: "/sys/class/dmi/id/bios_vendor",
    boardName: "/sys/class/dmi/id/board_name",
    boardVendor: "/sys/class/dmi/id/board_vendor",
    productVersion: "/sys/class/dmi/id/product_version",
  };

  const dmiInfo = {};
  for (const [key, file] of Object.entries(dmiFiles)) {
    const value = safeReadFile(file);
    if (value) dmiInfo[key] = value;
  }

  if (Object.keys(dmiInfo).length > 0) {
    detection.metadata.hardware = dmiInfo;
    const allValues = Object.values(dmiInfo).join(" ").toLowerCase();

    const providerMap = {
      amazon: "AWS", aws: "AWS", google: "Google Cloud",
      microsoft: "Azure", azure: "Azure", digitalocean: "DigitalOcean",
      hetzner: "Hetzner", ovh: "OVH", linode: "Linode", vultr: "Vultr",
      "oracle cloud": "Oracle Cloud", alibaba: "Alibaba Cloud",
      upcloud: "UpCloud", scaleway: "Scaleway",
    };

    if (detection.provider === "Unknown") {
      for (const [keyword, name] of Object.entries(providerMap)) {
        if (allValues.includes(keyword)) {
          detection.provider = name;
          detection.confidence = "high";
          detection.indicators.push(`DMI/SMBIOS info contains "${keyword}"`);
          break;
        }
      }
    }
  }

  // ── Virtualization ──
  const virtType = safeExec("systemd-detect-virt 2>/dev/null") || safeExec("virt-what 2>/dev/null");
  if (virtType && virtType !== "none") {
    detection.metadata.virtualization = virtType;
    detection.indicators.push(`Virtualization: ${virtType}`);
  }

  // ── CPU hypervisor flag ──
  const cpuFlags = safeReadFile("/proc/cpuinfo");
  if (cpuFlags && cpuFlags.includes("hypervisor")) {
    detection.indicators.push("CPU has hypervisor flag (running in VM)");
  }

  // ── Hostname patterns ──
  const hostname = os.hostname();
  if (detection.provider === "Unknown") {
    if (hostname.match(/^ip-\d+-\d+-\d+-\d+/)) {
      detection.provider = "AWS";
      detection.confidence = "medium";
      detection.indicators.push("Hostname matches AWS pattern");
    } else if (hostname.includes("railway")) {
      detection.provider = "Railway";
      detection.confidence = "medium";
    } else if (hostname.includes("vercel")) {
      detection.provider = "Vercel";
      detection.confidence = "medium";
    }
  }

  return detection;
}

// ─── Deep System Info Collectors ─────────────────────────────────────────────

function getKernelInfo() {
  return {
    procVersion: safeReadFile("/proc/version"),
    cmdline: safeReadFile("/proc/cmdline"),
    modules: (() => {
      const raw = safeReadFile("/proc/modules");
      if (!raw) return null;
      return raw.split("\n").slice(0, 50).map((line) => {
        const parts = line.split(" ");
        return { name: parts[0], size: parts[1], usedBy: parts[3] };
      });
    })(),
    parameters: (() => {
      const params = {};
      const keys = ["ostype", "osrelease", "version", "hostname", "domainname", "random/boot_id", "random/uuid"];
      for (const key of keys) {
        const val = safeReadFile(`/proc/sys/kernel/${key}`);
        if (val) params[key] = val;
      }
      return Object.keys(params).length > 0 ? params : null;
    })(),
  };
}

function getDistroInfo() {
  const result = {};

  const osRelease = safeReadFile("/etc/os-release");
  if (osRelease) {
    for (const line of osRelease.split("\n")) {
      const match = line.match(/^(\w+)=["']?(.+?)["']?$/);
      if (match) result[match[1]] = match[2];
    }
  }

  const lsbRelease = safeReadFile("/etc/lsb-release");
  if (lsbRelease && !result.NAME) {
    for (const line of lsbRelease.split("\n")) {
      const match = line.match(/^(\w+)=["']?(.+?)["']?$/);
      if (match) result[match[1]] = match[2];
    }
  }

  for (const file of ["/etc/debian_version", "/etc/redhat-release", "/etc/centos-release", "/etc/alpine-release", "/etc/arch-release"]) {
    const content = safeReadFile(file);
    if (content) result[file.replace("/etc/", "")] = content;
  }

  return Object.keys(result).length > 0 ? result : null;
}

function getDiskInfo() {
  const result = { filesystems: null, blockDevices: null, inodes: null };

  const dfOutput = safeExec("df -h 2>/dev/null");
  if (dfOutput) {
    result.filesystems = dfOutput.split("\n").slice(1).map((line) => {
      const parts = line.split(/\s+/);
      return { filesystem: parts[0], size: parts[1], used: parts[2], available: parts[3], usePercent: parts[4], mountedOn: parts[5] };
    });
  }

  const lsblkOutput = safeExec("lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT -J 2>/dev/null");
  if (lsblkOutput) {
    try { result.blockDevices = JSON.parse(lsblkOutput).blockdevices; } catch {}
  }

  const inodeOutput = safeExec("df -i 2>/dev/null");
  if (inodeOutput) {
    result.inodes = inodeOutput.split("\n").slice(1).map((line) => {
      const parts = line.split(/\s+/);
      return { filesystem: parts[0], inodes: parts[1], iUsed: parts[2], iFree: parts[3], iUsePercent: parts[4], mountedOn: parts[5] };
    });
  }

  return result;
}

function getDnsInfo() {
  const result = { resolv: null, nsswitch: null, hosts: null };

  const resolvConf = safeReadFile("/etc/resolv.conf");
  if (resolvConf) {
    const nameservers = [];
    const searchDomains = [];
    for (const line of resolvConf.split("\n")) {
      if (line.startsWith("nameserver")) nameservers.push(line.split(/\s+/)[1]);
      else if (line.startsWith("search") || line.startsWith("domain")) searchDomains.push(...line.split(/\s+/).slice(1));
    }
    result.resolv = { nameservers, searchDomains, raw: resolvConf };
  }

  const nsswitch = safeReadFile("/etc/nsswitch.conf");
  if (nsswitch) {
    const hostsLine = nsswitch.split("\n").find((l) => l.startsWith("hosts:"));
    result.nsswitch = hostsLine || null;
  }

  result.hosts = safeReadFile("/etc/hosts");
  return result;
}

function getSecurityInfo() {
  const result = { selinux: null, apparmor: null, capabilities: null, seccomp: null };

  result.selinux = safeExec("getenforce 2>/dev/null");

  const apparmorEnabled = safeReadFile("/sys/module/apparmor/parameters/enabled");
  if (apparmorEnabled) result.apparmor = apparmorEnabled === "Y" ? "enabled" : "disabled";

  const capStatus = safeReadFile("/proc/self/status");
  if (capStatus) {
    const caps = {};
    for (const line of capStatus.split("\n")) {
      if (line.startsWith("Cap")) { const [key, val] = line.split(":\t"); caps[key] = val; }
      if (line.startsWith("Seccomp:")) {
        const mode = line.split(":\t")[1];
        result.seccomp = mode === "0" ? "disabled" : mode === "1" ? "strict" : mode === "2" ? "filter" : mode;
      }
    }
    if (Object.keys(caps).length > 0) result.capabilities = caps;
  }

  return result;
}

function getResourceLimits() {
  const result = {};
  const limits = safeReadFile("/proc/self/limits");
  if (limits) {
    for (const line of limits.split("\n").slice(1)) {
      const match = line.match(/^(.+?)\s{2,}(\S+)\s{2,}(\S+)\s{2,}(\S+)\s*$/);
      if (match) result[match[1].trim()] = { soft: match[2], hard: match[3], units: match[4] };
    }
  }
  if (Object.keys(result).length === 0) {
    const ulimitAll = safeExec("ulimit -a 2>/dev/null");
    if (ulimitAll) return { raw: ulimitAll };
  }
  return Object.keys(result).length > 0 ? result : null;
}

function getSwapInfo() {
  const meminfo = safeReadFile("/proc/meminfo");
  if (!meminfo) return null;

  const result = {};
  for (const line of meminfo.split("\n")) {
    if (line.startsWith("SwapTotal:")) result.total = formatBytes(parseInt(line.split(/\s+/)[1]) * 1024);
    else if (line.startsWith("SwapFree:")) result.free = formatBytes(parseInt(line.split(/\s+/)[1]) * 1024);
  }
  if (result.total && result.free) result.used = formatBytes(result.total.bytes - result.free.bytes);
  return result.total ? result : null;
}

function getTimezoneLocale() {
  return {
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || null,
    locale: Intl.DateTimeFormat().resolvedOptions().locale || null,
    timezoneFile: safeReadFile("/etc/timezone"),
    localtime: safeExec("date +%Z 2>/dev/null"),
    langEnv: process.env.LANG || process.env.LC_ALL || null,
    allLocaleEnv: {
      LANG: process.env.LANG, LC_ALL: process.env.LC_ALL,
      LC_CTYPE: process.env.LC_CTYPE, TZ: process.env.TZ,
    },
  };
}

function getDetailedMemory() {
  const meminfo = safeReadFile("/proc/meminfo");
  if (!meminfo) return null;

  const result = {};
  const importantKeys = [
    "MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached",
    "SwapTotal", "SwapFree", "SwapCached", "Active", "Inactive",
    "Dirty", "AnonPages", "Mapped", "Shmem", "KernelStack",
    "PageTables", "CommitLimit", "Committed_AS",
    "HugePages_Total", "HugePages_Free", "Hugepagesize",
  ];
  for (const line of meminfo.split("\n")) {
    const match = line.match(/^(.+?):\s+(\d+)\s*(\w*)/);
    if (match && importantKeys.includes(match[1].trim())) {
      const kb = parseInt(match[2]);
      result[match[1].trim()] = match[3] === "kB" ? formatBytes(kb * 1024) : kb;
    }
  }
  return Object.keys(result).length > 0 ? result : null;
}

function getMountInfo() {
  const mounts = safeReadFile("/proc/mounts");
  if (!mounts) return null;
  return mounts.split("\n").filter(Boolean).map((line) => {
    const parts = line.split(" ");
    return { device: parts[0], mountPoint: parts[1], fsType: parts[2], options: parts[3] };
  });
}

function getOpenPorts() {
  const output = safeExec("ss -tlnp 2>/dev/null") || safeExec("netstat -tlnp 2>/dev/null");
  if (!output) return null;
  return { raw: output, listening: output.split("\n").slice(1).filter(Boolean) };
}

function getTopProcesses() {
  return safeExec("ps aux --sort=-%mem 2>/dev/null | head -20");
}

function getInstalledSoftware() {
  const software = {};
  const tools = [
    { name: "node", cmd: "node --version 2>/dev/null" },
    { name: "npm", cmd: "npm --version 2>/dev/null" },
    { name: "yarn", cmd: "yarn --version 2>/dev/null" },
    { name: "pnpm", cmd: "pnpm --version 2>/dev/null" },
    { name: "bun", cmd: "bun --version 2>/dev/null" },
    { name: "python", cmd: "python3 --version 2>/dev/null || python --version 2>/dev/null" },
    { name: "ruby", cmd: "ruby --version 2>/dev/null" },
    { name: "go", cmd: "go version 2>/dev/null" },
    { name: "rustc", cmd: "rustc --version 2>/dev/null" },
    { name: "java", cmd: "java --version 2>/dev/null || java -version 2>&1 | head -1" },
    { name: "docker", cmd: "docker --version 2>/dev/null" },
    { name: "git", cmd: "git --version 2>/dev/null" },
    { name: "curl", cmd: "curl --version 2>/dev/null | head -1" },
    { name: "openssl", cmd: "openssl version 2>/dev/null" },
    { name: "gcc", cmd: "gcc --version 2>/dev/null | head -1" },
    { name: "make", cmd: "make --version 2>/dev/null | head -1" },
    { name: "bash", cmd: "bash --version 2>/dev/null | head -1" },
    { name: "nix", cmd: "nix --version 2>/dev/null" },
    { name: "nginx", cmd: "nginx -v 2>&1" },
  ];

  for (const tool of tools) {
    const version = safeExec(tool.cmd);
    if (version) software[tool.name] = version;
  }

  const pkgCount = safeExec("dpkg -l 2>/dev/null | wc -l") ||
    safeExec("rpm -qa 2>/dev/null | wc -l") ||
    safeExec("apk list --installed 2>/dev/null | wc -l");
  if (pkgCount) software._installedPackageCount = parseInt(pkgCount) || pkgCount;

  return Object.keys(software).length > 0 ? software : null;
}

// ─── Main Export ─────────────────────────────────────────────────────────────

export async function getServerInfo() {
  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memUsagePercent = ((usedMem / totalMem) * 100).toFixed(2);

  // Network interfaces
  const networkInterfaces = os.networkInterfaces();
  const networkInfo = {};
  const publicIPv4 = [];
  const publicIPv6 = [];
  const privateIPv4 = [];
  const privateIPv6 = [];
  const internalIPv4 = [];
  const internalIPv6 = [];

  Object.entries(networkInterfaces).forEach(([name, interfaces]) => {
    networkInfo[name] = interfaces.map((iface) => {
      if (iface.family === "IPv4") {
        if (iface.internal) internalIPv4.push(iface.address);
        else if (isPrivateIP(iface.address)) privateIPv4.push(iface.address);
        else publicIPv4.push(iface.address);
      } else if (iface.family === "IPv6") {
        if (iface.internal) internalIPv6.push(iface.address);
        else {
          const addr = iface.address.toLowerCase();
          if (addr.startsWith("fe80") || addr.startsWith("fc") || addr.startsWith("fd"))
            privateIPv6.push(iface.address);
          else publicIPv6.push(iface.address);
        }
      }
      return { address: iface.address, netmask: iface.netmask, family: iface.family, mac: iface.mac, internal: iface.internal, cidr: iface.cidr, scopeid: iface.scopeid };
    });
  });

  let realExternalIP = null;
  try { realExternalIP = await fetchExternalIP(); } catch {}

  const hostingProvider = await detectHostingProvider();
  const loadAvg = os.loadavg();
  const userInfo = os.userInfo();
  const uptimeSeconds = os.uptime();

  return {
    // ── Timestamp ──
    timestamp: new Date().toISOString(),
    buildTime: new Date().toLocaleString(),

    // ── OS / Distribution ──
    os: {
      platform: os.platform(),
      type: os.type(),
      release: os.release(),
      version: os.version(),
      arch: os.arch(),
      endianness: os.endianness(),
      hostname: os.hostname(),
      uptime: { seconds: uptimeSeconds, formatted: formatUptime(uptimeSeconds) },
      tmpdir: os.tmpdir(),
      homedir: os.homedir(),
      eol: os.EOL === "\n" ? "\\n (LF)" : "\\r\\n (CRLF)",
      machine: os.machine ? os.machine() : null,
    },
    distro: getDistroInfo(),

    // ── Kernel ──
    kernel: getKernelInfo(),

    // ── CPU ──
    cpu: {
      count: cpus.length,
      model: cpus[0]?.model,
      speed: `${cpus[0]?.speed} MHz`,
      cores: cpus.map((cpu, index) => ({
        core: index, model: cpu.model, speed: `${cpu.speed} MHz`, times: cpu.times,
      })),
      loadAverage: { "1min": loadAvg[0].toFixed(2), "5min": loadAvg[1].toFixed(2), "15min": loadAvg[2].toFixed(2) },
    },

    // ── Memory ──
    memory: {
      total: formatBytes(totalMem),
      free: formatBytes(freeMem),
      used: formatBytes(usedMem),
      usagePercent: `${memUsagePercent}%`,
      detailed: getDetailedMemory(),
      swap: getSwapInfo(),
    },

    // ── Disk / Filesystem ──
    disk: getDiskInfo(),
    mounts: getMountInfo(),

    // ── Network ──
    network: {
      interfaces: networkInfo,
      realExternalIP: realExternalIP || "Unable to fetch (might be containerized/firewalled)",
      publicIPv4, publicIPv6, privateIPv4, privateIPv6, internalIPv4, internalIPv6,
      allIPs: [...publicIPv4, ...publicIPv6, ...privateIPv4, ...privateIPv6, ...internalIPv4, ...internalIPv6],
      hostname: os.hostname(),
      networkInterfaceCount: Object.keys(networkInfo).length,
      dns: getDnsInfo(),
    },

    // ── User ──
    user: {
      username: userInfo.username, uid: userInfo.uid, gid: userInfo.gid,
      shell: userInfo.shell, homedir: userInfo.homedir,
      groups: safeExec("groups 2>/dev/null"),
      whoami: safeExec("whoami 2>/dev/null"),
    },

    // ── Process ──
    process: {
      nodeVersion: process.version,
      v8Version: process.versions.v8,
      opensslVersion: process.versions.openssl,
      uvVersion: process.versions.uv,
      zlibVersion: process.versions.zlib,
      allVersions: process.versions,
      pid: process.pid, ppid: process.ppid,
      platform: process.platform, arch: process.arch,
      execPath: process.execPath, cwd: process.cwd(),
      title: process.title, argv: process.argv, execArgv: process.execArgv,
      memoryUsage: {
        rss: formatBytes(process.memoryUsage().rss),
        heapTotal: formatBytes(process.memoryUsage().heapTotal),
        heapUsed: formatBytes(process.memoryUsage().heapUsed),
        external: formatBytes(process.memoryUsage().external),
        arrayBuffers: formatBytes(process.memoryUsage().arrayBuffers),
      },
      resourceUsage: process.resourceUsage ? process.resourceUsage() : null,
      uptime: `${process.uptime().toFixed(2)} seconds`,
      features: process.features || null,
    },

    // ── Timezone / Locale ──
    timezone: getTimezoneLocale(),

    // ── Security ──
    security: getSecurityInfo(),

    // ── Resource Limits ──
    resourceLimits: getResourceLimits(),

    // ── Installed Software ──
    software: getInstalledSoftware(),

    // ── Top Processes ──
    topProcesses: getTopProcesses(),

    // ── Open Ports ──
    listeningPorts: getOpenPorts(),

    // ── Environment Variables (ALL) ──
    environment: { ...process.env },

    // ── Container Info ──
    container: hostingProvider.metadata.container || {
      isContainer: false, isDocker: false, isKubernetes: false, runtime: null,
    },

    // ── Hosting Provider Detection ──
    hostingProvider: {
      provider: hostingProvider.provider,
      confidence: hostingProvider.confidence,
      indicators: hostingProvider.indicators,
      metadata: (() => { const { container, ...rest } = hostingProvider.metadata; return rest; })(),
    },

    // ── System ──
    system: {
      cpuPriority: (() => { try { return process.getpriority ? process.getpriority() : "N/A"; } catch { return "N/A"; } })(),
      devNull: os.devNull,
      availableParallelism: os.availableParallelism ? os.availableParallelism() : cpus.length,
    },
  };
}

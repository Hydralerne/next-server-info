// lib/serverInfo.js
import os from "os";
import { execSync } from "child_process";

export function getServerInfo() {
  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memUsagePercent = ((usedMem / totalMem) * 100).toFixed(2);

  // Get all network interfaces with detailed info
  const networkInterfaces = os.networkInterfaces();
  const networkInfo = {};
  const externalIPv4 = [];
  const externalIPv6 = [];
  const internalIPv4 = [];
  const internalIPv6 = [];
  
  Object.entries(networkInterfaces).forEach(([name, interfaces]) => {
    networkInfo[name] = interfaces.map((iface) => {
      // Collect all IPs
      if (iface.family === "IPv4") {
        if (iface.internal) {
          internalIPv4.push(iface.address);
        } else {
          externalIPv4.push(iface.address);
        }
      } else if (iface.family === "IPv6") {
        if (iface.internal) {
          internalIPv6.push(iface.address);
        } else {
          externalIPv6.push(iface.address);
        }
      }
      return {
        address: iface.address,
        netmask: iface.netmask,
        family: iface.family,
        mac: iface.mac,
        internal: iface.internal,
        cidr: iface.cidr,
        scopeid: iface.scopeid,
      };
    });
  });

  // Get Docker container ID if inside Docker
  let containerId = null;
  try {
    const cgroup = execSync("cat /proc/self/cgroup").toString();
    const match = cgroup.match(/docker\/([0-9a-f]+)/);
    if (match) containerId = match[1].substring(0, 12);
  } catch (e) {
    // Not in Docker or not Linux
  }

  // Get load averages (1, 5, 15 minutes)
  const loadAvg = os.loadavg();

  // User info
  const userInfo = os.userInfo();

  // Format uptime to human readable
  const uptimeSeconds = os.uptime();
  const uptimeDays = Math.floor(uptimeSeconds / 86400);
  const uptimeHours = Math.floor((uptimeSeconds % 86400) / 3600);
  const uptimeMins = Math.floor((uptimeSeconds % 3600) / 60);

  // Memory formatting helper
  const formatBytes = (bytes) => {
    const gb = (bytes / 1024 / 1024 / 1024).toFixed(2);
    const mb = (bytes / 1024 / 1024).toFixed(2);
    return { bytes, mb: `${mb} MB`, gb: `${gb} GB` };
  };

  // Get environment info - ALL environment variables
  const allEnv = { ...process.env };

  return {
    // Timestamp
    timestamp: new Date().toISOString(),
    buildTime: new Date().toLocaleString(),

    // OS Information
    os: {
      platform: os.platform(),
      type: os.type(),
      release: os.release(),
      version: os.version(),
      arch: os.arch(),
      endianness: os.endianness(),
      hostname: os.hostname(),
      uptime: {
        seconds: uptimeSeconds,
        formatted: `${uptimeDays}d ${uptimeHours}h ${uptimeMins}m`,
      },
      tmpdir: os.tmpdir(),
      homedir: os.homedir(),
      eol: os.EOL === "\n" ? "\\n (LF)" : "\\r\\n (CRLF)",
    },

    // CPU Information
    cpu: {
      count: cpus.length,
      model: cpus[0]?.model,
      speed: `${cpus[0]?.speed} MHz`,
      cores: cpus.map((cpu, index) => ({
        core: index,
        model: cpu.model,
        speed: `${cpu.speed} MHz`,
        times: cpu.times,
      })),
      loadAverage: {
        "1min": loadAvg[0].toFixed(2),
        "5min": loadAvg[1].toFixed(2),
        "15min": loadAvg[2].toFixed(2),
      },
    },

    // Memory Information
    memory: {
      total: formatBytes(totalMem),
      free: formatBytes(freeMem),
      used: formatBytes(usedMem),
      usagePercent: `${memUsagePercent}%`,
    },

    // Network Information
    network: {
      interfaces: networkInfo,
      externalIPv4,
      externalIPv6,
      internalIPv4,
      internalIPv6,
      allIPs: [...externalIPv4, ...externalIPv6, ...internalIPv4, ...internalIPv6],
      hostname: os.hostname(),
      networkInterfaceCount: Object.keys(networkInfo).length,
    },

    // User Information
    user: {
      username: userInfo.username,
      uid: userInfo.uid,
      gid: userInfo.gid,
      shell: userInfo.shell,
      homedir: userInfo.homedir,
    },

    // Process Information
    process: {
      nodeVersion: process.version,
      pid: process.pid,
      ppid: process.ppid,
      platform: process.platform,
      arch: process.arch,
      execPath: process.execPath,
      cwd: process.cwd(),
      title: process.title,
      argv: process.argv,
      execArgv: process.execArgv,
      memoryUsage: {
        rss: formatBytes(process.memoryUsage().rss),
        heapTotal: formatBytes(process.memoryUsage().heapTotal),
        heapUsed: formatBytes(process.memoryUsage().heapUsed),
        external: formatBytes(process.memoryUsage().external),
        arrayBuffers: formatBytes(process.memoryUsage().arrayBuffers),
      },
      uptime: `${process.uptime().toFixed(2)} seconds`,
    },

    // Environment Variables (ALL)
    environment: allEnv,

    // Container Info
    container: {
      isDocker: !!containerId,
      containerId: containerId || "N/A",
    },

    // Constants
    constants: process.constants,

    // Additional System Info
    system: {
      cpuPriority: (() => {
        try {
          return process.getpriority ? process.getpriority() : "N/A";
        } catch (e) {
          return "N/A";
        }
      })(),
      devNull: os.devNull,
      availableParallelism: os.availableParallelism ? os.availableParallelism() : cpus.length,
    },
  };
}

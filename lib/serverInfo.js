// lib/serverInfo.js
import os from "os";
import { execSync } from "child_process";

// Helper function to check if an IP is private
function isPrivateIP(ip) {
  // IPv4 private ranges:
  // 10.0.0.0 – 10.255.255.255
  // 172.16.0.0 – 172.31.255.255
  // 192.168.0.0 – 192.168.255.255
  // 127.0.0.0 – 127.255.255.255 (loopback)
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false; // Not IPv4
  
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 127) return true;
  
  return false;
}

// Helper function to fetch real external IP
async function fetchExternalIP() {
  const services = [
    'https://api.ipify.org?format=json',
    'https://api.my-ip.io/ip.json',
    'https://ipapi.co/json/',
  ];
  
  for (const service of services) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000); // 3 second timeout
      
      const response = await fetch(service, { 
        signal: controller.signal,
        headers: { 'User-Agent': 'Node.js Server Info' }
      });
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const data = await response.json();
        // Different services return IP in different fields
        return data.ip || data.IP || data.query || null;
      }
    } catch (error) {
      // Try next service
      continue;
    }
  }
  
  return null;
}

// Helper function to safely execute commands
function safeExec(command) {
  try {
    return execSync(command, { encoding: 'utf8', timeout: 2000 }).trim();
  } catch (error) {
    return null;
  }
}

// Helper function to safely read files
function safeReadFile(filePath) {
  try {
    return execSync(`cat ${filePath}`, { encoding: 'utf8', timeout: 1000 }).trim();
  } catch (error) {
    return null;
  }
}

// Detect cloud provider via metadata endpoints and system info
async function detectHostingProvider() {
  const detection = {
    provider: 'Unknown',
    confidence: 'low',
    indicators: [],
    metadata: {},
  };

  // Check environment variables for common provider patterns
  const env = process.env;
  
  // Railway detection
  if (env.RAILWAY_ENVIRONMENT || env.RAILWAY_PROJECT_ID) {
    detection.provider = 'Railway';
    detection.confidence = 'high';
    detection.indicators.push('RAILWAY_* environment variables');
    detection.metadata.projectId = env.RAILWAY_PROJECT_ID;
    detection.metadata.environment = env.RAILWAY_ENVIRONMENT;
    return detection;
  }
  
  // Vercel detection
  if (env.VERCEL || env.VERCEL_ENV) {
    detection.provider = 'Vercel';
    detection.confidence = 'high';
    detection.indicators.push('VERCEL environment variables');
    detection.metadata.env = env.VERCEL_ENV;
    detection.metadata.region = env.VERCEL_REGION;
    return detection;
  }
  
  // Netlify detection
  if (env.NETLIFY) {
    detection.provider = 'Netlify';
    detection.confidence = 'high';
    detection.indicators.push('NETLIFY environment variable');
    return detection;
  }
  
  // Heroku detection
  if (env.DYNO) {
    detection.provider = 'Heroku';
    detection.confidence = 'high';
    detection.indicators.push('DYNO environment variable');
    return detection;
  }
  
  // Render detection
  if (env.RENDER) {
    detection.provider = 'Render';
    detection.confidence = 'high';
    detection.indicators.push('RENDER environment variable');
    return detection;
  }

  // Try cloud provider metadata endpoints (only for major cloud providers)
  const metadataChecks = [
    {
      name: 'AWS',
      url: 'http://169.254.169.254/latest/meta-data/instance-id',
      headers: {},
    },
    {
      name: 'Google Cloud',
      url: 'http://metadata.google.internal/computeMetadata/v1/instance/id',
      headers: { 'Metadata-Flavor': 'Google' },
    },
    {
      name: 'Azure',
      url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
      headers: { 'Metadata': 'true' },
    },
    {
      name: 'DigitalOcean',
      url: 'http://169.254.169.254/metadata/v1/id',
      headers: {},
    },
  ];

  for (const check of metadataChecks) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1000); // 1 second timeout
      
      const response = await fetch(check.url, {
        signal: controller.signal,
        headers: check.headers,
      });
      clearTimeout(timeoutId);
      
      if (response.ok) {
        detection.provider = check.name;
        detection.confidence = 'high';
        detection.indicators.push(`Metadata endpoint responded: ${check.url}`);
        try {
          const text = await response.text();
          detection.metadata.instanceId = text.substring(0, 100);
        } catch {}
        return detection;
      }
    } catch (error) {
      // Continue to next check
    }
  }

  // Check DMI/SMBIOS information (requires root or specific permissions)
  const dmiChecks = [
    { file: '/sys/class/dmi/id/product_name', key: 'productName' },
    { file: '/sys/class/dmi/id/sys_vendor', key: 'vendor' },
    { file: '/sys/class/dmi/id/chassis_vendor', key: 'chassisVendor' },
    { file: '/sys/class/dmi/id/bios_vendor', key: 'biosVendor' },
  ];

  const dmiInfo = {};
  for (const check of dmiChecks) {
    const value = safeReadFile(check.file);
    if (value) {
      dmiInfo[check.key] = value;
    }
  }

  if (Object.keys(dmiInfo).length > 0) {
    detection.metadata.hardware = dmiInfo;
    
    const allValues = Object.values(dmiInfo).join(' ').toLowerCase();
    
    // Check for known providers in DMI info
    if (allValues.includes('amazon') || allValues.includes('aws')) {
      detection.provider = 'AWS';
      detection.confidence = 'high';
      detection.indicators.push('DMI/SMBIOS info contains AWS/Amazon');
    } else if (allValues.includes('google')) {
      detection.provider = 'Google Cloud';
      detection.confidence = 'high';
      detection.indicators.push('DMI/SMBIOS info contains Google');
    } else if (allValues.includes('microsoft') || allValues.includes('azure')) {
      detection.provider = 'Azure';
      detection.confidence = 'high';
      detection.indicators.push('DMI/SMBIOS info contains Microsoft/Azure');
    } else if (allValues.includes('digitalocean')) {
      detection.provider = 'DigitalOcean';
      detection.confidence = 'high';
      detection.indicators.push('DMI/SMBIOS info contains DigitalOcean');
    } else if (allValues.includes('hetzner')) {
      detection.provider = 'Hetzner';
      detection.confidence = 'high';
      detection.indicators.push('DMI/SMBIOS info contains Hetzner');
    } else if (allValues.includes('ovh')) {
      detection.provider = 'OVH';
      detection.confidence = 'high';
      detection.indicators.push('DMI/SMBIOS info contains OVH');
    } else if (allValues.includes('linode')) {
      detection.provider = 'Linode';
      detection.confidence = 'high';
      detection.indicators.push('DMI/SMBIOS info contains Linode');
    } else {
      detection.confidence = 'medium';
      detection.indicators.push('DMI/SMBIOS info available but no known provider detected');
    }
  }

  // Check for virtualization type
  const virtType = safeExec('systemd-detect-virt 2>/dev/null') || 
                   safeExec('virt-what 2>/dev/null');
  if (virtType && virtType !== 'none') {
    detection.metadata.virtualization = virtType;
    detection.indicators.push(`Virtualization: ${virtType}`);
  }

  // Check CPU info for hypervisor flags
  const cpuInfo = safeReadFile('/proc/cpuinfo');
  if (cpuInfo) {
    if (cpuInfo.includes('hypervisor')) {
      detection.indicators.push('CPU has hypervisor flag (running in VM)');
    }
    // Extract hypervisor vendor if available
    const hvMatch = cpuInfo.match(/hypervisor.*:\s*(.+)/i);
    if (hvMatch) {
      detection.metadata.hypervisor = hvMatch[1].trim();
    }
  }

  // Check hostname patterns
  const hostname = os.hostname();
  if (hostname.includes('railway')) {
    detection.provider = 'Railway';
    detection.confidence = 'medium';
    detection.indicators.push('Hostname contains "railway"');
  } else if (hostname.includes('vercel')) {
    detection.provider = 'Vercel';
    detection.confidence = 'medium';
    detection.indicators.push('Hostname contains "vercel"');
  } else if (hostname.match(/^ip-\d+-\d+-\d+-\d+/)) {
    detection.provider = 'AWS';
    detection.confidence = 'medium';
    detection.indicators.push('Hostname matches AWS pattern (ip-xxx-xxx-xxx-xxx)');
  }

  // Check for docker/kubernetes environment
  const cgroupContent = safeReadFile('/proc/1/cgroup');
  if (cgroupContent) {
    if (cgroupContent.includes('docker')) {
      detection.metadata.containerRuntime = 'Docker';
      detection.indicators.push('Running in Docker container');
    } else if (cgroupContent.includes('kubepods')) {
      detection.metadata.containerRuntime = 'Kubernetes';
      detection.indicators.push('Running in Kubernetes pod');
    }
  }

  // If we still don't know, check for common containerization
  if (detection.provider === 'Unknown') {
    if (safeReadFile('/.dockerenv')) {
      detection.metadata.containerRuntime = 'Docker';
      detection.indicators.push('Docker environment detected (/.dockerenv exists)');
    }
  }

  return detection;
}

export async function getServerInfo() {
  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memUsagePercent = ((usedMem / totalMem) * 100).toFixed(2);

  // Get all network interfaces with detailed info
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
      // Collect all IPs
      if (iface.family === "IPv4") {
        if (iface.internal) {
          internalIPv4.push(iface.address);
        } else if (isPrivateIP(iface.address)) {
          privateIPv4.push(iface.address);
        } else {
          publicIPv4.push(iface.address);
        }
      } else if (iface.family === "IPv6") {
        if (iface.internal) {
          internalIPv6.push(iface.address);
        } else {
          // For now, treat non-internal IPv6 as private unless it's a global unicast
          const addr = iface.address.toLowerCase();
          if (addr.startsWith('fe80') || addr.startsWith('fc') || addr.startsWith('fd')) {
            privateIPv6.push(iface.address);
          } else {
            publicIPv6.push(iface.address);
          }
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
  
  // Try to fetch the real external/public IP from internet services
  let realExternalIP = null;
  try {
    realExternalIP = await fetchExternalIP();
  } catch (error) {
    // Failed to fetch external IP
  }
  
  // Detect hosting provider
  const hostingProvider = await detectHostingProvider();

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
      realExternalIP: realExternalIP || "Unable to fetch (might be containerized/firewalled)",
      publicIPv4,
      publicIPv6,
      privateIPv4,
      privateIPv6,
      internalIPv4,
      internalIPv6,
      allIPs: [...publicIPv4, ...publicIPv6, ...privateIPv4, ...privateIPv6, ...internalIPv4, ...internalIPv6],
      hostname: os.hostname(),
      networkInterfaceCount: Object.keys(networkInfo).length,
      note: "realExternalIP is fetched from external service. privateIPv4/v6 are non-routable IPs (10.x, 172.16-31.x, 192.168.x, Docker networks, etc.)",
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

    // Hosting Provider Detection
    hostingProvider,

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

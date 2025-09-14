#!/usr/bin/env python3
import asyncio
import subprocess
import sys
import logging
import re
import json
import os
from concurrent.futures import ThreadPoolExecutor
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("ultimate-complete-security")

mcp = FastMCP("Ultimate Complete Security Scanner")

MAX_WORKERS = 100
MIN_TIMEOUT = 6000  
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)


async def runCmdAsync(command: str, timeout: int = 6000) -> str:
    """
    Run a shell command asynchronously and stream stdout/stderr lines to logger as they arrive.
    Returns the combined stdout + stderr (stderr appended after a 'STDERR:' marker).
    Enforces MIN_TIMEOUT for non-nmap commands unless a larger timeout is provided.
    """
    cmd_lower = command.lower()
    if 'nmap' not in cmd_lower and timeout < MIN_TIMEOUT:
        timeout = MIN_TIMEOUT

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout_lines = []
        stderr_lines = []

        async def read_stream(stream, collector, label):
            try:
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    text = line.decode(errors="replace").rstrip("\n")
                    logger.info("CMD_STREAM %s %s", label, text)
                    collector.append(text)
            except asyncio.CancelledError:
                return

        stdout_task = asyncio.create_task(read_stream(proc.stdout, stdout_lines, "STDOUT"))
        stderr_task = asyncio.create_task(read_stream(proc.stderr, stderr_lines, "STDERR"))

        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            stdout_task.cancel()
            stderr_task.cancel()
            logger.info("CMD_STREAM_TIMEOUT %s", command)
            return "Command timed out"

        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

        combined = "\n".join(stdout_lines)
        if stderr_lines:
            combined += "\nSTDERR:\n" + "\n".join(stderr_lines)

        logger.info("CMD_FINISHED %s\n%s", command, combined)

        if proc.returncode == 0:
            return combined
        else:
            return f"Error (rc={proc.returncode}): {combined}"
    except Exception as e:
        logger.info("CMD_EXCEPTION %s %s", command, str(e))
        return f"Error: {str(e)}"


def runCommandSync(command: str, timeout: int = 6000) -> str:
    """
    Synchronous fallback runner (kept for tools that use blocking Popen/communicate).
    """
    if 'nmap' not in command.lower() and timeout < MIN_TIMEOUT:
        timeout = MIN_TIMEOUT
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        combined = stdout + ("\nSTDERR:\n" + stderr if stderr else "")
        logger.info("CMD_OUTPUT %s\n%s", command, combined)
        if result.returncode == 0:
            return combined
        else:
            return f"Error (rc={result.returncode}): {combined}"
    except subprocess.TimeoutExpired:
        logger.info("CMD_TIMEOUT %s", command)
        return "Command timed out"
    except Exception as e:
        logger.info("CMD_EXCEPTION %s %s", command, str(e))
        return f"Error: {str(e)}"


def parseNmapOutput(output: str) -> dict:
    lines = output.split("\n")
    hosts = []
    ports = []
    services = []
    vulnerabilities = []

    for line in lines:
        if 'nmap scan report for' in line.lower():
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                hosts.append(ip_match.group(1))
        elif '/tcp' in line and 'open' in line:
            port_match = re.search(r'(\d+)/tcp', line)
            if port_match:
                ports.append(port_match.group(1))
        elif 'open' in line and ('tcp' in line or 'udp' in line):
            services.append(line.strip())
        elif 'vulnerable' in line.lower() or 'cve' in line.upper() or 'vulnerability' in line.lower():
            vulnerabilities.append(line.strip())

    return {
        'hosts': hosts,
        'ports': ports,
        'services': services,
        'vulnerabilities': vulnerabilities
    }


@mcp.tool()
async def networkDiscovery(target: str = "192.168.1.0/24") -> str:
    command = f"nmap -sn {target}"
    result = await runCmdAsync(command, timeout=1200)
    parsed = parseNmapOutput(result)
    if parsed['hosts']:
        return "Found {0} live hosts on {1}:\n".format(len(parsed['hosts']), target) + "\n".join(f"- {h}" for h in parsed['hosts'])
    return f"No live hosts found on {target}\n{result}"

@mcp.tool()
async def portScan(target: str = "127.0.0.1", ports: str = "1-1000") -> str:
    command = f"nmap -p {ports} -sV -sC {target}"
    result = await runCmdAsync(command, timeout=3000)
    parsed = parseNmapOutput(result)
    if parsed['ports']:
        return f"Open ports on {target}: {', '.join(parsed['ports'])}\n{result}"
    return f"No open ports found on {target}\n{result}"

@mcp.tool()
async def fastPortScan(target: str = "192.168.1.0/24", ports: str = "80,443,22,21,25,53") -> str:
    command = f"masscan -p{ports} {target} --rate=1000"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if "discovered open port" in result.lower() or "open" in result.lower():
        return f"masscan found open ports on {target}:\n{result}"
    return f"masscan scan completed for {target}\n{result}"

@mcp.tool()
async def zmapScan(target: str = "192.168.1.0/24", port: str = "80") -> str:
    command = f"zmap -p {port} {target} -o-"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if result.strip():
        return f"zmap found hosts with port {port} open:\n{result}"
    return f"zmap scan completed for {target} on port {port}\n{result}"

@mcp.tool()
async def osDetection(target: str = "127.0.0.1") -> str:
    command = f"nmap -O {target}"
    result = await runCmdAsync(command, timeout=1200)
    os_info = []
    for line in result.split("\n"):
        if 'os details' in line.lower() or 'running' in line.lower() or 'os cpe' in line.lower():
            os_info.append(line.strip())
    if os_info:
        return "OS Detection for {0}:\n".format(target) + "\n".join(f"- {info}" for info in os_info)
    return f"OS detection completed for {target}\n{result}"


@mcp.tool()
async def vulnerabilityScan(target: str = "127.0.0.1") -> str:
    command = f"nmap --script vuln {target}"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    parsed = parseNmapOutput(result)
    if parsed['vulnerabilities']:
        return "Vulnerabilities found on {0}:\n".format(target) + "\n".join(f"- {v}" for v in parsed['vulnerabilities'][:10])
    return f"No obvious vulnerabilities found on {target}\n{result}"

@mcp.tool()
async def securityScan(target: str = "127.0.0.1") -> str:
    command = f"nmap --script safe,security {target}"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    return f"Security scan results for {target}:\n{result}"

@mcp.tool()
async def malwareScan(target: str = "127.0.0.1") -> str:
    command = f"nmap --script malware {target}"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if "malware" in result.lower() or "backdoor" in result.lower():
        return f"Potential malware found on {target}:\n{result}"
    return f"No malware detected on {target}\n{result}"

@mcp.tool()
async def exploitScan(target: str = "127.0.0.1") -> str:
    command = f"nmap --script exploit {target}"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if "exploit" in result.lower() or "cve" in result.lower():
        return f"Potential exploits found on {target}:\n{result}"
    return f"No exploits found on {target}\n{result}"

@mcp.tool()
async def intrusiveScan(target: str = "127.0.0.1") -> str:
    command = f"nmap --script intrusive {target}"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    return f"Intrusive scan results for {target}:\n{result}"


@mcp.tool()
async def webScan(target: str = "127.0.0.1") -> str:
    port_result = await runCmdAsync(f"nmap -p 80,443,8080,8443 {target}", timeout=1200)
    web_ports = []
    for line in port_result.split("\n"):
        if '/tcp' in line and 'open' in line:
            m = re.search(r'(\d+)/tcp', line)
            if m:
                web_ports.append(m.group(1))
    if not web_ports:
        return f"No web ports (80,443,8080,8443) open on {target}"
    web_result = await runCmdAsync(f"nmap --script http-* {target}", timeout=MIN_TIMEOUT)
    return f"Web scan results for {target}:\nOpen web ports: {', '.join(web_ports)}\n\n{web_result}"

@mcp.tool()
async def sslScan(target: str = "127.0.0.1", port: str = "443") -> str:
    command = f"nmap --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-ccs-injection {target} -p {port}"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    return f"SSL scan results for {target}:{port}:\n{result}"

@mcp.tool()
async def sslscanScan(target: str = "127.0.0.1:443") -> str:
    command = f"sslscan {target}"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if "vulnerable" in result.lower() or "weak" in result.lower():
        return f"sslscan found SSL issues on {target}:\n{result}"
    return f"sslscan completed for {target}\n{result}"

@mcp.tool()
async def opensslTest(target: str = "127.0.0.1", port: str = "443") -> str:
    command = f"echo | openssl s_client -connect {target}:{port} -servername {target}"
    result = await runCmdAsync(command, timeout=1200)
    if "verify return code" in result.lower():
        return f"OpenSSL connection test for {target}:{port}:\n{result}"
    return f"OpenSSL connection failed for {target}:{port}\n{result}"

@mcp.tool()
async def cameraScan(target: str = "192.168.1.0/24") -> str:
    camera_ports = "80,443,554,8080,8443,1935,8554"
    command = f"nmap -p {camera_ports} --script rtsp-url-brute,http-title {target}"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    cameras = []
    for line in result.split("\n"):
        if any(k in line.lower() for k in ['camera', 'rtsp', 'stream', 'webcam', 'dvr', 'nvr', 'axis', 'hikvision', 'dahua']):
            cameras.append(line.strip())
    if cameras:
        return f"Potential cameras found on {target}:\n" + "\n".join(f"- {c}" for c in cameras)
    return f"Camera scan completed for {target}\n{result}"

@mcp.tool()
async def printerScan(target: str = "192.168.1.0/24") -> str:
    printer_ports = "80,443,631,9100,515,721-731"
    command = f"nmap -p {printer_ports} --script printer-info,http-title {target}"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    printers = []
    for line in result.split("\n"):
        if any(k in line.lower() for k in ['printer', 'ipp', 'cups', 'hp', 'canon', 'epson', 'brother', 'xerox']):
            printers.append(line.strip())
    if printers:
        return f"Potential printers found on {target}:\n" + "\n".join(f"- {p}" for p in printers)
    return f"Printer scan completed for {target}\n{result}"

@mcp.tool()
async def routerScan(target: str = "192.168.1.0/24") -> str:
    command = f"nmap -p 23,80,443,8080,8443,161,162 --script routeros-brute,http-title,snmp-info {target}"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    routers = []
    for line in result.split("\n"):
        if any(k in line.lower() for k in ['router', 'gateway', 'cisco', 'netgear', 'linksys', 'tp-link', 'd-link', 'asus', 'belkin', 'switch', 'snmp']):
            routers.append(line.strip())
    if routers:
        return f"Potential network devices found on {target}:\n" + "\n".join(f"- {r}" for r in routers)
    return f"Router scan completed for {target}\n{result}"

@mcp.tool()
async def iotScan(target: str = "192.168.1.0/24") -> str:
    iot_ports = "80,443,8080,8443,1883,8883,5683,1900,5353,49152-65535"
    command = f"nmap -p {iot_ports} --script http-title,upnp-info,mdns-service-discovery {target}"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    iot_devices = []
    for line in result.split("\n"):
        if any(k in line.lower() for k in ['iot', 'smart', 'home', 'hue', 'nest', 'alexa', 'echo', 'upnp', 'mqtt', 'coap', 'zigbee', 'zwave']):
            iot_devices.append(line.strip())
    if iot_devices:
        return f"Potential IoT devices found on {target}:\n" + "\n".join(f"- {d}" for d in iot_devices)
    return f"IoT scan completed for {target}\n{result}"

@mcp.tool()
async def rtspScan(target: str = "192.168.1.100") -> str:
    command = f"nmap -p 554 --script rtsp-url-brute {target}"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if "rtsp://" in result.lower():
        return f"RTSP streams found on {target}:\n{result}"
    return f"RTSP scan completed for {target}\n{result}"

@mcp.tool()
async def onvifScan(target: str = "192.168.1.100") -> str:
    command = f"nmap -p 80,443 --script http-onvif-info {target}"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if "onvif" in result.lower():
        return f"ONVIF services found on {target}:\n{result}"
    return f"ONVIF scan completed for {target}\n{result}"

@mcp.tool()
async def sshBruteForce(target: str = "127.0.0.1", user: str = "root") -> str:
    command = f"hydra -l {user} -P /usr/share/wordlists/rockyou.txt ssh://{target}"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if "login:" in result and "password:" in result:
        return f"hydra found valid SSH credentials on {target}:\n{result}"
    return f"hydra SSH test completed for {target}\n{result}"

@mcp.tool()
async def ftpBruteForce(target: str = "127.0.0.1", user: str = "admin") -> str:
    command = f"hydra -l {user} -P /usr/share/wordlists/rockyou.txt ftp://{target}"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if "login:" in result and "password:" in result:
        return f"hydra found valid FTP credentials on {target}:\n{result}"
    return f"hydra FTP test completed for {target}\n{result}"

@mcp.tool()
async def httpBruteForce(target: str = "http://127.0.0.1/login", user: str = "admin") -> str:
    command = f"hydra -l {user} -P /usr/share/wordlists/rockyou.txt {target} http-post-form '/login:username=^USER^&password=^PASS^:Invalid'"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if "login:" in result and "password:" in result:
        return f"hydra found valid HTTP credentials on {target}:\n{result}"
    return f"hydra HTTP test completed for {target}\n{result}"

@mcp.tool()
async def medusaSshScan(target: str = "127.0.0.1") -> str:
    command = f"medusa -h {target} -u root -P /usr/share/wordlists/rockyou.txt -M ssh"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if "success" in result.lower():
        return f"medusa found valid SSH credentials on {target}:\n{result}"
    return f"medusa SSH test completed for {target}\n{result}"

@mcp.tool()
async def medusaFtpScan(target: str = "127.0.0.1") -> str:
    command = f"medusa -h {target} -u admin -P /usr/share/wordlists/rockyou.txt -M ftp"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if "success" in result.lower():
        return f"medusa found valid FTP credentials on {target}:\n{result}"
    return f"medusa FTP test completed for {target}\n{result}"

@mcp.tool()
async def dirbScan(target: str = "http://127.0.0.1") -> str:
    command = f"dirb {target} /usr/share/wordlists/dirb/common.txt"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    low = result.lower()
    if "code:200" in low or "code:301" in low or "code:302" in low:
        return f"dirb found directories on {target}:\n{result}"
    return f"dirb scan completed for {target}\n{result}"

@mcp.tool()
async def gobusterScan(target: str = "http://127.0.0.1") -> str:
    command = f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    low = result.lower()
    if "status: 200" in low or "status: 301" in low or "status: 302" in low:
        return f"gobuster found directories on {target}:\n{result}"
    return f"gobuster scan completed for {target}\n{result}"

@mcp.tool()
async def smbScan(target: str = "127.0.0.1") -> str:
    command = f"smbclient -L //{target} -N"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if "sharename" in result.lower():
        return f"SMB shares found on {target}:\n{result}"
    return f"SMB scan completed for {target}\n{result}"

@mcp.tool()
async def snmpScan(target: str = "127.0.0.1") -> str:
    command = f"snmpwalk -c public -v2c {target}"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if "snmpv2" in result.lower():
        return f"SNMP information for {target}:\n{result}"
    return f"SNMP scan completed for {target}\n{result}"

@mcp.tool()
async def ldapScan(target: str = "127.0.0.1") -> str:
    command = f"ldapsearch -x -H ldap://{target} -b '' -s base"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if "dn:" in result:
        return f"LDAP information for {target}:\n{result}"
    return f"LDAP scan completed for {target}\n{result}"


@mcp.tool()
async def aircrackScan(interface: str = "wlan0") -> str:
    command = f"airmon-ng start {interface} && airodump-ng {interface}mon --write scan --output-format csv"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if "bssid" in result.lower():
        return f"aircrack found wireless networks:\n{result}"
    return f"aircrack scan completed on {interface}\n{result}"

@mcp.tool()
async def bettercapScan(target: str = "192.168.1.0/24") -> str:
    command = "bettercap -eval 'net.probe on; net.recon on; sleep 10; net.show'"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    if "192.168" in result:
        return f"bettercap discovered hosts on {target}:\n{result}"
    return f"bettercap scan completed for {target}\n{result}"

@mcp.tool()
async def lynisAudit(target: str = "127.0.0.1") -> str:
    command = "lynis audit system --quiet"
    result = await runCmdAsync(command, timeout=MIN_TIMEOUT)
    low = result.lower()
    if "warning" in low or "suggestion" in low:
        return f"lynis found security issues:\n{result}"
    return f"lynis audit completed\n{result}"


@mcp.tool()
async def ultimateSecurityAudit(target: str = "192.168.1.0/24") -> str:
    results = []
    discovery_result = await runCmdAsync(f"nmap -sn {target}", timeout=120)
    parsed_discovery = parseNmapOutput(discovery_result)
    if parsed_discovery['hosts']:
        results.append(f"Found {len(parsed_discovery['hosts'])} live hosts")
    else:
        results.append("No live hosts found")
        return "\n".join(results)

    hosts = parsed_discovery['hosts'][:5]

    async def scanHost(h):
        host_res = [f"-- Host: {h} --"]
        tasks = [
            runCmdAsync(f"nmap -F {h}", timeout=1800),
            runCmdAsync(f"nmap -sV {h}", timeout=3000),
            runCmdAsync(f"nmap --script vuln {h}", timeout=MIN_TIMEOUT),
            runCmdAsync(f"nmap --script ssl-* {h}", timeout=MIN_TIMEOUT),
            runCmdAsync(f"nmap --script http-* {h}", timeout=MIN_TIMEOUT),
        ]
        port_r, serv_r, vuln_r, ssl_r, web_r = await asyncio.gather(*tasks, return_exceptions=True)

        p_parsed = parseNmapOutput(port_r if isinstance(port_r, str) else str(port_r))
        if p_parsed['ports']:
            host_res.append(f"Open ports: {', '.join(p_parsed['ports'])}")
        else:
            host_res.append("No open ports found")

        s_parsed = parseNmapOutput(serv_r if isinstance(serv_r, str) else str(serv_r))
        if s_parsed['services']:
            host_res.append("Services detected:")
            host_res.extend(s_parsed['services'][:5])

        v_parsed = parseNmapOutput(vuln_r if isinstance(vuln_r, str) else str(vuln_r))
        if v_parsed['vulnerabilities']:
            host_res.append(f"Vulnerabilities: {len(v_parsed['vulnerabilities'])}")

        if isinstance(ssl_r, str) and "vulnerable" in ssl_r.lower():
            host_res.append("SSL issues detected")
        if isinstance(web_r, str) and "vulnerable" in web_r.lower():
            host_res.append("Web vulnerabilities detected")

        return "\n".join(host_res)

    host_tasks = [scanHost(h) for h in hosts]
    host_scan_results = await asyncio.gather(*host_tasks, return_exceptions=True)
    for r in host_scan_results:
        results.append(str(r))

    device_result = await runCmdAsync(f"nmap --script http-title {target}", timeout=MIN_TIMEOUT)
    device_lines = device_result.split("\n")
    device_types = {
        'cameras': [line for line in device_lines if any(k in line.lower() for k in ['camera', 'rtsp', 'stream'])],
        'printers': [line for line in device_lines if any(k in line.lower() for k in ['printer', 'ipp', 'cups'])],
        'routers': [line for line in device_lines if any(k in line.lower() for k in ['router', 'gateway', 'cisco'])],
        'iot': [line for line in device_lines if any(k in line.lower() for k in ['iot', 'smart', 'upnp'])]
    }
    for device_type, devices in device_types.items():
        if devices:
            results.append(f"{device_type.title()}: {len(devices)} found")
        else:
            results.append(f"{device_type.title()}: None found")
    return "\n".join(results)

@mcp.tool()
async def completeHostScan(target: str = "192.168.1.1") -> str:
    results = []
    results.append(f"COMPLETE Host Scan for {target}\n")
    ping_result = await runCmdAsync(f"nmap -sn {target}", timeout=3000)
    if "host is up" in ping_result.lower() or "nmap scan report for" in ping_result.lower():
        results.append("Host is reachable")
    else:
        results.append("Host is not reachable")
        return "\n".join(results)

    port_result = await runCmdAsync(f"nmap -F {target}", timeout=1200)
    parsed_ports = parseNmapOutput(port_result)
    if parsed_ports['ports']:
        results.append(f"Open ports: {', '.join(parsed_ports['ports'])}")
    else:
        results.append("No open ports found")

    service_result = await runCmdAsync(f"nmap -sV {target}", timeout=1800)
    parsed_services = parseNmapOutput(service_result)
    if parsed_services['services']:
        results.append("Services detected:")
        for service in parsed_services['services'][:5]:
            results.append(f"  - {service}")
    else:
        results.append("No services detected")

    vuln_result = await runCmdAsync(f"nmap --script vuln {target}", timeout=MIN_TIMEOUT)
    parsed_vulns = parseNmapOutput(vuln_result)
    if parsed_vulns['vulnerabilities']:
        results.append(f"Found {len(parsed_vulns['vulnerabilities'])} vulnerabilities")
        for vuln in parsed_vulns['vulnerabilities'][:5]:
            results.append(f"  - {vuln}")
    else:
        results.append("No obvious vulnerabilities found")

    web_result = await runCmdAsync(f"nmap --script http-* {target}", timeout=MIN_TIMEOUT)
    if "vulnerable" in web_result.lower():
        results.append("Web vulnerabilities found")
    else:
        results.append("No web vulnerabilities found")

    ssl_result = await runCmdAsync(f"nmap --script ssl-* {target}", timeout=MIN_TIMEOUT)
    if "vulnerable" in ssl_result.lower():
        results.append("SSL vulnerabilities found")
    else:
        results.append("SSL configuration looks good")

    malware_result = await runCmdAsync(f"nmap --script malware {target}", timeout=MIN_TIMEOUT)
    if "malware" in malware_result.lower():
        results.append("Potential malware detected")
    else:
        results.append("No malware detected")

    return "\n".join(results)


@mcp.tool()
async def cmd(command: str, timeout: int = 6000) -> str:
    """
    Run an arbitrary shell command and stream output (human-friendly).
    """
    result = await runCmdAsync(command, timeout=timeout)
    return f"$ {command}\n\n{result}"

@mcp.tool()
async def directCmd(command: str, timeout: int = 6000) -> str:
    """
    Run a direct command via blocking Popen.communicate and return structured JSON.
    Also logs stdout/stderr.
    """
    try:
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout, stderr = proc.communicate(timeout=max(timeout, MIN_TIMEOUT))
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            logger.info("DIRECT_CMD_TIMEOUT %s", command)
            return json.dumps({"exit_code": proc.returncode, "stdout": stdout, "stderr": stderr, "timeout": True})
        logger.info("DIRECT_CMD_OUTPUT %s\nstdout:\n%s\nstderr:\n%s", command, stdout, stderr)
        return json.dumps({"exit_code": proc.returncode, "stdout": stdout, "stderr": stderr, "timeout": False})
    except Exception as e:
        logger.info("DIRECT_CMD_EXCEPTION %s %s", command, str(e))
        return json.dumps({"exit_code": -1, "stdout": "", "stderr": str(e), "timeout": False})


if __name__ == "__main__":
    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error("Server error: %s", str(e), exc_info=True)
        sys.exit(1)

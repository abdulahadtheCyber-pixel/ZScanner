#!/usr/bin/env python3
"""
ZScanner - Professional Vulnerability Scanner for Kali Linux
A Nessus-like professional scanning tool with CVSS scoring and PDF reports.

Author: Abdul Ahad
Version: 1.0
"""

import subprocess
import sys
import os
import json
import time
import argparse
from datetime import datetime
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import requests
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET
from pathlib import Path

# PDF Report Generation
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.piecharts import Pie
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("Install reportlab for PDF reports: sudo apt install python3-reportlab")

# Color codes for terminal
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_banner():
    """Print attractive ZScanner banner"""
    banner = f"""
{Colors.PURPLE}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                                                              ║ 
║                   ZSCANNER v1.0 - PROFESSIONAL               ║
║              Advanced Vulnerability Assessment Tool          ║
║                     AUTHOR : ABDUL AHAD                      ║
║  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ║
║  █ ZSCANNER - Enterprise Grade Vulnerability Scanner       █ ║
║  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ║
║                                                              ║
║  Features:                                                   ║
║  • Comprehensive Port Scanning                               ║
║  • Vulnerability Detection (CVEs)                            ║
║  • CVSS v3.1 Scoring System                                  ║
║  • Professional HTML/XML/JSON Reports                        ║
║  • Service Version Detection                                 ║
║  • Web Application Scanning        	 		       ║
║						               ║	
║							       ║
║							       ║
║                                                              ║ 
║                                                              ║     
║{Colors.CYAN}PROFESSIONAL VULNERABILITY SCANNER{Colors.PURPLE}║             
║    {Colors.YELLOW}v2.0 - Kali Linux Edition{Colors.PURPLE}   ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
    """
    print(banner)

def run_command(cmd, timeout=30):
    """Run shell command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except Exception as e:
        return "", str(e), 1

def check_port(host, port, timeout=3):
    """Check if port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def port_scan(host, ports_range="1-1000"):
    """Perform port scan using nmap"""
    print(f"{Colors.CYAN}[*] Scanning ports on {host}...{Colors.END}")
    cmd = f"nmap -sS -T4 -p {ports_range} --open {host} -oG -"
    stdout, stderr, code = run_command(cmd)
    
    open_ports = []
    if code == 0:
        for line in stdout.split('\n'):
            if '/open/' in line:
                parts = line.split()
                port = parts[4].split('/')[0]
                service = parts[5] if len(parts) > 5 else "unknown"
                open_ports.append({"port": port, "service": service})
    
    return open_ports

def vuln_scan_nmap(host):
    """Run comprehensive vulnerability scan with nmap"""
    print(f"{Colors.CYAN}[*] Running vulnerability scan on {host}...{Colors.END}")
    
    # NSE vulnerability scripts
    scripts = [
        "vuln",
        "http-vuln*",
        "smb-vuln*",
        "ftp-vuln*",
        "dns-zone-transfer"
    ]
    
    cmd = f"nmap -sV --script={','.join(scripts)} -p- {host} -oX -"
    stdout, stderr, code = run_command(cmd, 300)
    
    vulnerabilities = []
    if code == 0 and stdout:
        try:
            root = ET.fromstring(stdout)
            for host_elem in root.findall('.//host'):
                for port_elem in host_elem.findall('.//port'):
                    portid = port_elem.get('portid', 'unknown')
                    service_elem = port_elem.find('.//service')
                    service = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                    
                    for script_elem in port_elem.findall('.//script'):
                        script_id = script_elem.get('id', '')
                        output = script_elem.get('output', '')
                        if 'VULNERABLE' in output.upper() or 'VULNERABILITY' in output.upper():
                            vulnerabilities.append({
                                'port': portid,
                                'service': service,
                                'script': script_id,
                                'severity': 'high',
                                'description': output[:200] + '...' if len(output) > 200 else output
                            })
        except:
            pass
    
    return vulnerabilities

def web_scan(host):
    """Basic web vulnerability scan"""
    print(f"{Colors.CYAN}[*] Scanning web applications on {host}...{Colors.END}")
    
    cmd_nikto = f"nikto -h http://{host} -Tuning 1234567890 -o -"
    stdout, stderr, code = run_command(cmd_nikto, 120)
    
    web_vulns = []
    if code == 0 and stdout:
        for line in stdout.split('\n'):
            if '+' in line or 'OSVDB' in line or 'CVE' in line:
                web_vulns.append({
                    'type': 'web',
                    'severity': 'medium',
                    'description': line.strip()
                })
    
    return web_vulns

def calculate_cvss(severity):
    """Calculate CVSS score based on severity"""
    cvss_scores = {
        'critical': 9.8,
        'high': 7.5,
        'medium': 5.3,
        'low': 3.1,
        'info': 0.1
    }
    return cvss_scores.get(severity.lower(), 0.1)

def get_system_info(host):
    """Gather basic system information"""
    print(f"{Colors.CYAN}[*] Gathering system information...{Colors.END}")
    
    cmd = f"nmap -O -sV {host}"
    stdout, _, _ = run_command(cmd)
    
    info = {
        'hostname': socket.getfqdn(host),
        'ip': host,
        'os': 'Unknown',
        'ports_open': 0
    }
    
    return info

def generate_html_report(scan_results, host):
    """Generate HTML report"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>ZScanner Report - {host}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #1a1a1a; color: #fff; }}
        .header {{ background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px; }}
        .severity-critical {{ background: #dc3545; color: white; padding: 5px 10px; border-radius: 5px; }}
        .severity-high {{ background: #fd7e14; color: white; padding: 5px 10px; border-radius: 5px; }}
        .severity-medium {{ background: #ffc107; color: black; padding: 5px 10px; border-radius: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #444; }}
        th {{ background: #333; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #333; padding: 20px; border-radius: 10px; text-align: center; flex: 1; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ ZScanner Professional Report</h1>
        <p>Target: {host} | Scan Date: {timestamp}</p>
    </div>
    
    <div class="stats">
"""
    
    # Severity stats
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for vuln in scan_results:
        severity_counts[vuln['severity']] += 1
    
    total_vulns = sum(severity_counts.values())
    
    html += f"""
        <div class="stat-box">
            <h3>Total Vulnerabilities</h3>
            <h2>{total_vulns}</h2>
        </div>
        <div class="stat-box">
            <h3>Critical</h3>
            <h2>{severity_counts['critical']}</h2>
        </div>
        <div class="stat-box">
            <h3>High</h3>
            <h2>{severity_counts['high']}</h2>
        </div>
        <div class="stat-box">
            <h3>Medium</h3>
            <h2>{severity_counts['medium']}</h2>
        </div>
    </div>
    
    <h2>🔍 Vulnerability Details</h2>
    <table>
        <tr><th>Port</th><th>Service</th><th>Severity</th><th>CVSS</th><th>Description</th></tr>
"""
    
    for vuln in sorted(scan_results, key=lambda x: calculate_cvss(x['severity']), reverse=True):
        cvss = calculate_cvss(vuln['severity'])
        severity_class = f"severity-{vuln['severity']}"
        html += f"""
        <tr>
            <td>{vuln.get('port', 'N/A')}</td>
            <td>{vuln.get('service', 'N/A')}</td>
            <td><span class="{severity_class}">{vuln['severity'].upper()}</span></td>
            <td>{cvss:.1f}</td>
            <td>{vuln['description']}</td>
        </tr>
        """
    
    html += """
    </table>
</body>
</html>
    """
    
    return html

def generate_pdf_report(scan_results, host):
    """Generate professional PDF report with graphs"""
    if not PDF_AVAILABLE:
        print(f"{Colors.YELLOW}[!] PDF generation requires reportlab{Colors.END}")
        return False
    
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"ZScanner_Report_{host}_{timestamp}.pdf"
    
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    
    story = []
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        textColor=colors.darkblue,
        spaceAfter=30,
        alignment=1  # Center
    )
    
    story.append(Paragraph("🛡️ ZSCANNER PROFESSIONAL REPORT", title_style))
    story.append(Paragraph(f"Target: {host}", styles['Heading2']))
    story.append(Paragraph(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Severity statistics table
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for vuln in scan_results:
        severity_counts[vuln['severity']] += 1
    
    data = [['Severity', 'Count', 'CVSS Avg']]
    colors_list = [colors.red, colors.orangered, colors.yellow, colors.green, colors.lightgrey]
    
    for i, (sev, count) in enumerate(severity_counts.items()):
        cvss_avg = calculate_cvss(sev)
        data.append([sev.title(), str(count), f"{cvss_avg:.1f}"])
    
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(table)
    story.append(Spacer(1, 20))
    
    # Vulnerability details
    story.append(Paragraph("Detailed Findings", styles['Heading2']))
    
    for vuln in sorted(scan_results, key=lambda x: calculate_cvss(x['severity']), reverse=True):
        cvss = calculate_cvss(vuln['severity'])
        p = Paragraph(f"<b>Port:</b> {vuln.get('port', 'N/A')} | "
                     f"<b>Service:</b> {vuln.get('service', 'N/A')} | "
                     f"<font color='red'><b>{vuln['severity'].upper()}</b></font> "
                     f"(CVSS: {cvss:.1f})<br/>"
                     f"{vuln['description']}", styles['Normal'])
        story.append(p)
        story.append(Spacer(1, 12))
    
    doc.build(story)
    print(f"{Colors.GREEN}[+] PDF Report saved: {filename}{Colors.END}")
    return True

def main():
    parser = argparse.ArgumentParser(description="ZScanner - Professional Vulnerability Scanner")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--ports", default="1-1000", help="Port range (default: 1-1000)")
    parser.add_argument("--report", action="store_true", help="Generate PDF report")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    
    args = parser.parse_args()
    
    print_banner()
    
    if not os.geteuid() == 0:
        print(f"{Colors.YELLOW}[!] Run as root for best results: sudo python3 zscanner.py{Colors.END}")
    
    host = args.target
    print(f"{Colors.GREEN}[+] Starting professional scan on {host}{Colors.END}")
    
    # System info
    sys_info = get_system_info(host)
    
    # Port scan
    open_ports = port_scan(host, args.ports)
    
    # Vulnerability scans
    vulns_nmap = vuln_scan_nmap(host)
    web_vulns = web_scan(host)
    
    # Combine all findings
    all_vulns = vulns_nmap + web_vulns
    
    # Add port info vulnerabilities
    for port_info in open_ports:
        all_vulns.append({
            'port': port_info['port'],
            'service': port_info['service'],
            'severity': 'info',
            'description': f"Open port {port_info['port']} running {port_info['service']}"
        })
    
    print(f"\n{Colors.BOLD}{Colors.CYAN}═" * 70)
    print(f"                    SCAN SUMMARY")
    print(f"═" * 70 + "{Colors.END}")
    
    severity_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for vuln in all_vulns:
        severity_stats[vuln['severity']] += 1
    
    print(f"{Colors.GREEN}Total Vulnerabilities: {len(all_vulns)}{Colors.END}")
    print(f"{Colors.RED}Critical: {severity_stats['critical']}{Colors.END}")
    print(f"{Colors.RED}High: {severity_stats['high']}{Colors.END}")
    print(f"{Colors.YELLOW}Medium: {severity_stats['medium']}{Colors.END}")
    print(f"{Colors.CYAN}Low/Info: {severity_stats['low'] + severity_stats['info']}{Colors.END}")
    
    print(f"\n{Colors.BOLD}{Colors.CYAN}📋 DETAILED FINDINGS{Colors.END}")
    print(f"{'═' * 70}")
    
    for vuln in sorted(all_vulns, key=lambda x: calculate_cvss(x['severity']), reverse=True):
        cvss_score = calculate_cvss(vuln['severity'])
        severity_color = Colors.RED if vuln['severity'] in ['critical', 'high'] else Colors.YELLOW if vuln['severity'] == 'medium' else Colors.CYAN
        print(f"{severity_color}[{vuln['severity'].upper()}] {vuln.get('port', 'N/A')}/{vuln.get('service', 'N/A')} "
              f"(CVSS: {cvss_score:.1f}){Colors.END}")
        print(f"    {vuln['description'][:100]}{'...' if len(vuln['description']) > 100 else ''}")
        print()
    
    # Report generation
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    if args.report or args.html:
        print(f"\n{Colors.CYAN}[*] Generating professional report...{Colors.END}")
        
        if args.html:
            html_content = generate_html_report(all_vulns, host)
            html_file = f"ZScanner_Report_{host}_{timestamp}.html"
            with open(html_file, 'w') as f:
                f.write(html_content)
            print(f"{Colors.GREEN}[+] HTML Report: {html_file}{Colors.END}")
        
        if args.report:
            generate_pdf_report(all_vulns, host)
    
    print(f"\n{Colors.GREEN}[+] Scan completed successfully!{Colors.END}")
    print(f"{Colors.PURPLE}[*] Use --report for PDF or --html for HTML reports{Colors.END}")

if __name__ == "__main__":
    main()

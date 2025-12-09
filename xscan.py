version = "1.0"


class Style:
    violet = "\033[35;1m"
    red = "\u001b[31;1m"
    cyan = "\u001b[36;1m"
    green = "\u001b[32;1m"
    yellow = "\u001b[33;1m"
    fucsia = "\u001b[35;1m"
    gray = "\033[90;1m"
    italic = "\033[3;1m"
    reset = "\u001b[0m"


try:
    import nmap
    import requests
    import json
    import time
    import re
    import sys
    import os
    from typing import Dict, List, Any, Optional
    from datetime import datetime
    from packaging.version import parse as parse_version
except ImportError:
    print(f"{Style.red} Missing modules! Run 'pip install -r requirements.txt'{Style.reset}")
    exit(1)
    

# --- Global Configuration ---
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0" 
USER_AGENT = f'X-Scanner/{version}'
DEFAULT_PORTS = '1-1000' 
OUTPUT_DIR = 'scans'

# --- API Robustness Configuration ---
MAX_RETRIES = 5
API_TIMEOUT = 15 # Timeout for single requests


class Graphic:
    def clear():
            os.system("cls") if os.name == 'nt' else os.system("clear")
            
    def intro(dynamic):
        Graphic.clear()
        logo = [
            Style.red,
            "   __ __     _____ _____ _____ _____ \n",
            "  |  |  |___|   __|     |  _  |   | |\n",
            "  |-   -|___|__   |   --|     | | | |\n",
            "  |__|__|   |_____|_____|__|__|_|___|\n",
            f"  {Style.cyan} by alfanowski     {Style.gray} version: {version}\n",
            Style.reset
        ]
        for i in logo:
            for j in i:
                print(j, end='', flush=True)
                time.sleep(0.01) if dynamic else None
        time.sleep(0.7) if dynamic else None
        print('\n')
        

# --- PHASE 1: SCANNER ---
def run_aggressive_scan(target_input: str) -> Dict[str, Any]:
    nm = nmap.PortScanner()
    # Arguments: SYN Scan, Service Version Detection (sV), OS Detection (O)
    arguments = f'-sS -sV -O -p {DEFAULT_PORTS}'
    Graphic.intro(dynamic=False)
    print(f"{Style.cyan}  [-] Starting scan on {Style.yellow}{target_input}{Style.reset}...")
    try:
        # Check for root permissions for SYN scan on Linux
        if arguments.startswith('-sS') and sys.platform.startswith('linux') and os.geteuid() != 0:
            print(f"{Style.red}  [!!!] WARNING: SYN scan requires root privileges.")
            # Fallback to TCP Connect scan (-sT)
            arguments = arguments.replace('-sS', '-sT')
            print(f"{Style.yellow}  [!] Falling back to TCP Connect Scan (-sT).")
        nm.scan(target_input, arguments=arguments)
    except nmap.PortScannerError as e:
        return {'target': target_input, 'error': f"{Style.red}  Nmap Error. Check permissions or target syntax. Details: {e}"}
    except Exception as e:
        return {'target': target_input, 'error': f"{Style.red}  Generic error during scan: {e}"}
    results = {
        'target': target_input,
        'ports_data': []
    }   
    active_hosts = nm.all_hosts()
    for host in active_hosts:
        host_state = nm[host].state()
        if host_state == 'up':
            host_info = nm[host]           
            for proto in host_info.all_protocols():
                lport = host_info[proto].keys()
                for port in sorted(lport):
                    port_info = host_info[proto][port]                    
                    if port_info['state'] == 'open':                        
                        version_raw = port_info.get('version', '').strip()
                        # Clean version string
                        version_clean = version_raw.split()[0].split('-')[0].split('_')[0] if version_raw else ''                         
                        # Use 'unknown' if product is not detected
                        product = port_info.get('product', 'unknown').strip()                 
                        results['ports_data'].append({
                            'host': host,
                            'port': port,
                            'protocol': proto,
                            'product': product, 
                            'version': version_clean
                        })
        else:
            print(f"{Style.yellow}  [-] Host {host} status: {host_state}. Skipping analysis.")
    print(f"{Style.green}  [+] Scan complete. Found {len(results['ports_data'])} open services on {len(active_hosts)} analyzed host(s).")
    return results


# --- PHASE 2: DATA ACQUISITION (Retry & Timeout) ---
def fetch_vulnerabilities(product: str) -> List[Dict[str, Any]]:    
    params = {'keywordSearch': product, 'resultsPerPage': 50}
    headers = {'User-Agent': USER_AGENT}
    cve_list = []    
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=API_TIMEOUT)            
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data:
                    for entry in data['vulnerabilities']:
                        cve = entry['cve']                        
                        # Safely parse CVSS (V3.1 first, then V2 fallback)
                        score, severity = 0.0, 'UNKNOWN'
                        if 'metrics' in cve:                            
                            # Priority CVSS V3.1
                            if 'cvssMetricV31' in cve['metrics']:
                                metric_data = cve['metrics']['cvssMetricV31'][0].get('cvssData', {}) 
                                score = metric_data.get('baseScore', 0.0)
                                severity = metric_data.get('baseSeverity', 'UNKNOWN')                            
                            # Fallback CVSS V2
                            elif 'cvssMetricV2' in cve['metrics']: 
                                metric_data = cve['metrics']['cvssMetricV2'][0].get('cvssData', {})
                                score = metric_data.get('baseScore', 0.0)
                                severity = metric_data.get('baseSeverity', 'UNKNOWN')    
                        description = cve['descriptions'][0]['value'] if cve.get('descriptions') else 'N/A'                       
                        cve_list.append({
                            'cve_id': cve['id'],
                            'description': description,
                            'cvss_score': float(score),
                            'severity': severity
                        })
                return cve_list
            elif response.status_code in [403, 429]: # Rate Limit/Too Many Requests
                wait_time = 2 ** attempt + 1 # Exponential Backoff
                print(f"{Style.yellow}  [!] NVD Rate Limit (403/429) - Attempt {attempt+1}/{MAX_RETRIES}. Retrying in {wait_time}s.")
                time.sleep(wait_time)           
            else:
                 print(f"{Style.red}  [-] Unhandled NVD API Error: Code {response.status_code}. Exiting search.")
                 return []
        except requests.exceptions.Timeout:
            wait_time = 2 ** attempt + 1
            print(f"{Style.yellow}  [!] Connection Timeout - Attempt {attempt+1}/{MAX_RETRIES}. Retrying in {wait_time}s.")
            time.sleep(wait_time)
        except requests.exceptions.RequestException as e:
            print(f"{Style.red}  [-] Irreversible connection error (DNS/SSL/etc.): {e}")
            return []        
    print(f"{Style.red}  [!!!] Critical Failure: Cannot reach NVD after {MAX_RETRIES} attempts.")
    return []


# --- PHASE 3: PRIORITIZATION (Advanced Semantic Filtering) ---
def prioritize_vulnerabilities(raw_cves: List[Dict], product: str, version: str) -> List[Dict]:
    if not version or not version.strip():
        # Fail-safe: show all high-risk CVEs if version is unknown
        relevant_cves = [c for c in raw_cves if c['cvss_score'] >= 7.0]
        if relevant_cves:
            print(f"{Style.fucsia}  [LOGIC] Unknown version. Showing {len(relevant_cves)} CVEs (CVSS >= 7.0) (High False Positive Propensity).")
        return relevant_cves[:5]
    relevant_cves = []
    target_version_simple = version.split()[0]   
    try:
        parsed_target_version = parse_version(target_version_simple)
    except Exception:
        print(f"{Style.yellow}  [LOGIC] Could not parse target version '{target_version_simple}'. Skipping semantic comparison.")
        return [c for c in raw_cves if c['cvss_score'] >= 9.0][:3] # Show only Critical if parsing fails
    print(f"{Style.cyan}  [LOGIC] Semantic analysis for version: {target_version_simple}")
    for cve in raw_cves:     
        # Filter 1: Must be High/Critical
        if cve['cvss_score'] < 7.0:
            continue      
        description = cve['description'].lower()   
        is_relevant = False
        # Filter 2: Explicit Version Match (Before/Earlier)
        if 'before' in description or 'earlier' in description:
            try:
                # Search for a version number after keywords
                match = re.search(r'(version[s]?|up to|earlier than|through)\s*([\d\.]+)', description) 
                if match:
                    fix_version_str = match.group(2).strip().replace(',', '')
                    parsed_fix_version = parse_version(fix_version_str)
                    
                    if parsed_target_version < parsed_fix_version:
                        is_relevant = True                 
            except Exception:
                 # Error parsing CVE description version. Continue with other filters.
                 pass 
        # Filter 3: Exact Match (If not matched in Filter 2)
        if not is_relevant:
             # Exact match of product and version
            if target_version_simple in description and product.lower() in description:
                is_relevant = True
        if is_relevant:
            relevant_cves.append(cve)
    relevant_cves.sort(key=lambda x: x['cvss_score'], reverse=True)
    return relevant_cves[:5] 


def analyze_scan_data(scan_output: Dict) -> Dict:    
    full_report = {'target': scan_output['target'], 'analyzed_services': []}
    print(f"{Style.yellow}  [***] Starting Dynamic Analysis and Prioritization [***]{Style.reset}")
    for service_data in scan_output.get('ports_data', []):
        host = service_data['host']
        product = service_data['product']
        version = service_data['version']
        port = service_data['port']     
        if product.lower() == 'unknown' and not version:
            print(f"{Style.fucsia}  [-] Host {host} - Port {port}: Unknown Product and Version, skipping CVE analysis.{Style.reset}")
            continue       
        search_term = product if product.lower() != 'unknown' else 'version ' + version
        print(f"\n{Style.green}  [>] Analysis: Host {host} | {search_term} version {version} (Port {port}){Style.reset}")   
        # 1. NVD API Request
        raw_cves = fetch_vulnerabilities(search_term)     
        # 2. Prioritization
        prioritized_cves = prioritize_vulnerabilities(raw_cves, product, version)     
        if prioritized_cves:
            print(f"{Style.green}  [+] Found {len(prioritized_cves)} Prioritized CVEs.{Style.reset}")          
            # OUTPUT FIELDS IN ENGLISH (service details)
            full_report['analyzed_services'].append({
                'host_ip': host,
                'vulnerable_service': f"{product} {version}",
                'port': port,
                'vulnerabilities': prioritized_cves
            })
        else:
            print(f"{Style.cyan}  [-] No relevant or critical CVEs found on Host {host}.{Style.reset}")
    return full_report


def generate_txt_report(final_data: Dict):  
    now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"xscan-report_{now_str}.txt"
    full_path = os.path.join(OUTPUT_DIR, output_filename)
    try:
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)
            print(f"{Style.yellow}  [INFO] Created output directory: '{OUTPUT_DIR}'{Style.reset}")
    except OSError as e:
        print(f"{Style.red}  [FATAL] Cannot create directory '{OUTPUT_DIR}': {e}{Style.reset}")
        full_path = output_filename  
    report_lines = []
    # Header
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_lines.append("=" * 80)
    report_lines.append(f"X-SCAN REPORT | TARGET: {final_data['target']} | DATE: {now}")
    report_lines.append("TOOL DEVELOPED BY ALFANOWSKI")
    report_lines.append("=" * 80)
    report_lines.append("\n")
    # Executive Summary
    report_lines.append("--- EXECUTIVE SUMMARY ---")
    if final_data.get('analyzed_services'):
        count = len(set(s['host_ip'] for s in final_data['analyzed_services']))
        report_lines.append(f"STATUS: High/Critical Risk identified on {count} host(s). IMMEDIATE ACTION REQUIRED.")
    else:
        report_lines.append("STATUS: No critical or high-priority vulnerabilities (CVSS >= 7.0) detected.")
    report_lines.append("-" * 35)
    report_lines.append("\n")
    # Vulnerable Services Sections
    if final_data.get('analyzed_services'):
        current_host = ""
        for service in final_data['analyzed_services']:         
            host = service['host_ip']          
            if host != current_host:
                report_lines.append("\n" + "#" * 21)
                report_lines.append(f"### HOST ANALYZED ### --> {host}")
                report_lines.append("#" * 21)
                current_host = host
            report_lines.append("*" * 80)
            report_lines.append(f"VULNERABLE SERVICE: {service['vulnerable_service']} (Port TCP/{service['port']})")
            report_lines.append("*" * 80)           
            for vuln in service['vulnerabilities']:
                score = vuln['cvss_score']
                severity = vuln['severity']       
                report_lines.append(f"  [CRITICAL FINDING] CVE ID: {vuln['cve_id']} | SEVERITY: {severity} (CVSS: {score})")
                report_lines.append(f"      Description: {vuln['description']}")
                report_lines.append("      --- RECOMMENDED ACTION: Immediate patching by updating the service to a fixed version (consult NVD for exact fix version).")
                report_lines.append("-" * 75)            
            report_lines.append("\n")
    # Footer
    report_lines.append("=" * 133)
    report_lines.append("METHODOLOGY: Aggressive Nmap Scan (sV) + Dynamic NVD API Analysis with Exponential Backoff + Version & CVSS Match Prioritization.")
    report_lines.append("DISCLAIMER: This tool provides a risk assessment based on public data. It does not guarantee the complete absence of vulnerabilities.")
    report_lines.append("=" * 133)
    try:
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_lines))
        print(f"{Style.green}  [+] Report successfully generated: {Style.yellow}{full_path}{Style.reset}")      
    except Exception as e:
        print(f"{Style.red}  [-] Error writing file: {e}{Style.reset}")
    return full_path


def print_report_summary(final_data: Dict, final_report_path: str):  
    Graphic.intro(dynamic=False)  
    print(f"{Style.gray}  ------{Style.cyan} SUMMARY REPORT{Style.gray} ------{Style.reset}")   
    if not final_data.get('analyzed_services'):
        print(f"{Style.cyan}  NO CRITICAL OR RELEVANT VULNERABILITIES FOUND ON TARGET: {final_data['target']}.{Style.reset}")
        return
    for service in final_data['analyzed_services']:
        print(f"\n{Style.yellow}  --- HOST: {service['host_ip']} | VULNERABLE SERVICE: {service['vulnerable_service']} (Port TCP/{service['port']}) ---{Style.reset}")     
        for vuln in service['vulnerabilities']:
            score = vuln['cvss_score']        
            if score >= 9.0:
                score_color = f"{Style.red}  CRITICAL (CVSS > 9.0){Style.reset}"
            elif score >= 7.0:
                score_color = f"{Style.fucsia}  HIGH (CVSS >= 7.0){Style.reset}"
            else:
                score_color = f"{Style.yellow}  MEDIUM (CVSS < 7.0){Style.reset}"
            print(f"  [!!!] {vuln['cve_id']} - {score_color}{Style.reset} - Score: {score}")
            print(f"      - Description: {vuln['description'][:100]}...")
            print(f"      - {Style.red}ACTION: IMMEDIATE PATCHING/SPECIFIC SECURITY MITIGATION.{Style.reset}")
    print("\n")
    print(f"{Style.green}  ANALYSIS COMPLETE. {Style.yellow}Full report saved in {Style.green}{Style.italic}'{final_report_path}'{Style.yellow}.{Style.reset}")
    print("\n")
    print("  Press Enter...")
    input()


# --- CLI INTERFACE ---
def userInput() -> Optional[str]:    
    while True:
        Graphic.intro(dynamic=False)
        print(f"{Style.gray}  ({Style.yellow}1{Style.gray}){Style.reset} Scan Single IP")
        print(f"{Style.gray}  ({Style.yellow}2{Style.gray}){Style.reset} Scan CIDR Network")
        print(f"{Style.gray}  ({Style.red}X{Style.gray}){Style.red} Exit{Style.reset}")
        choice = input(f"\n{Style.green}  >> {Style.reset}").strip().lower()  
        if choice == 'x':
            Graphic.clear()
            exit(0)     
        target = ""      
        if choice == '1':
            while True:
                Graphic.intro(dynamic=False)
                print(f"{Style.gray}  ({Style.yellow}B{Style.gray}){Style.yellow} Back{Style.reset}\n")            
                target = input(f"   Enter target IP {Style.gray}(x.x.x.x){Style.reset}: ").strip()
                if target.lower() == 'b':
                    break
                if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
                    print(f"{Style.red}  [-] Invalid IP format. Try again.{Style.reset}")
                    time.sleep(1)
                    continue
                return target           
        elif choice == '2':
            while True:
                Graphic.intro(dynamic=False)
                print(f"{Style.gray}  ({Style.yellow}B{Style.gray}){Style.yellow} Back{Style.reset}\n")
                target = input(f"   Enter network in CIDR format {Style.gray}(x.x.x.x/y){Style.reset}: ").strip()
                if target.lower() == 'b':
                    break
                if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', target):
                    print(f"{Style.red}  [-] Invalid CIDR network format. Try again.{Style.reset}")
                    time.sleep(1)
                    continue
                return target
            
        

if __name__ == '__main__':
    Graphic.intro(dynamic=True)
    while True:
        target = userInput()       
        if target is None:
            break      
        # 1. Scan 
        scan_results = run_aggressive_scan(target)
        if 'error' in scan_results:
            print(f"{Style.red} [FATAL] Critical error: {scan_results['error']}")
        elif not scan_results['ports_data']:
            print(f"{Style.cyan} [INFO] Scan complete, no open/detected services found on the target/network.")
            print(f"{Style.cyan}        Nothing to analyze.")
        else:
            # 2. Analyze
            assessment_report = analyze_scan_data(scan_results)       
            # 3. Generate TXT Report
            final_report_path = generate_txt_report(assessment_report)
            # 4. Print Summary to console
            print_report_summary(assessment_report, final_report_path)
            
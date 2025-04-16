import logging
import subprocess
import json
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

def detect_technologies(url):
    """Phát hiện công nghệ bằng WhatWeb"""
    try:        
        result = subprocess.check_output(['whatweb', '--log-json=-', url], stderr=subprocess.DEVNULL, timeout=60)
        parsed = json.loads(result.decode())
        if parsed and isinstance(parsed, list):
            plugins = parsed[0].get('plugins', {})
            tech_details = {name: details.get('version', 'unknown') for name, details in plugins.items()}
            logger.info(f"Detected technologies for {url}: {tech_details}")
            return tech_details
        return {}
    except json.JSONDecodeError:
        logger.error(f"Failed to parse WhatWeb output for {url}")
        return {}
    except Exception as e:
        logger.error(f"Error detecting technologies for {url}: {str(e)}")
        return {}

def detect_vulnerabilities(ip, ports=None):
    """Phát hiện lỗ hổng bằng Nmap với script vuln"""
    try:
        cmd = ['nmap', '-sV', '--script', 'vuln', '-T4', '--max-retries', '2', '--host-timeout', '60s', '-oX', '-']
        if ports:
            cmd.extend(['-p', ports])  
        cmd.append(ip)
        
        result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        xml_str = result.decode()
        root = ET.fromstring(xml_str)
        
        vulnerabilities = []
        for host in root.findall('host'):
            for port in host.findall('.//port'):
                port_id = port.get('portid')
                for script in port.findall('.//script'):
                    if script.get('id').startswith('vuln'):
                        vuln_id = script.get('id')
                        output = script.get('output', 'No details')
                        vulnerabilities.append({
                            'port': port_id,
                            'vuln_id': vuln_id,
                            'description': output
                        })
        
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities for {ip}")
        return vulnerabilities
    except ET.ParseError:
        logger.error(f"Failed to parse Nmap XML output for {ip}")
        return []
    except Exception as e:
        logger.error(f"Error detecting vulnerabilities for {ip}: {str(e)}")
        return []
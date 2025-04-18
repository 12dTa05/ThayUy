import logging
import subprocess
import json
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

def detect_technologies(url):
    """Phát hiện công nghệ web với xử lý lỗi cải tiến"""
    try:
        # Thiết lập thời gian chờ và xử lý lỗi tốt hơn
        result = subprocess.check_output(['whatweb', '--log-json=-', url], 
                                         stderr=subprocess.PIPE, timeout=60)
        
        # Xử lý kết quả JSON
        try:
            parsed = json.loads(result.decode('utf-8', errors='ignore'))
            if parsed and isinstance(parsed, list):
                plugins = parsed[0].get('plugins', {})
                tech_details = {}
                
                # Xử lý các đối tượng và chuỗi phiên bản
                for name, details in plugins.items():
                    if isinstance(details, dict) and 'version' in details:
                        if isinstance(details['version'], list):
                            tech_details[name] = ', '.join(details['version'])
                        else:
                            tech_details[name] = str(details['version'])
                    else:
                        tech_details[name] = "unknown"
                
                logger.info(f"Đã phát hiện {len(tech_details)} công nghệ cho {url}")
                return tech_details
            
            # Trường hợp đặc biệt: Kết quả JSON hợp lệ nhưng cấu trúc không mong đợi
            logger.warning(f"Cấu trúc JSON không mong đợi từ WhatWeb cho {url}: {parsed}")
            return detect_technologies_alternative(url)
            
        except json.JSONDecodeError:
            # Thử phân tích định dạng văn bản nếu định dạng JSON thất bại
            logger.warning(f"Không thể phân tích JSON từ WhatWeb cho {url}, chuyển sang định dạng văn bản")
            output_text = result.decode('utf-8', errors='ignore')
            return parse_whatweb_text_output(output_text, url)
    
    except subprocess.TimeoutExpired:
        logger.error(f"WhatWeb timeout cho {url} sau 60 giây")
        return detect_technologies_alternative(url)
        
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode('utf-8', errors='ignore') if e.stderr else ""
        logger.error(f"WhatWeb báo lỗi cho {url}: {stderr}")
        return detect_technologies_alternative(url)
        
    except Exception as e:
        logger.error(f"Lỗi không mong đợi khi phát hiện công nghệ cho {url}: {str(e)}")
        return detect_technologies_alternative(url)

def parse_whatweb_text_output(output, url):
    """Phân tích đầu ra định dạng văn bản từ WhatWeb"""
    technologies = {}
    
    try:
        # Tìm dòng chứa URL của mục tiêu
        target_line = None
        for line in output.splitlines():
            if url in line:
                target_line = line
                break
        
        if not target_line:
            return {}
            
        # Phân tích mẫu: URL [Tech1][Tech2 v1.2.3][Tech3]
        parts = target_line.split('[')
        
        for part in parts[1:]:  # Bỏ qua phần URL
            if ']' in part:
                tech_info = part.split(']')[0].strip()
                
                # Xử lý phiên bản (nếu có)
                if ' ' in tech_info:
                    # Mẫu có thể là "WordPress 5.7.1" hoặc "jQuery v1.12.4"
                    tech_parts = tech_info.split(' ', 1)
                    tech_name = tech_parts[0].strip()
                    version = tech_parts[1].strip()
                    
                    # Loại bỏ 'v' từ phiên bản nếu có
                    if version.startswith('v'):
                        version = version[1:]
                        
                    technologies[tech_name] = version
                else:
                    technologies[tech_info] = "unknown"
        
        return technologies
    except Exception as e:
        logger.error(f"Lỗi khi phân tích định dạng văn bản WhatWeb: {str(e)}")
        return {}

def detect_technologies_alternative(url):
    """Phương pháp thay thế để phát hiện công nghệ web khi WhatWeb thất bại"""
    technologies = {}
    
    try:
        # Sử dụng requests để phân tích header và nội dung trang
        response = requests.get(url, timeout=10, verify=False, 
                               headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        headers = response.headers
        content = response.text.lower()
        
        # Phát hiện từ header
        if 'Server' in headers:
            server = headers['Server']
            technologies['Server'] = server
            
            # Phân tích phiên bản Apache, Nginx, IIS, v.v.
            if 'apache' in server.lower():
                match = re.search(r'Apache/(\d+\.\d+(\.\d+)?)', server)
                if match:
                    technologies['Apache'] = match.group(1)
            elif 'nginx' in server.lower():
                match = re.search(r'nginx/(\d+\.\d+(\.\d+)?)', server)
                if match:
                    technologies['Nginx'] = match.group(1)
                    
        # Phát hiện ngôn ngữ/framework từ X-Powered-By
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            technologies['X-Powered-By'] = powered_by
            
            if 'php' in powered_by.lower():
                match = re.search(r'PHP/(\d+\.\d+(\.\d+)?)', powered_by)
                if match:
                    technologies['PHP'] = match.group(1)
            elif 'asp.net' in powered_by.lower():
                technologies['ASP.NET'] = powered_by.replace('ASP.NET', '').strip()
        
        # Phát hiện JavaScript frameworks
        js_frameworks = {
            'jquery': r'jquery[.-](\d+\.\d+(\.\d+)?)',
            'bootstrap': r'bootstrap[.-](\d+\.\d+(\.\d+)?)',
            'react': r'react[.-](\d+\.\d+(\.\d+)?)',
            'vue': r'vue[.-](\d+\.\d+(\.\d+)?)',
            'angular': r'angular[.-](\d+\.\d+(\.\d+)?)'
        }
        
        for framework, pattern in js_frameworks.items():
            if framework in content:
                technologies[framework.capitalize()] = "detected"
                match = re.search(pattern, content)
                if match:
                    technologies[framework.capitalize()] = match.group(1)
        
        # Phát hiện CMS
        cms_patterns = {
            'wordpress': ['wp-content', 'wp-includes', 'wp-admin'],
            'joomla': ['com_content', 'com_users', 'joomla'],
            'drupal': ['drupal.js', 'drupal.min.js', 'drupal'],
            'magento': ['mage/', 'magento', 'Mage.'],
            'shopify': ['shopify', 'Shopify.']
        }
        
        for cms, indicators in cms_patterns.items():
            if any(indicator in content for indicator in indicators):
                technologies[cms.capitalize()] = "detected"
        
        logger.info(f"Phát hiện {len(technologies)} công nghệ cho {url} bằng phương pháp thay thế")
        return technologies
        
    except Exception as e:
        logger.error(f"Lỗi khi sử dụng phương pháp thay thế: {str(e)}")
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
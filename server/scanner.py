import os
import socket
import whois
import dns.resolver
import nmap
import re
import ftplib
import json
import time
import logging
import concurrent.futures
import ssl
import base64 
import urllib3
import requests

from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from bson import ObjectId
from cpe import CPE

from http_client import RequestsWithRetry
from cvss_calculator import CVSSCalculator
from utils import detect_technologies, detect_vulnerabilities

logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    def __init__(self, target):
        self.target = target
        self.ip_address = None
        self.hostname = None
        self.open_ports = []
        self.services = {}
        self.vulnerabilities = []
        self.whois_info = None
        self.dns_records = {}
        self.headers = {}
        self.technologies = []
        self.nvd_api_key = os.environ.get("NVD_API_KEY", "48ef6a3e-2945-48e3-8377-84b8a53d865c")
        
        # Khởi tạo cache
        self._nvd_cache = {}
        
        # Khởi tạo session với retry
        self.requests = RequestsWithRetry()
        
        # MongoDB setup
        self.mongo_uri = os.environ.get("MONGO_URI", "mongodb+srv://Death:DeathA_1205@death.8wudq.mongodb.net/ThayUy?retryWrites=true&w=majority&appName=Death")
        self.db_name = os.environ.get("MONGO_DB", "ThayUy")
        self.collection_name = os.environ.get("MONGO_COLLECTION", "scan_reports")
        self.mongo_client = None
        self.db = None
        self.collection = None
        self._connect_mongo()
        
        # Xử lý target
        if self._is_url(target):
            parsed = urlparse(target)
            self.hostname = parsed.netloc or target
            try:
                self.ip_address = socket.gethostbyname(self.hostname)
                logger.info(f"Đã phân giải tên miền {self.hostname} thành IP {self.ip_address}")
            except socket.gaierror as e:
                logger.error(f"Lỗi phân giải tên miền: {str(e)}")
                raise Exception(f"Không thể phân giải tên miền {self.hostname}")
        else:
            # Kiểm tra xem target có phải là IP không
            try:
                socket.inet_aton(target)
                self.ip_address = target
                try:
                    self.hostname = socket.gethostbyaddr(self.ip_address)[0]
                    logger.info(f"Đã phân giải IP {self.ip_address} thành hostname {self.hostname}")
                except socket.herror:
                    self.hostname = self.ip_address
                    logger.info(f"Không thể phân giải hostname cho IP {self.ip_address}, sử dụng IP làm hostname")
            except socket.error:
                # Nếu không phải IP, giả định là tên miền thuần
                self.hostname = target
                try:
                    self.ip_address = socket.gethostbyname(self.hostname)
                    logger.info(f"Đã phân giải tên miền {self.hostname} thành IP {self.ip_address}")
                except socket.gaierror as e:
                    logger.error(f"Lỗi phân giải tên miền: {str(e)}")
                    raise Exception(f"Target {target} không hợp lệ - không phải IP hoặc tên miền hợp lệ")
                    
    def _is_url(self, target):
        return target.startswith(('http://', 'https://'))
    
    def _connect_mongo(self):
        max_retries = 2
        retry_delay = 1
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Kết nối đến MongoDB (lần {attempt+1}/{max_retries})...")
                self.mongo_client = MongoClient(self.mongo_uri, serverSelectionTimeoutMS=5000)
                self.db = self.mongo_client[self.db_name]
                self.collection = self.db[self.collection_name]
                
                # Kiểm tra kết nối
                self.mongo_client.admin.command('ping')
                logger.info("Kết nối MongoDB thành công")
                return
                
            except ConnectionFailure as e:
                logger.error(f"Không thể kết nối MongoDB: {str(e)}")
                if attempt < max_retries - 1:
                    wait_time = retry_delay * (2 ** attempt)
                    logger.info(f"Thử lại sau {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    logger.critical("Không thể kết nối MongoDB sau nhiều lần thử")
                    raise
    
    def gather_basic_info(self): 
        logger.info(f"Thu thập thông tin cơ bản về {self.target}")
        
        # Lấy WHOIS nếu có hostname
        if self.hostname and self.hostname != self.ip_address:
            try:
                self.whois_info = whois.whois(self.hostname)
                logger.info(f"Thông tin WHOIS: Đã thu thập")
            except Exception as e:
                logger.error(f"Không thể lấy thông tin WHOIS: {str(e)}")
        
        # Lấy DNS records
        if self.hostname and self.hostname != self.ip_address:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.hostname, record_type)
                    self.dns_records[record_type] = [str(answer) for answer in answers]
                    logger.info(f"DNS {record_type} records: Đã thu thập")
                except Exception as e:
                    logger.debug(f"Không tìm thấy DNS record {record_type}: {str(e)}")
        
        # Lấy HTTP headers nếu là web server
        if self._is_url(self.target):
            try:
                response = self.requests.get(self.target, timeout=10)
                self.headers = dict(response.headers)
                logger.info(f"HTTP Headers: Đã thu thập")
                
                # Thu thập thông tin về công nghệ từ HTTP headers
                self._detect_technologies(response)
            except Exception as e:
                logger.error(f"Không thể lấy HTTP headers: {str(e)}")

    # def _detect_technologies(self, response=None):  
    #     url = f"https://{self.hostname}" if 443 in self.open_ports else f"http://{self.hostname}"
    #     tech_dict = detect_technologies(url)
    #     self.technologies = [{'name': name, 'version': version} for name, version in tech_dict.items()]

    def _detect_technologies(self, response=None):
        """Phát hiện công nghệ web với khả năng chịu lỗi tốt hơn"""
        url = f"https://{self.hostname}" if 443 in self.open_ports else f"http://{self.hostname}"
        
        try:
            # Thử phương pháp WhatWeb trước
            tech_dict = detect_technologies(url)
            
            # Nếu không tìm thấy công nghệ, thử phương pháp thay thế
            if not tech_dict:
                logger.warning(f"Không phát hiện được công nghệ bằng WhatWeb cho {url}, thử phương pháp thay thế")
                tech_dict = detect_technologies_alternative(url)
            
            # Chuyển đổi kết quả thành định dạng mong muốn
            self.technologies = [{'name': name, 'version': version} for name, version in tech_dict.items()]
            
            # Ghi nhật ký kết quả
            if self.technologies:
                logger.info(f"Đã phát hiện {len(self.technologies)} công nghệ cho {url}")
            else:
                logger.warning(f"Không phát hiện được công nghệ nào cho {url}")
                
        except Exception as e:
            logger.error(f"Lỗi không mong đợi trong _detect_technologies: {str(e)}")
            self.technologies = []
    
    def scan_ports(self, ports=None): #quét cổng mở
        logger.info(f"Bắt đầu quét cổng trên {self.ip_address}")
        
        # Nếu không có danh sách ports, quét 1000 cổng phổ biến
        if not ports:
            ports = range(1, 1001)
        
        nm = nmap.PortScanner()
        
        try:
            ports_str = ','.join(map(str, ports))
            # logger.info(f"Quét các cổng: {ports_str}")
            
            nm.scan(self.ip_address, ports_str, arguments='-sS -sV -T4')
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    lport = sorted(nm[host][proto].keys())
                    for port in lport:
                        if nm[host][proto][port]['state'] == 'open':
                            self.open_ports.append(port)
                            service_name = nm[host][proto][port]['name']
                            product = nm[host][proto][port].get('product', '')
                            version = nm[host][proto][port].get('version', '')
                            service_version = f"{product} {version}".strip()
                            
                            self.services[port] = {
                                'name': service_name,
                                'version': service_version,
                                'product': product,
                                'protocol': proto
                            }
                            
                            logger.info(f"Cổng {port}/{proto} mở: {service_name} ({service_version})")
            
            logger.info(f"Tìm thấy {len(self.open_ports)} cổng mở")
            
        except Exception as e:
            logger.error(f"Lỗi khi quét cổng: {str(e)}")
            logger.warning("Hãy đảm bảo bạn có quyền root/admin để chạy quét SYN")
            
            # Fallback sang quét TCP thông thường
            logger.info("Chuyển sang phương pháp quét TCP thông thường...")
            self._fallback_port_scan(ports)
    
    def _fallback_port_scan(self, ports): #sử dụng socket
        found_ports = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(100, len(ports))) as executor:
            futures = {executor.submit(self._check_port, port): port for port in ports}
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    is_open, service = future.result()
                    if is_open:
                        found_ports += 1
                        self.open_ports.append(port)
                        self.services[port] = {'name': service, 'version': 'Không xác định', 'protocol': 'tcp'}
                        logger.info(f"Cổng {port}/tcp mở: {service}")
                except Exception as e:
                    logger.error(f"Lỗi khi kiểm tra cổng {port}: {str(e)}")
        
        logger.info(f"Tìm thấy {found_ports} cổng mở")
    
    def _check_port(self, port): #quét cổng mở with socket
        common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 115: 'SFTP', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            8080: 'HTTP-Proxy', 27017: 'MongoDB', 6379: 'Redis', 9200: 'Elasticsearch'
        }
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((self.ip_address, port))
        service = common_services.get(port, 'Không xác định')
        sock.close()
        
        return (result == 0, service)
    
    def enumerate_services(self): #lấy thông tin dịch vụ đang chạy
        logger.info("Liệt kê thông tin chi tiết về các dịch vụ...")
        
        for port, service_info in list(self.services.items()):
            service_name = service_info['name']
            
            # HTTP/HTTPS Service detection
            if service_name in ['http', 'https'] or port in [80, 443, 8080, 8443]:
                protocol = 'https' if port == 443 or port == 8443 else 'http'
                url = f"{protocol}://{self.hostname}:{port}"
                if self.hostname == self.ip_address:
                    url = f"{protocol}://{self.ip_address}:{port}"
                
                try:
                    response = self.requests.get(url, timeout=10)
                    server = response.headers.get('Server', 'Không xác định')
                    self.services[port]['server'] = server
                    self.services[port]['status_code'] = response.status_code
                    logger.info(f"Web server trên cổng {port}: {server} (Status: {response.status_code})")
                    
                    # Kiểm tra các đường dẫn phổ biến
                    self._check_common_paths(url)
                            
                except Exception as e:
                    logger.error(f"Không thể kết nối đến web server trên cổng {port}: {str(e)}")
            
            # FTP 
            elif service_name == 'ftp' or port == 21:
                self._check_ftp_service(port)
            
            # SSH 
            elif service_name == 'ssh' or port == 22:
                self._check_ssh_service(port)
            
            # SMTP 
            elif service_name == 'smtp' or port == 25:
                self._check_smtp_service(port)
            
            # Database 
            elif service_name in ['mysql', 'postgresql', 'mongodb'] or port in [3306, 5432, 27017]:
                self._check_database_service(port, service_name)
    
    def _check_common_paths(self, base_url): #kiểm tra vài đường dẫn phổ biến
        common_paths = [
            '/robots.txt', 
            '/sitemap.xml', 
            '/admin', 
            '/login', 
            '/.git/HEAD',
            '/wp-login.php',
            '/wp-admin',
            '/administrator',
            '/phpmyadmin',
            '/server-status'
        ]
        
        for path in common_paths:
            try:
                path_url = f"{base_url}{path}"
                path_response = self.requests.get(path_url, timeout=10)
                if path_response.status_code == 200:
                    content = path_response.text.lower()
                    if path == '/robots.txt' and 'user-agent' not in content:
                        continue
                    elif path == '/sitemap.xml' and '<urlset' not in content:
                        continue
                    elif path in ['/wp-login.php', '/wp-admin'] and 'wordpress' not in content:
                        continue
                    elif path == '/phpmyadmin' and 'phpmyadmin' not in content:
                        continue
                    elif path == '/server-status' and 'server status' not in content:
                        continue
                    logger.info(f"Đường dẫn tồn tại: {path_url} (Status: 200)")
                elif path_response.status_code != 404:
                    logger.debug(f"Đường dẫn {path_url} trả về mã trạng thái: {path_response.status_code}")
            except Exception as e:
                logger.debug(f"Lỗi khi kiểm tra đường dẫn {path_url}: {str(e)}")
    
    def _check_ftp_service(self, port): #FTP
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((self.ip_address, port))
                banner = s.recv(1024).decode('utf-8', errors='ignore')
                self.services[port]['banner'] = banner.strip()
                logger.info(f"FTP Banner: {banner.strip()}")
                
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(self.ip_address, port)
                    ftp.login('anonymous', 'anonymous@domain.com')
                    logger.warning(f"CẢNH BÁO: FTP cho phép truy cập ẩn danh!")
                    
                    # Tính toán CVSS và mức độ nghiêm trọng
                    cvss_calc = CVSSCalculator()
                    cvss_calc.set_from_vulnerability_type('FTP-ANONYMOUS')
                    cvss_score = cvss_calc.calculate_base_score()
                    severity = cvss_calc.get_severity()
                    vector = cvss_calc.get_vector_string()
                    
                    # Thêm vào vulnerabilities
                    vuln_info = {
                        'port': port,
                        'service': 'ftp',
                        'id': 'FTP-ANONYMOUS',
                        'severity': severity,
                        'description': 'FTP server cho phép đăng nhập ẩn danh',
                        'cvss_score': cvss_score,
                        'cvss_vector': vector,
                        'published': datetime.now().isoformat()
                    }
                    self.vulnerabilities.append(vuln_info)
                    
                    ftp.quit()
                except ftplib.all_errors as e:
                    logger.info(f"FTP không cho phép truy cập ẩn danh: {str(e)}")
        except Exception as e:
            logger.error(f"Không thể lấy thông tin FTP: {str(e)}")
    
    def _check_ssh_service(self, port): #SSH
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((self.ip_address, port))
                banner = s.recv(1024).decode('utf-8', errors='ignore')
                self.services[port]['banner'] = banner.strip()
                logger.info(f"SSH Banner: {banner.strip()}")
                
                # Phân tích phiên bản SSH
                ssh_version_match = re.search(r'SSH-\d+\.\d+-([^\s]+)', banner)
                if ssh_version_match:
                    ssh_version = ssh_version_match.group(1)
                    self.services[port]['version'] = ssh_version
                    logger.info(f"SSH Version: {ssh_version}")
        except Exception as e:
            logger.error(f"Không thể lấy thông tin SSH: {str(e)}")
    
    def _check_smtp_service(self, port): #SMTP
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((self.ip_address, port))
                banner = s.recv(1024).decode('utf-8', errors='ignore')
                self.services[port]['banner'] = banner.strip()
                logger.info(f"SMTP Banner: {banner.strip()}")
        except Exception as e:
            logger.error(f"Không thể lấy thông tin SMTP: {str(e)}")
    
    def _check_database_service(self, port, service_name):
        """Kiểm tra dịch vụ cơ sở dữ liệu"""
        db_type = service_name
        if port == 3306:
            db_type = 'MySQL'
        elif port == 5432:
            db_type = 'PostgreSQL'
        elif port == 27017:
            db_type = 'MongoDB'
        elif port == 6379:
            db_type = 'Redis'
        elif port == 1521:
            db_type = 'Oracle'
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                result = s.connect_ex((self.ip_address, port))
                if result == 0:
                    logger.info(f"Database {db_type} đang chạy trên cổng {port}")
                    self.services[port]['name'] = db_type.lower()
        except Exception as e:
            logger.error(f"Lỗi khi kiểm tra database {db_type}: {str(e)}")
    
    def _check_web_vulnerabilities(self, base_url, port):
        """Kiểm tra lỗ hổng web trên một URL và cổng cụ thể"""
        logger.info(f"Kiểm tra lỗ hổng web trên {base_url}...")
        
        # Kiểm tra XSS phản xạ đơn giản
        self._check_reflected_xss(base_url, port)
        
        # Kiểm tra lỗi SQL Injection đơn giản
        self._check_sql_injection(base_url, port)
        
        # Kiểm tra thông tin rò rỉ trong HTTP Headers
        self._check_info_disclosure(base_url, port)
        
        # Kiểm tra Directory Listing
        self._check_directory_listing(base_url, port)
        
        # Check for CSRF vulnerabilities
        self._check_for_csrf(base_url, port)
        
        # Check for SSRF vulnerabilities
        self._check_for_ssrf(base_url, port)
        
        # Check for JWT vulnerabilities
        self._check_jwt_vulnerabilities(base_url, port)
        
        # Check for XXE vulnerabilities
        self._check_xxe_vulnerabilities(base_url, port)
        
        # Check for stored XSS
        self._check_stored_xss(base_url, port)

    
    def _check_reflected_xss(self, base_url, port):
        """Kiểm tra lỗ hổng XSS phản xạ"""
        try:
            test_param = {'test': '<script>alert(1)</script>'}
            response = self.requests.get(f"{base_url}/search", params=test_param, timeout=10)
            if '<script>alert(1)</script>' in response.text:
                # Tính toán CVSS và mức độ nghiêm trọng
                cvss_calc = CVSSCalculator()
                cvss_calc.set_from_vulnerability_type('XSS-REFLECTED')
                cvss_score = cvss_calc.calculate_base_score()
                severity = cvss_calc.get_severity()
                vector = cvss_calc.get_vector_string()
                
                vuln = {
                    'port': port,
                    'service': 'Web Application',
                    'id': 'XSS-REFLECTED',
                    'severity': severity,
                    'description': 'Ứng dụng web có thể bị tấn công XSS phản xạ',
                    'cvss_score': cvss_score,
                    'cvss_vector': vector,
                    'published': datetime.now().isoformat(),
                    'url': f"{base_url}/search"
                }
                self.vulnerabilities.append(vuln)
                logger.warning(f"Phát hiện lỗ hổng XSS phản xạ: {base_url}/search (CVSS: {cvss_score}, {severity})")
        except Exception as e:
            logger.debug(f"Kiểm tra XSS không thành công: {str(e)}")
    
    def _check_sql_injection(self, base_url, port): #SQL injection 
        try:
            # Yêu cầu bình thường để so sánh
            normal_param = {'id': '1'}
            normal_response = self.requests.get(f"{base_url}/item", params=normal_param, timeout=10)
            normal_text = normal_response.text.lower()

            # Yêu cầu với payload SQL Injection
            test_param = {'id': "1' OR '1'='1"}
            response = self.requests.get(f"{base_url}/item", params=test_param, timeout=10)
            response_text = response.text.lower()

            # So sánh phản hồi để phát hiện khác biệt đáng kể
            error_keywords = ['sql', 'mysql', 'database', 'query', 'syntax', 'exception']
            if (response.status_code == 200 and normal_response.status_code == 200 and 
                response_text != normal_text and any(keyword in response_text for keyword in error_keywords)):
                
                # Tính toán CVSS và mức độ nghiêm trọng
                cvss_calc = CVSSCalculator()
                cvss_calc.set_from_vulnerability_type('SQL-INJECTION')
                cvss_score = cvss_calc.calculate_base_score()
                severity = cvss_calc.get_severity()
                vector = cvss_calc.get_vector_string()
                
                vuln = {
                    'port': port,
                    'service': 'Web Application',
                    'id': 'SQL-INJECTION',
                    'severity': severity,
                    'description': 'Ứng dụng web có thể bị tấn công SQL Injection',
                    'cvss_score': cvss_score,
                    'cvss_vector': vector,
                    'published': datetime.now().isoformat(),
                    'url': f"{base_url}/item"
                }
                self.vulnerabilities.append(vuln)
                logger.warning(f"Phát hiện lỗ hổng SQL Injection: {base_url}/item (CVSS: {cvss_score}, {severity})")
            else:
                logger.debug(f"Không phát hiện SQL Injection tại {base_url}/item")
        except Exception as e:
            logger.debug(f"Kiểm tra SQL Injection không thành công: {str(e)}")
    
    def _check_info_disclosure(self, base_url, port):#rò rit HTTP header
        try:
            response = self.requests.get(base_url, timeout=10)
            headers = response.headers
            
            if 'X-Powered-By' in headers:
                logger.info(f"Thông tin công nghệ được tiết lộ: {headers['X-Powered-By']}")
            
            if 'Server' in headers and headers['Server'] not in ['nginx', 'Apache']:
                logger.info(f"Thông tin máy chủ chi tiết được tiết lộ: {headers['Server']}")
                
            if 'X-AspNet-Version' in headers:
                # Tính toán CVSS và mức độ nghiêm trọng
                cvss_calc = CVSSCalculator()
                cvss_calc.set_from_vulnerability_type('INFO-DISCLOSURE')
                cvss_score = cvss_calc.calculate_base_score()
                severity = cvss_calc.get_severity()
                vector = cvss_calc.get_vector_string()
                
                vuln = {
                    'port': port,
                    'service': 'Web Application',
                    'id': 'INFO-DISCLOSURE',
                    'severity': severity,
                    'description': f"Phiên bản ASP.NET được tiết lộ: {headers['X-AspNet-Version']}",
                    'cvss_score': cvss_score,
                    'cvss_vector': vector,
                    'published': datetime.now().isoformat(),
                    'url': base_url
                }
                self.vulnerabilities.append(vuln)
                logger.warning(f"Phát hiện rò rỉ thông tin ASP.NET: {headers['X-AspNet-Version']} (CVSS: {cvss_score}, {severity})")
        except Exception as e:
            logger.debug(f"Kiểm tra rò rỉ thông tin không thành công: {str(e)}")
    
    def _check_directory_listing(self, base_url, port): #directory listing 
        directories = ['/images/', '/uploads/', '/backup/', '/admin/', '/includes/', '/temp/']
        for directory in directories:
            try:
                response = self.requests.get(f"{base_url}{directory}", timeout=10)
                if response.status_code == 200:
                    if 'Index of' in response.text or 'Directory Listing' in response.text:
                        # Tính toán CVSS và mức độ nghiêm trọng
                        cvss_calc = CVSSCalculator()
                        cvss_calc.set_from_vulnerability_type('DIR-LISTING')
                        cvss_score = cvss_calc.calculate_base_score()
                        severity = cvss_calc.get_severity()
                        vector = cvss_calc.get_vector_string()
                        
                        vuln = {
                            'port': port,
                            'service': 'Web Server',
                            'id': 'DIR-LISTING',
                            'severity': severity,
                            'description': f"Thư mục {directory} cho phép liệt kê nội dung",
                            'cvss_score': cvss_score,
                            'cvss_vector': vector,
                            'published': datetime.now().isoformat(),
                            'url': f"{base_url}{directory}"
                        }
                        self.vulnerabilities.append(vuln)
                        logger.warning(f"Phát hiện Directory Listing: {base_url}{directory} (CVSS: {cvss_score}, {severity})")
            except Exception as e:
                logger.debug(f"Kiểm tra Directory Listing không thành công cho {directory}: {str(e)}")

    def _check_ssl_tls_security(self, hostname, port):
        """Perform comprehensive SSL/TLS security assessment"""
        logger.info(f"Checking SSL/TLS security configuration on {hostname}:{port}")
        
        try:
            # Check supported versions
            versions = {
                ssl.PROTOCOL_TLSv1: 'TLSv1.0',
                ssl.PROTOCOL_TLSv1_1: 'TLSv1.1',
                ssl.PROTOCOL_TLSv1_2: 'TLSv1.2'
            }
            
            supported_versions = []
            unsupported_versions = []
            
            for version, name in versions.items():
                try:
                    context = ssl.SSLContext(version)
                    with socket.create_connection((hostname, port), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cipher = ssock.cipher()
                            supported_versions.append({
                                'version': name,
                                'cipher': cipher[0],
                                'protocol': cipher[1],
                                'bits': cipher[2]
                            })
                            logger.info(f"Server supports {name} with cipher {cipher[0]}")
                except Exception as e:
                    unsupported_versions.append(name)
                    logger.debug(f"Server does not support {name}: {str(e)}")
            
            # Check for TLSv1.0 or TLSv1.1 (outdated)
            outdated_tls = [v for v in supported_versions if v['version'] in ['TLSv1.0', 'TLSv1.1']]
            if outdated_tls:
                versions_str = ', '.join([v['version'] for v in outdated_tls])
                cvss_calc = CVSSCalculator()
                cvss_calc.set_from_vulnerability_type('TLS-OUTDATED')
                cvss_score = cvss_calc.calculate_base_score()
                severity = cvss_calc.get_severity()
                vector = cvss_calc.get_vector_string()
                
                vuln = {
                    'port': port,
                    'service': 'TLS',
                    'id': 'TLS-OUTDATED-VERSION',
                    'severity': severity,
                    'description': f'Server supports outdated TLS versions: {versions_str}',
                    'cvss_score': cvss_score,
                    'cvss_vector': vector,
                    'published': datetime.now().isoformat(),
                    'remediation': cvss_calc.recommend_mitigation('TLS-OUTDATED')
                }
                self.vulnerabilities.append(vuln)
                logger.warning(f"Server supports outdated TLS versions: {versions_str}")
            
            # Check for weak ciphers
            weak_ciphers = [
                v for v in supported_versions 
                if any(c in v['cipher'].lower() for c in ['null', 'anon', 'export', 'des', 'rc4', 'md5'])
            ]
            
            if weak_ciphers:
                ciphers_str = ', '.join([v['cipher'] for v in weak_ciphers])
                cvss_calc = CVSSCalculator()
                cvss_calc.set_from_vulnerability_type('SSL-WEAK-CIPHER')
                cvss_score = cvss_calc.calculate_base_score()
                severity = cvss_calc.get_severity()
                vector = cvss_calc.get_vector_string()
                
                vuln = {
                    'port': port,
                    'service': 'TLS',
                    'id': 'TLS-WEAK-CIPHER',
                    'severity': severity,
                    'description': f'Server supports weak ciphers: {ciphers_str}',
                    'cvss_score': cvss_score,
                    'cvss_vector': vector,
                    'published': datetime.now().isoformat(),
                    'remediation': cvss_calc.recommend_mitigation('SSL-WEAK-CIPHER')
                }
                self.vulnerabilities.append(vuln)
                logger.warning(f"Server supports weak ciphers: {ciphers_str}")
                
            # Check certificate validity
            try:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Check if certificate is self-signed
                        is_self_signed = cert.get('issuer') == cert.get('subject')
                        if is_self_signed:
                            cvss_calc = CVSSCalculator()
                            cvss_calc.set_from_vulnerability_type('SSL-SELF-SIGNED')
                            cvss_score = cvss_calc.calculate_base_score()
                            severity = cvss_calc.get_severity()
                            vector = cvss_calc.get_vector_string()
                            
                            vuln = {
                                'port': port,
                                'service': 'TLS',
                                'id': 'SSL-SELF-SIGNED',
                                'severity': severity,
                                'description': 'Server uses self-signed certificate',
                                'cvss_score': cvss_score,
                                'cvss_vector': vector,
                                'published': datetime.now().isoformat(),
                                'remediation': cvss_calc.recommend_mitigation('SSL-SELF-SIGNED')
                            }
                            self.vulnerabilities.append(vuln)
                            logger.warning(f"Server uses self-signed certificate")
                        
                        # Check certificate expiration
                        if 'notAfter' in cert:
                            notAfter = ssl.cert_time_to_seconds(cert['notAfter'])
                            current_time = time.time()
                            days_remaining = (notAfter - current_time) / (60*60*24)
                            
                            if days_remaining < 0:
                                cvss_calc = CVSSCalculator()
                                cvss_calc.set_from_vulnerability_type('SSL-EXPIRED-CERT')
                                cvss_score = cvss_calc.calculate_base_score()
                                severity = cvss_calc.get_severity()
                                vector = cvss_calc.get_vector_string()
                                
                                vuln = {
                                    'port': port,
                                    'service': 'TLS',
                                    'id': 'SSL-EXPIRED-CERT',
                                    'severity': severity,
                                    'description': f'Certificate expired {abs(int(days_remaining))} days ago',
                                    'cvss_score': cvss_score,
                                    'cvss_vector': vector,
                                    'published': datetime.now().isoformat(),
                                    'remediation': cvss_calc.recommend_mitigation('SSL-EXPIRED-CERT')
                                }
                                self.vulnerabilities.append(vuln)
                                logger.warning(f"Certificate expired {abs(int(days_remaining))} days ago")
                            elif days_remaining < 30:
                                logger.warning(f"Certificate will expire in {int(days_remaining)} days")
            except Exception as e:
                logger.debug(f"Error checking certificate: {str(e)}")
                
        except Exception as e:
            logger.error(f"Error checking SSL/TLS security: {str(e)}")

    def _check_for_csrf(self, base_url, port):
        """Check for CSRF vulnerabilities on forms"""
        try:
            # First get the form page
            response = self.requests.get(f"{base_url}/login", timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form', method=re.compile('post', re.I))
                
                for form in forms:
                    # Check if there's any CSRF token in the form
                    csrf_fields = form.find_all('input', {'name': re.compile('csrf|token|nonce', re.I)})
                    
                    if not csrf_fields:
                        cvss_calc = CVSSCalculator()
                        cvss_calc.set_from_vulnerability_type('CSRF')
                        cvss_score = cvss_calc.calculate_base_score()
                        severity = cvss_calc.get_severity()
                        vector = cvss_calc.get_vector_string()
                        
                        form_action = form.get('action', '')
                        form_url = f"{base_url}{form_action}" if form_action.startswith('/') else form_action
                        
                        vuln = {
                            'port': port,
                            'service': 'Web Application',
                            'id': 'CSRF-VULNERABILITY',
                            'severity': severity,
                            'description': f'Form at {form_url} lacks CSRF protection',
                            'cvss_score': cvss_score,
                            'cvss_vector': vector,
                            'published': datetime.now().isoformat(),
                            'url': form_url,
                            'remediation': cvss_calc.recommend_mitigation('CSRF')
                        }
                        self.vulnerabilities.append(vuln)
                        logger.warning(f"Potential CSRF vulnerability in form at {form_url}")
        except Exception as e:
            logger.debug(f"Error checking for CSRF: {str(e)}")

    def _check_for_ssrf(self, base_url, port):
        """Check for Server-Side Request Forgery vulnerabilities"""
        ssrf_payloads = [
            f"http://127.0.0.1:{port}/admin",
            f"http://localhost:{port}/internal",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/"  # GCP metadata
        ]
        
        endpoints_to_check = ['/api/fetch', '/proxy', '/load', '/url', '/import', '/export']
        
        for endpoint in endpoints_to_check:
            for payload in ssrf_payloads:
                try:
                    # Try both GET and POST
                    # GET request with parameter
                    params = {'url': payload, 'endpoint': payload, 'site': payload}
                    get_response = self.requests.get(f"{base_url}{endpoint}", params=params, timeout=10)
                    
                    # POST request with JSON body
                    post_response = self.requests.post(
                        f"{base_url}{endpoint}",
                        json={'url': payload, 'endpoint': payload, 'site': payload},
                        timeout=10
                    )
                    
                    for response in [get_response, post_response]:
                        # Look for indicators of successful SSRF
                        if response.status_code == 200 and (
                            ('internal' in response.text.lower()) or 
                            ('metadata' in response.text.lower()) or
                            ('admin' in response.text.lower()) or
                            (len(response.text) > 0 and ('<html' in response.text.lower() or '{' in response.text))
                        ):
                            cvss_calc = CVSSCalculator()
                            cvss_calc.set_from_vulnerability_type('SSRF-VULNERABILITY')
                            cvss_score = cvss_calc.calculate_base_score()
                            severity = cvss_calc.get_severity()
                            vector = cvss_calc.get_vector_string()
                            
                            vuln = {
                                'port': port,
                                'service': 'Web Application',
                                'id': 'SSRF-VULNERABILITY',
                                'severity': severity,
                                'description': f'Potential SSRF vulnerability at {endpoint}',
                                'cvss_score': cvss_score,
                                'cvss_vector': vector,
                                'published': datetime.now().isoformat(),
                                'url': f"{base_url}{endpoint}",
                                'evidence': f"Response contained indicators of internal access",
                                'remediation': cvss_calc.recommend_mitigation('SSRF-VULNERABILITY')
                            }
                            self.vulnerabilities.append(vuln)
                            logger.warning(f"Potential SSRF vulnerability at {base_url}{endpoint}")
                            break  # If we found a vulnerability, no need to check other responses
                except Exception as e:
                    logger.debug(f"SSRF test failed for {endpoint}: {str(e)}")

    def _check_jwt_vulnerabilities(self, base_url, port):
        """Check for JWT token vulnerabilities"""
        jwt_endpoints = ['/api', '/api/user', '/auth', '/token']
        
        for endpoint in jwt_endpoints:
            try:
                # First check if the endpoint might return JWT
                headers = {'Accept': 'application/json'}
                response = self.requests.get(f"{base_url}{endpoint}", headers=headers, timeout=10)
                
                # Check Authorization header and response body for JWT patterns
                auth_header = response.headers.get('Authorization', '')
                if 'Bearer ' in auth_header:
                    jwt_token = auth_header.split(' ')[1]
                    self._analyze_jwt_token(jwt_token, base_url, endpoint, port)
                
                # Check response body for JWT
                if response.headers.get('Content-Type', '').startswith('application/json'):
                    try:
                        json_data = response.json()
                        # Common JWT field names
                        jwt_fields = ['token', 'access_token', 'id_token', 'jwt', 'accessToken', 'idToken']
                        
                        for field in jwt_fields:
                            if field in json_data and isinstance(json_data[field], str):
                                self._analyze_jwt_token(json_data[field], base_url, endpoint, port)
                    except Exception as e:
                        logger.debug(f"Error parsing JSON from {endpoint}: {str(e)}")
            except Exception as e:
                logger.debug(f"Error checking JWT at {endpoint}: {str(e)}")

    def _analyze_jwt_token(self, jwt_token, base_url, endpoint, port):
        """Analyze JWT token for vulnerabilities"""
        try:
            # Check for none algorithm vulnerability
            token_parts = jwt_token.split('.')
            if len(token_parts) != 3:
                return
                
            header_part = token_parts[0]
            padded_header = header_part + '=' * (-len(header_part) % 4)
            
            try:
                decoded_header = json.loads(base64.b64decode(padded_header).decode('utf-8'))
                
                # Check for 'none' algorithm
                if decoded_header.get('alg', '').lower() == 'none':
                    cvss_calc = CVSSCalculator()
                    cvss_calc.set_from_vulnerability_type('JWT-NONE-ALGORITHM')
                    cvss_score = cvss_calc.calculate_base_score()
                    severity = cvss_calc.get_severity()
                    vector = cvss_calc.get_vector_string()
                    
                    vuln = {
                        'port': port,
                        'service': 'Web Application',
                        'id': 'JWT-NONE-ALGORITHM',
                        'severity': severity,
                        'description': 'JWT token uses "none" algorithm which allows token forgery',
                        'cvss_score': cvss_score,
                        'cvss_vector': vector,
                        'published': datetime.now().isoformat(),
                        'url': f"{base_url}{endpoint}",
                        'remediation': cvss_calc.recommend_mitigation('JWT-NONE-ALGORITHM')
                    }
                    self.vulnerabilities.append(vuln)
                    logger.warning(f"JWT vulnerability: None algorithm accepted at {base_url}{endpoint}")
                
                # Check for weak algorithm (HS256 with potential weak key)
                if decoded_header.get('alg') == 'HS256':
                    logger.info(f"JWT token uses HS256 algorithm at {base_url}{endpoint} - potential for weak key")
            except Exception as e:
                logger.debug(f"Error decoding JWT header: {str(e)}")
        except Exception as e:
            logger.debug(f"Error analyzing JWT token: {str(e)}")

    def _check_xxe_vulnerabilities(self, base_url, port):
        """Check for XML External Entity vulnerabilities"""
        xml_endpoints = ['/api/xml', '/upload', '/import', '/process', '/parse']
        
        # XXE payload with external entity
        xxe_payload = '''<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [
        <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
        <foo>&xxe;</foo>'''
        
        for endpoint in xml_endpoints:
            try:
                headers = {'Content-Type': 'application/xml'}
                response = self.requests.post(f"{base_url}{endpoint}", data=xxe_payload, headers=headers, timeout=10)
                
                # Check for indicators of successful XXE
                if response.status_code == 200 and (
                    'root:' in response.text or 
                    'nobody:' in response.text or
                    '/bin/' in response.text
                ):
                    cvss_calc = CVSSCalculator()
                    cvss_calc.set_from_vulnerability_type('XXE-VULNERABILITY')
                    cvss_score = cvss_calc.calculate_base_score()
                    severity = cvss_calc.get_severity()
                    vector = cvss_calc.get_vector_string()
                    
                    vuln = {
                        'port': port,
                        'service': 'Web Application',
                        'id': 'XXE-VULNERABILITY',
                        'severity': severity,
                        'description': f'XXE vulnerability detected at {endpoint}',
                        'cvss_score': cvss_score,
                        'cvss_vector': vector,
                        'published': datetime.now().isoformat(),
                        'url': f"{base_url}{endpoint}",
                        'evidence': 'Response contained sensitive file contents',
                        'remediation': cvss_calc.recommend_mitigation('XXE-VULNERABILITY')
                    }
                    self.vulnerabilities.append(vuln)
                    logger.warning(f"XXE vulnerability detected at {base_url}{endpoint}")
            except Exception as e:
                logger.debug(f"XXE test failed for {endpoint}: {str(e)}")

    def _check_stored_xss(self, base_url, port):
        """Check for stored XSS vulnerabilities"""
        # Common forms that might be vulnerable
        form_endpoints = ['/comment', '/post', '/message', '/feedback', '/review']
        
        xss_payload = '<script>alert(document.domain)</script>'
        
        for endpoint in form_endpoints:
            try:
                # Try to submit the payload
                form_data = {
                    'name': 'Security Tester',
                    'email': 'test@example.com',
                    'message': xss_payload,
                    'content': xss_payload,
                    'comment': xss_payload
                }
                
                post_response = self.requests.post(f"{base_url}{endpoint}", data=form_data, timeout=10)
                
                # Now try to retrieve the page to see if our payload was stored
                get_response = self.requests.get(f"{base_url}{endpoint}", timeout=10)
                
                if xss_payload in get_response.text:
                    cvss_calc = CVSSCalculator()
                    cvss_calc.set_from_vulnerability_type('XSS-STORED')
                    cvss_score = cvss_calc.calculate_base_score()
                    severity = cvss_calc.get_severity()
                    vector = cvss_calc.get_vector_string()
                    
                    vuln = {
                        'port': port,
                        'service': 'Web Application',
                        'id': 'XSS-STORED',
                        'severity': severity,
                        'description': f'Stored XSS vulnerability detected at {endpoint}',
                        'cvss_score': cvss_score,
                        'cvss_vector': vector,
                        'published': datetime.now().isoformat(),
                        'url': f"{base_url}{endpoint}",
                        'evidence': 'XSS payload was stored and reflected in the response',
                        'remediation': cvss_calc.recommend_mitigation('XSS-STORED')
                    }
                    self.vulnerabilities.append(vuln)
                    logger.warning(f"Stored XSS vulnerability detected at {base_url}{endpoint}")
            except Exception as e:
                logger.debug(f"Stored XSS test failed for {endpoint}: {str(e)}")

    
    def query_nvd(self, cpe_string, max_retries=2, retry_delay=1): #NVD API
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
        
        if cpe_string in self._nvd_cache:
            logger.info(f"Sử dụng kết quả cache cho {cpe_string}")
            return self._nvd_cache[cpe_string]
        
        all_vulnerabilities = []
        start_index = 0
        
        while True:
            for attempt in range(max_retries):
                try:
                    params = {
                        "cpeName": cpe_string,
                        "resultsPerPage": 50,
                        "startIndex": start_index
                    }
                    
                    logger.info(f"Truy vấn NVD API: {cpe_string} (startIndex={start_index})")
                    response = self.requests.get(base_url, headers=headers, params=params, timeout=12)
                    
                    if response.status_code == 200:
                        data = response.json()
                        total_results = data.get("totalResults", 0)
                        vulnerabilities = data.get("vulnerabilities", [])
                        all_vulnerabilities.extend(vulnerabilities)
                        
                        logger.info(f"Tìm thấy {len(vulnerabilities)} lỗ hổng cho {cpe_string} (trang {start_index//50 + 1})")
                        
                        if start_index + 50 >= total_results:
                            result = self._process_vulnerabilities(all_vulnerabilities)
                            self._nvd_cache[cpe_string] = result
                            return result
                        
                        start_index += 50
                        break
                        
                    elif response.status_code == 404:
                        logger.info(f"Không tìm thấy lỗ hổng cho {cpe_string} trong NVD")
                        self._nvd_cache[cpe_string] = []
                        return []
                    
                    elif response.status_code == 403:
                        logger.error(f"NVD API key không hợp lệ hoặc vượt giới hạn yêu cầu")
                        if attempt < max_retries - 1:
                            wait_time = retry_delay * (2 ** attempt)
                            logger.info(f"Thử lại sau {wait_time}s...")
                            time.sleep(wait_time)
                        else:
                            return self._process_vulnerabilities(all_vulnerabilities) if all_vulnerabilities else []
                            
                    elif response.status_code == 429:
                        logger.error(f"Vượt quá giới hạn yêu cầu API")
                        if attempt < max_retries - 1:
                            wait_time = retry_delay * (3 ** attempt)
                            logger.info(f"Thử lại sau {wait_time}s...")
                            time.sleep(wait_time)
                        else:
                            return self._process_vulnerabilities(all_vulnerabilities) if all_vulnerabilities else []
                            
                    else:
                        logger.error(f"NVD API trả về lỗi: {response.status_code} - {response.text}")
                        if attempt < max_retries - 1:
                            time.sleep(retry_delay)
                        else:
                            return self._process_vulnerabilities(all_vulnerabilities) if all_vulnerabilities else []
                            
                except Exception as e:
                    logger.error(f"Lỗi khi truy vấn NVD: {str(e)}")
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                    else:
                        return self._process_vulnerabilities(all_vulnerabilities) if all_vulnerabilities else []
        
        return self._process_vulnerabilities(all_vulnerabilities) if all_vulnerabilities else []
    
    def _process_vulnerabilities(self, vulnerabilities): #NVD API
        results = []
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            
            # Lấy thông tin CVSS
            cvss_info = self._get_cvss_info(cve)
            
            # Sử dụng CVSSCalculator để xác định mức độ nghiêm trọng nếu chỉ có điểm số và không có severity
            if cvss_info.get("severity") == "Không xác định" and isinstance(cvss_info.get("score"), (int, float)):
                calculator = CVSSCalculator()
                cvss_info["severity"] = calculator.get_severity(cvss_info["score"])
            
            # Nếu có vector CVSS, phân tích nó để tính toán lại nếu cần
            if cvss_info.get("vector") != "Không xác định" and (
                cvss_info.get("score") == "Không xác định" or 
                cvss_info.get("severity") == "Không xác định"
            ):
                calculator = CVSSCalculator()
                if calculator.set_from_vector_string(cvss_info["vector"]):
                    if cvss_info.get("score") == "Không xác định":
                        cvss_info["score"] = calculator.calculate_base_score()
                    if cvss_info.get("severity") == "Không xác định":
                        cvss_info["severity"] = calculator.get_severity()
            
            # Tìm mô tả
            description = "Không có mô tả"
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "Không có mô tả")
                    break
            
            vuln_info = {
                "id": cve.get("id", "Unknown"),
                "severity": cvss_info.get("severity", "Không xác định"),
                "description": description,
                "published": cve.get("published"),
                "cvss_score": cvss_info.get("score", "Không xác định"),
                "cvss_vector": cvss_info.get("vector", "Không xác định")
            }
            results.append(vuln_info)
        
        return results
    
    def _get_cvss_info(self, cve):
        """Lấy thông tin CVSS từ dữ liệu CVE"""
        if not cve:
            return {"severity": "Không xác định", "score": "Không xác định", "vector": "Không xác định"}
        
        metrics = cve.get("metrics", {})
        if not metrics:
            return {"severity": "Không xác định", "score": "Không xác định", "vector": "Không xác định"}
        
        # Kiểm tra các phiên bản CVSS theo thứ tự ưu tiên
        for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metric_type in metrics:
                try:
                    # Ưu tiên metric "Primary" nếu có
                    primary_metric = next(
                        (m for m in metrics[metric_type] if m.get("type") == "Primary"),
                        metrics[metric_type][0] if metrics[metric_type] else None
                    )
                    
                    if primary_metric:
                        cvss_data = primary_metric.get("cvssData", {})
                        vector_string = primary_metric.get("vectorString", "Không xác định")
                        
                        return {
                            "severity": cvss_data.get("baseSeverity", "Không xác định"),
                            "score": cvss_data.get("baseScore", "Không xác định"),
                            "vector": vector_string
                        }
                except (IndexError, KeyError):
                    continue
        
        return {"severity": "Không xác định", "score": "Không xác định", "vector": "Không xác định"}
    
    def _generate_cpe(self, service_name, version=""): #CPE string
        if not service_name:
            return None
        
        # Dictionary ánh xạ các dịch vụ phổ biến
        service_mapping = {
            'apache': {'vendor': 'apache', 'product': 'http_server'},
            'httpd': {'vendor': 'apache', 'product': 'http_server'},
            'nginx': {'vendor': 'nginx', 'product': 'nginx'},
            'iis': {'vendor': 'microsoft', 'product': 'iis'},
            'lighttpd': {'vendor': 'lighttpd', 'product': 'lighttpd'},
            'caddy': {'vendor': 'caddyserver', 'product': 'caddy'},
            'tomcat': {'vendor': 'apache', 'product': 'tomcat'},
            'jetty': {'vendor': 'eclipse', 'product': 'jetty'},
            'websphere': {'vendor': 'ibm', 'product': 'websphere_application_server'},
            'weblogic': {'vendor': 'oracle', 'product': 'weblogic_server'},
            'openssh': {'vendor': 'openssh', 'product': 'openssh'},
            'ssh': {'vendor': 'openssh', 'product': 'openssh'},
            'mysql': {'vendor': 'mysql', 'product': 'mysql'},
            'mariadb': {'vendor': 'mariadb', 'product': 'mariadb'},
            'postgresql': {'vendor': 'postgresql', 'product': 'postgresql'},
            'mongodb': {'vendor': 'mongodb', 'product': 'mongodb'},
            'redis': {'vendor': 'redis', 'product': 'redis'},
            'wordpress': {'vendor': 'wordpress', 'product': 'wordpress'},
            'drupal': {'vendor': 'drupal', 'product': 'drupal'},
            'joomla': {'vendor': 'joomla', 'product': 'joomla'},
            'django': {'vendor': 'djangoproject', 'product': 'django'},
            'laravel': {'vendor': 'laravel', 'product': 'laravel'},
            'spring': {'vendor': 'pivotal', 'product': 'spring_framework'},
            'proxygen': {'vendor': 'facebook', 'product': 'proxygen'},
            'proxygen-bolt': {'vendor': 'facebook', 'product': 'proxygen'},  # Thêm proxygen-bolt
            'nodejs': {'vendor': 'nodejs', 'product': 'node.js'},
            'php': {'vendor': 'php', 'product': 'php'},
            'openssl': {'vendor': 'openssl', 'product': 'openssl'},
            'jquery': {'vendor': 'jquery', 'product': 'jquery'},
            'bootstrap': {'vendor': 'getbootstrap', 'product': 'bootstrap'},
            'http': {'vendor': 'apache', 'product': 'http_server'},  # Default cho HTTP
            'https': {'vendor': 'apache', 'product': 'http_server'}  # Default cho HTTPS
        }
        
        service_name_lower = service_name.lower()
        vendor = None
        product = None
        
        # Tìm trong service_mapping
        for key, mapping in service_mapping.items():
            if key in service_name_lower:
                vendor = mapping['vendor']
                product = mapping['product']
                break
        
        # Nếu không tìm thấy, sử dụng mặc định
        if not vendor:
            vendor = service_name_lower
            product = service_name_lower
        
        # Xử lý version
        clean_version = "*"
        if version and version != "Không xác định":
            version_clean = version.lower().strip()
            version_match = re.search(r'(\d+(\.\d+)+)', version_clean)
            if version_match:
                clean_version = version_match.group(1)
            else:
                clean_version = version_clean.split()[0] if version_clean.split() else "*"
            clean_version = ''.join(c for c in clean_version if c.isalnum() or c in '.-')
            if not clean_version:
                clean_version = "*"
        
        try:
            cpe = CPE(f"cpe:2.3:a:{vendor}:{product}:{clean_version}")
            cpe_str = cpe.as_uri_2_3()
            if not cpe_str:
                raise ValueError("Invalid CPE generated")
            return cpe_str
        except Exception as e:
            logger.error(f"Lỗi khi tạo CPE: {str(e)}")
            return f"cpe:2.3:a:{vendor}:{product}:{clean_version}"

    def detect_cloud_resources(self):
        """Phát hiện tài nguyên đám mây liên quan đến tên miền mục tiêu"""
        logger.info(f"Kiểm tra tài nguyên đám mây liên quan cho {self.hostname}")
        
        if not self.hostname or self.hostname == self.ip_address:
            return
        
        # Sử dụng khối try/except cho từng phương thức riêng biệt
        # để một lỗi không làm dừng toàn bộ quá trình kiểm tra
        
        try:
            self._check_s3_buckets()
        except Exception as e:
            logger.error(f"Lỗi kiểm tra S3 buckets: {str(e)}")
        
        try:
            self._check_azure_storage()
        except Exception as e:
            logger.error(f"Lỗi kiểm tra Azure storage: {str(e)}")
        
        try:
            self._check_gcp_storage()
        except Exception as e:
            logger.error(f"Lỗi kiểm tra GCP storage: {str(e)}")
        
        try:
            self._check_digital_ocean_spaces()
        except Exception as e:
            logger.error(f"Lỗi kiểm tra Digital Ocean Spaces: {str(e)}")
        
        try:
            self._check_cloudfront_distributions()
        except Exception as e:
            logger.error(f"Lỗi kiểm tra CloudFront distributions: {str(e)}")

    def _check_cloudfront_distributions(self):
        """Kiểm tra các CloudFront distributions liên quan đến tên miền"""
        if not self.hostname or self.hostname == self.ip_address:
            return
        
        # Tạo các mẫu tên miền có thể liên quan đến CloudFront
        possible_domains = [
            self.hostname,
            f"cdn.{self.hostname}",
            f"static.{self.hostname}",
            f"media.{self.hostname}",
            f"assets.{self.hostname}"
        ]
        
        # Thêm tên miền chính nếu đang kiểm tra subdomain
        domain_parts = self.hostname.split('.')
        if len(domain_parts) > 2:
            main_domain = '.'.join(domain_parts[-2:])
            possible_domains.extend([
                main_domain,
                f"cdn.{main_domain}",
                f"static.{main_domain}"
            ])
        
        # Kiểm tra từng tên miền
        for domain in possible_domains:
            try:
                # Kiểm tra nếu tên miền trỏ đến CloudFront
                cloudfront_signs = [".cloudfront.net"]
                
                # Thử lấy CNAME record
                try:
                    answers = dns.resolver.resolve(domain, 'CNAME')
                    for rdata in answers:
                        cname_target = str(rdata.target).rstrip('.')
                        for sign in cloudfront_signs:
                            if sign in cname_target:
                                logger.info(f"Phát hiện CloudFront distribution cho {domain}: {cname_target}")
                                # Kiểm tra phiên bản TLS và thiết lập bảo mật
                                self._check_cloudfront_security(domain, cname_target)
                except dns.resolver.NoAnswer:
                    # Không có CNAME record, thử A record
                    try:
                        answers = dns.resolver.resolve(domain, 'A')
                        # Thực hiện kiểm tra thêm nếu cần
                    except Exception as e:
                        logger.debug(f"Không thể phân giải A record cho {domain}: {str(e)}")
                except Exception as e:
                    logger.debug(f"Không thể kiểm tra CNAME record cho {domain}: {str(e)}")
                    
                # Thực hiện kiểm tra trực tiếp
                try:
                    response = self.requests.get(f"https://{domain}", timeout=10, 
                                                headers={'User-Agent': 'Mozilla/5.0'})
                    
                    # Kiểm tra header đặc trưng của CloudFront
                    headers = response.headers
                    if 'X-Amz-Cf-Id' in headers or 'Via' in headers and 'cloudfront' in headers.get('Via', '').lower():
                        logger.info(f"Phát hiện CloudFront distribution qua HTTP headers cho {domain}")
                        
                        # Kiểm tra thiết lập bảo mật
                        self._check_cloudfront_security(domain, None)
                except Exception as e:
                    logger.debug(f"Không thể kiểm tra HTTP response cho {domain}: {str(e)}")
                    
            except Exception as e:
                logger.debug(f"Lỗi kiểm tra CloudFront cho {domain}: {str(e)}")
    
    def _check_cloudfront_security(self, domain, distribution_domain=None):
        """Kiểm tra cấu hình bảo mật của CloudFront distribution"""
        try:
            # Chuẩn bị URL
            url = f"https://{domain}"
            
            # Kiểm tra HTTP headers liên quan đến bảo mật
            response = self.requests.get(url, timeout=10, 
                                        headers={'User-Agent': 'Mozilla/5.0'})
            
            headers = response.headers
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection'
            ]
            
            # Kiểm tra các header bảo mật còn thiếu
            missing_headers = [h for h in security_headers if h not in headers]
            
            if missing_headers:
                missing_str = ', '.join(missing_headers)
                logger.warning(f"CloudFront distribution cho {domain} thiếu các header bảo mật quan trọng: {missing_str}")
                
                # Đánh giá mức độ nghiêm trọng của vấn đề
                cvss_calc = CVSSCalculator()
                cvss_calc.set_from_vulnerability_type('INFO-DISCLOSURE')  # Có thể tinh chỉnh thêm
                cvss_score = cvss_calc.calculate_base_score()
                severity = cvss_calc.get_severity()
                vector = cvss_calc.get_vector_string()
                
                vuln = {
                    'service': 'CloudFront',
                    'id': 'CLOUDFRONT-MISSING-SECURITY-HEADERS',
                    'severity': severity,
                    'description': f'CloudFront distribution cho {domain} thiếu các header bảo mật: {missing_str}',
                    'cvss_score': cvss_score,
                    'cvss_vector': vector,
                    'published': datetime.now().isoformat(),
                    'url': url,
                    'remediation': 'Cấu hình CloudFront distribution để thêm các header bảo mật thiếu'
                }
                self.vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.debug(f"Lỗi kiểm tra bảo mật CloudFront cho {domain}: {str(e)}")

    # def _create_ssl_context(self, expected_hostname):
    #     """Tạo context SSL với hostname mong đợi cụ thể"""
    #     import ssl
    #     context = ssl.create_default_context()
    #     context.check_hostname = True
    #     context.verify_mode = ssl.CERT_REQUIRED
    
    #     return context

    def _check_cloud_resource(self, url, expected_hostname=None, timeout=5):
        """Hàm trợ giúp kiểm tra tài nguyên đám mây với xử lý SSL tốt hơn"""
        try:
            # Tạo session SSL custom với hostname mong đợi
            session = requests.Session()
            if expected_hostname:
                # Tạo adapter với server_hostname cụ thể
                adapter = requests.adapters.HTTPAdapter()
                session.mount('https://', adapter)
                session.get_adapter('https://').init_poolmanager(
                    connections=1,
                    maxsize=1,
                    block=False,
                    assert_hostname=expected_hostname
                )
            
            response = session.get(url, timeout=timeout)
            return response
        except requests.exceptions.SSLError as e:
            logger.debug(f"Lỗi SSL khi kết nối đến {url}: {str(e)}")
            # Ghi nhật ký nhưng không gây lỗi nghiêm trọng
            return None
        except requests.exceptions.RequestException as e:
            logger.debug(f"Không thể kết nối đến {url}: {str(e)}")
            return None

    def _check_s3_buckets(self):
        """Kiểm tra các S3 buckets liên quan đến tên miền với xử lý lỗi SSL tốt hơn"""
        possible_bucket_names = [
            self.hostname,
            self.hostname.replace('.', '-'),
            f"assets-{self.hostname}",
            f"static-{self.hostname}",
            f"media-{self.hostname}",
            f"data-{self.hostname}",
            f"backup-{self.hostname}",
            f"images-{self.hostname}",
            f"uploads-{self.hostname}"
        ]
        
        domain_parts = self.hostname.split('.')
        if len(domain_parts) > 1:
            # Thêm tên miền chính không có subdomain
            main_domain = '.'.join(domain_parts[-2:])
            possible_bucket_names.extend([
                main_domain,
                main_domain.replace('.', '-'),
                f"assets-{main_domain}",
                f"static-{main_domain}"
            ])
        
        for bucket_name in possible_bucket_names:
            s3_urls = [
                f"https://s3.amazonaws.com/{bucket_name}"  # Ưu tiên URL này trước vì ít có khả năng gặp lỗi SSL
            ]
            
            for url in s3_urls:
                try:
                    # Sử dụng verify=False để bỏ qua lỗi SSL
                    response = self.requests.get(url, timeout=10)
                    
                    # Chỉ xử lý nếu không phải lỗi 404
                    if response.status_code != 404:
                        logger.info(f"Phát hiện S3 bucket tiềm năng: {url} (Status: {response.status_code})")
                        
                        # Kiểm tra quyền bucket
                        try:
                            acl_url = f"{url}?acl"
                            acl_response = self.requests.get(acl_url, timeout=10)
                            if acl_response.status_code == 200:
                                cvss_calc = CVSSCalculator()
                                cvss_calc.set_from_vulnerability_type('S3-PUBLIC-ACL')
                                cvss_score = cvss_calc.calculate_base_score()
                                severity = cvss_calc.get_severity()
                                vector = cvss_calc.get_vector_string()
                                
                                vuln = {
                                    'service': 'Amazon S3',
                                    'id': 'S3-PUBLIC-ACL',
                                    'severity': severity,
                                    'description': f'S3 bucket {bucket_name} cho phép xem ACL công khai',
                                    'cvss_score': cvss_score,
                                    'cvss_vector': vector,
                                    'published': datetime.now().isoformat(),
                                    'url': acl_url,
                                    'remediation': cvss_calc.recommend_mitigation('S3-PUBLIC-ACL')
                                }
                                self.vulnerabilities.append(vuln)
                                logger.warning(f"S3 bucket {bucket_name} cho phép xem ACL công khai")
                        except Exception as e:
                            logger.debug(f"Lỗi kiểm tra ACL bucket cho {bucket_name}: {str(e)}")
                            
                        # Chỉ kiểm tra URL buckets theo định dạng cũ nếu phát hiện được bucket
                        try:
                            alternative_url = f"https://{bucket_name}.s3.amazonaws.com"
                            alt_response = self.requests.get(alternative_url, timeout=10)
                            if alt_response.status_code == 200:
                                logger.info(f"Bucket cũng có thể truy cập qua: {alternative_url}")
                        except Exception as e:
                            logger.debug(f"Không thể truy cập URL thay thế cho bucket {bucket_name}: {str(e)}")
                except Exception as e:
                    logger.debug(f"Lỗi kiểm tra S3 bucket {bucket_name}: {str(e)}")
    
    def _check_azure_storage(self):
        """Check for Azure blob storage associated with the domain"""
        possible_names = [
            self.hostname.split('.')[0],
            self.hostname.replace('.', ''),
            f"{self.hostname.split('.')[0]}storage",
            f"{self.hostname.replace('.', '')}blob"
        ]
        
        for name in possible_names:
            azure_urls = [
                f"https://{name}.blob.core.windows.net",
                f"https://{name}.file.core.windows.net",
                f"https://{name}.table.core.windows.net"
            ]
            
            for url in azure_urls:
                try:
                    response = self.requests.get(url, timeout=10)
                    if response.status_code != 404:
                        logger.info(f"Potential Azure storage found: {url} (Status: {response.status_code})")
                        
                        # Check if we can list containers
                        list_url = f"{url}?comp=list"
                        list_response = self.requests.get(list_url, timeout=10)
                        if list_response.status_code == 200 and ('<Container>' in list_response.text or '<Containers>' in list_response.text):
                            cvss_calc = CVSSCalculator()
                            cvss_calc.set_from_vulnerability_type('AZURE-STORAGE-EXPOSED')
                            cvss_score = cvss_calc.calculate_base_score()
                            severity = cvss_calc.get_severity()
                            vector = cvss_calc.get_vector_string()
                            
                            vuln = {
                                'service': 'Azure Storage',
                                'id': 'AZURE-STORAGE-EXPOSED',
                                'severity': severity,
                                'description': f'Azure storage {name} exposes container listing',
                                'cvss_score': cvss_score,
                                'cvss_vector': vector,
                                'published': datetime.now().isoformat(),
                                'url': list_url,
                                'remediation': cvss_calc.recommend_mitigation('AZURE-STORAGE-EXPOSED')
                            }
                            self.vulnerabilities.append(vuln)
                            logger.warning(f"Azure storage {name} exposes container listing")
                except Exception as e:
                    logger.debug(f"Error checking Azure storage {name}: {str(e)}")

    def _check_gcp_storage(self):
        """Check for Google Cloud Storage buckets with improved SSL handling"""
        possible_names = [
            self.hostname,
            self.hostname.replace('.', '-'),
            f"{self.hostname.split('.')[0]}-storage",
            f"storage-{self.hostname.split('.')[0]}"
        ]
        
        for name in possible_names:
            gcp_urls = [
                f"https://storage.googleapis.com/{name}",  # Ưu tiên URL này vì ít gặp lỗi SSL
                f"https://{name}.storage.googleapis.com"
            ]
            
            for url in gcp_urls:
                try:
                    # Kiểm tra xem URL có định dạng mà có thể gây lỗi SSL không
                    if '.storage.googleapis.com' in url:
                        # Tạo session tùy chỉnh để bỏ qua kiểm tra hostname
                        import ssl
                        from urllib3.poolmanager import PoolManager
                        from requests.adapters import HTTPAdapter
                        
                        class HostNameIgnoringAdapter(HTTPAdapter):
                            def init_poolmanager(self, connections, maxsize, block=False):
                                self.poolmanager = PoolManager(
                                    num_pools=connections,
                                    maxsize=maxsize,
                                    block=block,
                                    ssl_version=ssl.PROTOCOL_TLS,
                                    assert_hostname=False
                                )
                        
                        session = requests.Session()
                        session.mount('https://', HostNameIgnoringAdapter())
                        response = session.get(url, timeout=10, verify=True)
                    else:
                        # URL thông thường, sử dụng requests thông thường
                        response = self.requests.get(url, timeout=10)
                    
                    if response.status_code != 404:
                        logger.info(f"Potential GCP storage bucket found: {url} (Status: {response.status_code})")
                        
                        if response.status_code == 200:
                            cvss_calc = CVSSCalculator()
                            cvss_calc.set_from_vulnerability_type('S3-PUBLIC-ACCESS')  # Reuse S3 scoring
                            cvss_score = cvss_calc.calculate_base_score()
                            severity = cvss_calc.get_severity()
                            vector = cvss_calc.get_vector_string()
                            
                            vuln = {
                                'service': 'Google Cloud Storage',
                                'id': 'GCP-STORAGE-PUBLIC',
                                'severity': severity,
                                'description': f'GCP storage bucket {name} is publicly accessible',
                                'cvss_score': cvss_score,
                                'cvss_vector': vector,
                                'published': datetime.now().isoformat(),
                                'url': url,
                                'remediation': 'Configure proper access controls for Google Cloud Storage buckets'
                            }
                            self.vulnerabilities.append(vuln)
                            logger.warning(f"GCP storage bucket {name} is publicly accessible")
                except requests.exceptions.SSLError as e:
                    # Ghi nhật ký lỗi SSL nhưng không gây lỗi nghiêm trọng
                    logger.debug(f"SSL Error checking GCP storage bucket {name}: {str(e)}")
                except Exception as e:
                    logger.debug(f"Error checking GCP storage bucket {name}: {str(e)}")

    def _check_digital_ocean_spaces(self):
        """Check for Digital Ocean Spaces associated with the domain"""
        possible_names = [
            self.hostname.split('.')[0],
            self.hostname.replace('.', '-'),
            f"{self.hostname.split('.')[0]}-space"
        ]
        
        regions = ['nyc3', 'ams3', 'sfo2', 'sgp1', 'fra1']
        
        for name in possible_names:
            for region in regions:
                do_url = f"https://{name}.{region}.digitaloceanspaces.com"
                try:
                    response = self.requests.get(do_url, timeout=10)
                    if response.status_code != 404:
                        logger.info(f"Potential Digital Ocean Space found: {do_url} (Status: {response.status_code})")
                        
                        if response.status_code == 200:
                            cvss_calc = CVSSCalculator()
                            cvss_calc.set_from_vulnerability_type('S3-PUBLIC-ACCESS')
                            cvss_score = cvss_calc.calculate_base_score()
                            severity = cvss_calc.get_severity()
                            vector = cvss_calc.get_vector_string()
                            
                            vuln = {
                                'service': 'Digital Ocean Spaces',
                                'id': 'DO-SPACE-PUBLIC',
                                'severity': severity,
                                'description': f'Digital Ocean Space {name} in {region} region is publicly accessible',
                                'cvss_score': cvss_score,
                                'cvss_vector': vector,
                                'published': datetime.now().isoformat(),
                                'url': do_url,
                                'remediation': 'Configure proper access controls for Digital Ocean Spaces'
                            }
                            self.vulnerabilities.append(vuln)
                            logger.warning(f"Digital Ocean Space {name} in {region} region is publicly accessible")
                            
                            # Try to check if we can list objects
                            try:
                                list_response = self.requests.get(do_url, timeout=10)
                                if '<Contents>' in list_response.text or '<Key>' in list_response.text:
                                    logger.warning(f"Digital Ocean Space {name} allows listing objects")
                            except Exception as e:
                                logger.debug(f"Error checking Space listing permissions: {str(e)}")
                except Exception as e:
                    logger.debug(f"Error checking Digital Ocean Space {name}.{region}: {str(e)}")

    def _check_container_security(self):
        """Check for container-related security issues"""
        logger.info(f"Checking for container security issues on {self.hostname}")
        
        # Check for exposed Docker API
        docker_ports = [2375, 2376]
        
        for port in docker_ports:
            if port in self.open_ports:
                try:
                    # Check if Docker API is accessible
                    url = f"http://{self.ip_address}:{port}/info"
                    response = self.requests.get(url, timeout=10)
                    
                    if response.status_code == 200 and ("OperatingSystem" in response.text or "DockerRootDir" in response.text):
                        cvss_calc = CVSSCalculator()
                        cvss_calc.set_from_vulnerability_type('DOCKER-EXPOSED-API')
                        cvss_score = cvss_calc.calculate_base_score()
                        severity = cvss_calc.get_severity()
                        vector = cvss_calc.get_vector_string()
                        
                        vuln = {
                            'port': port,
                            'service': 'Docker API',
                            'id': 'DOCKER-EXPOSED-API',
                            'severity': severity,
                            'description': 'Docker API is exposed without authentication',
                            'cvss_score': cvss_score,
                            'cvss_vector': vector,
                            'published': datetime.now().isoformat(),
                            'remediation': cvss_calc.recommend_mitigation('DOCKER-EXPOSED-API')
                        }
                        self.vulnerabilities.append(vuln)
                        logger.warning(f"Docker API is exposed without authentication on port {port}")
                except Exception as e:
                    logger.debug(f"Error checking Docker API on port {port}: {str(e)}")
        
        # Check for exposed Kubernetes API
        k8s_ports = [6443, 8080, 10250]
        
        for port in k8s_ports:
            if port in self.open_ports:
                try:
                    # Check if Kubernetes API is accessible
                    url = f"https://{self.ip_address}:{port}/api"
                    response = self.requests.get(url, timeout=10)
                    
                    if response.status_code == 200 and ("versions" in response.text or "serverAddressByClientCIDRs" in response.text):
                        cvss_calc = CVSSCalculator()
                        cvss_calc.set_from_vulnerability_type('K8S-EXPOSED-API')
                        cvss_score = cvss_calc.calculate_base_score()
                        severity = cvss_calc.get_severity()
                        vector = cvss_calc.get_vector_string()
                        
                        vuln = {
                            'port': port,
                            'service': 'Kubernetes API',
                            'id': 'K8S-EXPOSED-API',
                            'severity': severity,
                            'description': 'Kubernetes API is exposed without proper authentication',
                            'cvss_score': cvss_score,
                            'cvss_vector': vector,
                            'published': datetime.now().isoformat(),
                            'remediation': cvss_calc.recommend_mitigation('K8S-EXPOSED-API')
                        }
                        self.vulnerabilities.append(vuln)
                        logger.warning(f"Kubernetes API is exposed without proper authentication on port {port}")
                        
                        # Try to access more sensitive endpoints
                        sensitive_endpoints = ['/api/v1/pods', '/api/v1/secrets', '/api/v1/namespaces']
                        for endpoint in sensitive_endpoints:
                            try:
                                endpoint_url = f"https://{self.ip_address}:{port}{endpoint}"
                                endpoint_response = self.requests.get(endpoint_url, timeout=10)
                                
                                if endpoint_response.status_code == 200:
                                    logger.warning(f"Kubernetes API endpoint {endpoint} is accessible")
                            except Exception as e:
                                logger.debug(f"Error checking Kubernetes API endpoint {endpoint}: {str(e)}")
                except Exception as e:
                    logger.debug(f"Error checking Kubernetes API on port {port}: {str(e)}")

    def _check_dns_security(self):
        """Check for DNS-related security issues"""
        logger.info(f"Checking for DNS security issues on {self.hostname}")
        
        if not self.hostname or self.hostname == self.ip_address:
            return
        
        # Check for subdomain takeover potential
        self._check_subdomain_takeover()
        
        # Check for zone transfer
        self._check_zone_transfer()
        
        # Check for open DNS resolver
        self._check_open_dns_resolver()

    def _check_subdomain_takeover(self):
        """Check for potential subdomain takeover vulnerabilities"""
        # Generate potential subdomains to check
        common_subdomains = ['www', 'api', 'mail', 'remote', 'blog', 'webmail', 'server', 
                            'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'app', 'test', 'dev', 
                            'staging', 'portal', 'admin']
        
        main_domain_parts = self.hostname.split('.')
        if len(main_domain_parts) > 2:
            # It's already a subdomain, so use it directly
            domains_to_check = [self.hostname]
        else:
            # It's a main domain, so generate subdomains
            base_domain = self.hostname
            domains_to_check = [f"{sub}.{base_domain}" for sub in common_subdomains]
        
        # Check each subdomain for potential takeover
        for domain in domains_to_check:
            try:
                # Try to resolve the subdomain
                try:
                    ip_addresses = socket.gethostbyname_ex(domain)[2]
                    if not ip_addresses:
                        continue
                except socket.gaierror:
                    # Could not resolve - potential candidate for subdomain takeover
                    logger.debug(f"Could not resolve {domain} - potential candidate for subdomain takeover")
                    continue
                
                # Check CNAME record
                try:
                    cname_records = dns.resolver.resolve(domain, 'CNAME')
                    for record in cname_records:
                        cname_target = str(record.target).rstrip('.')
                        
                        # Check if CNAME points to a known service
                        cloud_services = [
                            'aws.amazon.com', 's3.amazonaws.com', 'herokuapp.com', 
                            'github.io', 'azure-api.net', 'cloudapp.net', 'cloudfront.net',
                            'github.com', 'shopify.com', 'statuspage.io', 'fastly.net',
                            'zendesk.com', 'bitbucket.io', 'azurewebsites.net'
                        ]
                        
                        for service in cloud_services:
                            if service in cname_target:
                                # Try to resolve the CNAME target
                                try:
                                    socket.gethostbyname(cname_target)
                                except socket.gaierror:
                                    # CNAME target doesn't resolve - potential subdomain takeover
                                    cvss_calc = CVSSCalculator()
                                    cvss_calc.set_from_vulnerability_type('SUBDOMAIN-TAKEOVER')
                                    cvss_score = cvss_calc.calculate_base_score()
                                    severity = cvss_calc.get_severity()
                                    vector = cvss_calc.get_vector_string()
                                    
                                    vuln = {
                                        'service': 'DNS',
                                        'id': 'SUBDOMAIN-TAKEOVER',
                                        'severity': severity,
                                        'description': f'Potential subdomain takeover: {domain} points to unresolvable {cname_target}',
                                        'cvss_score': cvss_score,
                                        'cvss_vector': vector,
                                        'published': datetime.now().isoformat(),
                                        'remediation': cvss_calc.recommend_mitigation('SUBDOMAIN-TAKEOVER')
                                    }
                                    self.vulnerabilities.append(vuln)
                                    logger.warning(f"Potential subdomain takeover: {domain} points to unresolvable {cname_target}")
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
                    logger.debug(f"No CNAME record for {domain}: {str(e)}")
            except Exception as e:
                logger.debug(f"Error checking subdomain {domain}: {str(e)}")

    def _check_zone_transfer(self):
        """Check if DNS zone transfer is allowed"""
        if not self.hostname or self.hostname == self.ip_address:
            return
        
        # Extract base domain
        domain_parts = self.hostname.split('.')
        if len(domain_parts) >= 2:
            base_domain = '.'.join(domain_parts[-2:])
        else:
            base_domain = self.hostname
        
        # Get name servers for the domain
        nameservers = []
        try:
            ns_records = dns.resolver.resolve(base_domain, 'NS')
            nameservers = [str(ns.target).rstrip('.') for ns in ns_records]
        except Exception as e:
            logger.debug(f"Error getting nameservers for {base_domain}: {str(e)}")
            return
        
        # Try zone transfer with each nameserver
        for ns in nameservers:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, base_domain, timeout=10))
                
                if zone:
                    cvss_calc = CVSSCalculator()
                    cvss_calc.set_from_vulnerability_type('ZONE-TRANSFER')
                    cvss_score = cvss_calc.calculate_base_score()
                    severity = cvss_calc.get_severity()
                    vector = cvss_calc.get_vector_string()
                    
                    vuln = {
                        'service': 'DNS',
                        'id': 'ZONE-TRANSFER',
                        'severity': severity,
                        'description': f'DNS zone transfer allowed on nameserver {ns} for domain {base_domain}',
                        'cvss_score': cvss_score,
                        'cvss_vector': vector,
                        'published': datetime.now().isoformat(),
                        'remediation': cvss_calc.recommend_mitigation('ZONE-TRANSFER')
                    }
                    self.vulnerabilities.append(vuln)
                    logger.warning(f"DNS zone transfer allowed on nameserver {ns} for domain {base_domain}")
            except Exception as e:
                logger.debug(f"Zone transfer not allowed or error with nameserver {ns}: {str(e)}")

    def _check_open_dns_resolver(self):
        """Check if the server is running an open DNS resolver"""
        if 53 not in self.open_ports:
            return
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.ip_address]
            resolver.timeout = 10
            resolver.lifetime = 12
            
            # Try to resolve a well-known domain
            try:
                answers = resolver.resolve('google.com', 'A')
                if answers:
                    cvss_calc = CVSSCalculator()
                    cvss_calc.set_from_vulnerability_type('OPEN-DNS-RESOLVER')
                    cvss_score = cvss_calc.calculate_base_score()
                    severity = cvss_calc.get_severity()
                    vector = cvss_calc.get_vector_string()
                    
                    vuln = {
                        'port': 53,
                        'service': 'DNS',
                        'id': 'OPEN-DNS-RESOLVER',
                        'severity': severity,
                        'description': 'Server is running an open DNS resolver which could be used for amplification attacks',
                        'cvss_score': cvss_score,
                        'cvss_vector': vector,
                        'published': datetime.now().isoformat(),
                        'remediation': cvss_calc.recommend_mitigation('OPEN-DNS-RESOLVER')
                    }
                    self.vulnerabilities.append(vuln)
                    logger.warning(f"Server is running an open DNS resolver on port 53")
            except Exception as e:
                logger.debug(f"Server is not an open DNS resolver: {str(e)}")
        except Exception as e:
            logger.debug(f"Error checking for open DNS resolver: {str(e)}")

    def _enhanced_service_fingerprinting(self):
        """Perform enhanced service fingerprinting beyond basic version detection"""
        logger.info(f"Performing enhanced service fingerprinting")
        
        for port, service_info in list(self.services.items()):
            service_name = service_info.get('name', '').lower()
            
            # Enhanced database fingerprinting
            if service_name in ['mysql', 'mariadb'] or port == 3306:
                self._fingerprint_mysql(port)
            elif service_name in ['postgresql', 'postgres'] or port == 5432:
                self._fingerprint_postgresql(port)
            elif service_name in ['mongodb'] or port == 27017:
                self._fingerprint_mongodb(port)
            elif service_name in ['redis'] or port == 6379:
                self._fingerprint_redis(port)
            
            # Enhanced application server fingerprinting
            elif service_name in ['tomcat'] or port in [8080, 8443]:
                self._fingerprint_tomcat(port)
            elif service_name in ['jboss', 'wildfly'] or port in [8080, 9990]:
                self._fingerprint_jboss(port)
            elif service_name in ['weblogic'] or port in [7001, 7002]:
                self._fingerprint_weblogic(port)
            
            # Enhanced mail server fingerprinting
            elif service_name in ['smtp'] or port == 25:
                self._enhanced_smtp_fingerprinting(port)
            elif service_name in ['pop3'] or port == 110:
                self._fingerprint_pop3(port)
            elif service_name in ['imap'] or port == 143:
                self._fingerprint_imap(port)

    def _fingerprint_mysql(self, port):
        """Enhanced MySQL/MariaDB fingerprinting"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((self.ip_address, port))
                banner = s.recv(1024).decode('utf-8', errors='ignore')
                
                self.services[port]['banner'] = banner.strip()
                
                # Check for authentication bypass
                if "MariaDB" in banner:
                    self.services[port]['product'] = 'MariaDB'
                    version_match = re.search(r'(\d+\.\d+\.\d+)', banner)
                    if version_match:
                        self.services[port]['version'] = version_match.group(1)
                elif "MySQL" in banner:
                    self.services[port]['product'] = 'MySQL'
                    version_match = re.search(r'(\d+\.\d+\.\d+)', banner)
                    if version_match:
                        self.services[port]['version'] = version_match.group(1)
                
                # Attempt basic security checks without authentication
                try:
                    # This is a passive test - send a malformed packet and check response
                    s.send(b'\x85\x23\x01')  # Intentionally malformed packet
                    response = s.recv(1024)
                    
                    if b'Access denied' not in response and len(response) > 0:
                        logger.info(f"MySQL/MariaDB on port {port} responded to malformed packet without proper error")
                except Exception as e:
                    logger.debug(f"Error during MySQL security check: {str(e)}")
        except Exception as e:
            logger.debug(f"Error fingerprinting MySQL on port {port}: {str(e)}")

    def _fingerprint_redis(self, port):
        """Enhanced Redis fingerprinting"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((self.ip_address, port))
                
                # Send INFO command
                s.sendall(b'INFO\r\n')
                response = s.recv(4096).decode('utf-8', errors='ignore')
                
                if 'redis_version' in response:
                    self.services[port]['product'] = 'Redis'
                    version_match = re.search(r'redis_version:([0-9.]+)', response)
                    if version_match:
                        version = version_match.group(1)
                        self.services[port]['version'] = version
                        logger.info(f"Redis version {version} detected on port {port}")
                    
                    # Check for authentication
                    if 'Authentication required' not in response:
                        cvss_calc = CVSSCalculator()
                        cvss_calc.set_from_vulnerability_type('DEFAULT-CREDENTIALS')
                        cvss_score = cvss_calc.calculate_base_score()
                        severity = cvss_calc.get_severity()
                        vector = cvss_calc.get_vector_string()
                        
                        vuln = {
                            'port': port,
                            'service': 'Redis',
                            'id': 'REDIS-NO-AUTH',
                            'severity': severity,
                            'description': 'Redis server is running without password protection',
                            'cvss_score': cvss_score,
                            'cvss_vector': vector,
                            'published': datetime.now().isoformat(),
                            'remediation': 'Configure Redis to require authentication'
                        }
                        self.vulnerabilities.append(vuln)
                        logger.warning(f"Redis server on port {port} is running without password protection")
                        
                        # Check if we can run arbitrary commands
                        try:
                            s.sendall(b'CONFIG GET *\r\n')
                            config_response = s.recv(4096).decode('utf-8', errors='ignore')
                            
                            if 'bind' in config_response or 'dbfilename' in config_response:
                                logger.warning(f"Redis server on port {port} allows CONFIG commands")
                        except Exception as e:
                            logger.debug(f"Error checking Redis CONFIG command: {str(e)}")
        except Exception as e:
            logger.debug(f"Error fingerprinting Redis on port {port}: {str(e)}")

    def _enhanced_smtp_fingerprinting(self, port):
        """Enhanced SMTP server fingerprinting"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((self.ip_address, port))
                banner = s.recv(1024).decode('utf-8', errors='ignore')
                self.services[port]['banner'] = banner.strip()
                
                # Try EHLO to get supported extensions
                try:
                    s.sendall(b'EHLO example.com\r\n')
                    ehlo_response = s.recv(4096).decode('utf-8', errors='ignore')
                    
                    # Check for supported extensions
                    extensions = []
                    for line in ehlo_response.splitlines():
                        if line.startswith('250-'):
                            extension = line[4:].strip().upper()
                            extensions.append(extension)
                    
                    self.services[port]['extensions'] = extensions
                    
                    # Check for STARTTLS support
                    if 'STARTTLS' not in [ext.upper() for ext in extensions]:
                        cvss_calc = CVSSCalculator()
                        cvss_calc.set_from_vulnerability_type('TLS-OUTDATED')  # Reuse TLS scoring
                        cvss_score = cvss_calc.calculate_base_score()
                        severity = cvss_calc.get_severity()
                        vector = cvss_calc.get_vector_string()
                        
                        vuln = {
                            'port': port,
                            'service': 'SMTP',
                            'id': 'SMTP-NO-STARTTLS',
                            'severity': severity,
                            'description': 'SMTP server does not support STARTTLS for encryption',
                            'cvss_score': cvss_score,
                            'cvss_vector': vector,
                            'published': datetime.now().isoformat(),
                            'remediation': 'Configure SMTP server to support STARTTLS'
                        }
                        self.vulnerabilities.append(vuln)
                        logger.warning(f"SMTP server on port {port} does not support STARTTLS")
                    
                    # Check for VRFY command support (can be used for user enumeration)
                    try:
                        s.sendall(b'VRFY root\r\n')
                        vrfy_response = s.recv(1024).decode('utf-8', errors='ignore')
                        
                        if not vrfy_response.startswith('5'):  # Not rejected
                            logger.warning(f"SMTP server on port {port} supports VRFY command which can be used for user enumeration")
                            
                            cvss_calc = CVSSCalculator()
                            cvss_calc.set_from_vulnerability_type('INFO-DISCLOSURE')
                            cvss_score = cvss_calc.calculate_base_score()
                            severity = cvss_calc.get_severity()
                            vector = cvss_calc.get_vector_string()
                            
                            vuln = {
                                'port': port,
                                'service': 'SMTP',
                                'id': 'SMTP-VRFY-ENABLED',
                                'severity': severity,
                                'description': 'SMTP server supports VRFY command which can be used for user enumeration',
                                'cvss_score': cvss_score,
                                'cvss_vector': vector,
                                'published': datetime.now().isoformat(),
                                'remediation': 'Disable VRFY command in SMTP server configuration'
                            }
                            self.vulnerabilities.append(vuln)
                    except Exception as e:
                        logger.debug(f"Error checking VRFY command: {str(e)}")
                except Exception as e:
                    logger.debug(f"Error during EHLO command: {str(e)}")
        except Exception as e:
            logger.debug(f"Error fingerprinting SMTP on port {port}: {str(e)}")

    
    
    def detect_vulnerabilities(self):
        logger.info("Kiểm tra lỗ hổng thực tế với Nmap...")
        
        # Nếu có cổng mở thì chỉ quét các cổng đó
        if self.open_ports:
            ports_str = ','.join(str(port) for port in self.open_ports)
        else:
            logger.warning("Không tìm thấy cổng mở nào, bỏ qua quét lỗ hổng.")
            return  # Không có cổng mở thì không cần chạy script vuln
        
        # Gọi hàm thực hiện quét lỗ hổng
        vuln_results = detect_vulnerabilities(self.ip_address, ports=ports_str)
        
        for vuln in vuln_results:
            port = int(vuln['port'])
            service_info = self.services.get(port, {'name': 'unknown'})
            
            # Tạo một ước lượng CVSS dựa trên loại lỗ hổng
            vuln_id = vuln['vuln_id']
            cvss_calc = CVSSCalculator()
            vuln_type = 'unknown'
            
            # Đoán loại lỗ hổng dựa trên ID hoặc mô tả
            if 'xss' in vuln_id.lower():
                vuln_type = 'XSS-REFLECTED'
            elif 'sql' in vuln_id.lower():
                vuln_type = 'SQL-INJECTION'
            elif 'directory' in vuln_id.lower() or 'listing' in vuln_id.lower():
                vuln_type = 'DIR-LISTING'
            elif 'info' in vuln_id.lower() or 'disclosure' in vuln_id.lower():
                vuln_type = 'INFO-DISCLOSURE'
            
            cvss_calc.set_from_vulnerability_type(vuln_type)
            cvss_score = cvss_calc.calculate_base_score()
            severity = cvss_calc.get_severity()
            vector = cvss_calc.get_vector_string()
            
            self.vulnerabilities.append({
                'id': vuln['vuln_id'],
                'service': service_info['name'],
                'port': port,
                'version': service_info.get('version', 'unknown'),
                'severity': severity,
                'description': vuln['description'],
                'cvss_score': cvss_score,
                'cvss_vector': vector,
                'published': datetime.now().isoformat()
            })
            
            logger.warning(f"Phát hiện lỗ hổng: {vuln['vuln_id']} từ Nmap (CVSS: {cvss_score}, {severity})")
    
    def create_report(self, output_format="json", report_id=None):#lưu mongo
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Hàm đệ quy chuyển tất cả khóa dict thành string và xử lý kiểu dữ liệu đặc biệt
        def prepare_for_mongo(data):
            if isinstance(data, dict):
                return {str(k): prepare_for_mongo(v) for k, v in data.items()}
            elif isinstance(data, (list, tuple)):
                return [prepare_for_mongo(item) for item in data]
            elif isinstance(data, datetime):
                return data.isoformat()
            elif isinstance(data, bytes):
                return data.decode('utf-8', errors='ignore')
            else:
                return data
        
        # Chuẩn bị dữ liệu báo cáo
        report_data = {
            "scan_info": prepare_for_mongo({
                "target": self.target,
                "ip_address": self.ip_address,
                "hostname": self.hostname,
                "scan_time": datetime.now().isoformat(),
                "timestamp": timestamp
            }),
            "whois_info": prepare_for_mongo(self.whois_info),
            "dns_records": prepare_for_mongo(self.dns_records),
            "open_ports": prepare_for_mongo(self.open_ports),
            "services": prepare_for_mongo(self.services),
            "technologies": prepare_for_mongo(self.technologies),
            "vulnerabilities": prepare_for_mongo(self.vulnerabilities)
        }
        
        try:
            if report_id:
                # Cập nhật báo cáo thay vì chèn mới để giữ trạng thái cũ
                self.collection.update_one(
                    {"_id": ObjectId(report_id)},
                    {"$set": report_data},
                    upsert=True  # Nếu không tồn tại thì chèn mới
                )
                logger.info(f"Đã cập nhật báo cáo vào MongoDB với ID: {report_id}")
                return report_id
            else:
                result = self.collection.insert_one(report_data)
                report_id = str(result.inserted_id)
                logger.info(f"Đã lưu báo cáo mới vào MongoDB với ID: {report_id}")
                return report_id
            
        except Exception as e:
            logger.error(f"Lỗi MongoDB:")
            logger.error(f"Kiểu lỗi: {type(e).__name__}")
            logger.error(f"Chi tiết: {str(e)}")
            
            # Nếu có thông tin lỗi từ PyMongo
            if hasattr(e, 'details'):
                logger.error(f"Lỗi chi tiết từ MongoDB: {e.details}")
            
            # Lưu báo cáo vào file local nếu không lưu được vào MongoDB
            if output_format in ["json", "all"]:
                try:
                    filename = f"report_{self.target.replace('://', '_').replace('/', '_').replace(':', '_')}_{timestamp}.json"
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(report_data, f, ensure_ascii=False, indent=4)
                    logger.info(f"Đã lưu báo cáo vào file: {filename}")
                    return filename
                except Exception as file_error:
                    logger.error(f"Không thể lưu báo cáo vào file: {str(file_error)}")
            
            return None

    def run_scan(self, ports=None, output_format="all", report_id=None, scan_options=None):
        """
        Run the full vulnerability scan with enhanced capabilities
        
        Args:
            ports: Specific ports to scan (optional)
            output_format: Format for report output (json, html, xml, all)
            report_id: Existing report ID to update (optional)
            scan_options: Dictionary of scan options to enable/disable features
        """
        try:
            # Set default scan options if not provided
            if scan_options is None:
                scan_options = {
                    'port_scan': True,
                    'service_enum': True,
                    'web_checks': True,
                    'advanced_web_checks': True,
                    'ssl_checks': True,
                    'cloud_checks': True,
                    'container_checks': True,
                    'dns_checks': True,
                    'enhanced_fingerprinting': True
                }
            
            logger.info(f"Bắt đầu quét cho mục tiêu: {self.target}")
            start_time = time.time()
            
            # Basic information gathering
            self.gather_basic_info()
            
            # Port scanning
            if scan_options.get('port_scan', True):
                self.scan_ports(ports)
            
            # Basic service enumeration
            if scan_options.get('service_enum', True):
                self.enumerate_services()
            
            # Enhanced service fingerprinting
            if scan_options.get('enhanced_fingerprinting', True):
                self._enhanced_service_fingerprinting()
            
            # SSL/TLS security checks
            if scan_options.get('ssl_checks', True):
                # Find all ports with HTTPS or other secure services
                ssl_ports = []
                for port, service in self.services.items():
                    if service.get('name') == 'https' or port in [443, 8443]:
                        ssl_ports.append(port)
                    
                for port in ssl_ports:
                    self._check_ssl_tls_security(self.hostname, port)
            
            # Basic and advanced web vulnerability checks
            if scan_options.get('web_checks', True):
                web_ports = [port for port, service in self.services.items() 
                            if service.get('name') in ['http', 'https'] or port in [80, 443, 8080, 8443]]
                
                for port in web_ports:
                    protocol = 'https' if port == 443 or port == 8443 else 'http'
                    base_url = f"{protocol}://{self.hostname}:{port}" if self.hostname != self.ip_address else f"{protocol}://{self.ip_address}:{port}"
                    self._check_web_vulnerabilities(base_url, port)
            
            # Cloud resource discovery
            if scan_options.get('cloud_checks', True):
                self.detect_cloud_resources()
            
            # Container and Kubernetes security checks
            if scan_options.get('container_checks', True):
                self._check_container_security()
            
            # DNS security checks
            if scan_options.get('dns_checks', True):
                self._check_dns_security()
            
            # Look for known vulnerabilities in NVD
            self.detect_vulnerabilities()
            
            # Generate scan report
            f_report_id = self.create_report(output_format, report_id)
            
            # Calculate scan duration
            scan_duration = time.time() - start_time
            
            # Update with completion status
            if self.collection is not None and report_id:
                self.collection.update_one(
                    {"_id": ObjectId(report_id)},
                    {
                        "$set": {
                            "scan_info.status": "completed", 
                            "scan_info.duration": scan_duration,
                            "end_time": datetime.now().isoformat()
                        }
                    }
                )

            # Cleanup
            if hasattr(self, 'requests') and self.requests:
                self.requests.close()
            
            if self.mongo_client:
                self.mongo_client.close()
                
            logger.info(f"Hoàn thành quét cho mục tiêu: {self.target} (Thời gian: {scan_duration:.2f}s)")
            return f_report_id
                
        except Exception as e:
            logger.error(f"Lỗi trong quá trình quét: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())

            if self.collection is not None and report_id:
                self.collection.update_one(
                    {"_id": ObjectId(report_id)},
                    {
                        "$set": {
                            "scan_info.status": "failed",
                            "scan_info.error": str(e),
                            "end_time": datetime.now().isoformat()
                        }
                    }
                )

            return None
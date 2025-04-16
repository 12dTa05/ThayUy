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
        self.nvd_api_key = os.environ.get("NVD_API_KEY", "A2C3AD60-CA13-F011-8359-129478FCB64D")
        
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
        max_retries = 3
        retry_delay = 2
        
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

    def _detect_technologies(self, response=None):  
        url = f"https://{self.hostname}" if 443 in self.open_ports else f"http://{self.hostname}"
        tech_dict = detect_technologies(url)
        self.technologies = [{'name': name, 'version': version} for name, version in tech_dict.items()]
    
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
        sock.settimeout(1)
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
                path_response = self.requests.get(path_url, timeout=5)
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
                s.settimeout(5)
                result = s.connect_ex((self.ip_address, port))
                if result == 0:
                    logger.info(f"Database {db_type} đang chạy trên cổng {port}")
                    self.services[port]['name'] = db_type.lower()
        except Exception as e:
            logger.error(f"Lỗi khi kiểm tra database {db_type}: {str(e)}")
    
    def _check_web_vulnerabilities(self): #ktra lỗ hổng web phổ biến
        web_ports = [port for port, service in self.services.items() 
                    if service['name'] in ['http', 'https'] or port in [80, 443, 8080, 8443]]
        
        for port in web_ports:
            protocol = 'https' if port == 443 or port == 8443 else 'http'
            base_url = f"{protocol}://{self.hostname}:{port}" if self.hostname != self.ip_address else f"{protocol}://{self.ip_address}:{port}"
            
            logger.info(f"Kiểm tra lỗ hổng web trên {base_url}...")
            
            # Kiểm tra XSS phản xạ đơn giản
            self._check_reflected_xss(base_url, port)
            
            # Kiểm tra lỗi SQL Injection đơn giản
            self._check_sql_injection(base_url, port)
                
            # Kiểm tra thông tin rò rỉ trong HTTP Headers
            self._check_info_disclosure(base_url, port)
                
            # Kiểm tra Directory Listing
            self._check_directory_listing(base_url, port)
    
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
                response = self.requests.get(f"{base_url}{directory}", timeout=5)
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
    
    def query_nvd(self, cpe_string, max_retries=3, retry_delay=2): #NVD API
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
                    response = self.requests.get(base_url, headers=headers, params=params, timeout=15)
                    
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
        
        # Kiểm tra lỗ hổng web nếu có dịch vụ web
        if any(service['name'] in ['http', 'https'] for service in self.services.values()):
            self._check_web_vulnerabilities()
    
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

    def run_scan(self, ports=None, output_format="all", report_id=None):
        try:
            logger.info(f"Bắt đầu quét cho mục tiêu: {self.target}")
            
            self.gather_basic_info()
            self.scan_ports(ports)
            self.enumerate_services()
            self.detect_vulnerabilities()
            
            f_report_id = self.create_report(output_format, report_id)
            
            if self.collection is not None and report_id:
                self.collection.update_one(
                    {"_id": ObjectId(report_id)},
                    {"$set": {"scan_info.status": "completed", "end_time": datetime.now().isoformat()}}
                )

            # Cleanup
            if hasattr(self, 'requests') and self.requests:
                self.requests.close()
            
            if self.mongo_client:
                self.mongo_client.close()
                
            logger.info(f"Hoàn thành quét cho mục tiêu: {self.target}")
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
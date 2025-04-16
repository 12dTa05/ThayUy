import logging

logger = logging.getLogger(__name__)

class CVSSCalculator: #tham khảo CVSS 3.1 calculator
    def __init__(self):
        # Khởi tạo các giá trị mặc định
        self.metrics = {
            # Base Metrics
            'AV': 'N',  # Attack Vector (Network)
            'AC': 'L',  # Attack Complexity (Low)
            'PR': 'N',  # Privileges Required (None)
            'UI': 'N',  # User Interaction (None)
            'S': 'U',   # Scope (Unchanged)
            'C': 'N',   # Confidentiality Impact (None)
            'I': 'N',   # Integrity Impact (None)
            'A': 'N',   # Availability Impact (None)
        }
        
        self.weights = {
            # Attack Vector
            'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
            # Attack Complexity
            'AC': {'L': 0.77, 'H': 0.44},
            # Privileges Required
            'PR': {
                'N': 0.85, 
                'L': {'U': 0.62, 'C': 0.68}, 
                'H': {'U': 0.27, 'C': 0.5}
            },
            # User Interaction
            'UI': {'N': 0.85, 'R': 0.62},
            # Scope
            'S': {'U': 'U', 'C': 'C'},  # Không có trọng số
            # Confidentiality, Integrity, Availability Impact
            'C': {'H': 0.56, 'L': 0.22, 'N': 0},
            'I': {'H': 0.56, 'L': 0.22, 'N': 0},
            'A': {'H': 0.56, 'L': 0.22, 'N': 0}
        }

    def set_metric(self, metric, value):
        """Thiết lập giá trị cho một tham số CVSS"""
        if metric in self.metrics and value in self._get_valid_values(metric):
            self.metrics[metric] = value
            return True
        return False
    
    def _get_valid_values(self, metric):
        """Lấy các giá trị hợp lệ cho một tham số"""
        if metric in ['AV', 'AC', 'UI']:
            return self.weights[metric].keys()
        elif metric in ['C', 'I', 'A']:
            return self.weights[metric].keys()
        elif metric == 'PR':
            return self.weights[metric].keys()
        elif metric == 'S':
            return self.weights[metric].keys()
        return []

    def set_from_vulnerability_type(self, vuln_type):
        """
        Thiết lập các tham số CVSS dựa trên loại lỗ hổng phát hiện được
        """
        # FTP Anonymous access
        if vuln_type == 'FTP-ANONYMOUS':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'L')   # Low integrity impact
            self.set_metric('A', 'N')   # No availability impact
        
        # XSS Reflected
        elif vuln_type == 'XSS-REFLECTED':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'R')  # User interaction required
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'L')   # Low confidentiality impact
            self.set_metric('I', 'L')   # Low integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        # SQL Injection
        elif vuln_type == 'SQL-INJECTION':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'L')   # Low availability impact
            
        # Information Disclosure
        elif vuln_type == 'INFO-DISCLOSURE':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'L')   # Low confidentiality impact
            self.set_metric('I', 'N')   # No integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        # Directory Listing
        elif vuln_type == 'DIR-LISTING':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'L')   # Low confidentiality impact
            self.set_metric('I', 'N')   # No integrity impact
            self.set_metric('A', 'N')   # No availability impact
        
        # Default case - moderate impact    
        else:
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'H')  # High complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'L')   # Low confidentiality impact
            self.set_metric('I', 'L')   # Low integrity impact
            self.set_metric('A', 'L')   # Low availability impact

    def set_from_vector_string(self, vector_string):
        """
        Thiết lập các tham số từ chuỗi vector CVSS
        Ví dụ: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        """
        if not vector_string or not vector_string.startswith("CVSS:"):
            return False
        
        try:
            # Loại bỏ phần đầu "CVSS:3.1/"
            if '/' in vector_string:
                metrics_part = vector_string.split('/', 1)[1]
                # Phân tích các phần của vector
                for metric in metrics_part.split('/'):
                    if ':' in metric:
                        key, value = metric.split(':')
                        if key in self.metrics:
                            self.set_metric(key, value)
                return True
        except Exception as e:
            logger.error(f"Lỗi khi phân tích vector CVSS: {str(e)}")
        return False

    def calculate_base_score(self):
        """Tính toán điểm CVSS 3.1 Base Score"""
        # Tính Impact Sub Score (ISS)
        impact_scores = {}
        for metric in ['C', 'I', 'A']:
            impact_scores[metric] = self.weights[metric][self.metrics[metric]]
        
        iss = 1 - ((1 - impact_scores['C']) * (1 - impact_scores['I']) * (1 - impact_scores['A']))
        
        # Tính Exploitability Sub Score (ESS)
        av_weight = self.weights['AV'][self.metrics['AV']]
        ac_weight = self.weights['AC'][self.metrics['AC']]
        
        # PR weight depends on Scope
        if isinstance(self.weights['PR'][self.metrics['PR']], dict):
            pr_weight = self.weights['PR'][self.metrics['PR']][self.metrics['S']]
        else:
            pr_weight = self.weights['PR'][self.metrics['PR']]
            
        ui_weight = self.weights['UI'][self.metrics['UI']]
        
        ess = 8.22 * av_weight * ac_weight * pr_weight * ui_weight
        
        # Tính Final Score based on Scope
        if self.metrics['S'] == 'U':  # Unchanged
            if iss <= 0:
                return 0
            else:
                return round(min(iss + ess, 10) * 10) / 10
        else:  # Changed
            if iss <= 0:
                return 0
            else:
                return round(min(1.08 * (iss + ess), 10) * 10) / 10

    def get_severity(self, score=None):
        """Xác định mức độ nghiêm trọng dựa trên điểm CVSS"""
        if score is None:
            score = self.calculate_base_score()
            
        if score == 0.0:
            return "Không"
        elif 0.1 <= score <= 3.9:
            return "Thấp"
        elif 4.0 <= score <= 6.9:
            return "Trung bình"
        elif 7.0 <= score <= 8.9:
            return "Cao"
        else:  # 9.0 - 10.0
            return "Nghiêm trọng"
            
    def get_vector_string(self):
        """Tạo chuỗi vector CVSS 3.1"""
        return f"CVSS:3.1/AV:{self.metrics['AV']}/AC:{self.metrics['AC']}/PR:{self.metrics['PR']}/UI:{self.metrics['UI']}/S:{self.metrics['S']}/C:{self.metrics['C']}/I:{self.metrics['I']}/A:{self.metrics['A']}"
import logging

logger = logging.getLogger(__name__)

class CVSSCalculator:
    def __init__(self):
        # Initialize default values
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
            'S': {'U': 'U', 'C': 'C'},  # No weight
            # Confidentiality, Integrity, Availability Impact
            'C': {'H': 0.56, 'L': 0.22, 'N': 0},
            'I': {'H': 0.56, 'L': 0.22, 'N': 0},
            'A': {'H': 0.56, 'L': 0.22, 'N': 0}
        }
        
        # Categorized vulnerability types for easier reference
        self.vulnerability_categories = {
            'authentication': ['FTP-ANONYMOUS', 'WEAK-CREDENTIALS', 'DEFAULT-CREDENTIALS', 'NO-PASSWORD-POLICY'],
            'web': ['XSS-REFLECTED', 'XSS-STORED', 'SQL-INJECTION', 'INFO-DISCLOSURE', 'DIR-LISTING', 'CSRF', 'OPEN-REDIRECT'],
            'api': ['API-EXPOSED', 'API-NO-AUTH', 'API-BROKEN-AUTH', 'API-EXCESSIVE-DATA', 'API-BROKEN-OBJECT-LEVEL-AUTH'],
            'ssl_tls': ['TLS-OUTDATED', 'SSL-WEAK-CIPHER', 'SSL-EXPIRED-CERT', 'SSL-SELF-SIGNED'],
            'cloud': ['S3-PUBLIC-ACL', 'S3-PUBLIC-ACCESS', 'AZURE-STORAGE-EXPOSED', 'CLOUD-API-KEY-EXPOSED'],
            'network': ['PORT-SCAN-ENABLED', 'EXCESSIVE-SERVICE-INFO', 'ZONE-TRANSFER'],
            'container': ['DOCKER-EXPOSED-API', 'K8S-EXPOSED-API', 'CONTAINER-PRIV-ESCALATION'],
            'application': ['JWT-NONE-ALGORITHM', 'SSRF-VULNERABILITY', 'XXE-VULNERABILITY', 'DESERIALIZATION'],
            'infrastructure': ['SUBDOMAIN-TAKEOVER', 'DNS-CACHE-POISONING', 'OPEN-DNS-RESOLVER']
        }

    def set_metric(self, metric, value):
        """Set a value for a CVSS metric"""
        if metric in self.metrics and value in self._get_valid_values(metric):
            self.metrics[metric] = value
            return True
        return False
    
    def _get_valid_values(self, metric):
        """Get valid values for a metric"""
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
        Set CVSS parameters based on the detected vulnerability type
        """
        # Original vulnerability types (retained for backward compatibility)
        if vuln_type == 'FTP-ANONYMOUS':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'L')   # Low integrity impact
            self.set_metric('A', 'N')   # No availability impact
        
        elif vuln_type == 'XSS-REFLECTED':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'R')  # User interaction required
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'L')   # Low confidentiality impact
            self.set_metric('I', 'L')   # Low integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'SQL-INJECTION':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'L')   # Low availability impact
            
        elif vuln_type == 'INFO-DISCLOSURE':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'L')   # Low confidentiality impact
            self.set_metric('I', 'N')   # No integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'DIR-LISTING':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'L')   # Low confidentiality impact
            self.set_metric('I', 'N')   # No integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        # === Web Application Security Enhancements ===
        elif vuln_type == 'XSS-STORED':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'L')  # Low privileges required
            self.set_metric('UI', 'R')  # User interaction required
            self.set_metric('S', 'C')   # Changed scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'CSRF':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'H')  # High complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'R')  # User interaction required
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'N')   # No confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'OPEN-REDIRECT':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'R')  # User interaction required
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'L')   # Low confidentiality impact
            self.set_metric('I', 'L')   # Low integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        # === JWT Token & Authentication Vulnerabilities ===
        elif vuln_type == 'JWT-NONE-ALGORITHM':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'WEAK-CREDENTIALS':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'H')  # High complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'L')   # Low availability impact
            
        elif vuln_type == 'DEFAULT-CREDENTIALS':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'H')   # High availability impact
        
        # === SSRF & XXE Vulnerabilities ===    
        elif vuln_type == 'SSRF-VULNERABILITY':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'H')  # High complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'C')   # Changed scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'L')   # Low integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'XXE-VULNERABILITY':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'L')   # Low integrity impact
            self.set_metric('A', 'L')   # Low availability impact
            
        # === SSL/TLS Vulnerabilities ===
        elif vuln_type == 'TLS-OUTDATED':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'H')  # High complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'L')   # Low integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'SSL-WEAK-CIPHER':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'H')  # High complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'SSL-EXPIRED-CERT':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'R')  # User interaction required
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'L')   # Low confidentiality impact
            self.set_metric('I', 'L')   # Low integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'SSL-SELF-SIGNED':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'R')  # User interaction required
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'L')   # Low confidentiality impact
            self.set_metric('I', 'L')   # Low integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        # === Cloud Service Vulnerabilities ===
        elif vuln_type == 'S3-PUBLIC-ACL':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'N')   # No integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'S3-PUBLIC-ACCESS':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'L')   # Low integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'AZURE-STORAGE-EXPOSED':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'L')   # Low integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'CLOUD-API-KEY-EXPOSED':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'C')   # Changed scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'L')   # Low availability impact
            
        # === API Security Vulnerabilities ===
        elif vuln_type == 'API-EXPOSED':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'L')   # Low confidentiality impact
            self.set_metric('I', 'N')   # No integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'API-NO-AUTH':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'API-BROKEN-AUTH':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'API-EXCESSIVE-DATA':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'L')  # Low privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'N')   # No integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'API-BROKEN-OBJECT-LEVEL-AUTH':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'L')  # Low privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'N')   # No availability impact
        
        # === Container Security Vulnerabilities ===
        elif vuln_type == 'DOCKER-EXPOSED-API':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'C')   # Changed scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'H')   # High availability impact
            
        elif vuln_type == 'K8S-EXPOSED-API':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'C')   # Changed scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'H')   # High availability impact
            
        elif vuln_type == 'CONTAINER-PRIV-ESCALATION':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'H')  # High complexity
            self.set_metric('PR', 'L')  # Low privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'C')   # Changed scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'H')   # High availability impact
            
        # === DNS Security Vulnerabilities ===
        elif vuln_type == 'SUBDOMAIN-TAKEOVER':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'H')  # High complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'C')   # Changed scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'DNS-CACHE-POISONING':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'H')  # High complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'C')   # Changed scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'ZONE-TRANSFER':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'N')   # No integrity impact
            self.set_metric('A', 'N')   # No availability impact
            
        elif vuln_type == 'OPEN-DNS-RESOLVER':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'L')  # Low complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'C')   # Changed scope
            self.set_metric('C', 'N')   # No confidentiality impact
            self.set_metric('I', 'N')   # No integrity impact
            self.set_metric('A', 'H')   # High availability impact (DDoS amplification)
            
        # === Advanced Application Vulnerabilities ===
        elif vuln_type == 'DESERIALIZATION':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'H')  # High complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'H')   # High confidentiality impact
            self.set_metric('I', 'H')   # High integrity impact
            self.set_metric('A', 'H')   # High availability impact
            
        elif vuln_type == 'NO-PASSWORD-POLICY':
            self.set_metric('AV', 'N')  # Network
            self.set_metric('AC', 'H')  # High complexity
            self.set_metric('PR', 'N')  # No privileges required
            self.set_metric('UI', 'N')  # No user interaction
            self.set_metric('S', 'U')   # Unchanged scope
            self.set_metric('C', 'L')   # Low confidentiality impact
            self.set_metric('I', 'L')   # Low integrity impact
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
        Set parameters from a CVSS vector string
        Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        """
        if not vector_string or not vector_string.startswith("CVSS:"):
            return False
        
        try:
            # Remove the prefix "CVSS:3.1/"
            if '/' in vector_string:
                metrics_part = vector_string.split('/', 1)[1]
                # Parse vector components
                for metric in metrics_part.split('/'):
                    if ':' in metric:
                        key, value = metric.split(':')
                        if key in self.metrics:
                            self.set_metric(key, value)
                return True
        except Exception as e:
            logger.error(f"Error parsing CVSS vector: {str(e)}")
        return False

    def calculate_base_score(self):
        """Calculate CVSS 3.1 Base Score"""
        # Calculate Impact Sub Score (ISS)
        impact_scores = {}
        for metric in ['C', 'I', 'A']:
            impact_scores[metric] = self.weights[metric][self.metrics[metric]]
        
        iss = 1 - ((1 - impact_scores['C']) * (1 - impact_scores['I']) * (1 - impact_scores['A']))
        
        # Calculate Exploitability Sub Score (ESS)
        av_weight = self.weights['AV'][self.metrics['AV']]
        ac_weight = self.weights['AC'][self.metrics['AC']]
        
        # PR weight depends on Scope
        if isinstance(self.weights['PR'][self.metrics['PR']], dict):
            pr_weight = self.weights['PR'][self.metrics['PR']][self.metrics['S']]
        else:
            pr_weight = self.weights['PR'][self.metrics['PR']]
            
        ui_weight = self.weights['UI'][self.metrics['UI']]
        
        ess = 8.22 * av_weight * ac_weight * pr_weight * ui_weight
        
        # Calculate Final Score based on Scope
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
        """Determine severity level based on CVSS score"""
        if score is None:
            score = self.calculate_base_score()
            
        if score == 0.0:
            return "None"
        elif 0.1 <= score <= 3.9:
            return "Low"
        elif 4.0 <= score <= 6.9:
            return "Medium"
        elif 7.0 <= score <= 8.9:
            return "High"
        else:  # 9.0 - 10.0
            return "Critical"
            
    def get_vector_string(self):
        """Generate CVSS 3.1 vector string"""
        return f"CVSS:3.1/AV:{self.metrics['AV']}/AC:{self.metrics['AC']}/PR:{self.metrics['PR']}/UI:{self.metrics['UI']}/S:{self.metrics['S']}/C:{self.metrics['C']}/I:{self.metrics['I']}/A:{self.metrics['A']}"
           
    def recommend_mitigation(self, vuln_type):
        """Provide recommended mitigation based on vulnerability type"""
        mitigations = {
            # Authentication vulnerabilities
            'FTP-ANONYMOUS': "Disable anonymous FTP access and enforce strong authentication",
            'WEAK-CREDENTIALS': "Implement a strong password policy and consider multi-factor authentication",
            'DEFAULT-CREDENTIALS': "Change all default credentials and implement a credential management process",
            'NO-PASSWORD-POLICY': "Implement and enforce a strong password policy with complexity requirements",
            
            # Web vulnerabilities
            'XSS-REFLECTED': "Implement proper input validation, output encoding, and use Content-Security-Policy headers",
            'XSS-STORED': "Implement proper input validation, sanitization, and output encoding",
            'SQL-INJECTION': "Use parameterized queries or prepared statements, implement input validation, and apply least privilege",
            'INFO-DISCLOSURE': "Remove version information from HTTP headers and error messages",
            'DIR-LISTING': "Disable directory listing in web server configuration",
            'CSRF': "Implement anti-CSRF tokens, use SameSite cookie attribute, and validate origin headers",
            'OPEN-REDIRECT': "Implement a whitelist of allowed redirect URLs and validate all redirects",
            
            # API vulnerabilities
            'API-EXPOSED': "Implement API gateway with proper request filtering and authentication",
            'API-NO-AUTH': "Add proper authentication mechanisms for all API endpoints",
            'API-BROKEN-AUTH': "Fix authentication implementation and consider using standardized auth frameworks",
            'API-EXCESSIVE-DATA': "Implement proper data filtering and ensure endpoints return only necessary data",
            'API-BROKEN-OBJECT-LEVEL-AUTH': "Implement proper access control checks for each object accessed via API",
            
            # SSL/TLS vulnerabilities
            'TLS-OUTDATED': "Disable TLS 1.0/1.1 and configure only TLS 1.2+ with strong cipher suites",
            'SSL-WEAK-CIPHER': "Remove weak ciphers and configure secure cipher suites",
            'SSL-EXPIRED-CERT': "Renew SSL certificate and implement automated certificate renewal",
            'SSL-SELF-SIGNED': "Replace self-signed certificate with a trusted certificate from a recognized CA",
            
            # Cloud vulnerabilities
            'S3-PUBLIC-ACL': "Disable public access settings for S3 buckets and implement proper bucket policies",
            'S3-PUBLIC-ACCESS': "Disable public access settings and implement proper authentication for bucket access",
            'AZURE-STORAGE-EXPOSED': "Configure proper access controls for Azure storage containers",
            'CLOUD-API-KEY-EXPOSED': "Rotate exposed API keys, restrict key permissions, and store securely",
            
            # Container vulnerabilities
            'DOCKER-EXPOSED-API': "Secure Docker API with TLS and authentication, restrict access with firewall",
            'K8S-EXPOSED-API': "Implement proper authentication and RBAC for Kubernetes API server",
            'CONTAINER-PRIV-ESCALATION': "Remove privileged container settings and implement proper access controls",
            
            # Advanced application vulnerabilities
            'JWT-NONE-ALGORITHM': "Fix JWT implementation to reject 'none' algorithm and properly validate signatures",
            'SSRF-VULNERABILITY': "Implement whitelist validation for all URLs and block access to internal resources",
            'XXE-VULNERABILITY': "Disable external entity processing in XML parsers and validate all XML input",
            'DESERIALIZATION': "Avoid deserialization of untrusted data or implement integrity checks",
            
            # DNS vulnerabilities
            'SUBDOMAIN-TAKEOVER': "Ensure proper decommissioning of unused subdomains and services",
            'DNS-CACHE-POISONING': "Implement DNSSEC and ensure DNS server is using latest security patches",
            'ZONE-TRANSFER': "Restrict zone transfers to authorized DNS servers only",
            'OPEN-DNS-RESOLVER': "Configure DNS server to respond only to queries from authorized networks"
        }
        
        return mitigations.get(vuln_type, "Consult vendor documentation for specific mitigation steps")
    
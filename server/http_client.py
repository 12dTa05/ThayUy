import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

class RequestsWithRetry:
    def __init__(self, retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504), timeout=12):
        self.session = requests.Session()
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.timeout = timeout
    
    def get(self, url, **kwargs):
        kwargs.setdefault('timeout', self.timeout)
        return self.session.get(url, **kwargs)
    
    def post(self, url, **kwargs):
        kwargs.setdefault('timeout', self.timeout)
        return self.session.post(url, **kwargs)
    
    def close(self):
        self.session.close()
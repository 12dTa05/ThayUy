from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, Union, List, Dict, Any

# Model for request input
class ScanRequest(BaseModel):
    target: str = Field(..., description="URL hoặc địa chỉ IP của mục tiêu")
    ports: Optional[str] = Field("1-1000", description="Danh sách các cổng cần quét (mặc định '1-1000')")
    output_format: Optional[str] = Field("json", description="Định dạng đầu ra (json)")

# Model for response
class ScanResponse(BaseModel):
    status: str
    report_id: Optional[str] = None
    message: Optional[str] = None

# Model for vulnerability
class Vulnerability(BaseModel):
    id: str
    service: str
    port: Optional[int] = None
    version: Optional[str] = None
    severity: str 
    description: str
    cvss_score: Union[str, float]
    cvss_vector: Optional[str] = None
    published: Optional[str] = None
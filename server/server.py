import os
import traceback
import logging
from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from bson import ObjectId

from models import ScanRequest, ScanResponse
from scanner import VulnerabilityScanner

from datetime import datetime

# Thiết lập logging
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Vulnerability Scanner API",
    description="API quét lỗ hổng bảo mật cho các mục tiêu web và máy chủ",
    version="1.0.0"
)

# Thêm CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_mongo_client():
    mongo_uri = os.environ.get("MONGO_URI", "mongodb+srv://Death:DeathA_1205@death.8wudq.mongodb.net/ThayUy?retryWrites=true&w=majority&appName=Death")
    client = MongoClient(mongo_uri)
    try:
        yield client
    finally:
        client.close()

@app.get("/", tags=["General"])
async def root():
    return {
        "message": "Welcome to Vulnerability Scanner API",
        "version": "1.0.0",
        "status": "active"
    }

@app.post("/scan", response_model=ScanResponse, tags=["Scanning"])
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks, client: MongoClient = Depends(get_mongo_client)):
    try:
        # Xử lý input ports
        if '-' in scan_request.ports:
            start, end = map(int, scan_request.ports.split('-'))
            ports = range(start, end + 1)
        else:
            ports = [int(p) for p in scan_request.ports.split(',') if p]

        # Khởi tạo scanner
        logger.info(f"Khởi tạo quét cho target: {scan_request.target}")
        scanner = VulnerabilityScanner(scan_request.target)
        report_id = str(ObjectId())

        # Lưu trạng thái ban đầu vào MongoDB
        db = client[os.environ.get("MONGO_DB", "ThayUy")]
        collection = db[os.environ.get("MONGO_COLLECTION", "scan_reports")]
        collection.insert_one({
            "_id": ObjectId(report_id),
            "scan_info": {
                "target": scan_request.target,
                "status": "pending",
                "start_time": datetime.now().isoformat()
            }
        })

        background_tasks.add_task(scanner.run_scan, ports, scan_request.output_format, report_id)
        
        return ScanResponse(
            status="success",
            report_id=report_id,  # Sẽ được cập nhật sau khi quét hoàn thành
            message=f"Quét đã bắt đầu cho {scan_request.target}. Báo cáo sẽ được lưu trong MongoDB."
        )
    except Exception as e:
        logger.error(f"Lỗi khi bắt đầu quét: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=500,
            detail=f"Không thể khởi tạo quét: {str(e)}"
        )

@app.get("/reports", tags=["Reports"])
async def get_reports(client: MongoClient = Depends(get_mongo_client)):
    """
    Lấy danh sách tất cả các báo cáo đã quét
    """
    try:
        db = client[os.environ.get("MONGO_DB", "ThayUy")]
        collection = db[os.environ.get("MONGO_COLLECTION", "scan_reports")]
        
        reports = []
        cursor = collection.find({}, {
            "scan_info": 1, 
            "open_ports": 1,
            "vulnerabilities": {"$slice": 125}  # Lấy tối đa 5 lỗ hổng cho preview
        }).sort("scan_info.timestamp", -1).limit(100)
        
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            reports.append(doc)
            
        return {
            "status": "success",
            "count": len(reports),
            "reports": reports
        }
    except Exception as e:
        logger.error(f"Lỗi khi lấy danh sách báo cáo: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Không thể lấy danh sách báo cáo: {str(e)}"
        )

@app.get("/report/{report_id}", tags=["Reports"])
async def get_report(report_id: str, client: MongoClient = Depends(get_mongo_client)):
    """
    Lấy chi tiết báo cáo quét theo ID
    """
    try:
        db = client[os.environ.get("MONGO_DB", "ThayUy")]
        collection = db[os.environ.get("MONGO_COLLECTION", "scan_reports")]
        
        report = collection.find_one({"_id": ObjectId(report_id)})
        
        if report:
            # Chuyển ObjectId thành string để trả về JSON
            report["_id"] = str(report["_id"])
            return {
                "status": "success",
                "report": report
            }
        else:
            raise HTTPException(
                status_code=404,
                detail=f"Không tìm thấy báo cáo với ID: {report_id}"
            )
    except Exception as e:
        logger.error(f"Lỗi khi lấy báo cáo: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Không thể lấy báo cáo: {str(e)}"
        )

@app.delete("/report/{report_id}", tags=["Reports"])
async def delete_report(report_id: str, client: MongoClient = Depends(get_mongo_client)):
    """
    Xóa một báo cáo quét theo ID
    """
    try:
        db = client[os.environ.get("MONGO_DB", "ThayUy")]
        collection = db[os.environ.get("MONGO_COLLECTION", "scan_reports")]
        
        result = collection.delete_one({"_id": ObjectId(report_id)})
        
        if result.deleted_count:
            return {
                "status": "success",
                "message": f"Đã xóa báo cáo với ID: {report_id}"
            }
        else:
            raise HTTPException(
                status_code=404,
                detail=f"Không tìm thấy báo cáo với ID: {report_id}"
            )
    except Exception as e:
        logger.error(f"Lỗi khi xóa báo cáo: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Không thể xóa báo cáo: {str(e)}"
        )

@app.get("/statistics", tags=["Reports"])
async def get_statistics(client: MongoClient = Depends(get_mongo_client)):
    try:
        db = client[os.environ.get("MONGO_DB", "ThayUy")]
        collection = db[os.environ.get("MONGO_COLLECTION", "scan_reports")]
        
        # Thống kê tổng số báo cáo
        total_reports = collection.count_documents({})
        
        # Thống kê lỗ hổng theo mức độ nghiêm trọng
        vulnerability_stats = collection.aggregate([
            {"$unwind": "$vulnerabilities"},
            {"$group": {
                "_id": "$vulnerabilities.severity",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}}
        ])
        
        # Thống kê dịch vụ phổ biến
        service_stats = collection.aggregate([
            {"$unwind": {"path": "$services", "preserveNullAndEmptyArrays": False}},
            {"$group": {
                "_id": "$services.name",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ])
        
        return {
            "status": "success",
            "total_reports": total_reports,
            "vulnerability_stats": list(vulnerability_stats),
            "service_stats": list(service_stats)
        }
    except Exception as e:
        logger.error(f"Lỗi khi lấy thống kê: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Không thể lấy thống kê: {str(e)}"
        )
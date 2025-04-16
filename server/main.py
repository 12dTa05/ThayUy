import sys
import argparse
import logging
import uvicorn
import os
from datetime import datetime
from scanner import VulnerabilityScanner

# Thiết lập logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("vulnerability_scanner.log")
    ]
)

logger = logging.getLogger(__name__)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Vulnerability Scanner')
    parser.add_argument('target', nargs='?', help='Mục tiêu để quét (URL hoặc IP) - bắt buộc khi chạy trực tiếp')
    parser.add_argument('--python-path', type=str, default=sys.executable,
                       help='Đường dẫn đến Python interpreter (default: hiện tại)')
    parser.add_argument('--host', type=str, default="0.0.0.0",
                       help='Host để chạy API (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8000,
                       help='Port để chạy API (default: 8000)')
    parser.add_argument('--ports', type=str, default="1-1000",
                       help='Các cổng cần quét (vd: 80,443 hoặc 1-1000)')
    parser.add_argument('--output', type=str, default="json",
                       help='Định dạng báo cáo (json, csv, text, all) - mặc định json cho MongoDB')
    parser.add_argument('--debug', action='store_true',
                       help='Bật chế độ debug với logging chi tiết hơn')
    return parser.parse_args()

def main():
    """Hàm chính của ứng dụng"""
    args = parse_arguments()
    
    # Thiết lập chế độ debug nếu được yêu cầu
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
        logger.debug("Đã bật chế độ debug")
    
    if args.target:
        # Chạy quét trực tiếp
        logger.info(f"Chạy quét trực tiếp cho mục tiêu: {args.target}")
        
        # Xử lý danh sách ports
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = range(start, end + 1)
        else:
            ports = [int(p) for p in args.ports.split(',') if p]
        
        # Khởi tạo scanner và chạy quét
        try:
            scanner = VulnerabilityScanner(args.target)
            report_id = scanner.run_scan(ports, args.output)
            logger.info(f"Quét hoàn thành. ID báo cáo: {report_id}")
        except Exception as e:
            logger.error(f"Lỗi khi chạy quét: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            sys.exit(1)
    else:
        # Chạy FastAPI server
        logger.info(f"Khởi động FastAPI với:")
        logger.info(f"Python path: {args.python_path}")
        logger.info(f"Host: {args.host}")
        logger.info(f"Port: {args.port}")
        
        import warnings
        warnings.filterwarnings("ignore")
        
        uvicorn.run(
            "server:app",
            host=args.host,
            port=args.port,
            reload=True,
            workers=1
        )

if __name__ == "__main__":
    main()
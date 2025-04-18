import React, { useEffect, useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  CircularProgress,
  Box,
  Typography,
  Alert,
} from '@mui/material';
import axios from 'axios';

const ProgressModal = ({ open, target, reportId, onClose }) => {
  const [status, setStatus] = useState('pending'); // Trạng thái quét: pending, completed, failed
  const [message, setMessage] = useState('Đang khởi tạo quét...');
  const [error, setError] = useState(null); // Lưu lỗi nếu có

  useEffect(() => {
    if (!open || !reportId) return;

    const interval = setInterval(async () => {
      const url = `http://localhost:8000/report/${reportId}`;
      console.log("📡 Gửi request tới:", url);

      try {
        const res = await axios.get(url);
        console.log("✅ Dữ liệu trả về:", res.data);

        if (res.data?.status === 'success' && res.data.report?.scan_info) {
          const scanInfo = res.data.report.scan_info;
          const currentStatus = scanInfo.status;

          setStatus(currentStatus);

          // Cập nhật thông điệp dựa trên trạng thái
          switch (currentStatus) {
            case 'pending':
              setMessage('Đang quét... Vui lòng đợi.');
              break;
            case 'completed':
              setMessage('Quét hoàn tất!');
              clearInterval(interval);
              setTimeout(() => {
                if (onClose) onClose(res.data.report); // Trả về báo cáo đầy đủ khi đóng
              }, 1200);
              break;
            case 'failed':
              setMessage('Quét thất bại.');
              setError(scanInfo.error || 'Đã xảy ra lỗi không xác định.');
              clearInterval(interval);
              setTimeout(() => {
                if (onClose) onClose(null); // Trả về null để báo lỗi
              }, 5000);
              break;
            default:
              setMessage('Trạng thái không xác định.');
          }
        }
      } catch (err) {
        console.error('❌ Lỗi khi gọi API:', err.message);
        if (err.response?.status === 404) {
          setMessage('Đang chờ dữ liệu...');
        } else {
          setStatus('failed');
          setMessage('Không thể kết nối đến server.');
          setError(err.message);
          clearInterval(interval);
          setTimeout(() => {
            if (onClose) onClose(null);
          }, 1200);
        }
      }
    }, 10000);

    return () => clearInterval(interval);
  }, [open, reportId, onClose]);

  return (
    <Dialog open={open} maxWidth="xs" fullWidth>
      <DialogTitle>Đang quét: {target}</DialogTitle>
      <DialogContent>
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 4 }}>
          {status === 'pending' && <CircularProgress />}
          <Typography sx={{ mt: 2 }}>{message}</Typography>
          {error && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {error}
            </Alert>
          )}
        </Box>
      </DialogContent>
    </Dialog>
  );
};

export default ProgressModal;
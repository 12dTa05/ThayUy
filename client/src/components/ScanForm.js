import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormHelperText,
  CircularProgress,
  Grid,
  Card,
  CardContent,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText
} from '@mui/material';
import ApiService from '../services/api';
import WebIcon from '@mui/icons-material/Web';
import DnsIcon from '@mui/icons-material/Dns';
import StorageIcon from '@mui/icons-material/Storage';
import SecurityIcon from '@mui/icons-material/Security';
import InfoIcon from '@mui/icons-material/Info';
import ProgressModal from './ProgressModal';

const ScanForm = ({ setNotification }) => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    target: '',
    ports: '1-1000',
    output_format: 'json'
  });
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [progressOpen, setProgressOpen] = useState(false);
  const [reportId, setReportId] = useState(null); // Thêm state để lưu reportId

  const validateForm = () => {
    const newErrors = {};
    if (!formData.target) {
      newErrors.target = 'Mục tiêu không được để trống';
    } else if (!isValidTarget(formData.target)) {
      newErrors.target = 'Mục tiêu phải là URL hoặc địa chỉ IP hợp lệ';
    }
    if (!formData.ports) {
      newErrors.ports = 'Danh sách cổng không được để trống';
    } else if (!isValidPorts(formData.ports)) {
      newErrors.ports = 'Định dạng cổng không hợp lệ (sử dụng 80,443 hoặc 1-1000)';
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const isValidTarget = (target) => {
    const urlPattern = /^(https?:\/\/)?([\w.-]+)\.([a-z]{2,})(\/\S*)?$/i;
    const ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    return urlPattern.test(target) || ipPattern.test(target);
  };

  const isValidPorts = (ports) => {
    const commaPattern = /^(\d+)(,\d+)*$/;
    const rangePattern = /^\d+-\d+$/;
    return commaPattern.test(ports) || rangePattern.test(ports);
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
    if (errors[name]) {
      setErrors({ ...errors, [name]: undefined });
    }
  };

  const handleCloseProgress = (report) => {
    setProgressOpen(false);
    setReportId(null); // Reset reportId sau khi đóng
    if (report) {
      navigate(`/report/${reportId}`); // Điều hướng tới trang chi tiết báo cáo
    } else {
      navigate('/reports'); // Nếu thất bại, quay lại danh sách báo cáo
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validateForm()) return;

    setLoading(true);

    try {
      console.log("Sending scan data:", formData);
      const response = await ApiService.startScan(formData);
      console.log("Scan response:", response);

      if (response.status === 'success' && response.report_id) {
        setReportId(response.report_id); // Lưu reportId
        setProgressOpen(true); // Mở modal
        setNotification({
          open: true,
          message: 'Quét bắt đầu thành công! Kết quả sẽ sớm có sẵn.',
          severity: 'success'
        });
      } else {
        throw new Error('Phản hồi từ server không hợp lệ');
      }
    } catch (error) {
      console.error('Error submitting scan:', error);
      console.error('Error details:', error.response?.data);
      setProgressOpen(false);
      setReportId(null);
      setNotification({
        open: true,
        message: `Lỗi khi bắt đầu quét: ${error.response?.data?.detail || error.message}`,
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Typography variant="h4" gutterBottom component="div" sx={{ mb: 4 }}>
        Quét lỗ hổng mới
      </Typography>
      <Grid container spacing={4}>
        <Grid item xs={12} md={7}>
          <Paper sx={{ p: 3 }}>
            <form onSubmit={handleSubmit}>
              <TextField
                fullWidth
                label="Mục tiêu (URL hoặc địa chỉ IP)"
                name="target"
                value={formData.target}
                onChange={handleChange}
                margin="normal"
                variant="outlined"
                error={!!errors.target}
                helperText={errors.target}
                placeholder="ví dụ: example.com hoặc 192.168.1.1"
                required
              />
              <TextField
                fullWidth
                label="Cổng cần quét"
                name="ports"
                value={formData.ports}
                onChange={handleChange}
                margin="normal"
                variant="outlined"
                error={!!errors.ports}
                helperText={errors.ports || "Định dạng: 80,443 hoặc 1-1000"}
                placeholder="ví dụ: 80,443 hoặc 1-1000"
              />
              <FormControl fullWidth margin="normal" variant="outlined">
                <InputLabel id="output-format-label">Định dạng đầu ra</InputLabel>
                <Select
                  labelId="output-format-label"
                  name="output_format"
                  value={formData.output_format}
                  onChange={handleChange}
                  label="Định dạng đầu ra"
                >
                  <MenuItem value="json">JSON</MenuItem>
                  <MenuItem value="csv">CSV</MenuItem>
                  <MenuItem value="text">Text</MenuItem>
                  <MenuItem value="all">Tất cả</MenuItem>
                </Select>
                <FormHelperText>Chọn định dạng cho báo cáo đầu ra</FormHelperText>
              </FormControl>
              <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end' }}>
                <Button
                  variant="contained"
                  color="primary"
                  type="submit"
                  disabled={loading}
                  startIcon={loading ? <CircularProgress size={20} /> : <SecurityIcon />}
                  size="large"
                >
                  {loading ? 'Đang xử lý...' : 'Bắt đầu quét'}
                </Button>
              </Box>
            </form>
          </Paper>
        </Grid>
        <Grid item xs={12} md={5}>
          {/* Info Cards giữ nguyên */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Chức năng quét
              </Typography>
              <Divider sx={{ mb: 2 }} />
              <List dense>
                <ListItem>
                  <ListItemIcon><WebIcon color="primary" /></ListItemIcon>
                  <ListItemText primary="Quét Web" secondary="Phát hiện lỗ hổng trong ứng dụng web và máy chủ" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><DnsIcon color="primary" /></ListItemIcon>
                  <ListItemText primary="Phân tích DNS" secondary="Kiểm tra cấu hình DNS và phát hiện vấn đề" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><StorageIcon color="primary" /></ListItemIcon>
                  <ListItemText primary="Kiểm tra dịch vụ" secondary="Phát hiện dịch vụ đang chạy và các lỗ hổng liên quan" />
                </ListItem>
              </List>
            </CardContent>
          </Card>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                <InfoIcon color="info" sx={{ mr: 1 }} /> Lưu ý
              </Typography>
              <Divider sx={{ mb: 2 }} />
              <Typography variant="body2" color="text.secondary" paragraph>
                Quá trình quét có thể mất đến vài phút tùy thuộc vào mục tiêu và phạm vi quét.
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Kết quả quét sẽ được lưu trong cơ sở dữ liệu và bạn có thể xem chúng trong trang "Báo cáo".
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Quét chỉ nên được thực hiện đối với hệ thống mà bạn có quyền kiểm tra.
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
      <ProgressModal 
        open={progressOpen} 
        target={formData.target}
        reportId={reportId} // Truyền reportId
        onClose={handleCloseProgress}
      />
    </Box>
  );
};

export default ScanForm;
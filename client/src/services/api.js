import axios from 'axios';

// Tạo instance axios với URL cơ sở
const API = axios.create({
  baseURL: 'http://localhost:8000'
});

// Dịch vụ API để tương tác với Python API
const ApiService = {
  // Kiểm tra trạng thái API
  checkStatus: async () => {
    try {
      const response = await API.get('/');
      return response.data;
    } catch (error) {
      console.error('Error checking API status:', error);
      throw error;
    }
  },

  // Bắt đầu quét mục tiêu mới
  startScan: async (scanData) => {
    try {
      const response = await axios.post(`http://localhost:8000/scan`, scanData);
      return response.data;
    } catch (error) {
      console.error('Error starting scan:', error);
      throw error;
    }
  },

  // Lấy tất cả báo cáo
  getReports: async () => {
    try {
      const response = await API.get('/reports');
      return response.data;
    } catch (error) {
      console.error('Error fetching reports:', error);
      throw error;
    }
  },

  // Lấy chi tiết báo cáo theo ID
  getReportById: async (reportId) => {
    try {
      const response = await API.get(`/report/${reportId}`);
      return response.data;
    } catch (error) {
      console.error(`Error fetching report with ID ${reportId}:`, error);
      throw error;
    }
  },

  // Xóa báo cáo theo ID
  deleteReport: async (reportId) => {
    try {
      const response = await API.delete(`/report/${reportId}`);
      return response.data;
    } catch (error) {
      console.error(`Error deleting report with ID ${reportId}:`, error);
      throw error;
    }
  },

  // Lấy thống kê tổng hợp
  getStatistics: async () => {
    try {
      const response = await API.get('/statistics');
      return response.data;
    } catch (error) {
      console.error('Error fetching statistics:', error);
      throw error;
    }
  }
};

export default ApiService;
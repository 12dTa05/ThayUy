import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Box from '@mui/material/Box';
import CircularProgress from '@mui/material/CircularProgress';
import Snackbar from '@mui/material/Snackbar';
import Alert from '@mui/material/Alert';

// Components
import Header from './components/Header';
import Footer from './components/Footer';
// import Dashboard from './components/Dashboard';
import ReportsList from './components/ReportsList';
import ReportDetails from './components/ReportDetails';
import ScanForm from './components/ScanForm';
import Statistics from './components/Statistics';

// API Service
import ApiService from './services/api';

// Theme configuration
const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#3f51b5',
    },
    secondary: {
      main: '#f50057',
    },
    background: {
      default: '#121212',
      paper: '#1e1e1e',
    },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
  },
});

function App() {
  const [apiStatus, setApiStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notification, setNotification] = useState({
    open: false,
    message: '',
    severity: 'info'
  });

  // Kiểm tra trạng thái API khi ứng dụng khởi động
  useEffect(() => {
    const checkApiStatus = async () => {
      try {
        const status = await ApiService.checkStatus();
        setApiStatus(status);
        setNotification({
          open: true,
          message: 'Kết nối đến API thành công!',
          severity: 'success'
        });
      } catch (error) {
        console.error('Không thể kết nối đến API:', error);
        setNotification({
          open: true,
          message: 'Không thể kết nối đến API. Vui lòng kiểm tra server.',
          severity: 'error'
        });
      } finally {
        setLoading(false);
      }
    };

    checkApiStatus();
  }, []);

  // Xử lý đóng thông báo
  const handleCloseNotification = (event, reason) => {
    if (reason === 'clickaway') {
      return;
    }
    setNotification({ ...notification, open: false });
  };

  // Hiển thị màn hình loading trong khi kiểm tra trạng thái API
  if (loading) {
    return (
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Box
          sx={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            minHeight: '100vh',
            textAlign: 'center',
            p: 4
          }}
        >
          <CircularProgress size={60} thickness={4} />
          <Box sx={{ mt: 2 }}>Đang kết nối đến API...</Box>
        </Box>
      </ThemeProvider>
    );
  }

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <Box
          sx={{
            display: 'flex',
            flexDirection: 'column',
            minHeight: '100vh',
          }}
        >
          <Header apiStatus={apiStatus} />
          <Box
            component="main"
            sx={{
              flexGrow: 1,
              p: 3,
              backgroundColor: 'background.default'
            }}
          >
            <Routes>
              <Route path="/" element={<ReportsList setNotification={setNotification} />} />
              <Route path="/scan" element={<ScanForm setNotification={setNotification} />} />
              <Route path="/reports" element={<ReportsList setNotification={setNotification} />} />
              <Route path="/report/:id" element={<ReportDetails setNotification={setNotification} />} />
              <Route path="/statistics" element={<Statistics setNotification={setNotification} />} />
            </Routes>
          </Box>
          <Footer />

          {/* Notification Snackbar */}
          <Snackbar 
            open={notification.open} 
            autoHideDuration={6000} 
            onClose={handleCloseNotification}
            anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
          >
            <Alert 
              onClose={handleCloseNotification} 
              severity={notification.severity}
              sx={{ width: '100%' }}
            >
              {notification.message}
            </Alert>
          </Snackbar>
        </Box>
      </Router>
    </ThemeProvider>
  );
}

export default App;
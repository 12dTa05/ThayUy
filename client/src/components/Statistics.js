import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Paper,
  Grid,
  Card,
  CardContent,
  CircularProgress,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon
} from '@mui/material';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend
} from 'chart.js';
import { Bar, Pie } from 'react-chartjs-2';
import WarningIcon from '@mui/icons-material/Warning';
import ComputerIcon from '@mui/icons-material/Computer';
import StorageIcon from '@mui/icons-material/Storage';
import ApiService from '../services/api';

// Register ChartJS components
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend
);

const Statistics = ({ setNotification }) => {
  const [statistics, setStatistics] = useState(null);
  const [loading, setLoading] = useState(true);

  // Color palettes for charts
  const severityColors = {
    'Cao': 'rgba(244, 67, 54, 0.7)',
    'High': 'rgba(244, 67, 54, 0.7)',
    'Critical': 'rgba(244, 67, 54, 0.7)',
    'Trung bình': 'rgba(255, 152, 0, 0.7)',
    'Medium': 'rgba(255, 152, 0, 0.7)',
    'Thấp': 'rgba(3, 169, 244, 0.7)',
    'Low': 'rgba(3, 169, 244, 0.7)',
    'Information': 'rgba(76, 175, 80, 0.7)',
    'Không xác định': 'rgba(158, 158, 158, 0.7)'
  };

  const serviceColors = [
    'rgba(63, 81, 181, 0.7)',
    'rgba(103, 58, 183, 0.7)',
    'rgba(233, 30, 99, 0.7)',
    'rgba(156, 39, 176, 0.7)',
    'rgba(33, 150, 243, 0.7)',
    'rgba(0, 188, 212, 0.7)',
    'rgba(0, 150, 136, 0.7)',
    'rgba(139, 195, 74, 0.7)',
    'rgba(205, 220, 57, 0.7)',
    'rgba(255, 235, 59, 0.7)'
  ];

  // Load statistics data
  useEffect(() => {
    const fetchStatistics = async () => {
      try {
        setLoading(true);
        const response = await ApiService.getStatistics();
        
        if (response.status === 'success') {
          setStatistics(response);
        } else {
          throw new Error('Failed to fetch statistics');
        }
      } catch (error) {
        console.error('Error fetching statistics:', error);
        setNotification({
          open: true,
          message: 'Error loading statistics. Please try again.',
          severity: 'error'
        });
      } finally {
        setLoading(false);
      }
    };

    fetchStatistics();
  }, [setNotification]);

  // Prepare vulnerability severity chart data
  const getVulnerabilitySeverityData = () => {
    if (!statistics || !statistics.vulnerability_stats) {
      return {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: []
        }]
      };
    }

    return {
      labels: statistics.vulnerability_stats.map(stat => stat._id || 'Unknown'),
      datasets: [{
        label: 'Số lỗ hổng',
        data: statistics.vulnerability_stats.map(stat => stat.count),
        backgroundColor: statistics.vulnerability_stats.map(stat => severityColors[stat._id] || 'rgba(158, 158, 158, 0.7)'),
        borderWidth: 1
      }]
    };
  };

  // Prepare service statistics chart data
  const getServiceStatsData = () => {
    if (!statistics || !statistics.service_stats) {
      return {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: []
        }]
      };
    }

    return {
      labels: statistics.service_stats.map(stat => stat._id || 'Unknown'),
      datasets: [{
        label: 'Số lượng',
        data: statistics.service_stats.map(stat => stat.count),
        backgroundColor: serviceColors.slice(0, statistics.service_stats.length),
        borderWidth: 1
      }]
    };
  };

  // Loading state
  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  // Error state
  if (!statistics) {
    return (
      <Box sx={{ textAlign: 'center', my: 4 }}>
        <Typography variant="h5" color="error" gutterBottom>
          Không thể tải thống kê
        </Typography>
        <Typography color="text.secondary">
          Vui lòng thử lại sau hoặc liên hệ quản trị viên.
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Typography variant="h4" gutterBottom component="div" sx={{ mb: 4 }}>
        Thống kê hệ thống
      </Typography>
      
      {/* Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={4}>
          <Card sx={{ height: '100%', bgcolor: 'primary.dark', color: 'white' }}>
            <CardContent sx={{ pb: 2 }}>
              <ComputerIcon sx={{ fontSize: 40, mb: 1, opacity: 0.8 }} />
              <Typography variant="h4" component="div">
                {statistics.total_reports || 0}
              </Typography>
              <Typography sx={{ opacity: 0.8 }}>
                Tổng số mục tiêu đã quét
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={4}>
          <Card sx={{ height: '100%', bgcolor: 'warning.dark', color: 'white' }}>
            <CardContent sx={{ pb: 2 }}>
              <WarningIcon sx={{ fontSize: 40, mb: 1, opacity: 0.8 }} />
              <Typography variant="h4" component="div">
                {statistics.vulnerability_stats?.reduce((total, stat) => total + stat.count, 0) || 0}
              </Typography>
              <Typography sx={{ opacity: 0.8 }}>
                Tổng số lỗ hổng đã phát hiện
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={4}>
          <Card sx={{ height: '100%', bgcolor: 'info.dark', color: 'white' }}>
            <CardContent sx={{ pb: 2 }}>
              <StorageIcon sx={{ fontSize: 40, mb: 1, opacity: 0.8 }} />
              <Typography variant="h4" component="div">
                {statistics.service_stats?.reduce((total, stat) => total + stat.count, 0) || 0}
              </Typography>
              <Typography sx={{ opacity: 0.8 }}>
                Tổng số dịch vụ đã phát hiện
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
      
      {/* Charts */}
      <Grid container spacing={3}>
        {/* Vulnerabilities by Severity */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              Lỗ hổng theo mức độ nghiêm trọng
            </Typography>
            <Divider sx={{ mb: 3 }} />
            
            {statistics.vulnerability_stats && statistics.vulnerability_stats.length > 0 ? (
              <Box sx={{ height: 300, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Pie 
                  data={getVulnerabilitySeverityData()} 
                  options={{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                      legend: {
                        position: 'right',
                      },
                      tooltip: {
                        callbacks: {
                          label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                          }
                        }
                      }
                    }
                  }}
                />
              </Box>
            ) : (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <Typography color="text.secondary">
                  Không có dữ liệu lỗ hổng.
                </Typography>
              </Box>
            )}
            
            {statistics.vulnerability_stats && statistics.vulnerability_stats.length > 0 && (
              <List dense sx={{ mt: 2 }}>
                {statistics.vulnerability_stats.map((stat, index) => (
                  <ListItem key={index}>
                    <ListItemIcon>
                      <Box 
                        sx={{ 
                          width: 16, 
                          height: 16, 
                          borderRadius: '50%', 
                          bgcolor: severityColors[stat._id] || 'grey' 
                        }} 
                      />
                    </ListItemIcon>
                    <ListItemText 
                      primary={`${stat._id || 'Unknown'}: ${stat.count}`} 
                    />
                  </ListItem>
                ))}
              </List>
            )}
          </Paper>
        </Grid>
        
        {/* Top Services */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              Dịch vụ phổ biến nhất
            </Typography>
            <Divider sx={{ mb: 3 }} />
            
            {statistics.service_stats && statistics.service_stats.length > 0 ? (
              <Box sx={{ height: 300 }}>
                <Bar 
                  data={getServiceStatsData()} 
                  options={{
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                      legend: {
                        display: false,
                      }
                    },
                    scales: {
                      x: {
                        beginAtZero: true,
                        title: {
                          display: true,
                          text: 'Số lượng'
                        }
                      }
                    }
                  }}
                />
              </Box>
            ) : (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <Typography color="text.secondary">
                  Không có dữ liệu dịch vụ.
                </Typography>
              </Box>
            )}
          </Paper>
        </Grid>
        
        {/* Additional Statistics & Info */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Thông tin thêm
            </Typography>
            <Divider sx={{ mb: 3 }} />
            
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  Các lỗ hổng nghiêm trọng nhất
                </Typography>
                
                {statistics.vulnerability_stats && 
                 statistics.vulnerability_stats.some(stat => 
                   stat._id === 'Cao' || stat._id === 'High' || stat._id === 'Critical') ? (
                  <List dense>
                    {statistics.vulnerability_stats
                      .filter(stat => 
                        stat._id === 'Cao' || stat._id === 'High' || stat._id === 'Critical')
                      .map((stat, index) => (
                        <ListItem key={index}>
                          <ListItemIcon>
                            <WarningIcon color="error" />
                          </ListItemIcon>
                          <ListItemText 
                            primary={`${stat._id}`} 
                            secondary={`${stat.count} lỗ hổng`} 
                          />
                        </ListItem>
                      ))}
                  </List>
                ) : (
                  <Typography color="text.secondary" sx={{ ml: 2 }}>
                    Không tìm thấy lỗ hổng nghiêm trọng.
                  </Typography>
                )}
              </Grid>
              
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  Dịch vụ phổ biến nhất
                </Typography>
                
                {statistics.service_stats && statistics.service_stats.length > 0 ? (
                  <List dense>
                    {statistics.service_stats.slice(0, 5).map((stat, index) => (
                      <ListItem key={index}>
                        <ListItemIcon>
                          <StorageIcon color="primary" />
                        </ListItemIcon>
                        <ListItemText 
                          primary={`${stat._id || 'Unknown'}`} 
                          secondary={`${stat.count} cổng`} 
                        />
                      </ListItem>
                    ))}
                  </List>
                ) : (
                  <Typography color="text.secondary" sx={{ ml: 2 }}>
                    Không có dữ liệu dịch vụ.
                  </Typography>
                )}
              </Grid>
            </Grid>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Statistics;
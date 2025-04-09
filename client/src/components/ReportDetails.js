import React, { useState, useEffect } from 'react';
import { useParams, Link as RouterLink } from 'react-router-dom';
import {
  Box,
  Typography,
  Paper,
  Grid,
  Tabs,
  Tab,
  CircularProgress,
  Chip,
  Button,
  List,
  ListItem,
  ListItemText,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Card,
  CardContent,
  IconButton,
  Tooltip
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import WarningIcon from '@mui/icons-material/Warning';
import SecurityIcon from '@mui/icons-material/Security';
import InfoIcon from '@mui/icons-material/Info';
import DnsIcon from '@mui/icons-material/Dns';
import StorageIcon from '@mui/icons-material/Storage';
import LanIcon from '@mui/icons-material/Lan';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ApiService from '../services/api';

// Tab Panel component
function TabPanel(props) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`scan-tabpanel-${index}`}
      aria-labelledby={`scan-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

const ReportDetails = ({ setNotification }) => {
  const { id } = useParams();
  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [tabValue, setTabValue] = useState(0);

  // Load report data
  useEffect(() => {
    const fetchReportData = async () => {
      try {
        setLoading(true);
        const response = await ApiService.getReportById(id);
        
        if (response.status === 'success') {
          setReportData(response.report);
        } else {
          throw new Error('Failed to fetch report data');
        }
      } catch (error) {
        console.error('Error fetching report:', error);
        setNotification({
          open: true,
          message: 'Error loading report data. Please try again.',
          severity: 'error'
        });
      } finally {
        setLoading(false);
      }
    };

    if (id) {
      fetchReportData();
    }
  }, [id, setNotification]);

  // Handle tab change
  const handleTabChange = (event, newValue) => {
    setTabValue(newValue);
  };

  // Format timestamp
  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'N/A';
    
    try {
      const date = new Date(timestamp);
      return date.toLocaleString();
    } catch (e) {
      return timestamp;
    }
  };

  // Get severity color
  const getSeverityColor = (severity) => {
    const severityMap = {
      'Cao': 'error',
      'High': 'error',
      'Critical': 'error',
      'Trung bình': 'warning',
      'Medium': 'warning',
      'Thấp': 'info',
      'Low': 'info',
      'Information': 'success',
      'Không xác định': 'default'
    };
    
    return severityMap[severity] || 'default';
  };

  // Determine overall severity
  const getOverallSeverity = () => {
    if (!reportData || !reportData.vulnerabilities || reportData.vulnerabilities.length === 0) {
      return { label: 'An toàn', color: 'success' };
    }
    
    if (reportData.vulnerabilities.some(v => 
      v.severity === 'Cao' || 
      v.severity === 'High' || 
      v.severity === 'Critical')) {
      return { label: 'Cao', color: 'error' };
    }
    
    if (reportData.vulnerabilities.some(v => 
      v.severity === 'Trung bình' || 
      v.severity === 'Medium')) {
      return { label: 'Trung bình', color: 'warning' };
    }
    
    return { label: 'Thấp', color: 'info' };
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
  if (!reportData) {
    return (
      <Box sx={{ textAlign: 'center', my: 4 }}>
        <Typography variant="h5" color="error" gutterBottom>
          Không thể tải báo cáo
        </Typography>
        <Button 
          variant="contained" 
          component={RouterLink} 
          to="/reports"
          startIcon={<ArrowBackIcon />}
        >
          Quay lại danh sách báo cáo
        </Button>
      </Box>
    );
  }

  const severity = getOverallSeverity();

  return (
    <Box sx={{ flexGrow: 1 }}>
      {/* Header with back button */}
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <Button 
          component={RouterLink} 
          to="/reports" 
          startIcon={<ArrowBackIcon />}
          sx={{ mr: 2 }}
        >
          Quay lại
        </Button>
        <Typography variant="h4" component="div">
          Chi tiết báo cáo
        </Typography>
      </Box>

      {/* Summary Card */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <Typography variant="h5" gutterBottom>
              {reportData.scan_info?.target || 'Unknown Target'}
            </Typography>
            <Typography variant="body1" color="text.secondary" gutterBottom>
              IP: {reportData.scan_info?.ip_address || 'N/A'}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Hostname: {reportData.scan_info?.hostname || reportData.scan_info?.ip_address || 'N/A'}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Thời gian quét: {formatTimestamp(reportData.scan_info?.scan_time)}
            </Typography>
          </Grid>
          <Grid item xs={12} md={6} sx={{ display: 'flex', flexDirection: 'column', alignItems: { xs: 'flex-start', md: 'flex-end' } }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
              <Typography variant="body1" sx={{ mr: 1 }}>
                Mức độ nghiêm trọng:
              </Typography>
              <Chip 
                label={severity.label} 
                color={severity.color} 
                icon={<WarningIcon />}
              />
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
              <Typography variant="body1" sx={{ mr: 1 }}>
                Lỗ hổng:
              </Typography>
              <Chip 
                label={`${reportData.vulnerabilities?.length || 0} phát hiện`}
                color={reportData.vulnerabilities?.length > 0 ? 'warning' : 'success'}
              />
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <Typography variant="body1" sx={{ mr: 1 }}>
                Cổng mở:
              </Typography>
              <Chip 
                label={`${reportData.open_ports?.length || 0} cổng`}
                color="primary"
              />
            </Box>
          </Grid>
        </Grid>
      </Paper>

      {/* Tabs Navigation */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={tabValue}
          onChange={handleTabChange}
          variant="scrollable"
          scrollButtons="auto"
          aria-label="report tabs"
        >
          <Tab label="Tổng quan" icon={<InfoIcon />} iconPosition="start" />
          <Tab label="Lỗ hổng" icon={<WarningIcon />} iconPosition="start" />
          <Tab label="Dịch vụ & Cổng" icon={<StorageIcon />} iconPosition="start" />
          <Tab label="Thông tin DNS" icon={<DnsIcon />} iconPosition="start" />
          <Tab label="Công nghệ" icon={<LanIcon />} iconPosition="start" />
        </Tabs>

        {/* Overview Tab */}
        <TabPanel value={tabValue} index={0}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Thông tin chung
                  </Typography>
                  <Divider sx={{ mb: 2 }} />
                  <List dense>
                    <ListItem>
                      <ListItemText 
                        primary="Mục tiêu" 
                        secondary={reportData.scan_info?.target || 'N/A'} 
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText 
                        primary="Địa chỉ IP" 
                        secondary={reportData.scan_info?.ip_address || 'N/A'} 
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText 
                        primary="Hostname" 
                        secondary={reportData.scan_info?.hostname || 'N/A'} 
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText 
                        primary="Thời gian quét" 
                        secondary={formatTimestamp(reportData.scan_info?.scan_time)} 
                      />
                    </ListItem>
                  </List>
                </CardContent>
              </Card>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Thống kê
                  </Typography>
                  <Divider sx={{ mb: 2 }} />
                  <List dense>
                    <ListItem>
                      <ListItemText 
                        primary="Cổng mở" 
                        secondary={`${reportData.open_ports?.length || 0} cổng`} 
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText 
                        primary="Dịch vụ phát hiện" 
                        secondary={`${Object.keys(reportData.services || {}).length} dịch vụ`} 
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText 
                        primary="Công nghệ phát hiện" 
                        secondary={`${reportData.technologies?.length || 0} công nghệ`} 
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText 
                        primary="Lỗ hổng" 
                        secondary={`${reportData.vulnerabilities?.length || 0} lỗ hổng`} 
                      />
                    </ListItem>
                  </List>
                </CardContent>
              </Card>
            </Grid>
            
            {/* Top Vulnerabilities */}
            {reportData.vulnerabilities && reportData.vulnerabilities.length > 0 && (
              <Grid item xs={12}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Lỗ hổng nghiêm trọng nhất
                    </Typography>
                    <Divider sx={{ mb: 2 }} />
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>ID</TableCell>
                            <TableCell>Mức độ</TableCell>
                            <TableCell>Dịch vụ</TableCell>
                            <TableCell>Điểm CVSS</TableCell>
                            <TableCell>Mô tả</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {reportData.vulnerabilities
                            .sort((a, b) => {
                              const severityOrder = { 'Cao': 3, 'High': 3, 'Critical': 3, 'Trung bình': 2, 'Medium': 2, 'Thấp': 1, 'Low': 1 };
                              return (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
                            })
                            .slice(0, 5)
                            .map((vuln, index) => (
                              <TableRow key={index}>
                                <TableCell>{vuln.id}</TableCell>
                                <TableCell>
                                  <Chip 
                                    label={vuln.severity} 
                                    color={getSeverityColor(vuln.severity)} 
                                    size="small"
                                  />
                                </TableCell>
                                <TableCell>{vuln.service}</TableCell>
                                <TableCell>{vuln.cvss_score}</TableCell>
                                <TableCell>
                                  {vuln.description?.length > 100 
                                    ? `${vuln.description.substring(0, 100)}...` 
                                    : vuln.description}
                                </TableCell>
                              </TableRow>
                            ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                    {reportData.vulnerabilities.length > 5 && (
                      <Box sx={{ mt: 2, textAlign: 'center' }}>
                        <Button 
                          variant="text" 
                          onClick={() => setTabValue(1)}
                        >
                          Xem tất cả {reportData.vulnerabilities.length} lỗ hổng
                        </Button>
                      </Box>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            )}
          </Grid>
        </TabPanel>

        {/* Vulnerabilities Tab */}
        <TabPanel value={tabValue} index={1}>
          {reportData.vulnerabilities && reportData.vulnerabilities.length > 0 ? (
            <Box>
              <Typography variant="h6" gutterBottom>
                Danh sách lỗ hổng ({reportData.vulnerabilities.length})
              </Typography>
              <Divider sx={{ mb: 3 }} />
              
              {reportData.vulnerabilities
                .sort((a, b) => {
                  const severityOrder = { 'Cao': 3, 'High': 3, 'Critical': 3, 'Trung bình': 2, 'Medium': 2, 'Thấp': 1, 'Low': 1 };
                  return (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
                })
                .map((vuln, index) => (
                  <Accordion key={index} sx={{ mb: 1 }}>
                    <AccordionSummary
                      expandIcon={<ExpandMoreIcon />}
                      aria-controls={`vuln-content-${index}`}
                      id={`vuln-header-${index}`}
                    >
                      <Grid container spacing={2} alignItems="center">
                        <Grid item xs={12} sm={3}>
                          <Typography sx={{ fontWeight: 'bold' }}>{vuln.id}</Typography>
                        </Grid>
                        <Grid item xs={6} sm={3}>
                          <Chip 
                            label={vuln.service} 
                            size="small" 
                            variant="outlined"
                          />
                        </Grid>
                        <Grid item xs={6} sm={3}>
                          <Chip 
                            label={vuln.severity} 
                            color={getSeverityColor(vuln.severity)} 
                            size="small"
                          />
                        </Grid>
                        <Grid item xs={6} sm={3}>
                          <Typography>CVSS: {vuln.cvss_score}</Typography>
                        </Grid>
                      </Grid>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ mb: 2 }}>
                        {vuln.description}
                      </Typography>
                      <Grid container spacing={2}>
                        {vuln.port && (
                          <Grid item xs={12} sm={4}>
                            <Typography variant="body2" color="text.secondary">
                              <strong>Cổng:</strong> {vuln.port}
                            </Typography>
                          </Grid>
                        )}
                        {vuln.version && (
                          <Grid item xs={12} sm={4}>
                            <Typography variant="body2" color="text.secondary">
                              <strong>Phiên bản:</strong> {vuln.version}
                            </Typography>
                          </Grid>
                        )}
                        {vuln.published && (
                          <Grid item xs={12} sm={4}>
                            <Typography variant="body2" color="text.secondary">
                              <strong>Công bố:</strong> {formatTimestamp(vuln.published)}
                            </Typography>
                          </Grid>
                        )}
                      </Grid>
                    </AccordionDetails>
                  </Accordion>
                ))}
            </Box>
          ) : (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <SecurityIcon color="success" sx={{ fontSize: 60, mb: 2, opacity: 0.7 }} />
              <Typography variant="h6" gutterBottom>
                Không phát hiện lỗ hổng
              </Typography>
              <Typography color="text.secondary">
                Không tìm thấy lỗ hổng bảo mật nào cho mục tiêu này.
              </Typography>
            </Box>
          )}
        </TabPanel>

        {/* Services & Ports Tab */}
        <TabPanel value={tabValue} index={2}>
          <Typography variant="h6" gutterBottom>
            Dịch vụ và cổng ({reportData.open_ports?.length || 0})
          </Typography>
          <Divider sx={{ mb: 3 }} />
          
          {reportData.open_ports && reportData.open_ports.length > 0 ? (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Cổng</TableCell>
                    <TableCell>Dịch vụ</TableCell>
                    <TableCell>Phiên bản</TableCell>
                    <TableCell>Giao thức</TableCell>
                    <TableCell>Thông tin thêm</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {reportData.open_ports.map((port) => {
                    const service = reportData.services[port] || {};
                    return (
                      <TableRow key={port} hover>
                        <TableCell>{port}</TableCell>
                        <TableCell>{service.name || 'N/A'}</TableCell>
                        <TableCell>{service.version || 'N/A'}</TableCell>
                        <TableCell>{service.protocol || 'tcp'}</TableCell>
                        <TableCell>
                          {service.banner ? (
                            <Tooltip title={service.banner}>
                              <IconButton size="small">
                                <InfoIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          ) : service.product ? service.product : 'N/A'}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Typography variant="body1" color="text.secondary">
                Không tìm thấy cổng mở nào.
              </Typography>
            </Box>
          )}
        </TabPanel>

        {/* DNS Info Tab */}
        <TabPanel value={tabValue} index={3}>
          <Typography variant="h6" gutterBottom>
            Thông tin DNS
          </Typography>
          <Divider sx={{ mb: 3 }} />
          
          {reportData.dns_records && Object.keys(reportData.dns_records).length > 0 ? (
            <Grid container spacing={3}>
              {Object.entries(reportData.dns_records).map(([recordType, records]) => (
                <Grid item xs={12} md={6} key={recordType}>
                  <Accordion defaultExpanded>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography sx={{ fontWeight: 'bold' }}>
                        {recordType} Records ({records.length})
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <List dense>
                        {records.map((record, index) => (
                          <ListItem key={index}>
                            <ListItemText primary={record} />
                          </ListItem>
                        ))}
                      </List>
                    </AccordionDetails>
                  </Accordion>
                </Grid>
              ))}
            </Grid>
          ) : (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Typography variant="body1" color="text.secondary">
                Không có thông tin DNS nào được thu thập.
              </Typography>
            </Box>
          )}
          
          {/* WHOIS Information */}
          {reportData.whois_info && Object.keys(reportData.whois_info).length > 0 && (
            <Box sx={{ mt: 4 }}>
              <Typography variant="h6" gutterBottom>
                Thông tin WHOIS
              </Typography>
              <Divider sx={{ mb: 3 }} />
              
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableBody>
                    {Object.entries(reportData.whois_info)
                      .filter(([key, value]) => value !== null && key !== 'raw')
                      .map(([key, value]) => (
                        <TableRow key={key}>
                          <TableCell component="th" scope="row" sx={{ fontWeight: 'bold', width: '30%' }}>
                            {key.charAt(0).toUpperCase() + key.slice(1).replace(/_/g, ' ')}
                          </TableCell>
                          <TableCell>
                            {Array.isArray(value) 
                              ? value.join(', ') 
                              : value instanceof Object 
                                ? JSON.stringify(value) 
                                : String(value)}
                          </TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}
        </TabPanel>

        {/* Technologies Tab */}
        <TabPanel value={tabValue} index={4}>
          <Typography variant="h6" gutterBottom>
            Công nghệ phát hiện
          </Typography>
          <Divider sx={{ mb: 3 }} />
          
          {reportData.technologies && reportData.technologies.length > 0 ? (
            <Grid container spacing={2}>
              {reportData.technologies.map((tech, index) => {
                // Handle different technology formats from the API
                const techName = typeof tech === 'string' ? tech : tech.name || 'Unknown';
                const techVersion = typeof tech === 'object' && tech.version ? tech.version : 'N/A';
                
                return (
                  <Grid item xs={12} sm={6} md={4} key={index}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography variant="h6" component="div">
                          {techName}
                        </Typography>
                        {techVersion !== 'N/A' && (
                          <Typography variant="body2" color="text.secondary">
                            Phiên bản: {techVersion}
                          </Typography>
                        )}
                      </CardContent>
                    </Card>
                  </Grid>
                );
              })}
            </Grid>
          ) : (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Typography variant="body1" color="text.secondary">
                Không phát hiện công nghệ nào.
              </Typography>
            </Box>
          )}
          
          {/* HTTP Headers */}
          {reportData.headers && Object.keys(reportData.headers).length > 0 && (
            <Box sx={{ mt: 4 }}>
              <Typography variant="h6" gutterBottom>
                HTTP Headers
              </Typography>
              <Divider sx={{ mb: 3 }} />
              
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Header</TableCell>
                      <TableCell>Value</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {Object.entries(reportData.headers).map(([header, value]) => (
                      <TableRow key={header}>
                        <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                          {header}
                        </TableCell>
                        <TableCell>{value}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}
        </TabPanel>
      </Paper>
    </Box>
  );
}

export default ReportDetails;
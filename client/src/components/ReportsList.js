import React, { useState, useEffect } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import {
  Box,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  IconButton,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Tooltip,
  TextField,
  InputAdornment
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import VisibilityIcon from '@mui/icons-material/Visibility';
import WarningIcon from '@mui/icons-material/Warning';
import SearchIcon from '@mui/icons-material/Search';
import ApiService from '../services/api';

const ReportsList = ({ setNotification }) => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [reportToDelete, setReportToDelete] = useState(null);
  const [filter, setFilter] = useState('');
  const [filteredReports, setFilteredReports] = useState([]);

  // Load reports from API
  const loadReports = async () => {
    setLoading(true);
    try {
      const response = await ApiService.getReports();
      if (response.status === 'success') {
        setReports(response.reports);
        setFilteredReports(response.reports);
      } else {
        throw new Error('Failed to fetch reports');
      }
    } catch (error) {
      console.error('Error loading reports:', error);
      setNotification({
        open: true,
        message: 'Error loading reports. Please try again later.',
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  // Load reports on component mount
  useEffect(() => {
    loadReports();
  }, []);

  // Filter reports when search changes
  useEffect(() => {
    if (!filter) {
      setFilteredReports(reports);
      return;
    }
    
    const lowerFilter = filter.toLowerCase();
    const filtered = reports.filter(report => 
      (report.scan_info?.target && report.scan_info.target.toLowerCase().includes(lowerFilter)) ||
      (report.scan_info?.ip_address && report.scan_info.ip_address.toLowerCase().includes(lowerFilter))
    );
    
    setFilteredReports(filtered);
    setPage(0); // Reset to first page when filtering
  }, [filter, reports]);

  // Handle page change
  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  // Handle rows per page change
  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  // Open delete confirmation dialog
  const handleOpenDeleteDialog = (report) => {
    setReportToDelete(report);
    setDeleteDialogOpen(true);
  };

  // Close delete confirmation dialog
  const handleCloseDeleteDialog = () => {
    setDeleteDialogOpen(false);
    setReportToDelete(null);
  };

  // Delete report
  const handleDeleteReport = async () => {
    if (!reportToDelete) return;
    
    try {
      const response = await ApiService.deleteReport(reportToDelete._id);
      
      if (response.status === 'success') {
        // Remove deleted report from state
        setReports(reports.filter(report => report._id !== reportToDelete._id));
        setFilteredReports(filteredReports.filter(report => report._id !== reportToDelete._id));
        
        setNotification({
          open: true,
          message: 'Report deleted successfully',
          severity: 'success'
        });
      } else {
        throw new Error('Failed to delete report');
      }
    } catch (error) {
      console.error('Error deleting report:', error);
      setNotification({
        open: true,
        message: 'Error deleting report. Please try again.',
        severity: 'error'
      });
    } finally {
      handleCloseDeleteDialog();
    }
  };

  // Get total vulnerabilities count for a report
  const getVulnerabilitiesCount = (report) => {
    return report.vulnerabilities?.length || 0;
  };

  // Get severity level based on vulnerabilities
  const getSeverityLevel = (report) => {
    const vulnerabilities = report.vulnerabilities || [];
    
    if (vulnerabilities.some(v => v.severity === 'Cao' || v.severity === 'Critical' || v.severity === 'High')) {
      return { label: 'Cao', color: 'error' };
    } else if (vulnerabilities.some(v => v.severity === 'Trung bình' || v.severity === 'Medium')) {
      return { label: 'Trung bình', color: 'warning' };
    } else if (vulnerabilities.length > 0) {
      return { label: 'Thấp', color: 'info' };
    } else {
      return { label: 'An toàn', color: 'success' };
    }
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

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="div">
          Báo cáo quét
        </Typography>
        
        <Button 
          variant="contained" 
          color="primary" 
          component={RouterLink} 
          to="/scan"
        >
          Quét mới
        </Button>
      </Box>
      
      {/* Search Field */}
      <Box sx={{ mb: 3 }}>
        <TextField
          fullWidth
          variant="outlined"
          placeholder="Tìm kiếm theo mục tiêu hoặc địa chỉ IP..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon />
              </InputAdornment>
            ),
          }}
        />
      </Box>
      
      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', my: 4 }}>
          <CircularProgress />
        </Box>
      ) : filteredReports.length === 0 ? (
        <Paper sx={{ p: 3, textAlign: 'center' }}>
          <Typography variant="h6" color="text.secondary">
            Không tìm thấy báo cáo nào
          </Typography>
          <Typography color="text.secondary" sx={{ mt: 1 }}>
            {filter ? 'Thử tìm kiếm với từ khóa khác' : 'Bắt đầu quét mục tiêu đầu tiên của bạn'}
          </Typography>
          {!filter && (
            <Button 
              variant="contained" 
              color="primary" 
              component={RouterLink} 
              to="/scan"
              sx={{ mt: 2 }}
            >
              Quét mới
            </Button>
          )}
        </Paper>
      ) : (
        <Paper>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Mục tiêu</TableCell>
                  <TableCell>Địa chỉ IP</TableCell>
                  <TableCell>Thời gian quét</TableCell>
                  <TableCell align="center">Cổng mở</TableCell>
                  <TableCell align="center">Lỗ hổng</TableCell>
                  <TableCell align="center">Mức độ</TableCell>
                  <TableCell align="center">Thao tác</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredReports
                  .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                  .map((report) => {
                    const severity = getSeverityLevel(report);
                    return (
                      <TableRow key={report._id} hover>
                        <TableCell component="th" scope="row">
                          {report.scan_info?.target || 'N/A'}
                        </TableCell>
                        <TableCell>{report.scan_info?.ip_address || 'N/A'}</TableCell>
                        <TableCell>{formatTimestamp(report.scan_info?.scan_time)}</TableCell>
                        <TableCell align="center">{report.open_ports?.length || 0}</TableCell>
                        <TableCell align="center">
                          {getVulnerabilitiesCount(report) > 0 ? (
                            <Chip 
                              icon={<WarningIcon />} 
                              label={getVulnerabilitiesCount(report)} 
                              color={severity.color}
                              size="small"
                            />
                          ) : (
                            '0'
                          )}
                        </TableCell>
                        <TableCell align="center">
                          <Chip 
                            label={severity.label} 
                            color={severity.color}
                            size="small"
                          />
                        </TableCell>
                        <TableCell align="center">
                          <Tooltip title="Xem chi tiết">
                            <IconButton 
                              component={RouterLink} 
                              to={`/report/${report._id}`}
                              color="primary"
                              size="small"
                            >
                              <VisibilityIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Xóa báo cáo">
                            <IconButton 
                              onClick={() => handleOpenDeleteDialog(report)}
                              color="error"
                              size="small"
                            >
                              <DeleteIcon />
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    );
                  })}
              </TableBody>
            </Table>
          </TableContainer>
          
          <TablePagination
            rowsPerPageOptions={[5, 10, 25, 50]}
            component="div"
            count={filteredReports.length}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            labelRowsPerPage="Hàng mỗi trang:"
            labelDisplayedRows={({ from, to, count }) => `${from}-${to} của ${count}`}
          />
        </Paper>
      )}
      
      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteDialogOpen}
        onClose={handleCloseDeleteDialog}
      >
        <DialogTitle>Xác nhận xóa</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Bạn có chắc chắn muốn xóa báo cáo cho mục tiêu "{reportToDelete?.scan_info?.target || 'Unknown'}"? Hành động này không thể hoàn tác.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDeleteDialog} color="primary">
            Hủy
          </Button>
          <Button onClick={handleDeleteReport} color="error" variant="contained">
            Xóa
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ReportsList;
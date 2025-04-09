import React from 'react';
import { Box, Typography, Container, Link } from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';

const Footer = () => {
  return (
    <Box
      component="footer"
      sx={{
        py: 3,
        px: 2,
        mt: 'auto',
        backgroundColor: (theme) => theme.palette.background.paper
      }}
    >
      <Container maxWidth="lg">
        <Box
          sx={{
            display: 'flex',
            flexDirection: { xs: 'column', sm: 'row' },
            justifyContent: 'space-between',
            alignItems: 'center'
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', mb: { xs: 2, sm: 0 } }}>
            <SecurityIcon sx={{ mr: 1 }} />
            <Typography variant="body2" color="text.secondary">
              Death © {new Date().getFullYear()}
            </Typography>
          </Box>
        </Box>
      </Container>
    </Box>
  );
};

export default Footer;
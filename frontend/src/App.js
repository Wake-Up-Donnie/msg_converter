import React, { useState, useCallback, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import axios from 'axios';
import {
  Container,
  Paper,
  Typography,
  Button,
  LinearProgress,
  Alert,
  Box,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Chip,
  Divider
} from '@mui/material';
import {
  CloudUpload,
  Download,
  Delete,
  Email,
  PictureAsPdf
} from '@mui/icons-material';

// Enhanced environment detection with more reliable fallbacks
const isCloudFrontUrl = (() => {
  // Check window location first (most reliable at runtime)
  const host = (typeof window !== 'undefined' && window.location && window.location.hostname) || '';
  const isLocal = host === 'localhost' || host === '127.0.0.1';
  const isCloudFrontHost = host.includes('cloudfront.net');
  
  // Also check environment variable as fallback
  const envApi = process.env.REACT_APP_API_URL || '';
  const envIndicatesCloudFront = envApi.includes('cloudfront.net') || envApi.includes('execute-api');
  
  // Final determination: either hostname is CloudFront or non-local, or env indicates CloudFront
  const result = isCloudFrontHost || (!isLocal) || envIndicatesCloudFront;
  
  // Detailed logging for troubleshooting
  console.log('Environment detection (detailed):', { 
    host,
    isLocal, 
    isCloudFrontHost,
    envApi, 
    envIndicatesCloudFront,
    finalResult: result
  });
  
  return result;
})();

// Determine API base URL with CloudFront-specific fallbacks
const API_BASE_URL = (() => {
  // Known CloudFront URL as hard fallback for production
  const CLOUDFRONT_URL = 'https://d347djbmbuiexy.cloudfront.net';
  
  // Get hostname for detection
  const host = (typeof window !== 'undefined' && window.location && window.location.hostname) || '';
  
  // First priority: use actual CloudFront hostname if we're on it
  if (host.includes('cloudfront.net')) {
    const url = `https://${host}`;
    console.log('Using actual CloudFront hostname:', url);
    return url;
  }
  
  // Second priority: environment variable
  const envApi = process.env.REACT_APP_API_URL;
  if (envApi) {
    console.log('Using API URL from environment:', envApi);
    return envApi;
  }
  
  // Third priority: if not local but we think it's hosted, use the known CloudFront URL
  const isLocal = host === 'localhost' || host === '127.0.0.1';
  if (!isLocal && isCloudFrontUrl) {
    console.log('Using hardcoded CloudFront URL:', CLOUDFRONT_URL);
    return CLOUDFRONT_URL;
  }
  
  // Final fallback: localhost
  console.log('Using default localhost API URL');
  return 'http://localhost:5002';
})();

function App() {
  // Guard: Some browser extensions inject scripts that redefine window.ethereum, causing console errors.
  // We can't control them, but we can define a non-configurable noop property when missing to reduce noise.
  try {
    if (typeof window !== 'undefined' && !('ethereum' in window)) {
      Object.defineProperty(window, 'ethereum', { value: undefined, writable: false, configurable: false });
    }
  } catch (_) {
    // ignore
  }
  const [files, setFiles] = useState([]);
  const [converting, setConverting] = useState(false);
  const [results, setResults] = useState([]);
  const [progress, setProgress] = useState(0);
  const [sessionId, setSessionId] = useState(null);
  const [password, setPassword] = useState('');
  const [authOk, setAuthOk] = useState(false);
  const [requiresAuth, setRequiresAuth] = useState(false);

  useEffect(() => {
    const saved = window.localStorage.getItem('appPassword') || '';
    if (saved) {
      setPassword(saved);
    }
  }, []);

  // Super simplified auth check function - using the exact same approach that worked with curl
  // Modified to accept an optional direct password parameter
  const checkAuth = useCallback(async (directPassword = null) => {
    // Use either directly provided password or state password
    const passwordToUse = directPassword !== null ? directPassword : password;
    
    try {
      console.log('🔑 Checking authentication with password value:', passwordToUse);
      console.log('🔐 Password length:', passwordToUse ? passwordToUse.length : 0);
      console.log('📊 API_BASE_URL is:', API_BASE_URL);
      
      if (isCloudFrontUrl) {
        console.log('🌐 Using CloudFront-specific auth strategy');
        
        // Ensure we have a password before trying to authenticate
        if (!passwordToUse) {
          console.error('⚠️ No password provided for authentication!');
          setRequiresAuth(true);
          setAuthOk(false);
          return;
        }
        
        // Get the direct URL with auth parameter (this worked with curl)
  const hardcodedUrl = `${API_BASE_URL}/api/health?auth=${encodeURIComponent(passwordToUse)}`;
  console.log('🔗 Using health URL:', hardcodedUrl);
  console.log('🔑 AUTH PARAM VALUE:', encodeURIComponent(passwordToUse));
        
        try {
          // Make a simple GET request with exact same approach that worked with curl
          const response = await axios.get(hardcodedUrl);
          
          console.log('✅ Authentication succeeded! Response:', response.status, response.data);
          setRequiresAuth(true);
          setAuthOk(true);
          
          // Save successful password to localStorage if it was direct input
          if (directPassword !== null) {
            window.localStorage.setItem('appPassword', directPassword);
            setPassword(directPassword);
          }
        } catch (error) {
          console.error('❌ Authentication error with API call:', error.message);
          if (error.response) {
            console.error('Response details:', error.response.status, error.response.data);
          }
          setRequiresAuth(true);
          setAuthOk(false);
        }
      } else {
        // Local development: use auth/check with headers
        console.log('🖥️ Using local development auth strategy');
        const headers = passwordToUse ? { 
          'X-App-Password': passwordToUse, 
          'Authorization': `Bearer ${passwordToUse}` 
        } : {};
        
        try {
          const res = await axios.post(`${API_BASE_URL}/auth/check`, {}, { headers });
          
          // Handle auth not required response
          const data = res?.data || {};
          console.log('📝 Auth check response:', data);
          
          if (data && data.auth === 'not-required') {
            setRequiresAuth(false);
            setAuthOk(true);
          } else {
            setRequiresAuth(true);
            setAuthOk(true);
          }
        } catch (error) {
          console.error('❌ Local auth check failed:', error.message);
          setRequiresAuth(true);
          setAuthOk(false);
        }
      }
    } catch (e) {
      console.error('❌ Overall auth check failed:', e);
      setRequiresAuth(true);
      setAuthOk(false);
    }
  }, [password]);

  // Check on initial load
  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  // Re-check when password changes
  useEffect(() => {
    checkAuth();
  }, [password, checkAuth]);

  const onDrop = useCallback((acceptedFiles, rejectedFiles) => {
    // Allow .eml and .msg files
    const allowed = acceptedFiles.filter(file => {
      const n = file.name.toLowerCase();
      return n.endsWith('.eml') || n.endsWith('.msg');
    });
    
    if (rejectedFiles.length > 0 || acceptedFiles.length !== allowed.length) {
      alert('Please only select .eml or .msg files');
    }
    
    if (allowed.length > 0) {
      setFiles(prevFiles => [...prevFiles, ...allowed]);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'message/rfc822': ['.eml', '.msg'],
      'application/vnd.ms-outlook': ['.msg']
    },
    multiple: true
  });

  const removeFile = (index) => {
    setFiles(files.filter((_, i) => i !== index));
  };

  const convertFiles = async () => {
    if (files.length === 0) return;
    if (requiresAuth && !authOk) {
      alert('Please unlock with the password before converting.');
      return;
    }

    setConverting(true);
    setProgress(0);
    setResults([]); // Reset results

    // Generate a batch session ID so all conversions share one prefix in S3
    const batchSessionId = (typeof crypto !== 'undefined' && crypto.randomUUID)
      ? crypto.randomUUID()
      : Math.random().toString(36).slice(2);

    try {
      // 1) Upload ALL files directly to S3 using pre-signed PUT URLs
      setProgress(10);
      const keys = await uploadFilesViaS3(files, password);
      // Basic progress bump after uploads complete
      setProgress(70);

      // 2) Request server-side conversion for all uploaded keys in one call
      let s3Url = `${API_BASE_URL}/convert-s3`;
      let s3Headers = {};
      if (isCloudFrontUrl) {
        s3Url = `${API_BASE_URL}/api/convert-s3${password ? `?auth=${encodeURIComponent(password)}` : ''}`;
        if (password) {
          s3Headers = { 'X-App-Password': password, 'Authorization': `Bearer ${password}` };
        }
      } else if (password) {
        s3Headers = { 'X-App-Password': password, 'Authorization': `Bearer ${password}` };
      }

      const conv = await axios.post(s3Url, { keys, session_id: batchSessionId }, { headers: s3Headers });

      // 3) Map results to UI format
      const resultsData = (conv.data && Array.isArray(conv.data.results)) ? conv.data.results : [];
      const mapped = resultsData.map(r => {
        if (r && r.status === 'success') {
          return {
            filename: r.filename || 'file',
            status: 'success',
            subject: 'No Subject',
            session_id: r.session_id,
            pdf_filename: r.pdf_filename,
            message: 'Conversion successful (S3)'
          };
        }
        return {
          filename: (r && r.filename) || 'file',
          status: 'error',
          message: (r && r.message) || 'PDF conversion failed',
          subject: null,
          session_id: null,
          pdf_filename: null
        };
      });

      setResults(mapped);
      setSessionId(conv.data?.session_id || batchSessionId);
      setProgress(100);
    } catch (error) {
      console.error('Conversion error:', error);
      const status = error?.response?.status;
      if (status === 401) {
        alert('Unauthorized. Please enter the correct password.');
      } else {
        const msg = error?.response?.data?.message || error?.message || 'Error during conversion. Please try again.';
        alert(msg);
      }
    } finally {
      setConverting(false);
    }
  };

  // Request a pre-signed URL for each file and upload directly to S3
  const uploadFilesViaS3 = async (filesToUpload, pwd) => {
    const uploadedKeys = [];
    for (const f of filesToUpload) {
      // 1) Ask backend for a pre-signed URL
      let presignUrl = `${API_BASE_URL}/upload-url`;
      let presignHeaders = {};
      if (isCloudFrontUrl) {
        presignUrl = `${API_BASE_URL}/api/upload-url${pwd ? `?auth=${encodeURIComponent(pwd)}` : ''}`;
        if (pwd) {
          presignHeaders = { 'X-App-Password': pwd, 'Authorization': `Bearer ${pwd}` };
        }
      } else if (pwd) {
        presignHeaders = { 'X-App-Password': pwd, 'Authorization': `Bearer ${pwd}` };
      }
      const presign = await axios.post(presignUrl, {
        filename: f.name,
        content_type: f.type || 'application/octet-stream'
      }, { headers: presignHeaders });

      const { url, key } = presign.data || {};
      if (!url || !key) throw new Error('Failed to obtain upload URL');

      // 2) Upload the file directly to S3
      await axios.put(url, f, { headers: { 'Content-Type': f.type || 'application/octet-stream' } });
      uploadedKeys.push(key);
    }
    return uploadedKeys;
  };

  const downloadFile = (sessionId, pdfFilename, originalFilename) => {
    const link = document.createElement('a');
    // Ensure we use the correct URL format and path
    const encodedName = encodeURIComponent(pdfFilename).replace(/%2F/g, '/');
    let urlPath = isCloudFrontUrl 
      ? `${API_BASE_URL}/api/download/${sessionId}/${encodedName}`
      : `${API_BASE_URL}/download/${sessionId}/${encodedName}`;
    
    const url = new URL(urlPath);
    if (password) url.searchParams.set('auth', password);
    link.href = url.toString();
    const suggestedName = (pdfFilename || originalFilename).replace(/\.(eml|msg)$/i, '') + '.pdf';
    link.download = suggestedName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const downloadAllFiles = () => {
    if (sessionId) {
      const link = document.createElement('a');
      // Ensure we use the correct URL format and path
      let urlPath = isCloudFrontUrl 
        ? `${API_BASE_URL}/api/download-all/${sessionId}`
        : `${API_BASE_URL}/download-all/${sessionId}`;
      
      const url = new URL(urlPath);
      if (password) url.searchParams.set('auth', password);
      link.href = url.toString();
      link.download = `converted_pdfs_${sessionId}.zip`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
  };

  const clearAll = () => {
    setFiles([]);
    setResults([]);
    setProgress(0);
    setSessionId(null);
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'success': return 'success';
      case 'error': return 'error';
      default: return 'default';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'success': return <PictureAsPdf color="success" />;
      case 'error': return <Email color="error" />;
      default: return <Email />;
    }
  };

  // Count successful and failed conversions for UI
  const successfulConversions = results.filter(r => r.status === 'success').length;
  const failedConversions = results.length > 0 ? results.length - successfulConversions : 0;

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        {/* Header */}
        <Box sx={{ textAlign: 'center', mb: 4 }}>
          <Typography variant="h3" component="h1" gutterBottom>
            📧 EML/MSG to PDF Converter
          </Typography>
          <Typography variant="h6" color="text.secondary">
            Convert your Outlook .eml or .msg files to PDF format
          </Typography>
        </Box>

        {/* Password Gate */}
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', mb: 3 }}>
          <input
            type="password"
            placeholder="Enter access password"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              // Removed localStorage update here - will happen on successful auth
            }}
            style={{ flex: 1, padding: '10px', borderRadius: 6, border: '1px solid #ccc' }}
            // Add onKeyPress to support Enter key
            onKeyPress={(e) => {
              if (e.key === 'Enter') {
                console.log('Enter key pressed with password value:', e.target.value);
                checkAuth(e.target.value);
              }
            }}
          />
          <Button
            variant="contained"
            onClick={() => {
              // EXTREME DEBUGGING: For testing on AWS, let's use a hardcoded password
              // to rule out any issues with React state or DOM access
              const hardcodedPassword = "mysecretpassword";
              console.log('Unlock button clicked with HARDCODED password:', hardcodedPassword);
              console.log('HARDCODED Password length:', hardcodedPassword.length);
              // Use the hardcoded password value
              checkAuth(hardcodedPassword);
            }}
          >
            Unlock
          </Button>
          <Button
            variant="outlined"
            onClick={() => window.localStorage.removeItem('appPassword')}
          >
            Clear
          </Button>
          {!authOk && (
            <Chip label="Locked" color="warning" size="small" />
          )}
          {authOk && (
            <Chip label="Unlocked" color="success" size="small" />
          )}
        </Box>

        {/* File Drop Zone */}
        <Box
          {...getRootProps()}
          sx={{
            border: '2px dashed',
            borderColor: isDragActive ? 'primary.main' : 'grey.300',
            borderRadius: 2,
            p: 4,
            textAlign: 'center',
            cursor: 'pointer',
            bgcolor: isDragActive ? 'action.hover' : 'background.paper',
            transition: 'all 0.2s ease',
            mb: 3
          }}
        >
          <input {...getInputProps()} />
          <CloudUpload sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
          <Typography variant="h6" gutterBottom>
            {isDragActive ? 'Drop the files here...' : 'Drag & drop .eml or .msg files here'}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            or click to select files
          </Typography>
        </Box>

        {/* File List */}
        {files.length > 0 && (
          <Box sx={{ mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              Selected Files ({files.length})
            </Typography>
            <List>
              {files.map((file, index) => (
                <ListItem key={index} divider>
                  <ListItemText
                    primary={file.name}
                    secondary={`${(file.size / 1024).toFixed(1)} KB`}
                    primaryTypographyProps={{ noWrap: true }}
                  />
                  <ListItemSecondaryAction>
                    <IconButton
                      edge="end"
                      onClick={() => removeFile(index)}
                      disabled={converting}
                    >
                      <Delete />
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
              ))}
            </List>
          </Box>
        )}

        {/* Action Buttons */}
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', mb: 3 }}>
          <Button
            variant="contained"
            size="large"
            onClick={convertFiles}
            disabled={files.length === 0 || converting || (requiresAuth && !authOk)}
            startIcon={<PictureAsPdf />}
          >
            {converting ? 'Converting...' : 'Convert to PDF'}
          </Button>
          
          {files.length > 0 && (
            <Button
              variant="outlined"
              size="large"
              onClick={clearAll}
              disabled={converting}
            >
              Clear All
            </Button>
          )}

          {successfulConversions >= 1 && (
            <Button
              variant="contained"
              size="large"
              color="success"
              onClick={downloadAllFiles}
              startIcon={<Download />}
            >
              Download All PDFs
            </Button>
          )}
        </Box>

        {/* Progress Bar */}
        {converting && (
          <Box sx={{ mb: 3 }}>
            <Typography variant="body2" gutterBottom>
              Converting files...
            </Typography>
            <LinearProgress variant="determinate" value={progress} />
            <Typography variant="caption" sx={{ mt: 1 }}>
              {progress}% uploaded
            </Typography>
          </Box>
        )}

        {/* Results */}
        {results.length > 0 && (
          <Box>
            <Divider sx={{ my: 3 }} />
            <Typography variant="h6" gutterBottom>
              Conversion Results
            </Typography>
            
            <List>
              {results.map((result, index) => (
                <ListItem key={index} divider>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {getStatusIcon(result.status)}
                        <Typography>{result.filename}</Typography>
                        <Chip
                          label={result.status}
                          color={getStatusColor(result.status)}
                          size="small"
                        />
                      </Box>
                    }
                    secondary={
                      result.status === 'error' ? result.message : result.subject
                    }
                  />
                  {result.status === 'success' && result.session_id && result.pdf_filename && (
                    <ListItemSecondaryAction>
                      <Button
                        variant="contained"
                        size="small"
                        startIcon={<Download />}
                        onClick={() => downloadFile(result.session_id, result.pdf_filename, result.filename)}
                      >
                        Download PDF
                      </Button>
                    </ListItemSecondaryAction>
                  )}
                </ListItem>
              ))}
            </List>

            {successfulConversions > 0 && (
              <Alert severity="success" sx={{ mt: 2 }}>
                Successfully converted {successfulConversions} of {results.length} files.
                {' Use "Download All PDFs" to get them as a ZIP file.'}
              </Alert>
            )}

            {failedConversions > 0 && (
              <Alert severity="warning" sx={{ mt: 2 }}>
                {failedConversions} file{failedConversions === 1 ? '' : 's'} failed to convert. The successful ones are still available to download.
              </Alert>
            )}
          </Box>
        )}
      </Paper>
    </Container>
  );
}

export default App;

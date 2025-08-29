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
  // Password/auth states
  // passwordInput: what user is typing
  // validatedPassword: last successfully validated full password
  const [passwordInput, setPasswordInput] = useState('');
  const [validatedPassword, setValidatedPassword] = useState('');
  const [authOk, setAuthOk] = useState(false); // true immediately after successful validation (paired with validatedPassword)
  const [requiresAuth, setRequiresAuth] = useState(false); // true when backend requires a password
  const [authError, setAuthError] = useState('');
  const [authLoading, setAuthLoading] = useState(false);

  // Attempt silent validation of stored password on mount (without setting error states)
  useEffect(() => {
    const saved = window.localStorage.getItem('appPassword') || '';
    if (saved) {
      setPasswordInput(saved);
      (async () => {
        const ok = await attemptAuth(saved, true);
        if (ok) {
          setValidatedPassword(saved);
          setAuthOk(true);
          setRequiresAuth(true); // backend requires password
        } else {
          // clear bad stored password
          window.localStorage.removeItem('appPassword');
        }
      })();
    } else {
      // Probe whether auth is required without a password
      (async () => {
        const needAuth = await detectAuthRequirement();
        setRequiresAuth(needAuth);
        if (!needAuth) setAuthOk(true);
      })();
    }
  }, []);

  // Detect if backend requires auth (no password supplied). Returns boolean.
  const detectAuthRequirement = useCallback(async () => {
    try {
      // Use auth/check without password; backend returns auth:not-required when open.
      const url = isCloudFrontUrl ? `${API_BASE_URL}/api/auth/check` : `${API_BASE_URL}/auth/check`;
      // Backend lambda implementation expects GET; Flask version uses POST. We'll try GET then fallback.
      try {
        const res = await axios.get(url, { validateStatus: () => true });
        if (res.status === 200 && res.data?.auth === 'not-required') return false;
        if (res.status === 200 && res.data?.ok) return true; // password required but not provided -> ambiguous, treat as required
        if (res.status === 401) return true;
      } catch {
        // Fallback to POST (Flask local dev)
        const res2 = await axios.post(url.replace('/api', ''), {}, { validateStatus: () => true });
        if (res2.status === 200 && res2.data?.auth === 'not-required') return false;
        if (res2.status === 200 && res2.data?.ok) return true;
        if (res2.status === 401) return true;
      }
    } catch (e) {
      console.warn('Auth requirement probe failed:', e);
    }
    return true; // default to requiring auth for safety
  }, []);

  // Core auth attempt using provided password. silent=true suppresses user-facing error messages.
  const attemptAuth = useCallback(async (pwd, silent = false) => {
    setAuthError('');
    if (!pwd) {
      if (!silent) setAuthError('Password required');
      setAuthOk(false);
      return false;
    }
    setAuthLoading(true);
    try {
      const url = isCloudFrontUrl ? `${API_BASE_URL}/api/auth/check` : `${API_BASE_URL}/auth/check`;
      const headers = { 'X-App-Password': pwd, 'Authorization': `Bearer ${pwd}` };
      // Try GET first (Lambda path), fallback to POST (Flask local dev)
      let res = await axios.get(url, { headers, validateStatus: () => true }).catch(() => null);
      if (!res) {
        res = await axios.post(url.replace('/api', ''), {}, { headers, validateStatus: () => true }).catch(() => null);
      }
      if (res && res.status === 200 && (res.data?.ok === true)) {
        if (!silent) console.log('Auth success');
        return true;
      }
      if (!silent) setAuthError('Invalid password');
      return false;
    } catch (e) {
      if (!silent) setAuthError('Network/auth error');
      return false;
    } finally {
      setAuthLoading(false);
    }
  }, []);

  const handleUnlock = useCallback(async () => {
    const candidate = passwordInput.trim();
    if (!candidate) {
      setAuthError('Enter a password');
      return;
    }
    const ok = await attemptAuth(candidate, false);
    if (ok) {
      setValidatedPassword(candidate);
      setAuthOk(true);
      setRequiresAuth(true);
      window.localStorage.setItem('appPassword', candidate);
    } else {
      setValidatedPassword('');
      setAuthOk(false);
    }
  }, [attemptAuth, passwordInput]);

  const handleClearPassword = useCallback(() => {
    setPasswordInput('');
    setValidatedPassword('');
    setAuthOk(false);
    setAuthError('');
    window.localStorage.removeItem('appPassword');
  }, []);

  // If user edits the password after unlocking, immediately relock (remove validated password)
  useEffect(() => {
    if (validatedPassword && passwordInput !== validatedPassword) {
      setAuthOk(false);
      setValidatedPassword(''); // prevent stale password usage
    }
  }, [passwordInput, validatedPassword]);

  // Derived effective auth: must both have authOk and a validatedPassword matching current input
  const effectiveAuth = authOk && validatedPassword && passwordInput === validatedPassword;

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
    if (requiresAuth && !effectiveAuth) {
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
  const keys = await uploadFilesViaS3(files, validatedPassword);
      // Basic progress bump after uploads complete
      setProgress(70);

      // 2) Request server-side conversion for all uploaded keys in one call
      let s3Url = `${API_BASE_URL}/convert-s3`;
      let s3Headers = {};
      if (isCloudFrontUrl) {
        s3Url = `${API_BASE_URL}/api/convert-s3${validatedPassword ? `?auth=${encodeURIComponent(validatedPassword)}` : ''}`;
        if (validatedPassword) {
          s3Headers = { 'X-App-Password': validatedPassword, 'Authorization': `Bearer ${validatedPassword}` };
        }
      } else if (validatedPassword) {
        s3Headers = { 'X-App-Password': validatedPassword, 'Authorization': `Bearer ${validatedPassword}` };
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
  if (validatedPassword && effectiveAuth) url.searchParams.set('auth', validatedPassword);
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
  if (validatedPassword && effectiveAuth) url.searchParams.set('auth', validatedPassword);
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
            placeholder={requiresAuth ? 'Enter access password' : 'Password not required'}
            value={passwordInput}
            onChange={(e) => {
              setPasswordInput(e.target.value);
              setAuthError('');
            }}
            style={{ flex: 1, padding: '10px', borderRadius: 6, border: '1px solid #ccc' }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                handleUnlock();
              }
            }}
            disabled={authLoading}
          />
          <Button
            variant="contained"
            onClick={handleUnlock}
            disabled={authLoading || effectiveAuth || !passwordInput}
          >
            {authLoading ? 'Checking...' : (effectiveAuth ? 'Unlocked' : 'Unlock')}
          </Button>
          <Button
            variant="outlined"
            onClick={handleClearPassword}
            disabled={authLoading}
          >
            Clear
          </Button>
          {!effectiveAuth && (
            <Chip label={validatedPassword ? 'Modified - Relock' : 'Locked'} color="warning" size="small" />
          )}
          {effectiveAuth && <Chip label="Unlocked" color="success" size="small" />}
        </Box>
        {authError && (
          <Box sx={{ mb: 2 }}>
            <Alert severity="error" onClose={() => setAuthError('')}>{authError}</Alert>
          </Box>
        )}

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
            disabled={files.length === 0 || converting || (requiresAuth && !effectiveAuth)}
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

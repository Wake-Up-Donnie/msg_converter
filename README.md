## 🎉 **Updated for EML Files!**

The applicat### Fastest way (simple frontend, no Node required)


deploy on dev
bash aws/deploy-container.sh --env dev --password ""

deploy on prod

bash aws/deploy-container.sh --env prod --password ""

```bash
# From repo root
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt
python -m playwright install chromium

# Optional: Set password protection
export APP_PASSWORD="your-secret-password"

chmod +x start_both_servers.sh
./start_both_servers.sh
```

What you'll get:
- Backend: http://localhost:5002
- Simple frontend: http://localhost:8000
- Password protection: enabled if `APP_PASSWORD` is setcessfully updated to process **Microsoft Outlook .eml files** instead of .msg files. EML files are the standard email format and are more widely supported.

### **Key Changes Made:**
- ✅ **Native EML Processing**: Uses Python's built-in `email` library instead of extract-msg
- ✅ **Enhanced HTML Rendering**: Better parsing of email content, headers, and formatting
- ✅ **Improved Security**: HTML sanitization to remove potentially dangerous content
- ✅ **Better Compatibility**: Works with EML files from any email client
- ✅ **Robust Error Handling**: Graceful handling of malformed email files

# EML to PDF Converter Web Application

A full-stack web application that converts Outlook .eml files to PDF format. Users can drag & drop multiple .eml files and download the converted PDFs individually.

## Features

- 🎯 **Drag & Drop Interface**: Simple, intuitive file upload
- 📧 **Batch Processing**: Convert multiple .eml files at once
- 📄 **High-Quality PDFs**: Preserves email formatting and content
- 📎 **PDF Attachments**: Automatically merges PDF attachments to the email PDF
- 🔐 **Password Protection**: Optional password gate for website access
- ☁️ **Cloud-Ready**: Deployable to AWS with serverless architecture
- 🔒 **Temporary Storage**: Files auto-deleted after conversion
- 📱 **Responsive Design**: Works on desktop and mobile devices

## Architecture

### Local Development
- **Frontend**: React.js with Material-UI
- **Backend**: Python Flask with built-in email parser and Playwright
- **File Processing**: Local temporary storage

### AWS Production
- **Frontend**: React app hosted on S3 + CloudFront
- **Backend**: AWS Lambda with API Gateway
- **Storage**: S3 with lifecycle policies for auto-cleanup
- **PDF Generation**: Playwright with Chromium layer

## Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+ (only if using the React frontend)
- Git

### Fastest way (simple frontend, no Node required)
```bash
# From repo root
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt
python -m playwright install chromium

chmod +x start_both_servers.sh
./start_both_servers.sh
```

What you’ll get:
- Backend: http://localhost:5002
- Simple frontend: http://localhost:8000

Stop servers:
```bash
pkill -f 'python.*app.py'
pkill -f 'http.server.*8000'
```

### Option B: React frontend (Material‑UI)
```bash
# Backend
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt
python -m playwright install chromium

# Optional: Set password protection
export APP_PASSWORD="your-secret-password"

# Start backend (port 5002)
./start_server.sh
```

In a new terminal:
```bash
cd frontend
npm install
echo 'REACT_APP_API_URL=http://localhost:5002' > .env.local
npm start
```

Open:
- React frontend: http://localhost:3000
- Backend API: http://localhost:5002

### AWS Deployment

1. **Prerequisites**:
   - AWS CLI configured (`aws configure`)
   - SAM CLI installed
   - Appropriate AWS permissions

2. **Deploy**:
   ```bash
   # Standard deployment
   chmod +x deploy.sh
   ./deploy.sh [environment] [region]
   
   # Examples:
   ./deploy.sh dev us-east-1
   ./deploy.sh prod us-west-2
   
   # Updated deployment scripts with improved parameter handling
   ./aws/deploy-container.sh --env prod --region us-east-1  # Container-based (recommended)
   ./aws/deploy-with-custom-layer.sh --env prod             # S3 bucket layer approach
   ./aws/deploy-with-playwright.sh                          # Direct layer publication
   ```
   
   See the `DEPLOYMENT_FIX_SUMMARY.md` file for detailed information about deployment script improvements.

3. **Playwright Support for PDF Generation on AWS**:
   - For PDF conversion to work on AWS Lambda, you need to add a Playwright layer
   - Follow the instructions in [AWS_PLAYWRIGHT_INSTRUCTIONS.md](AWS_PLAYWRIGHT_INSTRUCTIONS.md)
   - The layer provides Chromium browser binaries required for HTML-to-PDF conversion

## Usage

1. **Open the web application**
2. **Enter password** (if password protection is enabled - look for the password input field)
3. **Drag & drop .eml files** onto the upload area (or click to select)
4. **Click "Convert to PDF"** to start the conversion process
5. **Download individual PDFs** once conversion is complete
6. **Download All PDFs** as a ZIP file if multiple files were converted

### Password Protection

If `APP_PASSWORD` is set in the environment:
- All API routes (except `/health` and `/twemoji/*`) require authentication
- Users see a password input field in the frontend
- Enter the correct password to unlock the "Unlocked" status
- The password is stored in browser localStorage for convenience
- Downloads include the password as a query parameter automatically

### Environment Variables

| Variable | Description |
| --- | --- |
| `APP_PASSWORD` | Optional password gate for all endpoints. |
| `AUTH_MODE` | Set to `subscription` to enable JWT-based registration and login. |
| `SECRET_KEY` | Key used to sign JWTs when `AUTH_MODE=subscription`. |

## Project Structure

```
msg_converter/
├── frontend/                 # React.js frontend
│   ├── src/
│   │   ├── App.js           # Main application component
│   │   ├── index.js         # React entry point
│   │   └── index.css        # Styles
│   ├── public/
│   │   └── index.html       # HTML template
│   └── package.json         # Node.js dependencies
├── backend/                 # Python Flask backend
│   ├── app.py              # Flask application (local dev)
│   ├── lambda_function.py  # AWS Lambda handler
│   └── requirements.txt    # Python dependencies
├── converted_files/         # Persistent output and Twemoji cache (local dev)
│   └── twemoji_cache/       # Cached Twemoji SVG assets
├── aws/                    # AWS deployment configs
│   └── template.yaml       # SAM/CloudFormation template
├── setup_local.sh         # Local development setup
├── deploy.sh              # AWS deployment script
├── start_server.sh         # Starts backend on port 5002
├── start_both_servers.sh   # Starts backend (5002) + simple frontend (8000)
└── README.md              # This file
```

## API Endpoints

- `GET /health` - Health check (no password required)
- `POST /auth/check` - Validate password (if `APP_PASSWORD` is set)
- `POST /convert` - Convert .eml files to PDF
  - **Input**: multipart/form-data with .eml files
  - **Output**: JSON with conversion results and download URLs
  - **Headers**: `X-App-Password` (if password protection enabled)
- `GET /download/<session_id>/<filename>` - Download a converted PDF
  - **Query**: `auth` parameter (if password protection enabled)
- `GET /download-all/<session_id>` - Download all PDFs as a ZIP
  - **Query**: `auth` parameter (if password protection enabled)
- `GET /twemoji/<filename>` - Serve emoji SVG assets (no password required)

## Configuration

### Environment Variables

**Backend (Local/Lambda)**:
- `S3_BUCKET`: S3 bucket for temporary storage (AWS only)
- `AWS_REGION`: AWS region (default: us-east-1)
- `APP_PASSWORD`: Optional password for website access (if set, users must enter this password)

**Frontend**:
- `REACT_APP_API_URL`: Backend API URL

## Security Considerations

⚠️ **Privacy Notice**: Email files are temporarily uploaded to the server for processing. Consider the following:

- Files are auto-deleted after 24 hours
- Use HTTPS in production
- Consider client-side processing for sensitive emails
- Implement authentication for production use

## Troubleshooting

### Local Development

**Playwright Issues**:
```bash
# Ensure browsers are installed with the right Python
source .venv/bin/activate
python -m playwright install chromium
```

**Port Conflicts**:
- Backend runs on port 5002. Free the port:
```bash
lsof -nP -iTCP:5002 -sTCP:LISTEN | awk 'NR>1 {print $2}' | xargs -r kill -9
```
- React frontend can run on another port if prompted, or start with:
```bash
PORT=3001 npm start
```

**Health Check & Smoke Tests**:
```bash
curl http://localhost:5002/health
curl -i http://localhost:5002/twemoji/1f4a7.svg | head -n 5
```

**Convert via cURL** (without UI):
```bash
curl -F "files=@/absolute/path/to/email.eml" http://localhost:5002/convert | jq
```

### AWS Deployment

**Lambda Timeout**:
- Increase timeout in `aws/template.yaml`
- Large files may need longer processing time

**PDF Conversion Issues**:
- If you see "PDF conversion requires Playwright layer" error, follow the instructions in [AWS_PLAYWRIGHT_INSTRUCTIONS.md](AWS_PLAYWRIGHT_INSTRUCTIONS.md)
- Run `./aws/create-playwright-layer.sh` to create the layer
- Run `./aws/deploy-with-playwright.sh` to deploy with the layer

**Chromium Layer Issues**:
- Ensure Chromium layer is properly packaged
- Check Lambda function size limits

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test locally
5. Submit a pull request

## License

This project is open source. See LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review AWS CloudWatch logs (for production issues)
3. Open an issue on GitHub

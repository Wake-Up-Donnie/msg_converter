# 🚀 Deploy Fixed Lambda Code

## ✅ **Issue Fixed Locally - Ready for Lambda Deployment**

The embedded .msg attachment issue has been **completely fixed** in the code. The local debug shows:

```
✅ Extracted 2 attachments using direct method:
  Attachment 1: Jacumba Construction__Water_Application_2025.pdf (199222 bytes)
  Attachment 2: Fwd: JCSD construction water sales availablity.msg.txt (2805 bytes, type: text/plain)
```

**The problem**: Your AWS Lambda is running the **old code** without the fix.

## 🔧 **Deploy the Fixed Code**

### **Option 1: Quick Deploy (Recommended)**
```bash
# Navigate to your AWS deployment directory
cd /Users/tylerbobik/Code/msg_converter/aws

# Deploy the updated Lambda function
./deploy-container.sh
```

### **Option 2: Manual Upload**
1. **Zip the backend code**:
   ```bash
   cd /Users/tylerbobik/Code/msg_converter/backend
   zip -r lambda-deployment.zip . -x "*.pyc" "__pycache__/*" ".DS_Store"
   ```

2. **Upload to AWS Lambda**:
   - Go to AWS Lambda Console
   - Find your function
   - Upload the new `lambda-deployment.zip`
   - Click "Deploy"

### **Option 3: AWS CLI Deploy**
```bash
cd /Users/tylerbobik/Code/msg_converter/backend
zip -r deployment.zip .
aws lambda update-function-code \
  --function-name YOUR_LAMBDA_FUNCTION_NAME \
  --zip-file fileb://deployment.zip
```

## 🧪 **Test After Deployment**

1. **Upload your test .msg file** to the Lambda endpoint
2. **Look for these log messages** in CloudWatch:
   ```
   PROCESSING 2 MSG ATTACHMENTS FOR PDF CONVERSION
   MSG ATTACHMENT 1: Jacumba Construction__Water_Application_2025.pdf (type: application/pdf, size: 199222 bytes)
   MSG ATTACHMENT 2: Fwd: JCSD construction water sales availablity.msg.txt (type: text/plain, size: 2805 bytes)
   Converting embedded text to PDF: Fwd: JCSD construction water sales availablity.msg.txt
   Successfully converted embedded text to PDF: Fwd: JCSD construction water sales availablity.pdf
   ```

3. **Check the final PDF** - it should now include the embedded message content as a formatted PDF page

## 🔍 **What Was Fixed**

### **Before (Bug)**:
- Lambda extracted embedded .msg as `text/plain` content
- But attachment processing **only handled**: PDF, .msg, and Office docs
- **Missing**: `text/plain` handler → text attachments ignored

### **After (Fixed)**:
- ✅ Added `text/plain` content type handler in `convert_eml_to_pdf()`
- ✅ Converts embedded message text to formatted HTML
- ✅ Uses Playwright to convert HTML to PDF
- ✅ Includes converted PDF in final merged output
- ✅ Added comprehensive debug logging

## 📊 **Expected Result**

Your final PDF will now contain **3 sections**:
1. **Main email body** (original message)
2. **Jacumba Construction Water Application PDF** (regular attachment) 
3. **Embedded Message Content PDF** (the forwarded email, nicely formatted)

The embedded `.msg` attachment will appear as a properly formatted PDF page with the message content displayed in a clean, readable layout.

## 🚨 **If Still Not Working After Deployment**

Check CloudWatch logs for:
- "PROCESSING X MSG ATTACHMENTS" - confirms attachments detected
- "Converting embedded text to PDF" - confirms text processing 
- "Successfully converted embedded text to PDF" - confirms conversion success

If you don't see these messages, the deployment may not have taken effect.

## 💾 Optional: Increase Lambda Ephemeral Storage

For workflows that handle large attachments, consider allocating more than the default 512 MB of temporary storage:

```bash
aws lambda update-function-configuration \
  --function-name YOUR_LAMBDA_FUNCTION_NAME \
  --ephemeral-storage '{"Size": 1024}'
```

The example above provisions 1 GB of `/tmp` space for the function.

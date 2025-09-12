#!/bin/bash

echo "🧪 Testing the 'No file provided' fix..."
echo "📧 Using test file: test1.eml"

# Check if test file exists
if [[ ! -f "test1.eml" ]]; then
    echo "❌ Test file test1.eml not found"
    exit 1
fi

# Test the API endpoint directly with the corrected form field name
echo "🔗 Testing CloudFront API endpoint..."
curl -X POST \
  "https://d347djbmbuiexy.cloudfront.net/api/convert?auth=mysecretpassword" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@test1.eml" \
  -v 2>&1 | grep -E "(No file provided|HTTP.*200|session_id|filename)"

echo ""
echo "✅ Test completed. If you see 'No file provided' error, the issue persists."
echo "🎯 If you see session_id and filename in response, the fix is working!"
echo ""
echo "🌐 You can now test the web interface at:"
echo "   https://d2a79jfkoxjkg0.cloudfront.net"
echo ""
echo "📝 To test the fix:"
echo "   1. Go to the website"
echo "   2. Enter password: mysecretpassword"
echo "   3. Upload one or more .eml files"
echo "   4. Click 'Convert to PDF'"
echo "   5. You should no longer see 'No file provided' error"

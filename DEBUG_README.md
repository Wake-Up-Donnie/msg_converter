# 🐛 MSG Attachment Debug Tools

This directory contains debug tools to help identify issues with .msg files that have embedded .msg attachments.

## Quick Start

1. **Run the automatic test**:
   ```bash
   python test_msg_debug.py
   ```
   This will find .msg files in your test directories and let you pick one to analyze.

2. **Or manually test a specific file**:
   ```bash
   python debug_msg_attachments.py "path/to/your/file.msg"
   ```

## Example

```bash
# Test the sample file that was found
python debug_msg_attachments.py "test_msg_files/Demoss D JCSD 8.07.25.msg"
```

## What the Debug Script Does

### 1. **Attachment Analysis**
- Opens the .msg file using extract-msg
- Lists all attachments found
- Identifies embedded .msg attachments
- Tests extracting embedded .msg files with `extractEmbedded=True`

### 2. **Backend Function Testing**
- Tests `convert_msg_bytes_to_eml_bytes()` - basic conversion
- Tests `convert_msg_bytes_to_eml_bytes_with_attachments()` - with attachment extraction
- Tests `extract_msg_attachments_with_embedded()` - direct attachment extraction
- Shows detailed output for each step

### 3. **Nested Conversion Testing**
- For each embedded .msg found, tests converting it to PDF
- Shows file sizes and success/failure at each step

## Expected Output

The script will show you:
- ✅ What's working correctly
- ❌ What's failing and why
- 📄 File sizes and details at each step
- 🔧 Technical details about attachment types

## Common Issues to Look For

1. **No attachments found** - The .msg file might not have embedded attachments
2. **extractEmbedded=True fails** - There might be an issue with the extract-msg version
3. **Conversion failures** - Backend functions might have bugs
4. **Empty data** - Attachments might be corrupted or not properly embedded

## Next Steps

After running the debug script:

1. **If attachments are found but conversion fails** - There's likely a bug in our backend code
2. **If no attachments are found** - The .msg file might not have embedded messages
3. **If extractEmbedded=True fails** - We might need to update the extract-msg library

Share the output with the development team to help identify the exact issue.
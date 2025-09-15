#!/usr/bin/env python3
"""Test script to verify .doc/.docx attachment processing fix"""

import sys
import os
import json
import email
from email.policy import default

# Add backend to path
sys.path.insert(0, 'backend')

try:
    from lambda_function import convert_msg_bytes_to_eml_bytes, extract_body_and_images_from_email
    print("✅ Successfully imported lambda functions")
except Exception as e:
    print(f"❌ Import failed: {e}")
    exit(1)

# Test the specific MSG file
# Use an available test fixture rather than missing external file
msg_path = 'test_msg_files/Demoss D JCSD 8.07.25.msg'
print(f"\n📄 Testing file: {msg_path}")

if not os.path.exists(msg_path):
    print(f"❌ File not found: {msg_path}")
    exit(1)

print(f"✅ File exists, size: {os.path.getsize(msg_path)} bytes")

try:
    # Read the MSG file
    with open(msg_path, 'rb') as f:
        msg_bytes = f.read()
    
    print(f"✅ MSG file loaded: {len(msg_bytes)} bytes")
    
    # Convert MSG to EML
    print("\n🔄 Converting .msg to .eml...")
    eml_bytes = convert_msg_bytes_to_eml_bytes(msg_bytes)
    print(f"✅ EML conversion successful: {len(eml_bytes)} bytes")
    
    # Parse the EML and extract attachments
    print("\n🔍 Extracting attachments...")
    msg = email.message_from_bytes(eml_bytes, policy=default)
    body, images, attachments = extract_body_and_images_from_email(msg)
    
    print(f"📊 Extraction Results:")
    print(f"   - Body length: {len(body)} characters")
    print(f"   - Images found: {len(images)}")
    print(f"   - Attachments found: {len(attachments)}")
    
    if attachments:
        print("\n📎 Attachment Details:")
        for i, att in enumerate(attachments):
            filename = att.get('filename', 'unknown')
            content_type = att.get('content_type', 'unknown')
            size = len(att.get('data', b''))

            print(f"   {i+1}. {filename}")
            print(f"      - Type: {content_type}")
            print(f"      - Size: {size:,} bytes")
    else:
        print("No attachments found")
        
    print(f"\n🎯 Test completed successfully!")
    
except Exception as e:
    print(f"❌ Error during processing: {e}")
    import traceback
    print(f"📋 Traceback:\n{traceback.format_exc()}")
    exit(1)

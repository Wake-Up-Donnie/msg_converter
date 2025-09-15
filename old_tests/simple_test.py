#!/usr/bin/env python3
import sys
import os

print("=== Simple MSG Attachment Test ===")
print(f"Python version: {sys.version}")
print(f"Working directory: {os.getcwd()}")

# Test basic imports
try:
    sys.path.insert(0, 'backend')
    print("✅ Added backend to path")
    
    import extract_msg
    print("✅ extract_msg imported")
    
    from lambda_function import convert_msg_bytes_to_eml_bytes, extract_body_and_images_from_email
    print("✅ lambda functions imported")
    
    # Test file exists
    # Use available fixture for automated tests
    msg_path = 'test_msg_files/Demoss D JCSD 8.07.25.msg'
    if os.path.exists(msg_path):
        print(f"✅ MSG file found: {os.path.getsize(msg_path)} bytes")
        
        # Try to read and convert
        with open(msg_path, 'rb') as f:
            msg_bytes = f.read()
        print(f"✅ MSG file read: {len(msg_bytes)} bytes")
        
        # Convert to EML
        eml_bytes = convert_msg_bytes_to_eml_bytes(msg_bytes)
        print(f"✅ EML conversion: {len(eml_bytes)} bytes")
        
        # Parse EML
        import email
        from email.policy import default
        msg = email.message_from_bytes(eml_bytes, policy=default)
        print("✅ EML parsed successfully")
        
        # Extract attachments
        body, images, attachments = extract_body_and_images_from_email(msg)
        print(f"📊 Results:")
        print(f"   - Body: {len(body)} chars")
        print(f"   - Images: {len(images)}")
        print(f"   - Attachments: {len(attachments)}")
        
        for i, att in enumerate(attachments):
            print(f"   📎 Attachment {i+1}: {att.get('filename', 'unknown')} ({len(att.get('data', b''))} bytes)")
            
        if len(attachments) > 0:
            print("🎉 SUCCESS: Attachments detected!")
        else:
            print("No attachments found")
            
    else:
        print(f"❌ MSG file not found: {msg_path}")
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()

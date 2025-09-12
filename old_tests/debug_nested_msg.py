#!/usr/bin/env python3

import sys
import os
sys.path.append('backend')

try:
    import extract_msg
    
    # Load the .msg file directly to understand its structure
    msg_path = 'test_msg_files/Demoss D JCSD 8.07.25.msg'
    print(f"=== ANALYZING .MSG FILE STRUCTURE ===")
    
    msg = extract_msg.Message(msg_path)
    print(f"Subject: {msg.subject}")
    print(f"From: {msg.sender}")
    
    # Check for attachments
    attachments = msg.attachments
    print(f"\nFound {len(attachments)} attachments:")
    
    for i, att in enumerate(attachments):
        print(f"\nAttachment {i+1}:")
        filename = getattr(att, 'longFilename', None) or getattr(att, 'shortFilename', None)
        print(f"  Filename: {filename}")
        print(f"  MIME Type: {getattr(att, 'mimeType', None)}")
        
        # Check if this is a nested .msg
        if hasattr(att, 'msg'):
            print(f"  >>> This has a .msg property! <<<")
            try:
                nested = att.msg
                if nested:
                    print(f"    Nested type: {type(nested)}")
                    if hasattr(nested, 'subject'):
                        print(f"    Nested subject: {nested.subject}")
                    if hasattr(nested, 'sender'):
                        print(f"    Nested sender: {nested.sender}")
                    if hasattr(nested, 'body'):
                        body = nested.body or ''
                        print(f"    Nested body length: {len(body)} chars")
                        if len(body) > 0:
                            print(f"    Nested body preview: {body[:100]}...")
                else:
                    print(f"    Nested msg is None")
            except Exception as e:
                print(f"    Error accessing nested msg: {e}")
        
        # Check the raw data
        try:
            data = getattr(att, 'data', None)
            if data:
                print(f"  Data size: {len(data)} bytes")
                if len(data) >= 8:
                    magic = data[:8]
                    print(f"  Magic bytes: {magic.hex()}")
                    if magic == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                        print(f"  >>> Contains .msg magic bytes! <<<")
            else:
                print(f"  No data property")
        except Exception as e:
            print(f"  Error checking data: {e}")

    print(f"\n=== CONVERTING TO EML AND ANALYZING ===")
    
    # Now convert to EML and see what we get
    from lambda_function import convert_msg_bytes_to_eml_bytes
    import email
    from email.policy import default
    
    with open(msg_path, 'rb') as f:
        msg_bytes = f.read()
    
    eml_bytes = convert_msg_bytes_to_eml_bytes(msg_bytes)
    eml_msg = email.message_from_bytes(eml_bytes, policy=default)
    
    print(f"EML message is multipart: {eml_msg.is_multipart()}")
    
    part_count = 0
    for part in eml_msg.walk():
        if part is eml_msg:
            continue
        part_count += 1
        ctype = part.get_content_type()
        fname = part.get_filename()
        cdisp = part.get('Content-Disposition') or 'None'
        
        print(f"\nEML Part {part_count}:")
        print(f"  Content-Type: {ctype}")
        print(f"  Filename: {fname}")
        print(f"  Disposition: {cdisp}")
        
        # Check payload
        payload = part.get_payload(decode=True) or part.get_payload()
        print(f"  Payload type: {type(payload)}")
        
        if isinstance(payload, (bytes, bytearray)):
            print(f"  Payload size: {len(payload)} bytes")
            if len(payload) >= 8:
                magic = payload[:8]
                print(f"  Magic bytes: {magic.hex()}")
                if magic == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                    print(f"  >>> FOUND .MSG MAGIC BYTES IN EML PART! <<<")
                elif any(payload.lower().startswith(header) for header in [b'from:', b'to:', b'subject:', b'date:', b'message-id:']):
                    print(f"  >>> FOUND EML-LIKE HEADERS! <<<")
        elif isinstance(payload, list):
            print(f"  Payload is list with {len(payload)} items")
            for j, item in enumerate(payload):
                print(f"    Item {j}: {type(item)}")
                if hasattr(item, 'get_content_type'):
                    print(f"      Content-Type: {item.get_content_type()}")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
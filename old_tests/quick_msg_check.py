#!/usr/bin/env python3

import sys
import os
sys.path.append('backend')

try:
    import extract_msg
    
    # Load the .msg file directly
    msg_path = 'test_msg_files/Demoss D JCSD 8.07.25.msg'
    print(f"Loading .msg file: {msg_path}")
    
    msg = extract_msg.Message(msg_path)
    print(f"Subject: {msg.subject}")
    print(f"From: {msg.sender}")
    print(f"Date: {msg.date}")
    
    # Check for attachments
    attachments = msg.attachments
    print(f"\nFound {len(attachments)} attachments:")
    
    for i, att in enumerate(attachments):
        print(f"\nAttachment {i+1}:")
        print(f"  Filename: {getattr(att, 'longFilename', None) or getattr(att, 'shortFilename', None)}")
        print(f"  MIME Type: {getattr(att, 'mimeType', None)}")
        print(f"  Size: {len(getattr(att, 'data', b'') or b'')} bytes")
        
        # Check if this is a nested .msg
        if hasattr(att, 'msg'):
            print(f"  >>> This is a nested .msg attachment! <<<")
            try:
                nested = att.msg
                if nested:
                    print(f"    Nested subject: {getattr(nested, 'subject', 'No subject')}")
                    print(f"    Nested sender: {getattr(nested, 'sender', 'No sender')}")
            except Exception as e:
                print(f"    Error accessing nested msg: {e}")
        
        # Check for .msg magic bytes in data
        data = getattr(att, 'data', None)
        if data and len(data) >= 8:
            magic = data[:8]
            if magic == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                print(f"  >>> Contains .msg magic bytes! <<<")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
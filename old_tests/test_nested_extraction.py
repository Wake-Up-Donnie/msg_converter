#!/usr/bin/env python3

import sys
import os
sys.path.append('backend')

try:
    import extract_msg
    import tempfile
    
    # Load the .msg file directly to understand its structure
    msg_path = 'test_msg_files/Demoss D JCSD 8.07.25.msg'
    print(f"=== TESTING NESTED .MSG EXTRACTION ===")
    
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
                    
                    # Try different methods to get bytes
                    print(f"    Trying to extract bytes...")
                    
                    # Method 1: Try save method
                    try:
                        if hasattr(nested, 'save'):
                            with tempfile.NamedTemporaryFile(suffix='.msg', delete=False) as tmp:
                                nested.save(tmp.name)
                                with open(tmp.name, 'rb') as f:
                                    nested_bytes = f.read()
                                print(f"    Method 1 (save): Got {len(nested_bytes)} bytes")
                                # Check magic bytes
                                if len(nested_bytes) >= 8:
                                    magic = nested_bytes[:8]
                                    print(f"    Magic bytes: {magic.hex()}")
                                    if magic == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                                        print(f"    >>> VALID .MSG MAGIC BYTES! <<<")
                                os.unlink(tmp.name)
                        else:
                            print(f"    Method 1: No save method")
                    except Exception as e:
                        print(f"    Method 1 failed: {e}")
                    
                    # Method 2: Try to get raw data from attachment
                    try:
                        data = getattr(att, 'data', None)
                        if data:
                            print(f"    Method 2 (att.data): Got {len(data)} bytes")
                            if len(data) >= 8:
                                magic = data[:8]
                                print(f"    Magic bytes: {magic.hex()}")
                                if magic == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                                    print(f"    >>> VALID .MSG MAGIC BYTES! <<<")
                        else:
                            print(f"    Method 2: No data property")
                    except Exception as e:
                        print(f"    Method 2 failed: {e}")
                    
                    # Method 3: Try binary property
                    try:
                        binary = getattr(att, 'binary', None)
                        if binary:
                            print(f"    Method 3 (att.binary): Got {len(binary)} bytes")
                            if len(binary) >= 8:
                                magic = binary[:8]
                                print(f"    Magic bytes: {magic.hex()}")
                                if magic == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                                    print(f"    >>> VALID .MSG MAGIC BYTES! <<<")
                        else:
                            print(f"    Method 3: No binary property")
                    except Exception as e:
                        print(f"    Method 3 failed: {e}")
                        
                else:
                    print(f"    Nested msg is None")
            except Exception as e:
                print(f"    Error accessing nested msg: {e}")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
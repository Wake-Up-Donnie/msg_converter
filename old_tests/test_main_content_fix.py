#!/usr/bin/env python3

import sys
import os
sys.path.append('backend')

from lambda_function import *
import logging

def test_main_content_extraction():
    """Test if main content is properly extracted"""
    try:
        # Load the test file
        with open('test_msg_files/Demoss D JCSD 8.07.25.msg', 'rb') as f:
            msg_bytes = f.read()
        
        print(f"Loaded .msg file: {len(msg_bytes)} bytes")
        
        # Convert to EML
        eml_bytes = convert_msg_bytes_to_eml_bytes(msg_bytes)
        print(f"Converted to EML: {len(eml_bytes)} bytes")
        
        # Parse message
        msg = email.message_from_bytes(eml_bytes, policy=default)
        
        # Extract content using our fixed function
        body, images, attachments = extract_body_and_images_from_email(msg)
        
        print(f"\n=== EXTRACTION RESULTS ===")
        print(f"Body length: {len(body)} chars")
        print(f"Images found: {len(images)}")
        print(f"Attachments found: {len(attachments)}")
        
        # Test for main content
        target_text = "Good afternoon, Nick"
        if target_text in body:
            print("✓ SUCCESS: Main message content found!")
        else:
            print("✗ FAILED: Main message content missing")
        
        # Test for nested message
        if "Attached Message" in body:
            print("✓ SUCCESS: Nested message section found!")
        else:
            print("✗ FAILED: Nested message section missing")
        
        # Show body preview
        print(f"\nBody preview (first 300 chars):")
        print(f"{body[:300]}...")
        
        # Show where target text would be
        if target_text not in body:
            print(f"\nSearching for '{target_text}' in EML content...")
            eml_text = eml_bytes.decode('utf-8', errors='replace')
            if target_text in eml_text:
                pos = eml_text.find(target_text)
                print(f"Found in raw EML at position {pos}")
                print(f"Context: {eml_text[max(0, pos-50):pos+100]}")
            else:
                print("Not found in raw EML either")
                
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_main_content_extraction()

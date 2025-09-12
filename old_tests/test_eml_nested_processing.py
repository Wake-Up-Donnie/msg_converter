#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from lambda_function import extract_body_and_images_from_email, extract_simple_message_content
import email
from email.policy import default

def test_eml_nested_processing():
    """Test the .eml file to see if nested message attachments are being processed."""
    
    # Read the .eml file
    eml_path = "test_eml_files/Demoss, D JCSD 8.07.25.eml"
    
    print(f"Testing EML file: {eml_path}")
    
    with open(eml_path, 'rb') as f:
        eml_content = f.read()
    
    print(f"EML file size: {len(eml_content)} bytes")
    
    # Parse the EML
    msg = email.message_from_bytes(eml_content, policy=default)
    
    print(f"Message type: {msg.get_content_type()}")
    print(f"Is multipart: {msg.is_multipart()}")
    
    # Walk through all parts to see what we have
    print("\n=== Walking through all message parts ===")
    part_count = 0
    for part in msg.walk():
        part_count += 1
        ctype = part.get_content_type()
        fname = part.get_filename()
        cdisp = part.get('Content-Disposition') or ''
        
        print(f"Part {part_count}: {ctype}")
        if fname:
            print(f"  Filename: {fname}")
        if cdisp:
            print(f"  Disposition: {cdisp}")
        
        # Check for message/rfc822 parts specifically
        if ctype == 'message/rfc822':
            print(f"  *** FOUND message/rfc822 part! ***")
            payload = part.get_payload()
            print(f"  Payload type: {type(payload)}")
            if hasattr(payload, 'get'):
                nested_subject = payload.get('Subject', 'No Subject')
                nested_from = payload.get('From', 'Unknown')
                print(f"  Nested Subject: {nested_subject}")
                print(f"  Nested From: {nested_from}")
    
    print(f"\nTotal parts found: {part_count}")
    
    # Test the extraction functions
    print("\n=== Testing extract_body_and_images_from_email ===")
    try:
        body, images, attachments = extract_body_and_images_from_email(msg)
        print(f"Body length: {len(body)}")
        print(f"Images found: {len(images)}")
        print(f"Attachments found: {len(attachments)}")
        
        # Check if body contains nested message content
        if "Attached Message" in body:
            print("✓ Body contains nested message content")
        else:
            print("✗ Body does NOT contain nested message content")
        
        # Show a preview of the body
        print(f"\nBody preview (first 500 chars):")
        print(body[:500])
        print("...")
        
        # Check for nested message sections
        if "Katrina Westley" in body:
            print("✓ Found expected nested message content (Katrina Westley)")
        else:
            print("✗ Missing expected nested message content")
            
    except Exception as e:
        print(f"Error in extract_body_and_images_from_email: {e}")
        import traceback
        traceback.print_exc()
    
    # Test simple extraction too
    print("\n=== Testing extract_simple_message_content ===")
    try:
        simple_body, simple_images, nested_sections = extract_simple_message_content(msg)
        print(f"Simple body length: {len(simple_body)}")
        print(f"Simple images found: {len(simple_images)}")
        print(f"Nested sections found: {len(nested_sections)}")
        
        if nested_sections:
            print("✓ Found nested sections in simple extraction")
            for i, section in enumerate(nested_sections):
                print(f"  Section {i+1}: {len(section)} chars")
        else:
            print("✗ No nested sections found in simple extraction")
            
    except Exception as e:
        print(f"Error in extract_simple_message_content: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_eml_nested_processing()
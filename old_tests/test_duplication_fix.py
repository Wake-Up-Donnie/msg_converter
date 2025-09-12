#!/usr/bin/env python3

import sys
import os
sys.path.append('backend')

from lambda_function import *
import email
from email.policy import default

def test_duplication_fix():
    print("=== TESTING DUPLICATION FIX ===")
    
    # Load and convert the .msg file
    with open('test_msg_files/Demoss D JCSD 8.07.25.msg', 'rb') as f:
        msg_bytes = f.read()

    print('Converting .msg to .eml...')
    eml_bytes = convert_msg_bytes_to_eml_bytes(msg_bytes)

    print('Parsing EML message...')
    msg = email.message_from_bytes(eml_bytes, policy=default)

    print('\n=== EXTRACTING CONTENT ===')
    
    # Extract content using the fixed function
    try:
        body, images, attachments = extract_body_and_images_from_email(msg)
        
        print(f"Body length: {len(body)} characters")
        print(f"Images found: {len(images)}")
        print(f"Attachments found: {len(attachments)}")
        
        # Count how many times "Good afternoon" appears in the body
        good_afternoon_count = body.lower().count('good afternoon')
        print(f"\n'Good afternoon' appears {good_afternoon_count} times in the body")
        
        # Check for "Attached Message" sections
        attached_message_count = body.count('Attached Message')
        print(f"'Attached Message' sections found: {attached_message_count}")
        
        # Look for the specific content we expect
        if 'Good afternoon' in body:
            print("✓ Main message content found")
        else:
            print("✗ Main message content NOT found")
            
        if 'Attached Message' in body:
            print("✓ Nested message section found")
        else:
            print("✗ Nested message section NOT found")
            
        # Check for duplication
        if good_afternoon_count == 1:
            print("✓ No duplication detected - main content appears once")
        elif good_afternoon_count > 1:
            print(f"✗ DUPLICATION DETECTED - main content appears {good_afternoon_count} times")
        else:
            print("✗ Main content not found at all")
            
        # Show a preview of the body
        print(f"\n=== BODY PREVIEW (first 500 chars) ===")
        print(body[:500])
        print("...")
        
        # Show the end of the body to see nested content
        print(f"\n=== BODY END (last 500 chars) ===")
        print("...")
        print(body[-500:])
        
        return good_afternoon_count == 1 and attached_message_count >= 1
        
    except Exception as e:
        print(f"Error during extraction: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = test_duplication_fix()
    print(f"\n=== TEST RESULT ===")
    if success:
        print("✓ TEST PASSED - Fix appears to be working correctly")
    else:
        print("✗ TEST FAILED - Issues still exist")
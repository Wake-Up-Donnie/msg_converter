#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from lambda_function import convert_msg_bytes_to_eml_bytes, extract_body_and_images_from_email
import email
from email.policy import default

def test_final_msg_fix():
    """Test the complete .msg to PDF conversion with nested attachments."""
    
    # Read the original .msg file
    msg_path = "test_msg_files/Demoss D JCSD 8.07.25.msg"
    
    print(f"Testing MSG file: {msg_path}")
    
    with open(msg_path, 'rb') as f:
        msg_content = f.read()
    
    print(f"MSG file size: {len(msg_content)} bytes")
    
    # Convert .msg to .eml
    print("\n=== Converting .msg to .eml ===")
    try:
        eml_content = convert_msg_bytes_to_eml_bytes(msg_content)
        print(f"EML conversion successful: {len(eml_content)} bytes")
    except Exception as e:
        print(f"EML conversion failed: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Parse the converted EML
    print("\n=== Parsing converted EML ===")
    try:
        msg = email.message_from_bytes(eml_content, policy=default)
        print(f"Message type: {msg.get_content_type()}")
        print(f"Is multipart: {msg.is_multipart()}")
        
        # Check for nested message parts
        nested_count = 0
        for part in msg.walk():
            ctype = part.get_content_type()
            fname = part.get_filename()
            if ctype == 'message/rfc822':
                nested_count += 1
                print(f"Found nested message/rfc822 part: {fname}")
        
        print(f"Total nested message parts: {nested_count}")
        
    except Exception as e:
        print(f"EML parsing failed: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Test the extraction
    print("\n=== Testing extract_body_and_images_from_email ===")
    try:
        body, images, attachments = extract_body_and_images_from_email(msg)
        print(f"Body length: {len(body)}")
        print(f"Images found: {len(images)}")
        print(f"Attachments found: {len(attachments)}")
        
        # Check for duplication (main content should appear only once)
        main_content_indicators = [
            "Good afternoon, Nick",
            "I wanted to introduce or reintroduce myself",
            "Dan DeMoss"
        ]
        
        duplication_count = 0
        for indicator in main_content_indicators:
            count = body.lower().count(indicator.lower())
            if count > 1:
                duplication_count += count - 1
                print(f"⚠️  '{indicator}' appears {count} times (should be 1)")
            else:
                print(f"✓ '{indicator}' appears {count} time(s)")
        
        if duplication_count == 0:
            print("✅ NO DUPLICATION DETECTED - Main content appears only once")
        else:
            print(f"❌ DUPLICATION DETECTED - {duplication_count} extra occurrences found")
        
        # Check for nested message content
        nested_indicators = [
            "Katrina Westley",
            "JCSD construction water sales availablity",
            "Forwarded message"
        ]
        
        nested_found = 0
        for indicator in nested_indicators:
            if indicator.lower() in body.lower():
                nested_found += 1
                print(f"✓ Found nested content indicator: '{indicator}'")
            else:
                print(f"✗ Missing nested content indicator: '{indicator}'")
        
        if nested_found >= 2:
            print("✅ NESTED MESSAGE CONTENT FOUND")
        else:
            print("❌ NESTED MESSAGE CONTENT MISSING OR INCOMPLETE")
        
        # Check for proper separation
        if "Attached Message" in body:
            print("✓ Proper nested message formatting found")
        else:
            print("✗ Missing proper nested message formatting")
        
        # Show content structure
        print(f"\n=== Content Structure Analysis ===")
        print(f"Total body length: {len(body)} characters")
        
        # Look for the boundary between main and nested content
        if "Attached Message" in body:
            parts = body.split("Attached Message", 1)
            main_part = parts[0]
            nested_part = parts[1] if len(parts) > 1 else ""
            print(f"Main content section: {len(main_part)} chars")
            print(f"Nested content section: {len(nested_part)} chars")
        
        # Show a preview of the final body
        print(f"\nBody preview (first 300 chars):")
        print(body[:300])
        print("...")
        
        if len(body) > 1000:
            print(f"\nBody preview (last 300 chars):")
            print("...")
            print(body[-300:])
            
    except Exception as e:
        print(f"Error in extract_body_and_images_from_email: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_final_msg_fix()
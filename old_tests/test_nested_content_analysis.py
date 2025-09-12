#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from lambda_function import convert_msg_bytes_to_eml_bytes
import email
from email.policy import default

def test_nested_content_analysis():
    """Analyze what's actually in the nested message to understand the duplication."""
    
    # Read the original .msg file
    msg_path = "test_msg_files/Demoss D JCSD 8.07.25.msg"
    
    print(f"Testing MSG file: {msg_path}")
    
    with open(msg_path, 'rb') as f:
        msg_content = f.read()
    
    # Convert .msg to .eml
    print("\n=== Converting .msg to .eml ===")
    eml_content = convert_msg_bytes_to_eml_bytes(msg_content)
    
    # Parse the converted EML
    msg = email.message_from_bytes(eml_content, policy=default)
    
    print(f"Main message subject: {msg.get('Subject', 'No Subject')}")
    print(f"Main message from: {msg.get('From', 'Unknown')}")
    
    # Find the nested message
    print("\n=== Analyzing nested message content ===")
    for part in msg.walk():
        if part.get_content_type() == 'message/rfc822':
            print(f"Found nested message part: {part.get_filename()}")
            
            # Get the nested message
            payload = part.get_payload()
            if isinstance(payload, list) and payload:
                nested_msg = payload[0]
            else:
                nested_msg = payload
            
            print(f"Nested message subject: {nested_msg.get('Subject', 'No Subject')}")
            print(f"Nested message from: {nested_msg.get('From', 'Unknown')}")
            
            # Check if this is the same message (duplication) or different content
            main_subject = msg.get('Subject', '').lower()
            nested_subject = nested_msg.get('Subject', '').lower()
            
            main_from = msg.get('From', '').lower()
            nested_from = nested_msg.get('From', '').lower()
            
            print(f"\nDuplication analysis:")
            print(f"Same subject: {main_subject == nested_subject}")
            print(f"Same sender: {main_from == nested_from}")
            
            if main_subject == nested_subject and main_from == nested_from:
                print("⚠️  This appears to be a duplicate of the main message!")
            else:
                print("✓ This appears to be different content (forwarded message)")
            
            # Extract content from nested message to see what it contains
            print(f"\n=== Nested message content analysis ===")
            
            # Look for different content indicators
            nested_content = ""
            if nested_msg.is_multipart():
                for nested_part in nested_msg.walk():
                    if nested_part.get_content_type() == 'text/html':
                        try:
                            content = nested_part.get_payload(decode=True)
                            if content:
                                nested_content = content.decode('utf-8', errors='replace')
                                break
                        except Exception:
                            pass
                    elif nested_part.get_content_type() == 'text/plain' and not nested_content:
                        try:
                            content = nested_part.get_payload(decode=True)
                            if content:
                                nested_content = content.decode('utf-8', errors='replace')
                        except Exception:
                            pass
            else:
                try:
                    content = nested_msg.get_payload(decode=True)
                    if content:
                        nested_content = content.decode('utf-8', errors='replace')
                except Exception:
                    pass
            
            # Check for unique content in nested message
            unique_indicators = [
                "Katrina Westley",
                "JCSD construction water sales availablity", 
                "Forwarded message",
                "Chairman, Board of Directors",
                "Jacumba Community Services District"
            ]
            
            found_unique = []
            for indicator in unique_indicators:
                if indicator.lower() in nested_content.lower():
                    found_unique.append(indicator)
            
            print(f"Unique content indicators found: {found_unique}")
            print(f"Nested content length: {len(nested_content)} chars")
            
            if found_unique:
                print("✓ Nested message contains unique content (Katrina's forwarded message)")
            else:
                print("✗ Nested message appears to be duplicate content")
            
            # Show preview of nested content
            print(f"\nNested content preview (first 200 chars):")
            print(nested_content[:200])
            print("...")
            
            break

if __name__ == "__main__":
    test_nested_content_analysis()
#!/usr/bin/env python3

import sys
import os
sys.path.append('backend')

from lambda_function import *
import logging

# Simple logging setup
logging.basicConfig(level=logging.INFO)

def analyze_message_structure():
    # Test with the provided file
    with open('test_msg_files/Demoss D JCSD 8.07.25.msg', 'rb') as f:
        msg_bytes = f.read()

    print('Converting .msg to .eml...')
    eml_bytes = convert_msg_bytes_to_eml_bytes(msg_bytes)
    
    print('Parsing EML message...')
    msg = email.message_from_bytes(eml_bytes, policy=default)
    
    print(f'\n=== MESSAGE STRUCTURE ===')
    print(f'Message is multipart: {msg.is_multipart()}')
    print(f'Message content type: {msg.get_content_type()}')
    
    def analyze_part(part, level=0, part_num=0):
        indent = "  " * level
        ctype = part.get_content_type()
        cdisp = part.get('Content-Disposition') or 'None'
        fname = part.get_filename() or 'None'
        
        print(f'{indent}Part {part_num}: {ctype}')
        print(f'{indent}  Disposition: {cdisp}')
        print(f'{indent}  Filename: {fname}')
        
        # For text parts, show content preview
        if ctype.startswith('text/'):
            try:
                content = get_part_content(part)
                if content:
                    preview = content[:100].replace('\n', ' ').replace('\r', ' ')
                    print(f'{indent}  Content preview: {preview}...')
                    
                    # Check if this contains our target text
                    if 'Good afternoon, Nick' in content:
                        print(f'{indent}  *** FOUND TARGET CONTENT ***')
                        return True
            except Exception as e:
                print(f'{indent}  Error reading content: {e}')
        
        # For message/rfc822, recurse into it
        elif ctype == 'message/rfc822':
            print(f'{indent}  >>> Nested message found <<<')
            try:
                nested_payload = part.get_payload()
                if isinstance(nested_payload, list) and nested_payload:
                    nested_msg = nested_payload[0]
                    print(f'{indent}  Nested message multipart: {nested_msg.is_multipart()}')
                    
                    if nested_msg.is_multipart():
                        for i, nested_part in enumerate(nested_msg.walk()):
                            if nested_part is nested_msg:
                                continue
                            found = analyze_part(nested_part, level + 2, i)
                            if found:
                                return True
                    else:
                        found = analyze_part(nested_msg, level + 2, 0)
                        if found:
                            return True
                            
            except Exception as e:
                print(f'{indent}  Error processing nested message: {e}')
        
        return False
    
    # Walk through all parts
    found_target = False
    if msg.is_multipart():
        for i, part in enumerate(msg.walk()):
            if part is msg:
                continue
            found = analyze_part(part, 0, i)
            if found:
                found_target = True
                break
    else:
        found_target = analyze_part(msg, 0, 0)
    
    print(f'\n=== RESULT ===')
    print(f'Target content found: {found_target}')
    
    # Test our current extraction function
    print(f'\n=== TESTING CURRENT EXTRACTION ===')
    body, images, attachments = extract_body_and_images_from_email(msg)
    print(f'Extracted body length: {len(body)}')
    print(f'Contains target text: {"Good afternoon, Nick" in body}')
    
if __name__ == '__main__':
    analyze_message_structure()

#!/usr/bin/env python3

import sys
import os
sys.path.append('backend')

from lambda_function import convert_msg_bytes_to_eml_bytes
import email
from email.policy import default

def test_eml_conversion():
    print("=== TESTING EML CONVERSION ===")
    
    # Load and convert the .msg file
    with open('test_msg_files/Demoss D JCSD 8.07.25.msg', 'rb') as f:
        msg_bytes = f.read()

    print('Converting .msg to .eml...')
    eml_bytes = convert_msg_bytes_to_eml_bytes(msg_bytes)

    print('Parsing converted EML message...')
    msg = email.message_from_bytes(eml_bytes, policy=default)

    print(f'\n=== CONVERTED EML ANALYSIS ===')
    print(f'Message is multipart: {msg.is_multipart()}')
    print(f'Message content type: {msg.get_content_type()}')

    # Look for message/rfc822 parts
    msg_attachments = []
    part_count = 0
    
    for part in msg.walk():
        if part is msg:
            continue
        part_count += 1
        ctype = part.get_content_type()
        fname = part.get_filename()
        cdisp = part.get('Content-Disposition') or 'None'
        
        print(f'\nPart {part_count}: {ctype}')
        print(f'  Filename: {fname}')
        print(f'  Disposition: {cdisp}')
        
        # Check if this is a message/rfc822 part
        if ctype == 'message/rfc822':
            print(f'  >>> FOUND message/rfc822 PART! <<<')
            msg_attachments.append({
                'part_num': part_count,
                'filename': fname,
                'content_type': ctype,
                'disposition': cdisp
            })
            
            # Try to get the nested message
            try:
                payload = part.get_payload()
                if isinstance(payload, list) and payload:
                    nested_msg = payload[0]
                    print(f'    Nested message type: {type(nested_msg)}')
                    if hasattr(nested_msg, 'get'):
                        print(f'    Nested subject: {nested_msg.get("Subject", "No Subject")}')
                        print(f'    Nested from: {nested_msg.get("From", "No From")}')
                else:
                    print(f'    Payload type: {type(payload)}')
            except Exception as e:
                print(f'    Error accessing nested message: {e}')
        
        # Check for .eml filename attachments
        elif fname and fname.lower().endswith('.eml'):
            print(f'  >>> FOUND .eml ATTACHMENT! <<<')
            msg_attachments.append({
                'part_num': part_count,
                'filename': fname,
                'content_type': ctype,
                'disposition': cdisp
            })

    print(f'\n=== CONVERSION SUMMARY ===')
    print(f'Total parts: {part_count}')
    print(f'Message attachments found: {len(msg_attachments)}')
    for i, att in enumerate(msg_attachments):
        print(f'  {i+1}. Part {att["part_num"]}: {att["content_type"]} - {att.get("filename", "No filename")}')

if __name__ == '__main__':
    test_eml_conversion()
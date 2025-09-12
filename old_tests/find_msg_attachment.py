#!/usr/bin/env python3

import sys
import os
sys.path.append('backend')

from lambda_function import *
import email
from email.policy import default

def find_msg_attachment():
    # Load and convert the .msg file
    with open('test_msg_files/Demoss D JCSD 8.07.25.msg', 'rb') as f:
        msg_bytes = f.read()

    print('Converting .msg to .eml...')
    eml_bytes = convert_msg_bytes_to_eml_bytes(msg_bytes)

    print('Parsing EML message...')
    msg = email.message_from_bytes(eml_bytes, policy=default)

    print(f'\n=== COMPREHENSIVE MESSAGE ANALYSIS ===')
    print(f'Message is multipart: {msg.is_multipart()}')
    print(f'Message content type: {msg.get_content_type()}')

    # Look for ALL attachments, including .msg files
    all_attachments = []
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
        
        # Get payload to check for .msg magic bytes
        payload = part.get_payload(decode=True) or part.get_payload()
        print(f'  Payload type: {type(payload)}')
        
        if isinstance(payload, (bytes, bytearray)):
            print(f'  Payload size: {len(payload)} bytes')
            # Check for .msg magic bytes
            if len(payload) >= 8:
                magic = payload[:8]
                print(f'  Magic bytes: {magic.hex()}')
                if magic == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                    print(f'  >>> FOUND .MSG FILE BY MAGIC BYTES <<<')
                    all_attachments.append({
                        'part_num': part_count,
                        'type': 'msg_by_magic',
                        'filename': fname,
                        'content_type': ctype,
                        'size': len(payload)
                    })
        elif isinstance(payload, list):
            print(f'  Payload list length: {len(payload)}')
            for i, item in enumerate(payload):
                print(f'    Item {i}: {type(item)}')
                if hasattr(item, 'get_content_type'):
                    print(f'      Content-Type: {item.get_content_type()}')
                if hasattr(item, 'get_filename'):
                    print(f'      Filename: {item.get_filename()}')
        else:
            print(f'  Payload preview: {str(payload)[:100]}...')
        
        # Check if this is a .msg attachment by various criteria
        if (ctype == 'message/rfc822' or 
            (fname and fname.lower().endswith('.msg')) or
            (isinstance(payload, (bytes, bytearray)) and len(payload) >= 8 and payload[:8] == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1')):
            all_attachments.append({
                'part_num': part_count,
                'type': 'potential_msg',
                'filename': fname,
                'content_type': ctype,
                'disposition': cdisp
            })

    print(f'\n=== SUMMARY ===')
    print(f'Total parts: {part_count}')
    print(f'Potential .msg attachments found: {len(all_attachments)}')
    for i, att in enumerate(all_attachments):
        print(f'  {i+1}. Part {att["part_num"]}: {att["type"]} - {att.get("filename", "No filename")} ({att.get("content_type", "Unknown type")})')

if __name__ == '__main__':
    find_msg_attachment()
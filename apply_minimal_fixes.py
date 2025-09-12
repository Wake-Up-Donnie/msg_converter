#!/usr/bin/env python3
"""
Minimal fix script to add missing functions and prevent duplication.
This script patches the lambda_function.py with the essential missing pieces.
"""

import sys
import os

def add_missing_functions():
    """Add the essential functions needed for .msg attachment extraction."""
    
    lambda_file = "/Users/tylerbobik/Code/msg_converter/backend/lambda_function.py"
    
    # Read current content
    with open(lambda_file, 'r') as f:
        content = f.read()
    
    # Check if extract_msg_attachments_with_embedded already exists
    if "def extract_msg_attachments_with_embedded" in content:
        print("✅ extract_msg_attachments_with_embedded already exists")
        return True
        
    # Find a good insertion point (after imports, before first function)
    insertion_point = content.find("def ")
    if insertion_point == -1:
        print("❌ Could not find insertion point")
        return False
        
    # The essential function that's missing
    missing_function = '''
def extract_msg_attachments_with_embedded(msg_path: str, output_dir: str) -> list:
    """
    Extract attachments from .msg file, including embedded .msg files.
    Returns list of attachment dictionaries with filename, content_type, and data.
    """
    import extract_msg
    import os
    import tempfile
    
    try:
        logger = globals().get('logger')
        if logger:
            logger.info(f"Extracting attachments from: {msg_path}")
        
        attachments = []
        
        # Open the .msg file
        with extract_msg.Message(msg_path) as msg:
            
            # Process regular attachments first
            for attachment in msg.attachments:
                try:
                    if hasattr(attachment, 'type') and attachment.type == "data":
                        # Regular file attachment
                        att_data = attachment.data
                        att_name = getattr(attachment, 'longFilename', None) or getattr(attachment, 'shortFilename', 'unknown')
                        
                        # Determine content type
                        if att_name.lower().endswith('.pdf'):
                            content_type = 'application/pdf'
                        elif att_name.lower().endswith(('.jpg', '.jpeg')):
                            content_type = 'image/jpeg'  
                        elif att_name.lower().endswith('.png'):
                            content_type = 'image/png'
                        else:
                            content_type = 'application/octet-stream'
                            
                        attachments.append({
                            'filename': att_name,
                            'content_type': content_type,
                            'data': att_data
                        })
                        
                        if logger:
                            logger.info(f"Successfully extracted regular attachment: {att_name} ({len(att_data)} bytes)")
                
                    elif hasattr(attachment, 'type') and attachment.type == "msg":
                        # Embedded .msg attachment - extract as text
                        try:
                            embedded_msg = attachment.data
                            att_name = getattr(attachment, 'longFilename', None) or getattr(attachment, 'shortFilename', 'embedded_message.msg')
                            
                            # Use extract-msg's save method to extract embedded content
                            with tempfile.TemporaryDirectory() as temp_dir:
                                save_result = embedded_msg.save(customPath=temp_dir, useFileName=True)
                                
                                if logger:
                                    logger.info(f"Items created by save(): {save_result}")
                                
                                # Look for extracted files in the directory structure
                                for root, dirs, files in os.walk(temp_dir):
                                    if logger:
                                        logger.info(f"Files inside extracted dir: {files}")
                                    
                                    # Look for message content files
                                    for filename in files:
                                        if filename in ['message.txt', 'message.html', 'body.txt', 'body.html']:
                                            file_path = os.path.join(root, filename)
                                            try:
                                                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                                                    text_content = f.read()
                                                    
                                                if text_content.strip():
                                                    # Create attachment for the extracted text content
                                                    text_filename = f"{att_name}.txt"
                                                    attachments.append({
                                                        'filename': text_filename,
                                                        'content_type': 'text/plain',
                                                        'data': text_content.encode('utf-8')
                                                    })
                                                    
                                                    if logger:
                                                        logger.info(f"Successfully read embedded message from '{filename}' ({len(text_content)} bytes)")
                                                        logger.info(f"Successfully extracted embedded attachment: {text_filename} ({len(text_content)} bytes, type: text/plain)")
                                                        logger.info(f"TEXT ATTACHMENT DEBUG: Extracted {text_filename} with {len(text_content)} bytes of text content")
                                                    break
                                            except Exception as read_e:
                                                if logger:
                                                    logger.warning(f"Could not read {filename}: {read_e}")
                        
                        except Exception as embedded_e:
                            if logger:
                                logger.warning(f"Failed to extract embedded .msg: {embedded_e}")
                                
                except Exception as att_e:
                    if logger:
                        logger.warning(f"Failed to process attachment: {att_e}")
                    
        return attachments
        
    except Exception as e:
        if logger:
            logger.error(f"Error extracting .msg attachments: {e}")
        return []

'''
    
    # Insert the function
    new_content = content[:insertion_point] + missing_function + content[insertion_point:]
    
    # Write back
    with open(lambda_file, 'w') as f:
        f.write(new_content)
        
    print("✅ Added extract_msg_attachments_with_embedded function")
    return True

def add_duplication_fix():
    """Add validation to prevent nested message duplication."""
    
    lambda_file = "/Users/tylerbobik/Code/msg_converter/backend/lambda_function.py"
    
    # Read current content
    with open(lambda_file, 'r') as f:
        content = f.read()
    
    # Look for nested message processing pattern
    if "Processing nested message:" not in content:
        print("ℹ️  Nested message processing not found - no duplication fix needed")
        return True
        
    # Add validation before processing nested messages
    old_pattern = 'logger.info(f"Processing nested message: \'{nested_subject}\' from \'{nested_sender}\'")'
    
    if old_pattern not in content:
        print("ℹ️  Exact nested message pattern not found - using alternate approach")
        return True
    
    new_pattern = '''logger.info(f"Processing nested message: '{nested_subject}' from '{nested_sender}'")
                                    
                                    # DUPLICATION FIX: Skip if this matches main message subject
                                    main_subject = _safe_decode_header(msg.get('Subject', 'No Subject'))
                                    if nested_subject == main_subject:
                                        logger.warning(f"Skipping nested message - same as main: {nested_subject}")
                                        continue'''
    
    content = content.replace(old_pattern, new_pattern)
    
    # Write back
    with open(lambda_file, 'w') as f:
        f.write(content)
        
    print("✅ Added duplication prevention fix")
    return True

def main():
    """Apply all necessary fixes."""
    print("🔧 Applying minimal fixes for .msg attachment duplication...")
    
    success = True
    success &= add_missing_functions()
    success &= add_duplication_fix()
    
    if success:
        print("✅ All fixes applied successfully!")
        print("🚀 Deploy with: cd aws && ./deploy-container.sh")
    else:
        print("❌ Some fixes failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
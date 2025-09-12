#!/usr/bin/env python3
"""
Debug script for testing .msg files with embedded .msg attachments.
This script will help identify what's going wrong with the attachment extraction.
"""

import os
import sys
import tempfile
import traceback
from pathlib import Path

# Add backend to path so we can import the modules
backend_path = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_path))

try:
    import extract_msg
except ImportError:
    print("❌ ERROR: extract-msg not installed. Install with: pip install extract-msg")
    sys.exit(1)

def analyze_msg_file(msg_path: str):
    """Analyze a .msg file and show detailed information about its attachments."""
    print(f"\n🔍 Analyzing: {msg_path}")
    print("=" * 60)
    
    if not os.path.exists(msg_path):
        print(f"❌ File not found: {msg_path}")
        return
    
    try:
        # Open the .msg file
        msg = extract_msg.Message(msg_path)
        
        # Basic message info
        print(f"📧 Subject: {getattr(msg, 'subject', 'No Subject')}")
        print(f"📤 From: {getattr(msg, 'sender', 'Unknown Sender')}")
        print(f"📅 Date: {getattr(msg, 'date', 'Unknown Date')}")
        print(f"📎 Number of attachments: {len(msg.attachments)}")
        
        if not msg.attachments:
            print("⚠️  No attachments found in this .msg file")
            msg.close()
            return
        
        print("\n📎 ATTACHMENT ANALYSIS:")
        print("-" * 40)
        
        for i, att in enumerate(msg.attachments):
            print(f"\nAttachment #{i+1}:")
            
            # Get attachment properties
            filename = att.getFilename() or att.longFilename or att.shortFilename or f"attachment_{i+1}"
            print(f"  📄 Filename: {filename}")
            
            # Check attachment type
            att_type = type(att).__name__
            print(f"  🔧 Type: {att_type}")
            
            # Try to get data size
            try:
                if hasattr(att, 'data') and att.data:
                    data_size = len(att.data)
                    print(f"  📏 Data size: {data_size} bytes")
                else:
                    print(f"  ⚠️  No data attribute or empty data")
            except Exception as e:
                print(f"  ❌ Error getting data: {e}")
            
            # Check if it's an embedded .msg
            is_embedded_msg = filename.lower().endswith('.msg')
            is_embedded_type = att_type == 'EmbeddedMsgAttachment'
            print(f"  🔍 Is embedded .msg filename: {is_embedded_msg}")
            print(f"  🔍 Is EmbeddedMsgAttachment type: {is_embedded_type}")
            
            # For EmbeddedMsgAttachment, try to access the data differently
            if is_embedded_type:
                try:
                    embedded_data = att.data
                    print(f"  📋 Embedded data type: {type(embedded_data)}")
                    if hasattr(embedded_data, 'subject'):
                        print(f"  📧 Embedded subject: {getattr(embedded_data, 'subject', 'No subject')}")
                    if hasattr(embedded_data, 'as_email'):
                        print(f"  🔧 Has as_email method: True")
                        try:
                            eml_obj = embedded_data.as_email()
                            print(f"  📄 as_email() returned: {type(eml_obj)}")
                            if hasattr(eml_obj, 'as_bytes'):
                                eml_bytes = eml_obj.as_bytes()
                                print(f"  📏 EML bytes size: {len(eml_bytes)}")
                            else:
                                print(f"  ⚠️  EML object has no as_bytes method")
                        except Exception as ee:
                            print(f"  ❌ Error calling as_email(): {ee}")
                    else:
                        print(f"  ⚠️  Embedded data has no as_email method")
                except Exception as ed:
                    print(f"  ❌ Error accessing embedded data: {ed}")
            
            if is_embedded_msg or is_embedded_type:
                # Try to extract the embedded .msg
                try:
                    with tempfile.TemporaryDirectory() as temp_dir:
                        # Save with extractEmbedded=True
                        print(f"  🔄 Attempting to extract embedded .msg...")
                        att.save(customPath=temp_dir, extractEmbedded=True)
                        
                        saved_path = os.path.join(temp_dir, filename)
                        if os.path.exists(saved_path):
                            size = os.path.getsize(saved_path)
                            print(f"  ✅ Successfully saved to temp file ({size} bytes)")
                            
                            # Try to open the extracted .msg
                            try:
                                nested_msg = extract_msg.Message(saved_path)
                                nested_subject = getattr(nested_msg, 'subject', 'No Subject')
                                nested_sender = getattr(nested_msg, 'sender', 'Unknown Sender')
                                nested_att_count = len(nested_msg.attachments)
                                
                                print(f"  📧 Nested Subject: {nested_subject}")
                                print(f"  📤 Nested From: {nested_sender}")
                                print(f"  📎 Nested attachments: {nested_att_count}")
                                
                                nested_msg.close()
                            except Exception as ne:
                                print(f"  ❌ Error opening nested .msg: {ne}")
                        else:
                            print(f"  ❌ Failed to save embedded .msg")
                            
                except Exception as ee:
                    print(f"  ❌ Error extracting embedded .msg: {ee}")
                    traceback.print_exc()
            
        msg.close()
        print("\n✅ Analysis complete!")
        
    except Exception as e:
        print(f"❌ Error analyzing .msg file: {e}")
        traceback.print_exc()

def test_backend_conversion(msg_path: str):
    """Test the backend conversion functions with detailed logging."""
    print(f"\n🧪 Testing backend conversion: {msg_path}")
    print("=" * 60)
    
    try:
        # Import our backend functions
        from lambda_function import (
            extract_msg_attachments_with_embedded,
            convert_msg_bytes_to_eml_bytes_with_attachments,
            convert_msg_bytes_to_eml_bytes,
            eml_bytes_to_pdf_bytes
        )
        
        # Read the .msg file
        with open(msg_path, 'rb') as f:
            msg_bytes = f.read()
        
        print(f"📄 Read {len(msg_bytes)} bytes from .msg file")
        
        # Test 1: Basic .msg to EML conversion
        print("\n🔄 Test 1: Basic .msg to EML conversion...")
        try:
            eml_bytes = convert_msg_bytes_to_eml_bytes(msg_bytes)
            if eml_bytes:
                print(f"✅ Successfully converted to EML ({len(eml_bytes)} bytes)")
            else:
                print("❌ Failed to convert to EML (returned None)")
        except Exception as e:
            print(f"❌ Error in basic conversion: {e}")
            traceback.print_exc()
        
        # Test 2: .msg to EML with attachment extraction
        print("\n🔄 Test 2: .msg to EML with attachment extraction...")
        try:
            eml_bytes, attachments = convert_msg_bytes_to_eml_bytes_with_attachments(msg_bytes)
            if eml_bytes:
                print(f"✅ Successfully converted to EML ({len(eml_bytes)} bytes)")
                print(f"📎 Extracted {len(attachments)} attachments:")
                
                for i, att in enumerate(attachments):
                    print(f"  Attachment {i+1}:")
                    print(f"    📄 Filename: {att.get('filename', 'Unknown')}")
                    print(f"    🔧 Content-Type: {att.get('content_type', 'Unknown')}")
                    print(f"    📏 Data size: {len(att.get('data', b''))} bytes")
                    
                    # If it's a .msg attachment, try to convert it to PDF
                    if att.get('content_type') == 'application/vnd.ms-outlook' or att.get('filename', '').lower().endswith('.msg'):
                        print(f"    🔄 Testing nested .msg to PDF conversion...")
                        try:
                            nested_eml = convert_msg_bytes_to_eml_bytes(att.get('data', b''))
                            if nested_eml:
                                nested_pdf = eml_bytes_to_pdf_bytes(nested_eml)
                                if nested_pdf:
                                    print(f"    ✅ Successfully converted nested .msg to PDF ({len(nested_pdf)} bytes)")
                                else:
                                    print(f"    ❌ Failed to convert nested .msg to PDF")
                            else:
                                print(f"    ❌ Failed to convert nested .msg to EML")
                        except Exception as ne:
                            print(f"    ❌ Error converting nested .msg: {ne}")
            else:
                print("❌ Failed to convert to EML (returned None)")
                
        except Exception as e:
            print(f"❌ Error in attachment extraction: {e}")
            traceback.print_exc()
            
        # Test 3: Direct attachment extraction using extract-msg
        print("\n🔄 Test 3: Direct attachment extraction using extract-msg...")
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Save .msg file to temp location
                temp_msg_path = os.path.join(temp_dir, 'test.msg')
                with open(temp_msg_path, 'wb') as f:
                    f.write(msg_bytes)
                
                # Use our extraction function
                attachments_dir = os.path.join(temp_dir, 'attachments')
                extracted = extract_msg_attachments_with_embedded(temp_msg_path, attachments_dir)
                
                print(f"✅ Extracted {len(extracted)} attachments using direct method:")
                for i, att in enumerate(extracted):
                    print(f"  Attachment {i+1}:")
                    print(f"    📄 Filename: {att.get('filename', 'Unknown')}")
                    print(f"    🔧 Content-Type: {att.get('content_type', 'Unknown')}")
                    print(f"    📏 Data size: {len(att.get('data', b''))} bytes")
                    
        except Exception as e:
            print(f"❌ Error in direct extraction: {e}")
            traceback.print_exc()
        
        print("\n✅ Backend conversion test complete!")
        
    except ImportError as e:
        print(f"❌ Error importing backend functions: {e}")
        print("Make sure you're running this from the msg_converter directory")
    except Exception as e:
        print(f"❌ Error in backend test: {e}")
        traceback.print_exc()

def main():
    """Main function to run the debug analysis."""
    print("🐛 MSG Attachment Debug Script")
    print("=" * 60)
    
    if len(sys.argv) != 2:
        print("Usage: python debug_msg_attachments.py <path_to_msg_file>")
        print("\nExample:")
        print("  python debug_msg_attachments.py test_msg_files/sample_with_attachment.msg")
        sys.exit(1)
    
    msg_file = sys.argv[1]
    
    # Step 1: Analyze the .msg file structure
    analyze_msg_file(msg_file)
    
    # Step 2: Test backend conversion functions
    test_backend_conversion(msg_file)
    
    print(f"\n🎉 Debug analysis complete!")
    print("\nIf you see issues above, please share the output to help identify the problem.")

if __name__ == "__main__":
    main()
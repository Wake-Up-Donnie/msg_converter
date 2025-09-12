#!/usr/bin/env python3

import sys
import os

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# Now import our functions
try:
    from lambda_function import (
        convert_msg_bytes_to_eml_bytes, 
        extract_body_and_images_from_email,
        convert_eml_to_pdf,
        get_part_content
    )
    import email
    from email.policy import default
    import tempfile
    
    print("=== .MSG ATTACHMENT PROCESSING TEST ===")
    
    # Test file path
    test_file = 'test_msg_files/Demoss D JCSD 8.07.25.msg'
    
    if not os.path.exists(test_file):
        print(f"❌ Test file not found: {test_file}")
        sys.exit(1)
    
    print(f"📁 Loading test file: {test_file}")
    
    # Load the .msg file
    with open(test_file, 'rb') as f:
        msg_bytes = f.read()
    print(f"✓ Loaded {len(msg_bytes)} bytes")
    
    # Convert .msg to .eml
    print("🔄 Converting .msg to .eml...")
    eml_bytes = convert_msg_bytes_to_eml_bytes(msg_bytes)
    print(f"✓ Converted to EML: {len(eml_bytes)} bytes")
    
    # Parse the EML
    print("📧 Parsing EML message...")
    msg = email.message_from_bytes(eml_bytes, policy=default)
    print(f"✓ Message parsed, multipart: {msg.is_multipart()}")
    
    # Quick check for target text in raw EML
    eml_text = eml_bytes.decode('utf-8', errors='replace')
    target_text = "Good afternoon, Nick"
    
    if target_text in eml_text:
        print(f"✓ Target text '{target_text}' found in raw EML")
    else:
        print(f"❌ Target text '{target_text}' NOT found in raw EML")
        # Try to find similar text
        for variant in ["good afternoon", "Good afternoon", "afternoon", "Nick"]:
            if variant in eml_text.lower():
                print(f"  Found variant: '{variant}'")
    
    # Extract message parts for debugging
    print("\n🔍 Analyzing message structure...")
    part_count = 0
    for part in msg.walk():
        if part is msg:
            continue
        part_count += 1
        ctype = part.get_content_type()
        fname = part.get_filename() or "None"
        cdisp = part.get('Content-Disposition') or "None"
        
        print(f"  Part {part_count}: {ctype}")
        print(f"    Filename: {fname}")
        print(f"    Disposition: {cdisp}")
        
        # Check text parts for our target
        if ctype.startswith('text/'):
            try:
                content = get_part_content(part)
                if content:
                    if target_text in content:
                        print(f"    *** CONTAINS TARGET TEXT ***")
                        print(f"    Preview: {content[:100]}...")
                    else:
                        print(f"    Preview: {content[:50]}...")
                else:
                    print("    No content extracted")
            except Exception as e:
                print(f"    Error reading content: {e}")
    
    # Test our extraction function
    print(f"\n🎯 Testing extraction function...")
    body, images, attachments = extract_body_and_images_from_email(msg)
    
    print(f"✓ Extraction complete:")
    print(f"  Body length: {len(body)} chars")
    print(f"  Images found: {len(images)}")
    print(f"  Attachments found: {len(attachments)}")
    
    # Check results
    has_main_content = target_text in body
    has_nested_content = "Attached Message" in body
    
    print(f"\n📊 Results:")
    print(f"  Main content found: {'✓' if has_main_content else '❌'}")
    print(f"  Nested content found: {'✓' if has_nested_content else '❌'}")
    
    if not has_main_content:
        print(f"\n❌ Main content missing. Body preview:")
        print(f"   {body[:300]}...")
        
        # Try to find where the content might be
        print(f"\n🔍 Searching for content in body...")
        keywords = ["afternoon", "Nick", "Jacumba", "GM", "corresponded"]
        for keyword in keywords:
            if keyword.lower() in body.lower():
                print(f"  Found keyword: {keyword}")
    
    # Test PDF generation
    print(f"\n📄 Testing PDF generation...")
    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_pdf:
        pdf_path = tmp_pdf.name
    
    try:
        success = convert_eml_to_pdf(eml_bytes, pdf_path)
        if success and os.path.exists(pdf_path):
            pdf_size = os.path.getsize(pdf_path)
            print(f"✓ PDF generated successfully: {pdf_size} bytes")
            print(f"  PDF path: {pdf_path}")
        else:
            print(f"❌ PDF generation failed")
    finally:
        # Clean up
        try:
            os.unlink(pdf_path)
        except:
            pass
    
    print(f"\n=== TEST COMPLETE ===")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're running this from the project root directory")
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()

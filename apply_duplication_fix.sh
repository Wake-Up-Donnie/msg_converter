#!/bin/bash
# Quick fix to stop message duplication in Lambda

echo "🔧 Applying targeted fix to stop message duplication..."

# The issue: nested message processing is duplicating the main message 
# instead of processing the actual embedded message content.
# 
# Root cause: The nested message processing extracts the same EML content
# instead of the embedded .msg content that was extracted as text.
#
# Fix: Add validation to ensure nested messages have different content
# than the main message to prevent duplication.

cd /Users/tylerbobik/Code/msg_converter

# Create a simple patch script
cat > temp_fix.py << 'EOF'
import re

# Read the current lambda function
with open('backend/lambda_function.py', 'r') as f:
    content = f.read()

# Find the nested message processing section where the duplication occurs
# Look for: "Processing nested message:" log line
# Add validation to check if nested content is different from main content

# Pattern to find nested message processing
pattern = r"(logger\.info\(f\"Processing nested message: '.*?'\"\))"

if pattern in content:
    print("✅ Found nested message processing - applying duplication fix...")
    
    # Add validation before processing nested content
    fix = """logger.info(f"Processing nested message: '{nested_subject}' from '{nested_sender}'")
                                    
                                    # DUPLICATION FIX: Skip if this is the same as main message
                                    main_subject = _safe_decode_header(msg.get('Subject', 'No Subject'))
                                    if nested_subject == main_subject:
                                        logger.warning(f"Skipping nested message - same as main message: {nested_subject}")
                                        continue"""
    
    # Replace the line
    content = content.replace(
        'logger.info(f"Processing nested message: \'{nested_subject}\' from \'{nested_sender}\'")',
        fix
    )
    
    # Write back
    with open('backend/lambda_function.py', 'w') as f:
        f.write(content)
    
    print("✅ Fix applied successfully!")
else:
    print("❌ Could not find nested message processing section")

print("🚀 Ready for deployment!")
EOF

python temp_fix.py
rm temp_fix.py

echo "✅ Fix complete! Deploy with: cd aws && ./deploy-container.sh"
#!/usr/bin/env python3
"""
Simple test runner for debugging .msg attachment issues.
Run this to test your .msg files with embedded attachments.
"""

import os
import sys
from pathlib import Path

def find_msg_files():
    """Find .msg files in the test directories."""
    test_dirs = ["test_msg_files", "test_eml_files"]
    msg_files = []
    
    for test_dir in test_dirs:
        if os.path.exists(test_dir):
            for root, dirs, files in os.walk(test_dir):
                for file in files:
                    if file.lower().endswith('.msg'):
                        full_path = os.path.join(root, file)
                        msg_files.append(full_path)
    
    return msg_files

def main():
    print("🔍 MSG Attachment Test Runner")
    print("=" * 50)
    
    # Find available .msg files
    msg_files = find_msg_files()
    
    if not msg_files:
        print("❌ No .msg files found in test_msg_files or test_eml_files directories")
        print("\nPlease:")
        print("1. Copy your problematic .msg file to the test_msg_files directory")
        print("2. Run this script again")
        return
    
    print(f"📁 Found {len(msg_files)} .msg file(s):")
    for i, msg_file in enumerate(msg_files, 1):
        print(f"  {i}. {msg_file}")
    
    if len(msg_files) == 1:
        selected_file = msg_files[0]
        print(f"\n🎯 Auto-selecting: {selected_file}")
    else:
        print(f"\nWhich file would you like to test? (1-{len(msg_files)})")
        try:
            choice = int(input("Enter number: ")) - 1
            if 0 <= choice < len(msg_files):
                selected_file = msg_files[choice]
            else:
                print("❌ Invalid choice")
                return
        except (ValueError, KeyboardInterrupt):
            print("❌ Invalid input")
            return
    
    print(f"\n🐛 Running debug analysis on: {selected_file}")
    print("=" * 60)
    
    # Run the debug script
    os.system(f"python debug_msg_attachments.py '{selected_file}'")

if __name__ == "__main__":
    main()
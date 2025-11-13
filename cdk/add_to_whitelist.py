#!/usr/bin/env python3
"""
Helper script to add users to the whitelist configuration.

Usage:
    python3 add_to_whitelist.py --email user@example.com [--name "User Name"] [--notes "Notes"]
    python3 add_to_whitelist.py --list
    python3 add_to_whitelist.py --remove user@example.com
"""

import json
import argparse
import sys
from pathlib import Path


CONFIG_FILE = Path(__file__).parent / "whitelist_config.json"


def load_config():
    """Load whitelist configuration"""
    if not CONFIG_FILE.exists():
        return {
            "description": "Whitelist configuration for free unlimited users",
            "whitelisted_emails": [],
            "instructions": {
                "how_to_add_users": [
                    "1. Run: python3 add_to_whitelist.py --email user@example.com",
                    "2. Run: cdk deploy (or ./deploy.sh)",
                    "3. Users will be automatically created in DynamoDB with random passwords",
                    "4. Check CloudWatch Logs for the generated passwords"
                ]
            }
        }

    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)


def save_config(config):
    """Save whitelist configuration"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    print(f"✓ Configuration saved to {CONFIG_FILE}")


def add_user(email, name=None, notes=None):
    """Add a user to the whitelist"""
    config = load_config()

    # Check if user already exists
    existing_emails = [
        u.get('email') if isinstance(u, dict) else u
        for u in config['whitelisted_emails']
    ]

    if email in existing_emails:
        print(f"❌ User {email} already exists in whitelist")
        return False

    # Add new user
    user_entry = {"email": email}
    if name:
        user_entry["name"] = name
    if notes:
        user_entry["notes"] = notes

    config['whitelisted_emails'].append(user_entry)
    save_config(config)

    print(f"✓ Added {email} to whitelist")
    print(f"  Total whitelisted users: {len(config['whitelisted_emails'])}")
    print("\nNext steps:")
    print("  1. Deploy the stack: ./deploy.sh")
    print("  2. Check CloudWatch Logs for the generated password")
    print("  3. Share credentials with the user")

    return True


def remove_user(email):
    """Remove a user from the whitelist"""
    config = load_config()

    # Find and remove user
    initial_count = len(config['whitelisted_emails'])

    config['whitelisted_emails'] = [
        u for u in config['whitelisted_emails']
        if (u.get('email') if isinstance(u, dict) else u) != email
    ]

    if len(config['whitelisted_emails']) == initial_count:
        print(f"❌ User {email} not found in whitelist")
        return False

    save_config(config)
    print(f"✓ Removed {email} from whitelist")
    print(f"  Total whitelisted users: {len(config['whitelisted_emails'])}")
    print("\nNote: This only removes them from the whitelist config.")
    print("To remove from DynamoDB, use:")
    print(f"  aws dynamodb delete-item --table-name eml-converter-users-prod --key '{{\"email\": {{\"S\": \"{email}\"}}}}'")

    return True


def list_users():
    """List all whitelisted users"""
    config = load_config()

    users = config.get('whitelisted_emails', [])

    if not users:
        print("No whitelisted users configured")
        print("\nTo add a user:")
        print("  python3 add_to_whitelist.py --email user@example.com --name \"User Name\"")
        return

    print(f"Whitelisted Users ({len(users)} total):")
    print("=" * 60)

    for i, user in enumerate(users, 1):
        if isinstance(user, dict):
            email = user.get('email', 'Unknown')
            name = user.get('name', '')
            notes = user.get('notes', '')

            print(f"\n{i}. {email}")
            if name:
                print(f"   Name: {name}")
            if notes:
                print(f"   Notes: {notes}")
        else:
            print(f"\n{i}. {user}")

    print("\n" + "=" * 60)
    print("\nTo deploy these users:")
    print("  ./deploy.sh")


def main():
    parser = argparse.ArgumentParser(
        description='Manage whitelisted users for free unlimited access',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Add a user
  python3 add_to_whitelist.py --email user@example.com --name "John Doe" --notes "VIP customer"

  # List all users
  python3 add_to_whitelist.py --list

  # Remove a user
  python3 add_to_whitelist.py --remove user@example.com

After adding users, deploy with:
  ./deploy.sh
        """
    )

    parser.add_argument('--email', help='Email address to add to whitelist')
    parser.add_argument('--name', help='User display name (optional)')
    parser.add_argument('--notes', help='Additional notes (optional)')
    parser.add_argument('--list', '-l', action='store_true', help='List all whitelisted users')
    parser.add_argument('--remove', '-r', help='Remove user from whitelist')

    args = parser.parse_args()

    # Handle commands
    if args.list:
        list_users()
    elif args.remove:
        remove_user(args.remove)
    elif args.email:
        add_user(args.email, args.name, args.notes)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()

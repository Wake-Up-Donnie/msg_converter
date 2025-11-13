# Free Unlimited User Credentials

## User Account Information

A user with **free yearly unlimited access** has been created with the following credentials:

### Login Credentials
- **Email:** `tbobik91@gmail.com`
- **Password:** `vkCkAdlJbE14i99rX39T_w`
- **Account Type:** Free Yearly Unlimited
- **Subscription Status:** Active
- **Created:** 2025-11-13

### Account Features
✅ **Unlimited Conversions** - No limits on EML/MSG to PDF conversions
✅ **Active Subscription** - Full access to all features
✅ **Free Forever** - No expiration date
✅ **No Usage Tracking** - Conversions are not counted against any quota

---

## How to Log In

### Method 1: Using the Web Interface
1. Navigate to the application URL
2. Click "Login" or "Sign In"
3. Enter the email and password above
4. You will receive a JWT token for authentication

### Method 2: Using the API Directly

**Login Endpoint:** `POST /api/auth/login`

**Request:**
```bash
curl -X POST https://your-api-url.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "tbobik91@gmail.com",
    "password": "vkCkAdlJbE14i99rX39T_w"
  }'
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "email": "tbobik91@gmail.com",
    "subscription_status": "active",
    "is_unlimited": true
  }
}
```

**Using the Token:**
```bash
curl -X POST https://your-api-url.com/api/convert \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE" \
  -F "files=@email.eml"
```

---

## Database Details

The user is stored in the SQLite database (`msg_converter.db`) with the following configuration:

```sql
SELECT * FROM users WHERE email='tbobik91@gmail.com';
```

| Field | Value |
|-------|-------|
| `id` | 1 |
| `email` | tbobik91@gmail.com |
| `subscription_status` | active |
| `is_unlimited` | 1 (TRUE) |
| `free_conversions_used` | 0 |
| `created_at` | 2025-11-13T20:25:16.973622 |

---

## Creating Additional Free Users

To create more users with free unlimited access, use the script:

```bash
cd /home/user/msg_converter/backend
python3 create_free_user.py
```

Edit the `EMAIL` variable in the script to create users with different email addresses.

Or use it programmatically:

```python
from create_free_user import create_free_unlimited_user

# Create with random password
user_id, email, password = create_free_unlimited_user("newuser@example.com")

# Create with specific password
user_id, email, password = create_free_unlimited_user(
    "newuser@example.com",
    set_password="MyCustomPassword123!"
)
```

---

## Security Notes

⚠️ **Important Security Considerations:**

1. **Store Securely:** Keep this file secure and do not commit it to public repositories
2. **Change Password:** The user can change their password after first login (if password change endpoint is implemented)
3. **Rotate Credentials:** Consider rotating credentials periodically for security
4. **Database Backup:** Regularly backup the `msg_converter.db` file
5. **HTTPS Only:** Ensure all authentication is done over HTTPS in production

---

## Troubleshooting

### Cannot Log In
- Verify the email and password are correct (case-sensitive)
- Check that the database file `msg_converter.db` exists
- Ensure the backend server is running
- Check AUTH_MODE environment variable is set to "subscription"

### "User Not Found" Error
Run the verification script:
```bash
cd /home/user/msg_converter/backend
python3 -c "from models import get_user_by_email; print(get_user_by_email('tbobik91@gmail.com'))"
```

### Reset Password
Currently, there's no password reset endpoint. To manually reset:
```python
from models import get_connection
from werkzeug.security import generate_password_hash

new_password = "NewPassword123!"
password_hash = generate_password_hash(new_password)

with get_connection() as conn:
    conn.execute(
        "UPDATE users SET password_hash=? WHERE email=?",
        (password_hash, "tbobik91@gmail.com")
    )
    conn.commit()
```

---

## Next Steps

1. ✅ User created successfully
2. ✅ Credentials documented
3. ⏭️ Test login functionality
4. ⏭️ Verify unlimited conversion access
5. ⏭️ Update `.gitignore` to exclude this credentials file (recommended)

---

*Generated: 2025-11-13*
*Script: `/home/user/msg_converter/backend/create_free_user.py`*

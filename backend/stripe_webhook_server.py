"""Minimal Stripe webhook receiver for local testing.

This Flask application listens for incoming Stripe events on `/webhook` and
verifies each request using the endpoint's signing secret. The script is meant
for sandbox development: run it locally with `stripe listen` to forward events
from your Stripe test account.

Environment variables expected:

```
STRIPE_SECRET_KEY     Your Stripe test secret key (sk_test_...)
STRIPE_WEBHOOK_SECRET Signing secret from `stripe listen` or dashboard
```

Usage:

```
pip install -r backend/requirements.txt  # ensures `stripe` and `flask`
python backend/stripe_webhook_server.py
# In another terminal: stripe listen --forward-to localhost:4242/webhook
```
"""

from __future__ import annotations

import os
import stripe
from flask import Flask, request, abort


app = Flask(__name__)

# Configure Stripe with the test secret key
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "sk_test_your_key")

# Secret used to validate incoming webhook signatures
WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")


@app.post("/webhook")
def stripe_webhook() -> tuple[str, int]:
    """Receive and verify Stripe webhook events."""

    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError) as err:
        # Invalid payload or signature
        print(f"⚠️  Webhook verification failed: {err}")
        abort(400)

    # Handle event types as needed
    if event["type"] == "payment_intent.succeeded":
        payment_intent = event["data"]["object"]
        amount = payment_intent.get("amount", 0)
        print(f"Payment for {amount} succeeded.")
        # Place custom logic here
    else:
        print(f"Unhandled event type: {event['type']}")

    return "", 200


if __name__ == "__main__":
    # Default port matches Stripe's quickstart examples
    app.run(port=4242)


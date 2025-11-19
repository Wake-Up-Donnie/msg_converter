# Stripe Integration Playbook (for an Alternate Lambda Backend)

Use this checklist to graft the existing Stripe integration (webhook-driven subscription handling) into another backend Lambda that serves the same React frontend. The goal is to reproduce the current behavior and contracts, not to redesign payments.

## What Needs to Be Replicated
- Python SDK `stripe==12.5.1` (see `backend/requirements.txt`).
- Env vars: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `AUTH_MODE=subscription`, `SECRET_KEY` (JWT signing key for auth tokens).
- Webhook verification flow in `backend/stripe_webhook_server.py` (signature validation + event dispatch).
- User model fields used by the app: `subscription_status`, `is_unlimited`, `free_conversions_used`, `stripe_customer_id`, `stripe_subscription_id` (see DynamoDB model in `backend/models_dynamodb.py`).
- Auth endpoints expected by the frontend when `AUTH_MODE=subscription`: `POST /auth/register`, `POST /auth/login`, `POST /auth/check` (JWT bearer tokens in the `Authorization` header).

## Backend Implementation Steps (LLM-Friendly)
1) **Add dependencies**
   - Ensure the Lambda bundle installs `stripe==12.5.1` and `PyJWT==2.8.0`.
   - If using a separate layer, include both modules there so the function code stays small.

2) **Expose configuration**
   - Read the following from environment variables:
     - `STRIPE_SECRET_KEY`: Stripe secret key (`sk_test_*` for test).
     - `STRIPE_WEBHOOK_SECRET`: Signing secret from `stripe listen` or the dashboard.
     - `AUTH_MODE`: Set to `subscription` so the frontend switches to JWT auth.
     - `SECRET_KEY`: Secret for signing JWTs issued by `/auth/login` and `/auth/register`.
   - In infrastructure as code (SAM/CDK/Terraform), surface these as parameters and pass them into the Lambda.

3) **Match the user schema**
   - Persist the following per user (DynamoDB example from `backend/models_dynamodb.py`):
     - `email` (PK), `user_id` (UUID/GSI), `password_hash`
     - `subscription_status` (`active`, `inactive`, `canceled`, etc.)
     - `is_unlimited` (bool) and `free_conversions_used` (int counter)
     - `stripe_customer_id`, `stripe_subscription_id`
   - Implement helpers analogous to `update_user_subscription(email, status, is_unlimited=False, stripe_customer_id=None, stripe_subscription_id=None)` and `can_user_convert(email, free_limit=5)`.

4) **Auth endpoints the frontend expects**
   - `POST /auth/register` → body `{email, password}`; returns `{token}` (JWT with `user_id`, 7‑day expiry).
   - `POST /auth/login` → body `{email, password}`; returns `{token}`.
   - `POST /auth/check` → returns `{ok: true, auth: 'subscription'}` when `AUTH_MODE=subscription`.
   - All protected routes must accept `Authorization: Bearer <token>` and load the user from the token’s `user_id`.

5) **Implement the Stripe webhook endpoint**
   - Route: `POST /webhook` (or `/api/stripe/webhook` if you prefer namespacing).
   - Setup:
     ```python
     import stripe
     stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
     WEBHOOK_SECRET = os.environ["STRIPE_WEBHOOK_SECRET"]
     ```
   - Verification + dispatch (modeled on `backend/stripe_webhook_server.py`):
     ```python
     payload = request.data  # raw body
     sig_header = request.headers.get("Stripe-Signature", "")
     event = stripe.Webhook.construct_event(payload, sig_header, WEBHOOK_SECRET)
     event_type = event["type"]
     obj = event["data"]["object"]
     ```
   - Event handling (update your user store):
     - `checkout.session.completed`: read `customer` and `subscription` IDs; map `client_reference_id` or `customer_email` back to your user; set `subscription_status='active'`, store `stripe_customer_id` and `stripe_subscription_id`.
     - `customer.subscription.created` / `customer.subscription.updated`: keep `subscription_status` in sync (`status` from Stripe), refresh stored `stripe_subscription_id`.
     - `customer.subscription.deleted`: mark `subscription_status='canceled'`, `is_unlimited=False`.
     - `invoice.payment_succeeded`: optional place to mark `subscription_status='active'`.
     - `invoice.payment_failed` or `payment_intent.payment_failed`: mark user inactive; notify if needed.
     - `payment_intent.succeeded`: existing handler prints success; safe to no-op unless you use one-off payments.
   - Always return HTTP 200 on handled events; return 400 for signature failures.

6) **Local webhook testing**
   - Run the backend locally on port 4242 or your chosen port.
   - In another terminal: `stripe listen --forward-to localhost:4242/webhook` and export the printed `STRIPE_WEBHOOK_SECRET`.
   - Send test events: `stripe trigger checkout.session.completed`.

7) **Protect conversion routes using subscription state**
   - In your Lambda handler, wrap conversion endpoints with a guard:
     - Decode JWT → fetch user → call `can_user_convert(email)`.
     - Allow if `is_unlimited` or `subscription_status=='active'`, or if under the free tier limit.
     - Otherwise return 402/403.

8) **Deployment notes for a different Lambda**
   - Create an API Gateway (REST or HTTP) route for `/webhook` with **raw body passthrough** (don’t JSON-parse) so signature verification works.
   - Ensure the Lambda has outbound internet access to call Stripe’s API (VPC NAT if inside a VPC).
   - Set adequate timeouts; webhook handlers should be fast (<10s); avoid heavy work in the webhook—enqueue follow-up tasks if needed.

## Optional Enhancements (not in the current code but often needed)
- Expose a `POST /billing/create-checkout-session` that creates a Subscription Checkout session and returns the `url` to redirect the user; set `client_reference_id` to the app user ID/email so the webhook can map back.
- Add a Customer Portal endpoint (`/billing/create-portal-session`) tied to the stored `stripe_customer_id`.
- Send email receipts/notifications on `invoice.payment_failed` and `customer.subscription.deleted`.
- Write unit tests stubbing `stripe.Webhook.construct_event` and asserting `update_user_subscription` is called with the expected values.

## Acceptance Checklist
- Webhook signature verification enforced.
- User records capture `stripe_customer_id` and `stripe_subscription_id`.
- Subscription status changes propagate to conversion authorization.
- Frontend can register/login and call protected routes with a bearer token when `AUTH_MODE=subscription`.

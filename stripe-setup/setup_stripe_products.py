#!/usr/bin/env python3
"""
Stripe Product & Price Setup Script
Creates products and prices for the subscription landing page
"""
import stripe
import os
import json

# Use your test API key from environment variable
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
stripe.api_key = STRIPE_SECRET_KEY

def setup_products():
    """Create Stripe products and prices"""
    print("🔧 Setting up Stripe products and prices...")
    print(f"Using API Key: {STRIPE_SECRET_KEY[:20]}...")

    results = {}

    try:
        # Check if products already exist
        existing_products = stripe.Product.list(limit=100)
        existing_product_names = [p.name for p in existing_products.data]

        # Monthly Subscription Product
        if "EML Converter - Monthly" not in existing_product_names:
            print("\n📦 Creating Monthly Subscription Product...")
            monthly_product = stripe.Product.create(
                name="EML Converter - Monthly",
                description="Unlimited email conversions for $10/month",
                metadata={
                    "plan_type": "monthly",
                    "email_limit": "unlimited"
                }
            )
            print(f"✅ Monthly Product created: {monthly_product.id}")
        else:
            print("\n📦 Monthly Product already exists, fetching...")
            monthly_product = [p for p in existing_products.data if p.name == "EML Converter - Monthly"][0]
            print(f"✅ Found existing Monthly Product: {monthly_product.id}")

        results['monthly_product_id'] = monthly_product.id

        # Create Monthly Price
        existing_prices = stripe.Price.list(product=monthly_product.id, limit=10)
        monthly_price = None
        for price in existing_prices.data:
            if price.unit_amount == 1000 and price.recurring and price.recurring.interval == 'month':
                monthly_price = price
                break

        if not monthly_price:
            print("💰 Creating Monthly Price ($10/month)...")
            monthly_price = stripe.Price.create(
                product=monthly_product.id,
                unit_amount=1000,  # $10.00
                currency="usd",
                recurring={
                    "interval": "month",
                    "interval_count": 1
                },
                metadata={
                    "plan_type": "monthly"
                }
            )
            print(f"✅ Monthly Price created: {monthly_price.id}")
        else:
            print(f"✅ Found existing Monthly Price: {monthly_price.id}")

        results['monthly_price_id'] = monthly_price.id

        # Yearly Subscription Product
        if "EML Converter - Yearly" not in existing_product_names:
            print("\n📦 Creating Yearly Subscription Product...")
            yearly_product = stripe.Product.create(
                name="EML Converter - Yearly",
                description="Unlimited email conversions for $80/year (Save $40!)",
                metadata={
                    "plan_type": "yearly",
                    "email_limit": "unlimited"
                }
            )
            print(f"✅ Yearly Product created: {yearly_product.id}")
        else:
            print("\n📦 Yearly Product already exists, fetching...")
            yearly_product = [p for p in existing_products.data if p.name == "EML Converter - Yearly"][0]
            print(f"✅ Found existing Yearly Product: {yearly_product.id}")

        results['yearly_product_id'] = yearly_product.id

        # Create Yearly Price
        existing_prices = stripe.Price.list(product=yearly_product.id, limit=10)
        yearly_price = None
        for price in existing_prices.data:
            if price.unit_amount == 8000 and price.recurring and price.recurring.interval == 'year':
                yearly_price = price
                break

        if not yearly_price:
            print("💰 Creating Yearly Price ($80/year)...")
            yearly_price = stripe.Price.create(
                product=yearly_product.id,
                unit_amount=8000,  # $80.00
                currency="usd",
                recurring={
                    "interval": "year",
                    "interval_count": 1
                },
                metadata={
                    "plan_type": "yearly"
                }
            )
            print(f"✅ Yearly Price created: {yearly_price.id}")
        else:
            print(f"✅ Found existing Yearly Price: {yearly_price.id}")

        results['yearly_price_id'] = yearly_price.id

        # Save to config file
        config = {
            "monthly_product_id": results['monthly_product_id'],
            "monthly_price_id": results['monthly_price_id'],
            "yearly_product_id": results['yearly_product_id'],
            "yearly_price_id": results['yearly_price_id'],
            "publishable_key": "pk_test_51MrvdrIHRR0HEy4B5o2zAZshx9C3d0RVz5nrAnkEJZgbg6yc9ehZEV4BzNwRWO0weVUiTEg4qZNnUEFLPlGI3KrI00yH7ZbvNy"
        }

        with open('stripe_config.json', 'w') as f:
            json.dump(config, f, indent=2)

        print("\n" + "="*60)
        print("🎉 Stripe Setup Complete!")
        print("="*60)
        print("\n📋 Configuration saved to: stripe_config.json")
        print("\n🔑 Product & Price IDs:")
        print(f"   Monthly Product: {results['monthly_product_id']}")
        print(f"   Monthly Price:   {results['monthly_price_id']}")
        print(f"   Yearly Product:  {results['yearly_product_id']}")
        print(f"   Yearly Price:    {results['yearly_price_id']}")
        print("\n💡 Next Steps:")
        print("   1. Copy these IDs to your .env file")
        print("   2. Set up webhook endpoint in Stripe Dashboard")
        print("   3. Deploy the backend Lambda functions")
        print("="*60)

        return results

    except stripe.error.StripeError as e:
        print(f"\n❌ Stripe Error: {e}")
        return None
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return None

if __name__ == "__main__":
    setup_products()

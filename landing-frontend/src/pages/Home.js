import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import './Home.css';

const Home = () => {
  const navigate = useNavigate();
  const { user } = useAuth();

  const pricingPlans = [
    {
      name: 'Free',
      price: '$0',
      period: 'forever',
      features: [
        '5 emails per month',
        'PDF conversion',
        'Email attachments support',
        'Basic support'
      ],
      cta: user ? 'Try Now' : 'Get Started',
      ctaLink: user ? '/try' : '/register',
      highlighted: false
    },
    {
      name: 'Monthly',
      price: '$10',
      period: 'per month',
      features: [
        'Unlimited emails',
        'PDF conversion',
        'Email attachments support',
        'Priority support',
        'Cancel anytime'
      ],
      cta: user ? 'Upgrade' : 'Get Started',
      ctaLink: user ? '/dashboard?plan=monthly' : '/register',
      highlighted: true
    },
    {
      name: 'Yearly',
      price: '$80',
      period: 'per year',
      savings: 'Save $40!',
      features: [
        'Unlimited emails',
        'PDF conversion',
        'Email attachments support',
        'Priority support',
        'Best value'
      ],
      cta: user ? 'Upgrade' : 'Get Started',
      ctaLink: user ? '/dashboard?plan=yearly' : '/register',
      highlighted: false
    }
  ];

  return (
    <div className="home">
      <nav className="navbar">
        <div className="nav-container">
          <div className="nav-logo">
            <h2>EML Converter</h2>
          </div>
          <div className="nav-links">
            {user ? (
              <Link to="/dashboard" className="nav-button">Dashboard</Link>
            ) : (
              <>
                <Link to="/login" className="nav-button">Login</Link>
                <Link to="/register" className="nav-button primary">Sign Up</Link>
              </>
            )}
          </div>
        </div>
      </nav>

      <section className="hero">
        <div className="hero-content">
          <h1>Convert Outlook Emails to PDF</h1>
          <p className="hero-subtitle">
            The easiest way to convert your .eml files to professional PDFs.
            Preserve formatting, attachments, and more.
          </p>
          <div className="hero-cta">
            {user ? (
              <Link to="/try" className="cta-button large">Try It Now</Link>
            ) : (
              <Link to="/register" className="cta-button large">Get Started Free</Link>
            )}
          </div>
        </div>
      </section>

      <section className="features">
        <div className="features-container">
          <h2>Why Choose Us?</h2>
          <div className="features-grid">
            <div className="feature-card">
              <div className="feature-icon">📧</div>
              <h3>Easy to Use</h3>
              <p>Drag and drop your .eml files and get PDFs instantly</p>
            </div>
            <div className="feature-card">
              <div className="feature-icon">📄</div>
              <h3>High Quality</h3>
              <p>Preserves email formatting, images, and attachments</p>
            </div>
            <div className="feature-card">
              <div className="feature-icon">🔒</div>
              <h3>Secure</h3>
              <p>Your files are automatically deleted after conversion</p>
            </div>
            <div className="feature-card">
              <div className="feature-icon">⚡</div>
              <h3>Fast</h3>
              <p>Convert multiple emails in seconds</p>
            </div>
          </div>
        </div>
      </section>

      <section className="pricing">
        <div className="pricing-container">
          <h2>Simple, Transparent Pricing</h2>
          <p className="pricing-subtitle">Choose the plan that works for you</p>
          <div className="pricing-grid">
            {pricingPlans.map((plan, index) => (
              <div
                key={index}
                className={`pricing-card ${plan.highlighted ? 'highlighted' : ''}`}
              >
                {plan.highlighted && <div className="badge">Most Popular</div>}
                {plan.savings && <div className="savings-badge">{plan.savings}</div>}
                <h3>{plan.name}</h3>
                <div className="price">
                  <span className="amount">{plan.price}</span>
                  <span className="period">{plan.period}</span>
                </div>
                <ul className="features-list">
                  {plan.features.map((feature, i) => (
                    <li key={i}>✓ {feature}</li>
                  ))}
                </ul>
                <Link
                  to={plan.ctaLink}
                  className={`pricing-cta ${plan.highlighted ? 'primary' : ''}`}
                >
                  {plan.cta}
                </Link>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="cta-section">
        <div className="cta-content">
          <h2>Ready to Get Started?</h2>
          <p>Join thousands of users converting emails to PDFs</p>
          {user ? (
            <Link to="/try" className="cta-button large">Try It Now</Link>
          ) : (
            <Link to="/register" className="cta-button large">Sign Up Free</Link>
          )}
        </div>
      </section>

      <footer className="footer">
        <div className="footer-content">
          <p>&copy; 2025 EML Converter. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
};

export default Home;

import React, { useState, useEffect } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { loadStripe } from '@stripe/stripe-js';
import './Dashboard.css';

const stripePromise = loadStripe(process.env.REACT_APP_STRIPE_PUBLISHABLE_KEY || 'pk_test_51MrvdrIHRR0HEy4B5o2zAZshx9C3d0RVz5nrAnkEJZgbg6yc9ehZEV4BzNwRWO0weVUiTEg4qZNnUEFLPlGI3KrI00yH7ZbvNy');

const Dashboard = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { user, logout, refreshUser, getUsage, createCheckoutSession, createPortalSession } = useAuth();
  const [usage, setUsage] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showSuccess, setShowSuccess] = useState(false);

  useEffect(() => {
    // Check for success message from Stripe
    if (searchParams.get('success') === 'true') {
      setShowSuccess(true);
      refreshUser();
      setTimeout(() => setShowSuccess(false), 5000);
    }

    // Load usage data
    loadUsage();
  }, [searchParams]);

  const loadUsage = async () => {
    const usageData = await getUsage();
    setUsage(usageData);
  };

  const handleUpgrade = async (planType) => {
    setLoading(true);
    try {
      const { url } = await createCheckoutSession(planType);
      window.location.href = url;
    } catch (error) {
      console.error('Error creating checkout session:', error);
      alert('Failed to start checkout. Please try again.');
      setLoading(false);
    }
  };

  const handleManageBilling = async () => {
    setLoading(true);
    try {
      const { url } = await createPortalSession();
      window.location.href = url;
    } catch (error) {
      console.error('Error creating portal session:', error);
      alert('Failed to open billing portal. Please try again.');
      setLoading(false);
    }
  };

  const getPlanName = (planType) => {
    switch (planType) {
      case 'monthly':
        return 'Monthly Plan';
      case 'yearly':
        return 'Yearly Plan';
      case 'free':
      default:
        return 'Free Plan';
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'active':
        return <span className="badge badge-active">Active</span>;
      case 'past_due':
        return <span className="badge badge-warning">Past Due</span>;
      case 'canceled':
        return <span className="badge badge-canceled">Canceled</span>;
      default:
        return null;
    }
  };

  return (
    <div className="dashboard">
      <nav className="dashboard-nav">
        <div className="nav-container">
          <h2>EML Converter</h2>
          <div className="nav-links">
            <Link to="/">Home</Link>
            <Link to="/try" className="nav-button">Try App</Link>
            <button onClick={logout} className="nav-button">Logout</button>
          </div>
        </div>
      </nav>

      <div className="dashboard-container">
        {showSuccess && (
          <div className="success-banner">
            ✓ Subscription activated successfully! Welcome aboard!
          </div>
        )}

        <div className="dashboard-header">
          <h1>Welcome, {user?.email}</h1>
          <p>Manage your subscription and convert emails to PDFs</p>
        </div>

        <div className="dashboard-grid">
          {/* Subscription Card */}
          <div className="dashboard-card">
            <h2>Your Subscription</h2>
            <div className="subscription-info">
              <div className="plan-name">
                {getPlanName(user?.planType)}
                {user?.subscriptionStatus && getStatusBadge(user.subscriptionStatus)}
              </div>

              {user?.planType === 'free' && usage && (
                <div className="usage-info">
                  <p className="usage-text">
                    {usage.used || 0} of 5 emails used this month
                  </p>
                  <div className="usage-bar">
                    <div
                      className="usage-progress"
                      style={{ width: `${((usage.used || 0) / 5) * 100}%` }}
                    ></div>
                  </div>
                  {usage.remaining !== undefined && usage.remaining <= 2 && (
                    <p className="usage-warning">
                      ⚠️ Only {usage.remaining} emails remaining. Consider upgrading!
                    </p>
                  )}
                </div>
              )}

              {user?.planType !== 'free' && (
                <div className="unlimited-badge">
                  ✨ Unlimited Conversions
                </div>
              )}
            </div>

            <div className="subscription-actions">
              {user?.planType === 'free' ? (
                <>
                  <button
                    onClick={() => handleUpgrade('monthly')}
                    className="upgrade-button"
                    disabled={loading}
                  >
                    Upgrade to Monthly ($10/mo)
                  </button>
                  <button
                    onClick={() => handleUpgrade('yearly')}
                    className="upgrade-button secondary"
                    disabled={loading}
                  >
                    Upgrade to Yearly ($80/yr - Save $40!)
                  </button>
                </>
              ) : (
                <button
                  onClick={handleManageBilling}
                  className="manage-button"
                  disabled={loading}
                >
                  Manage Billing
                </button>
              )}
            </div>
          </div>

          {/* Quick Actions Card */}
          <div className="dashboard-card">
            <h2>Quick Actions</h2>
            <div className="quick-actions">
              <Link to="/try" className="action-card">
                <div className="action-icon">📧</div>
                <h3>Convert Emails</h3>
                <p>Upload and convert .eml files to PDF</p>
              </Link>

              {user?.planType === 'free' && (
                <div className="action-card promo">
                  <div className="action-icon">⭐</div>
                  <h3>Upgrade to Pro</h3>
                  <p>Get unlimited conversions and priority support</p>
                  <button
                    onClick={() => handleUpgrade('monthly')}
                    className="promo-button"
                  >
                    View Plans
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Plan Comparison Card (for free users) */}
          {user?.planType === 'free' && (
            <div className="dashboard-card full-width">
              <h2>Upgrade Your Plan</h2>
              <div className="plan-comparison">
                <div className="plan-card">
                  <h3>Monthly</h3>
                  <div className="plan-price">
                    <span className="amount">$10</span>
                    <span className="period">/month</span>
                  </div>
                  <ul className="plan-features">
                    <li>✓ Unlimited emails</li>
                    <li>✓ PDF conversion</li>
                    <li>✓ Priority support</li>
                    <li>✓ Cancel anytime</li>
                  </ul>
                  <button
                    onClick={() => handleUpgrade('monthly')}
                    className="plan-button"
                    disabled={loading}
                  >
                    {loading ? 'Loading...' : 'Upgrade'}
                  </button>
                </div>

                <div className="plan-card featured">
                  <div className="best-value">Best Value</div>
                  <h3>Yearly</h3>
                  <div className="plan-price">
                    <span className="amount">$80</span>
                    <span className="period">/year</span>
                  </div>
                  <div className="savings">Save $40!</div>
                  <ul className="plan-features">
                    <li>✓ Unlimited emails</li>
                    <li>✓ PDF conversion</li>
                    <li>✓ Priority support</li>
                    <li>✓ Best value</li>
                  </ul>
                  <button
                    onClick={() => handleUpgrade('yearly')}
                    className="plan-button primary"
                    disabled={loading}
                  >
                    {loading ? 'Loading...' : 'Upgrade'}
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

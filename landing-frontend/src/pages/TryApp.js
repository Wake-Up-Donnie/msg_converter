import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import './TryApp.css';

const TryApp = () => {
  const navigate = useNavigate();
  const { user, logout, getUsage } = useAuth();
  const [usage, setUsage] = useState(null);
  const [loading, setLoading] = useState(true);
  const [quotaExceeded, setQuotaExceeded] = useState(false);

  // URL of the existing EML converter app
  const CONVERTER_URL = process.env.REACT_APP_CONVERTER_URL || 'https://your-converter-app-url.com';

  useEffect(() => {
    checkQuota();
  }, []);

  const checkQuota = async () => {
    const usageData = await getUsage();
    setUsage(usageData);
    setLoading(false);

    if (usageData && !usageData.allowed) {
      setQuotaExceeded(true);
    }
  };

  if (loading) {
    return <div className="loading">Checking quota...</div>;
  }

  if (quotaExceeded) {
    return (
      <div className="try-app">
        <nav className="app-nav">
          <div className="nav-container">
            <h2>EML Converter</h2>
            <div className="nav-links">
              <Link to="/dashboard">Dashboard</Link>
              <button onClick={logout} className="nav-button">Logout</button>
            </div>
          </div>
        </nav>

        <div className="quota-exceeded">
          <div className="quota-message">
            <div className="quota-icon">⚠️</div>
            <h1>Free Tier Limit Reached</h1>
            <p>You've used all 5 of your free email conversions this month.</p>
            <p>Upgrade to a paid plan to continue converting emails.</p>

            <div className="upgrade-options">
              <button
                onClick={() => navigate('/dashboard')}
                className="upgrade-button"
              >
                View Upgrade Options
              </button>
            </div>

            <div className="reset-info">
              <p>Your free tier quota will reset next month.</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="try-app">
      <nav className="app-nav">
        <div className="nav-container">
          <h2>EML Converter</h2>
          <div className="nav-links">
            {usage && user?.planType === 'free' && (
              <div className="usage-indicator">
                {usage.used || 0} / 5 used
              </div>
            )}
            {usage && user?.planType !== 'free' && (
              <div className="usage-indicator unlimited">
                ✨ Unlimited
              </div>
            )}
            <Link to="/dashboard">Dashboard</Link>
            <button onClick={logout} className="nav-button">Logout</button>
          </div>
        </div>
      </nav>

      <div className="app-container">
        <div className="app-info">
          <h1>Convert EML Files to PDF</h1>
          {user?.planType === 'free' && usage && (
            <p className="quota-info">
              You have {usage.remaining || 0} conversions remaining this month.
              <Link to="/dashboard" className="upgrade-link"> Upgrade for unlimited</Link>
            </p>
          )}
        </div>

        <div className="app-frame">
          {/* Embed the actual converter app */}
          <iframe
            src={`${CONVERTER_URL}?token=${localStorage.getItem('token')}`}
            title="EML to PDF Converter"
            className="converter-iframe"
            sandbox="allow-same-origin allow-scripts allow-forms allow-downloads"
          />

          {/* Alternative: Link to the converter app */}
          <div className="converter-alternative">
            <p>Having trouble with the embedded converter?</p>
            <a
              href={`${CONVERTER_URL}?token=${localStorage.getItem('token')}`}
              target="_blank"
              rel="noopener noreferrer"
              className="open-new-tab"
            >
              Open in New Tab
            </a>
          </div>
        </div>

        {user?.planType === 'free' && usage && usage.remaining <= 2 && (
          <div className="low-quota-banner">
            <p>
              ⚠️ You're running low on conversions!
              <Link to="/dashboard"> Upgrade now</Link> for unlimited access.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default TryApp;

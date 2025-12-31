// Netlify Function - server.js (DEBUG VERSION)
const express = require('express');
const axios = require('axios');
const session = require('express-session');
const cors = require('cors');
const serverless = require('serverless-http');

const app = express();

// Simple CORS for debugging
app.use(cors({
  origin: ['https://divine-apex.netlify.app', 'http://localhost:8888'],
  credentials: true
}));

app.use(express.json());

// Simple session for debugging
app.use(session({
  secret: process.env.SESSION_SECRET || 'debug-secret-123',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'none',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// ==================== DEBUG ROUTES ====================

// 1. Test if server is running
app.get("/api/test", (req, res) => {
  res.json({ 
    message: "Server is running",
    time: new Date().toISOString(),
    node_env: process.env.NODE_ENV
  });
});

// 2. Check environment variables (without exposing secrets)
app.get("/api/env-check", (req, res) => {
  res.json({
    has_discord_client_id: !!process.env.DISCORD_CLIENT_ID,
    has_discord_client_secret: !!process.env.DISCORD_CLIENT_SECRET,
    has_discord_bot_token: !!process.env.DISCORD_BOT_TOKEN,
    has_discord_guild_id: !!process.env.DISCORD_GUILD_ID,
    redirect_uri: process.env.REDIRECT_URI || "not set",
    frontend_url: process.env.FRONTEND_URL || "not set",
    session_secret_set: !!process.env.SESSION_SECRET
  });
});

// 3. Simple login endpoint
app.get("/api/login", (req, res) => {
  console.log('LOGIN ENDPOINT HIT - Environment check:', {
    client_id: process.env.DISCORD_CLIENT_ID ? 'SET' : 'MISSING',
    redirect_uri: process.env.REDIRECT_URI || 'not set'
  });

  if (!process.env.DISCORD_CLIENT_ID) {
    return res.status(500).json({
      error: "Discord Client ID not configured",
      message: "Please set DISCORD_CLIENT_ID environment variable in Netlify"
    });
  }

  const redirectUri = encodeURIComponent(
    process.env.REDIRECT_URI || 
    "https://divine-apex.netlify.app/.netlify/functions/server/callback"
  );

  const discordAuthUrl = `https://discord.com/oauth2/authorize` +
    `?client_id=${process.env.DISCORD_CLIENT_ID}` +
    `&redirect_uri=${redirectUri}` +
    `&response_type=code` +
    `&scope=identify` +
    `&prompt=none`;

  console.log('Redirecting to Discord OAuth:', discordAuthUrl);
  res.redirect(discordAuthUrl);
});

// 4. Simple callback for testing
app.get("/api/callback", async (req, res) => {
  console.log('CALLBACK RECEIVED - Query params:', req.query);
  
  try {
    const code = req.query.code;
    
    if (!code) {
      console.error('No authorization code received');
      return res.redirect('https://divine-apex.netlify.app?login=error&message=No+code+received');
    }
    
    console.log('Authorization code received:', code.substring(0, 10) + '...');
    
    // For testing - create a fake user session
    req.session.user = {
      id: 'test_' + Date.now(),
      username: 'TestUser',
      discriminator: '0000',
      avatar: null,
      global_name: 'Test User'
    };
    req.session.role = 'customer';
    
    console.log('Session created:', req.session.user);
    
    // Redirect back to frontend
    const frontendUrl = process.env.FRONTEND_URL || 'https://divine-apex.netlify.app';
    res.redirect(`${frontendUrl}?login=success&username=TestUser&role=customer`);
    
  } catch (error) {
    console.error('Callback error:', error);
    const frontendUrl = process.env.FRONTEND_URL || 'https://divine-apex.netlify.app';
    res.redirect(`${frontendUrl}?login=error&message=${encodeURIComponent(error.message)}`);
  }
});

// 5. Check session status
app.get("/api/auth/status", (req, res) => {
  console.log('Auth status check - Session ID:', req.sessionID);
  
  if (req.session.user) {
    res.json({
      authenticated: true,
      user: req.session.user,
      role: req.session.role || 'customer'
    });
  } else {
    res.json({ 
      authenticated: false,
      message: "Not authenticated"
    });
  }
});

// 6. Logout
app.get("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect('https://divine-apex.netlify.app?logout=success');
  });
});

// ==================== ERROR HANDLING ====================
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({ 
    error: "Internal server error",
    message: err.message 
  });
});

module.exports.handler = serverless(app);
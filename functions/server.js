// Netlify Function - server.js
const express = require('express');
const axios = require('axios');
const session = require('express-session');
const cors = require('cors');
const serverless = require('serverless-http');

const app = express();

// Load environment variables
require('dotenv').config();

// Netlify requires session storage adaptation
const MemoryStore = require('memorystore')(session);

// ==================== MIDDLEWARE ====================
// CORS configuration for Netlify
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      "https://divine-apex.netlify.app",
      "https://*.netlify.app",
      "http://localhost:8888",
      "http://localhost:8000",
      "http://localhost:3000"
    ];
    
    if (allowedOrigins.some(allowed => origin === allowed || origin.endsWith(allowed.replace('*', '')))) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Preflight requests
app.options('*', cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration for Netlify
app.use(session({
  store: new MemoryStore({
    checkPeriod: 86400000 // 24 hours
  }),
  name: 'gtav_session',
  secret: process.env.SESSION_SECRET || "gtav-dealership-secret-key-2023-change-this",
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    secure: true, // MUST be true for Netlify (HTTPS)
    httpOnly: true,
    sameSite: 'none', // MUST be 'none' for cross-site cookies
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    domain: '.netlify.app' // Important for Netlify
  }
}));

// ==================== ENVIRONMENT VARIABLES ====================
const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_BOT_TOKEN,
  DISCORD_GUILD_ID,
  REDIRECT_URI = "https://divine-apex.netlify.app/.netlify/functions/server/callback",
  FRONTEND_URL = "https://divine-apex.netlify.app",
  DISCORD_WEBHOOK_URL,
  NODE_ENV = 'production'
} = process.env;

// Log environment check (will appear in Netlify logs)
console.log('Environment check:', {
  has_client_id: !!DISCORD_CLIENT_ID,
  has_client_secret: !!DISCORD_CLIENT_SECRET,
  has_bot_token: !!DISCORD_BOT_TOKEN,
  has_guild_id: !!DISCORD_GUILD_ID,
  redirect_uri: REDIRECT_URI,
  frontend_url: FRONTEND_URL,
  node_env: NODE_ENV
});

const ROLES = {
  OWNER: process.env.ROLE_ID_OWNER || "ROLE_ID_OWNER",
  MANAGER: process.env.ROLE_ID_MANAGER || "ROLE_ID_MANAGER",
  CUSTOMER: process.env.ROLE_ID_CUSTOMER || "ROLE_ID_CUSTOMER"
};

// ==================== VEHICLE DATA ====================
const defaultVehicles = [
  {
    id: 1,
    model: "sultan",
    name: "Karin Sultan",
    price: 250000,
    class: "Sports",
    category: "sedan",
    seats: 4,
    topSpeed: "210 km/h",
    acceleration: "5.2s",
    description: "Classic Japanese sports sedan",
    modelFile: "sultan.glb",
    scale: 1.0,
    position: { x: 0, y: -0.5, z: 0 },
    rotation: { x: 0, y: 0, z: 0 }
  },
  {
    id: 2,
    model: "buffalo",
    name: "Bravado Buffalo",
    price: 350000,
    class: "Muscle",
    category: "muscle",
    seats: 4,
    topSpeed: "230 km/h",
    acceleration: "4.8s",
    description: "Modern American muscle car",
    modelFile: "buffalo.glb",
    scale: 1.0,
    position: { x: 0, y: -0.5, z: 0 },
    rotation: { x: 0, y: 0, z: 0 }
  },
  {
    id: 3,
    model: "comet2",
    name: "Pfister Comet",
    price: 450000,
    class: "Sports",
    category: "sports",
    seats: 2,
    topSpeed: "240 km/h",
    acceleration: "4.2s",
    description: "German sports car",
    modelFile: "comet2.glb",
    scale: 1.0,
    position: { x: 0, y: -0.5, z: 0 },
    rotation: { x: 0, y: 0, z: 0 }
  },
  {
    id: 4,
    model: "zentorno",
    name: "Pegassi Zentorno",
    price: 750000,
    class: "Super",
    category: "super",
    seats: 2,
    topSpeed: "270 km/h",
    acceleration: "3.5s",
    description: "Italian hypercar",
    modelFile: "zentorno.glb",
    scale: 0.9,
    position: { x: 0, y: -0.4, z: 0 },
    rotation: { x: 0, y: 0, z: 0 }
  }
];

// ==================== MIDDLEWARE FUNCTIONS ====================
const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Authentication required" });
  }
  next();
};

function getPermissions(role) {
  const permissions = {
    canOrder: false,
    canManage: false,
    canApprove: false,
    canViewAllOrders: false
  };

  switch(role) {
    case 'owner':
      permissions.canOrder = true;
      permissions.canManage = true;
      permissions.canApprove = true;
      permissions.canViewAllOrders = true;
      break;
    case 'manager':
      permissions.canOrder = true;
      permissions.canManage = true;
      permissions.canApprove = true;
      permissions.canViewAllOrders = true;
      break;
    case 'customer':
      permissions.canOrder = true;
      break;
    default:
      permissions.canOrder = false;
  }

  return permissions;
}

// ==================== ROUTES ====================

// 1. DEBUG ENDPOINT (Check if server is working)
app.get("/api/debug", (req, res) => {
  res.json({
    status: "server is running",
    session: req.sessionID ? "session exists" : "no session",
    user: req.session.user || "no user",
    env: {
      client_id_set: !!DISCORD_CLIENT_ID,
      client_secret_set: !!DISCORD_CLIENT_SECRET,
      bot_token_set: !!DISCORD_BOT_TOKEN,
      guild_id_set: !!DISCORD_GUILD_ID,
      node_env: NODE_ENV
    },
    timestamp: new Date().toISOString(),
    cookies: req.headers.cookie || "no cookies"
  });
});

// 2. AUTH STATUS
app.get("/api/auth/status", (req, res) => {
  console.log('Auth status check:', req.sessionID);
  
  if (req.session.user) {
    res.json({
      authenticated: true,
      user: req.session.user,
      role: req.session.role,
      permissions: getPermissions(req.session.role)
    });
  } else {
    res.json({ 
      authenticated: false,
      permissions: { canOrder: false, canManage: false }
    });
  }
});

// 3. LOGIN ENDPOINT
app.get("/api/login", (req, res) => {
  console.log('Login endpoint hit');
  
  if (!DISCORD_CLIENT_ID) {
    return res.status(500).send('Discord Client ID not configured. Please set DISCORD_CLIENT_ID environment variable.');
  }

  const discordAuthUrl = `https://discord.com/oauth2/authorize` +
    `?client_id=${DISCORD_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&response_type=code` +
    `&scope=identify%20guilds%20guilds.join` +
    `&prompt=none`;
  
  console.log('Redirecting to Discord:', discordAuthUrl);
  res.redirect(discordAuthUrl);
});

// 4. DISCORD CALLBACK (CRITICAL - FIXED)
app.get("/api/callback", async (req, res) => {
  console.log('Discord callback received');
  
  try {
    const code = req.query.code;
    const error = req.query.error;
    const errorDescription = req.query.error_description;

    if (error) {
      console.error('Discord OAuth error:', error, errorDescription);
      throw new Error(`Discord OAuth error: ${errorDescription || error}`);
    }

    if (!code) {
      console.error('No authorization code provided');
      throw new Error("No authorization code provided");
    }

    console.log("Authorization code received");

    // ======== 1. EXCHANGE CODE FOR TOKEN ========
    const tokenResponse = await axios.post(
      "https://discord.com/api/oauth2/token",
      new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code: code,
        redirect_uri: REDIRECT_URI
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Accept-Encoding": "application/json"
        }
      }
    );

    const accessToken = tokenResponse.data.access_token;
    const refreshToken = tokenResponse.data.refresh_token;
    console.log("Access token received");

    // ======== 2. GET USER INFO ========
    const userResponse = await axios.get("https://discord.com/api/users/@me", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Accept-Encoding": "application/json"
      }
    });

    const user = userResponse.data;
    console.log(`User authenticated: ${user.username}#${user.discriminator} (ID: ${user.id})`);

    // ======== 3. ADD USER TO DISCORD SERVER ========
    if (DISCORD_BOT_TOKEN && DISCORD_GUILD_ID) {
      try {
        await axios.put(
          `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${user.id}`,
          {
            access_token: accessToken
          },
          {
            headers: {
              Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
              "Content-Type": "application/json"
            }
          }
        );
        console.log("User added to server");
      } catch (serverError) {
        // User might already be in the server (error code 204)
        if (serverError.response?.status !== 204) {
          console.log("Could not add user to server (might already be member):", serverError.message);
        }
      }
    } else {
      console.log("Skipping server join - bot token or guild ID not configured");
    }

    // ======== 4. CHECK/ASSIGN ROLES ========
    let role = "customer";
    
    if (DISCORD_BOT_TOKEN && DISCORD_GUILD_ID) {
      try {
        const memberResponse = await axios.get(
          `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${user.id}`,
          {
            headers: {
              Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
              "Accept-Encoding": "application/json"
            }
          }
        );

        const memberRoles = memberResponse.data.roles || [];
        
        if (memberRoles.includes(ROLES.OWNER)) {
          role = "owner";
          console.log("User is owner");
        } else if (memberRoles.includes(ROLES.MANAGER)) {
          role = "manager";
          console.log("User is manager");
        } else if (!memberRoles.includes(ROLES.CUSTOMER)) {
          // Assign customer role if not present
          try {
            await axios.put(
              `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${user.id}/roles/${ROLES.CUSTOMER}`,
              {},
              { 
                headers: { 
                  Authorization: `Bot ${DISCORD_BOT_TOKEN}` 
                } 
              }
            );
            console.log("Assigned customer role");
          } catch (roleError) {
            console.log("Could not assign customer role:", roleError.message);
          }
        } else {
          console.log("User already has customer role");
        }
      } catch (roleError) {
        console.log("Error checking member roles:", roleError.message);
      }
    }

    // ======== 5. CREATE SESSION ========
    req.session.user = {
      id: user.id,
      username: user.username,
      discriminator: user.discriminator,
      avatar: user.avatar,
      global_name: user.global_name || user.username,
      email: user.email
    };
    req.session.role = role;
    req.session.accessToken = accessToken;
    req.session.refreshToken = refreshToken;

    console.log(`Session created for user: ${user.username}, Role: ${role}`);

    // ======== 6. REDIRECT TO FRONTEND ========
    // Save session before redirect
    req.session.save((err) => {
      if (err) {
        console.error("Session save error:", err);
        return res.redirect(`${FRONTEND_URL}?login=error&message=Session+error`);
      }
      
      const redirectUrl = `${FRONTEND_URL}?login=success&username=${encodeURIComponent(user.username)}&role=${role}`;
      console.log("Redirecting to:", redirectUrl);
      res.redirect(redirectUrl);
    });

  } catch (error) {
    console.error("Authentication error:", {
      message: error.message,
      response: error.response?.data,
      status: error.response?.status
    });

    let errorMessage = "Authentication failed";
    if (error.response?.data?.error) {
      errorMessage = error.response.data.error;
    } else if (error.message) {
      errorMessage = error.message;
    }

    const redirectUrl = `${FRONTEND_URL}?login=error&message=${encodeURIComponent(errorMessage)}`;
    res.redirect(redirectUrl);
  }
});

// 5. LOGOUT
app.get("/api/logout", (req, res) => {
  const username = req.session.user?.username || "User";
  
  req.session.destroy((err) => {
    if (err) {
      console.error("Session destroy error:", err);
    }
    
    console.log(`User logged out: ${username}`);
    
    // Clear session cookie
    res.clearCookie('gtav_session', {
      domain: '.netlify.app',
      path: '/',
      secure: true,
      sameSite: 'none'
    });
    
    res.redirect(`${FRONTEND_URL}?logout=success`);
  });
});

// 6. VEHICLES
app.get("/api/vehicles", (req, res) => {
  res.json(defaultVehicles);
});

// 7. SUBMIT ORDER
app.post("/api/orders", requireAuth, async (req, res) => {
  try {
    const order = req.body;
    const user = req.session.user;
    const role = req.session.role;

    console.log("New order received from:", user.username);

    // Validate order data
    if (!order.vehicle_model || !order.vehicle_name || !order.price) {
      return res.status(400).json({ 
        error: "Missing required order information" 
      });
    }

    // Send to Discord webhook if configured
    if (DISCORD_WEBHOOK_URL) {
      try {
        const embed = {
          title: "🚗 New Vehicle Order",
          color: role === "owner" ? 0xff0000 : role === "manager" ? 0xffa500 : 0x00ff00,
          fields: [
            { 
              name: "Discord User", 
              value: `<@${user.id}> (${user.global_name || user.username})`, 
              inline: true 
            },
            { 
              name: "Role", 
              value: role.charAt(0).toUpperCase() + role.slice(1), 
              inline: true 
            },
            { 
              name: "Vehicle", 
              value: order.vehicle_name, 
              inline: true 
            },
            { 
              name: "Price", 
              value: `$${order.price.toLocaleString()}`, 
              inline: true 
            },
            { 
              name: "Player Name", 
              value: order.player_name || "Not provided", 
              inline: true 
            },
            { 
              name: "Colors", 
              value: `**Primary:** ${order.primary_color}\n**Secondary:** ${order.secondary_color}\n**Accent:** ${order.accent_color}` 
            },
            { 
              name: "Special Requests", 
              value: order.special_requests || "None" 
            }
          ],
          timestamp: new Date().toISOString(),
          footer: { 
            text: "GTA V Showroom • Order ID: " + Date.now() 
          },
          thumbnail: {
            url: user.avatar ? 
              `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png` : 
              'https://cdn.discordapp.com/embed/avatars/0.png'
          }
        };

        await axios.post(DISCORD_WEBHOOK_URL, {
          content: role === "customer" ? `<@&${ROLES.MANAGER}> <@&${ROLES.OWNER}>` : '',
          embeds: [embed]
        });

        console.log("Discord notification sent");
      } catch (webhookError) {
        console.error("Failed to send Discord webhook:", webhookError.message);
      }
    }

    const orderId = Date.now();
    
    res.json({ 
      success: true, 
      message: "Order submitted successfully!",
      orderId: orderId,
      details: {
        vehicle: order.vehicle_name,
        price: order.price,
        estimatedDelivery: "24-48 hours",
        contact: "Check Discord for updates"
      }
    });

  } catch (error) {
    console.error("Order processing error:", error);
    res.status(500).json({ 
      error: "Failed to process order",
      details: error.message 
    });
  }
});

// 8. HEALTH CHECK
app.get("/api/health", (req, res) => {
  res.json({ 
    status: "healthy",
    service: "GTA V Showroom",
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    version: "1.0.0"
  });
});

// 9. TEST SESSION
app.get("/api/test-session", (req, res) => {
  req.session.test = req.session.test ? req.session.test + 1 : 1;
  res.json({
    sessionId: req.sessionID,
    testValue: req.session.test,
    user: req.session.user || "No user",
    cookies: req.headers.cookie
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

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: "Route not found",
    path: req.path,
    method: req.method
  });
});

// ==================== EXPORT FOR NETLIFY ====================
module.exports.handler = serverless(app);
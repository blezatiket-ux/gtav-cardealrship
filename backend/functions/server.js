// server.js - Complete Discord Authentication Server
const express = require("express");
const axios = require("axios");
const session = require("express-session");
const cors = require("cors");
require("dotenv").config();

const app = express();

// Middleware
app.use(cors({
  origin: ["http://localhost:8000", "http://127.0.0.1:5500", "http://localhost:5500"],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || "gtav-dealership-secret-key-2023",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true in production with HTTPS
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Environment variables
const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_BOT_TOKEN,
  DISCORD_GUILD_ID,
  REDIRECT_URI = "http://localhost:3001/callback",
  FRONTEND_URL = "http://localhost:8000",
  PORT = 3001
} = process.env;

const ROLES = {
  OWNER: process.env.ROLE_ID_OWNER || "ROLE_ID_OWNER",
  MANAGER: process.env.ROLE_ID_MANAGER || "ROLE_ID_MANAGER",
  CUSTOMER: process.env.ROLE_ID_CUSTOMER || "ROLE_ID_CUSTOMER"
};

// Default vehicle data (for demo purposes)
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
    model: "baller",
    name: "Gallivanter Baller",
    price: 300000,
    class: "SUV",
    category: "suv",
    seats: 4,
    topSpeed: "190 km/h",
    acceleration: "6.5s",
    description: "Luxury SUV",
    modelFile: "baller.glb",
    scale: 1.2,
    position: { x: 0, y: -0.7, z: 0 },
    rotation: { x: 0, y: 0, z: 0 }
  },
  {
    id: 5,
    model: "dominator",
    name: "Vapid Dominator",
    price: 320000,
    class: "Muscle",
    category: "muscle",
    seats: 2,
    topSpeed: "220 km/h",
    acceleration: "5.0s",
    description: "Classic muscle car",
    modelFile: "dominator.glb",
    scale: 1.1,
    position: { x: 0, y: -0.6, z: 0 },
    rotation: { x: 0, y: 0, z: 0 }
  },
  {
    id: 6,
    model: "zentorno",
    name: "Pegassi Zentorno",
    price: 750000,
    class: "Super",
    category: "super",
    seats: 2,
    topSpeed: "260 km/h",
    acceleration: "3.2s",
    description: "Italian supercar",
    modelFile: "zentorno.glb",
    scale: 0.9,
    position: { x: 0, y: -0.4, z: 0 },
    rotation: { x: 0, y: 0, z: 0 }
  }
];

// Middleware to check authentication
const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Authentication required" });
  }
  next();
};

// Check authentication status
app.get("/api/auth/status", (req, res) => {
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

// Get permissions based on role
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
  }

  return permissions;
}

// Login endpoint
app.get("/login", (req, res) => {
  const url = `https://discord.com/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&response_type=code&scope=identify guilds guilds.join`;
  
  res.redirect(url);
});

// Callback endpoint
app.get("/callback", async (req, res) => {
  try {
    const code = req.query.code;

    if (!code) {
      throw new Error("No authorization code provided");
    }

    console.log("Received authorization code");

    // Exchange code for access token
    const tokenRes = await axios.post(
      "https://discord.com/api/oauth2/token",
      new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI
      }),
      { 
        headers: { 
          "Content-Type": "application/x-www-form-urlencoded",
          "Accept-Encoding": "application/json"
        }
      }
    );

    const accessToken = tokenRes.data.access_token;
    console.log("Got access token");

    // Get user info
    const userRes = await axios.get("https://discord.com/api/users/@me", {
      headers: { 
        Authorization: `Bearer ${accessToken}`,
        "Accept-Encoding": "application/json"
      }
    });

    const user = userRes.data;
    console.log(`User authenticated: ${user.username}#${user.discriminator}`);

    // Add user to Discord server
    try {
      await axios.put(
        `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${user.id}`,
        { access_token: accessToken },
        {
          headers: {
            Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
            "Content-Type": "application/json"
          }
        }
      );
      console.log("User added to server");
    } catch (error) {
      console.log("User might already be in server or error adding:", error.message);
    }

    // Get member roles
    let role = "customer";
    try {
      const memberRes = await axios.get(
        `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${user.id}`,
        { 
          headers: { 
            Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
            "Accept-Encoding": "application/json"
          } 
        }
      );

      const memberRoles = memberRes.data.roles || [];
      
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
            { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
          );
          console.log("Assigned customer role");
        } catch (roleError) {
          console.log("Error assigning customer role:", roleError.message);
        }
      } else {
        console.log("User already has customer role");
      }
    } catch (error) {
      console.log("Error fetching member roles:", error.message);
    }

    // Store user in session
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

    console.log(`Session created for user: ${user.username}, Role: ${role}`);

    // Redirect back to frontend with success message
    res.redirect(`${FRONTEND_URL}/index.html?login=success&username=${encodeURIComponent(user.username)}&role=${role}`);
    
  } catch (error) {
    console.error("Authentication error:", error.response?.data || error.message);
    res.redirect(`${FRONTEND_URL}/index.html?login=error&message=${encodeURIComponent(error.message)}`);
  }
});

// Logout endpoint
app.get("/logout", (req, res) => {
  const username = req.session.user?.username || "User";
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
    }
    console.log(`User logged out: ${username}`);
    res.redirect(`${FRONTEND_URL}/index.html?logout=success`);
  });
});

// Get vehicles (protected)
app.get("/api/vehicles", (req, res) => {
  // Allow access to vehicles without authentication for demo
  // In production, you might want to protect this
  res.json(defaultVehicles);
});

// Submit order (protected)
app.post("/api/orders", requireAuth, async (req, res) => {
  try {
    const order = req.body;
    const user = req.session.user;
    const role = req.session.role;

    console.log("New order received from:", user.username);
    console.log("Order details:", order);

    // Validate order data
    if (!order.vehicle_model || !order.vehicle_name || !order.price) {
      return res.status(400).json({ 
        error: "Missing required order information" 
      });
    }

    // Send to Discord webhook if configured
    const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
    if (webhookUrl) {
      try {
        // Create role mentions
        let mention = "";
        if (role === "customer") {
          // Notify managers and owners for customer orders
          mention = `<@&${ROLES.MANAGER}> <@&${ROLES.OWNER}>`;
        } else if (role === "manager") {
          // Notify owners for manager orders
          mention = `<@&${ROLES.OWNER}>`;
        }

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
              name: "Player Phone", 
              value: order.player_phone || "Not provided", 
              inline: true 
            },
            { 
              name: "Colors", 
              value: `**Primary:** ${order.primary_color}\n**Secondary:** ${order.secondary_color}\n**Pearl:** ${order.pearl_color}` 
            },
            { 
              name: "Special Requests", 
              value: order.special_requests || "None" 
            }
          ],
          timestamp: new Date().toISOString(),
          footer: { 
            text: "GTA V Dealership System • Order ID: " + Date.now() 
          },
          thumbnail: {
            url: user.avatar ? 
              `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png` : 
              'https://cdn.discordapp.com/embed/avatars/0.png'
          }
        };

        await axios.post(webhookUrl, {
          content: mention,
          embeds: [embed]
        });

        console.log("Discord notification sent successfully");
      } catch (webhookError) {
        console.error("Failed to send Discord webhook:", webhookError.message);
        // Don't fail the order if webhook fails
      }
    }

    // Here you would typically save to a database
    // For now, we'll just return success
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

// Get user orders (protected)
app.get("/api/orders", requireAuth, (req, res) => {
  const userId = req.session.user.id;
  // In a real app, you'd fetch from database
  res.json({
    orders: [],
    message: "No orders found for this user"
  });
});

// Admin endpoints (owner/manager only)
app.get("/api/admin/orders", requireAuth, (req, res) => {
  if (req.session.role !== "owner" && req.session.role !== "manager") {
    return res.status(403).json({ error: "Insufficient permissions" });
  }
  
  // Return all orders (in real app, from database)
  res.json({
    totalOrders: 0,
    pending: 0,
    completed: 0,
    orders: []
  });
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ 
    status: "healthy",
    service: "GTA V Dealership Auth Server",
    timestamp: new Date().toISOString(),
    discord: {
      clientId: DISCORD_CLIENT_ID ? "Configured" : "Missing",
      guildId: DISCORD_GUILD_ID ? "Configured" : "Missing",
      botToken: DISCORD_BOT_TOKEN ? "Configured" : "Missing"
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({ 
    error: "Internal server error",
    message: err.message 
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`
  🚗 GTA V Dealership Auth Server
  ==================================
  📡 Server running on: http://localhost:${PORT}
  🔗 Frontend URL: ${FRONTEND_URL}
  🔐 Discord OAuth: ${DISCORD_CLIENT_ID ? "Configured" : "NOT CONFIGURED"}
  👥 Discord Server: ${DISCORD_GUILD_ID || "NOT CONFIGURED"}
  
  📝 Available Endpoints:
  - GET  /health                - Health check
  - GET  /login                 - Discord OAuth login
  - GET  /callback              - OAuth callback
  - GET  /logout                - Logout
  - GET  /api/auth/status       - Check auth status
  - GET  /api/vehicles          - Get vehicles
  - POST /api/orders            - Submit order
  - GET  /api/orders            - Get user orders
  - GET  /api/admin/orders      - Admin orders view
  
  ⚠️  Make sure to:
  1. Set up .env file with Discord credentials
  2. Run frontend on ${FRONTEND_URL}
  3. Configure Discord bot with correct permissions
  ==================================
  `);
});
// server.js
require("dotenv").config();
const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { OAuth2Client } = require("google-auth-library");

const app = express();

// ---------- Middleware ----------
app.use(cors());
app.use(express.json());

// ---------- Google OAuth client init ----------
const creds = require("./credentials/client_secret.json");   // direct JSON file load
const googleClient = new OAuth2Client(creds.web.client_id);
// ---------- MongoDB ----------
console.log("DEBUG: MONGODB_URI =>", process.env.MONGODB_URI);
const uri = process.env.MONGODB_URI;
if (!uri) {
  console.error("❌ MONGODB_URI missing.");
  process.exit(1);
}
mongoose
  .connect(uri)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ Mongo connect error:", err);
    process.exit(1);
  });

// ---------- Schemas & Models ----------
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, trim: true, lowercase: true, index: true, sparse: true },
    phone: { type: String, trim: true, index: true, sparse: true },
    passwordHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
  },
  { collection: "Users" }
);

const User = mongoose.model("User", userSchema);

// ---------- Auth APIs ----------

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body || {};
    if (!name || !password || (!email && !phone)) {
      return res.status(400).json({ error: "Name, Email/Phone, and Password required hai" });
    }

    const emailNorm = email ? String(email).toLowerCase().trim() : undefined;
    const phoneNorm = phone ? String(phone).trim() : undefined;

    // Duplicate check
    const existing = await User.findOne({
      $or: [
        ...(emailNorm ? [{ email: emailNorm }] : []),
        ...(phoneNorm ? [{ phone: phoneNorm }] : []),
      ],
    });
    if (existing) {
      return res.status(400).json({ error: "Email/Phone already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    await User.create({
      name: String(name).trim(),
      email: emailNorm,
      phone: phoneNorm,
      passwordHash,
    });

    return res.json({ success: true, message: "Registration successful ✅" });
  } catch (e) {
    console.error("register error:", e);
    return res.status(500).json({ error: "Server error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const identifier = (req.body.identifier || req.body.email || req.body.phone || "").trim();
    const { password } = req.body || {};

    if (!identifier || !password) {
      return res.status(400).json({ error: "Email/Phone aur Password required hai" });
    }

    const idLower = identifier.toLowerCase();
    const user = await User.findOne({
      $or: [{ email: idLower }, { phone: identifier }],
    });

    if (!user) {
      return res.status(400).json({ error: "Invalid Email/Phone or Password" });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(400).json({ error: "Invalid Email/Phone or Password" });
    }

    // Success
    return res.json({
      success: true,
      user: { id: user._id, name: user.name },
    });
  } catch (e) {
    console.error("login error:", e);
    return res.status(500).json({ error: "Server error" });
  }
});

// Forgot Password
app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    if (!email || !newPassword) {
      return res.status(400).json({ error: "Email aur new password required hai" });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    user.passwordHash = hash;
    await user.save();

    return res.json({ success: true, message: "Password reset successful ✅" });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Google Login
app.post("/api/google-login", async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) {
      return res.status(400).json({ success: false, message: "Token required" });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: creds.web.client_id,
    });

    const payload = ticket.getPayload();
    const userInfo = {
      email: payload.email,
      name: payload.name,
      googleId: payload.sub,
    };

    // find-or-create user
    let user = await User.findOne({ email: userInfo.email });
    if (!user) {
      user = await User.create({
        name: userInfo.name,
        email: userInfo.email,
        passwordHash: await bcrypt.hash(payload.sub, 10), // demo hash
      });
    }

    return res.json({ success: true, user: userInfo });
  } catch (e) {
    console.error("Google login error:", e);
    return res.status(401).json({ success: false, message: "Invalid Google token" });
  }
});

// ---------- Static (Vite build in /dist) ----------
app.use(express.static(path.join(__dirname, "dist")));

// SPA fallback
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "dist", "index.html"));
});

// ---------- Start ----------
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log('🚀 Server listening on ${PORT}'));

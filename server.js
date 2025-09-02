// server.js
require("dotenv").config();
const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { OAuth2Client } = require("google-auth-library");
const nodemailer = require("nodemailer"); // ✅ new

const app = express();

// ---------- Middleware ----------
app.use(cors());
app.use(express.json());

// ---------- Google OAuth client init ----------
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ---------- MongoDB ----------
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
    email: { type: String, required: true, trim: true, lowercase: true, unique: true },
    phone: { type: String, required: true, trim: true },
    gender: { type: String, enum: ["male", "female", "other"], required: false },
    passwordHash: { type: String },
    otp: { type: String }, // ✅ OTP field
    otpExpiry: { type: Date }, // ✅ OTP expiry time
    createdAt: { type: Date, default: Date.now },
  },
  { collection: "Users" }
);

const User = mongoose.model("User", userSchema);

// ---------- Utility: Generate OTP ----------
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ---------- Email Transporter ----------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER, // your gmail
    pass: process.env.EMAIL_PASS, // app password
  },
});

// ---------- Auth APIs ----------

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, phone, gender, password } = req.body || {};
    if (!name || !email || !phone || !gender || !password) {
      return res.status(400).json({ error: "⚠ All fields are required" });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: "❌ Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    await User.create({
      name,
      email,
      phone,
      gender,
      passwordHash,
    });

    return res.json({ success: true, message: "✅ Registration successful! Please login." });
  } catch (e) {
    console.error("register error:", e);
    return res.status(500).json({ error: "Server error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "⚠ Email and Password required" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "❌ Invalid Email or Password" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(400).json({ error: "❌ Invalid Email or Password" });

    return res.json({ success: true, user: { id: user._id, name: user.name } });
  } catch (e) {
    console.error("login error:", e);
    return res.status(500).json({ error: "Server error" });
  }
});

// ---------- Forgot Password with OTP ----------

// Step 1: Send OTP
app.post("/api/send-otp", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "⚠ Email required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "❌ User not found" });

    const otp = generateOTP();
    user.otp = otp;
    user.otpExpiry = Date.now() + 1 * 60 * 1000; // 5 minutes
    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'NeoLearn - Password Reset OTP',
      text: 'Your OTP for password reset is ${otp}. It is valid for 1 minutes.',
    });

    return res.json({ success: true, message: "✅ OTP sent to email" });
  } catch (err) {
    console.error("send-otp error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Step 2: Verify OTP
app.post("/api/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "❌ User not found" });

    if (user.otp !== otp || Date.now() > user.otpExpiry) {
      return res.status(400).json({ error: "❌ Invalid or expired OTP" });
    }

    return res.json({ success: true, message: "✅ OTP verified" });
  } catch (err) {
    console.error("verify-otp error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Step 3: Reset Password
app.post("/api/reset-password", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "❌ User not found" });

    if (user.otp !== otp || Date.now() > user.otpExpiry) {
      return res.status(400).json({ error: "❌ Invalid or expired OTP" });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    user.passwordHash = hash;
    user.otp = null;
    user.otpExpiry = null;
    await user.save();

    return res.json({ success: true, message: "✅ Password reset successful" });
  } catch (err) {
    console.error("reset-password error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- Google Login ----------
app.post("/api/google-login", async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ success: false, message: "Token required" });

    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
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
        phone: "NA",
        gender: "other",
        passwordHash: await bcrypt.hash(userInfo.googleId, 10), // fake hash
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

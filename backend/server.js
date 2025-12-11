import express from 'express';
import cors from 'cors';
import session from 'express-session';
import passport from 'passport';
import GoogleStrategy from 'passport-google-oauth20';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';
import bcrypt from 'bcrypt';
dotenv.config();
const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

// MongoDB connection
let db;
let usersCollection;
let winnersCollection;

async function connectToMongoDB() {
  try {
    const client = new MongoClient(process.env.MONGODB_URI || 'mongodb://localhost:27017/hall-of-fame');
    await client.connect();
    db = client.db();
    usersCollection = db.collection('users');
    winnersCollection = db.collection('winners');
    console.log('Connected to MongoDB');
  } catch (error) {
    console.error('MongoDB connection error:', error);
  }
}

// File upload config - use memory storage for Vercel
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Mail transporter (Gmail App Password or other SMTP)
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 587,
  secure: String(process.env.SMTP_SECURE||'false') === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// --------------------
// User Profile
// --------------------
app.get('/api/profile', requireAuth, (req, res) => {
  res.json({
    email: req.user.email,
    name: req.user.name || '',
    picture: req.user.picture || '',
    provider: req.user.provider || (req.user.passwordHash ? 'local' : 'google'),
    emailVerified: req.user.emailVerified !== false
  });
});

app.put('/api/profile', requireAuth, upload.single('avatar'), (req, res) => {
  const users = readUsers();
  const idx = users.findIndex(u => u.email === req.user.email);
  if (idx === -1) return res.status(404).json({ success:false });
  const { name, picture } = req.body || {};
  if (typeof name === 'string') users[idx].name = name.trim() || users[idx].name;
  if (typeof picture === 'string') users[idx].picture = picture;
  if (req.file) {
    users[idx].picture = `/uploads/${req.file.filename}`;
    console.log('Profile picture updated:', users[idx].picture);
  }
  writeUsers(users);
  console.log('Updated user profile:', users[idx]);
  res.json({ 
    success:true,
    profile: {
      email: users[idx].email,
      name: users[idx].name,
      picture: users[idx].picture,
      provider: users[idx].provider || 'google',
      emailVerified: users[idx].emailVerified !== false
    }
  });
});

// User functions using MongoDB
async function findUserByEmail(email){
  if (!usersCollection) return null;
  return await usersCollection.findOne({ 
    email: { $regex: new RegExp('^' + email + '$', 'i') }
  });
}

async function saveUser(user){
  if (!usersCollection) return;
  await usersCollection.replaceOne(
    { email: user.email },
    user,
    { upsert: true }
  );
}

async function readUsers(){
  if (!usersCollection) return [];
  return await usersCollection.find({}).toArray();
}

function randomToken(){
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
}

async function sendMail(to, subject, html){
  if(!process.env.SMTP_HOST){
    console.log('EMAIL (dev fallback):', { to, subject, html });
    return;
  }
  const from = process.env.SMTP_FROM || `Hall of Fame <${process.env.SMTP_USER||'no-reply@example.com'}>`;
  await transporter.sendMail({ from, to, subject, html });
}

// Middleware
app.use(cors({
  origin: ['https://hall-of-fame-git-main-timmytallys-projects.vercel.app/'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Use memory store for Vercel (no filesystem)
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false,
  // Using memory store for development to avoid file permission issues
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
    httpOnly: true,
    sameSite: 'none', // Allow cross-origin cookies
    secure: process.env.NODE_ENV === 'production' // Only secure in production
  },
  rolling: true
}));
app.use(passport.initialize());
app.use(passport.session());

// Serve frontend static files
app.use(express.static('../frontend'));

// Serve uploads directory
app.use('/uploads', express.static('uploads'));

// Winners storage using MongoDB
async function getUserWinners(userEmail) {
  if (!winnersCollection) return [];
  const result = await winnersCollection.find({ userEmail }).toArray();
  return result.map(w => ({ ...w, _id: undefined }));
}

async function saveWinner(userEmail, winner) {
  if (!winnersCollection) return;
  await winnersCollection.insertOne({ ...winner, userEmail });
}

async function updateWinner(winnerId, winner) {
  if (!winnersCollection) return;
  await winnersCollection.updateOne(
    { id: parseInt(winnerId) },
    { $set: winner }
  );
}

async function deleteWinner(winnerId) {
  if (!winnersCollection) return;
  await winnersCollection.deleteOne({ id: parseInt(winnerId) });
}

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID || '',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
  callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
    if (!email) return done(null, false);
    
    let user = await findUserByEmail(email);
    
    if (!user) {
      // Generate username from email or name
      const baseUsername = profile.displayName.toLowerCase().replace(/\s+/g, '') || email.split('@')[0];
      const username = baseUsername + Date.now().toString().slice(-4); // Add random to make unique
      
      user = {
        email,
        name: profile.displayName,
        username: username,
        picture: profile.photos && profile.photos[0] ? profile.photos[0].value : '',
        role: 'user',  // Everyone starts as regular user
        followers: [],  // People who follow this user
        following: [],  // People this user follows
        admins: [],     // Admins granted by this user
        createdAt: Date.now()
      };
      await saveUser(user);
    } else if (!user.username) {
      // Add username to existing users who don't have one
      const baseUsername = user.name ? user.name.toLowerCase().replace(/\s+/g, '') : user.email.split('@')[0];
      user.username = baseUsername + Date.now().toString().slice(-4);
      await saveUser(user);
    }
    
    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}));

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/admin.html?auth=fail' }),
  (req, res) => {
    console.log('Google OAuth callback - user authenticated:', req.user);
    console.log('req.isAuthenticated():', req.isAuthenticated());
    
    // Create a simple session cookie approach
    if (req.user) {
      // Set a simple session cookie with user info
      res.cookie('user_session', JSON.stringify({
        email: req.user.email,
        name: req.user.name,
        picture: req.user.picture,
        role: req.user.role
      }), {
        maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
        httpOnly: false, // Allow JavaScript to read for now
        sameSite: 'lax'
      });
      console.log('Set user session cookie');
      res.redirect('/admin.html');
    } else {
      console.log('No user available');
      res.redirect('/admin.html?auth=fail');
    }
  }
);

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.user || null, isAdmin: !!(req.user && req.user.role === 'admin') });
});

app.get('/api/logout', (req, res) => {
  const done = () => res.json({ success: true });
  if (req.logout) {
    req.logout(() => {
      req.session.destroy(done);
    });
  } else {
    req.session.destroy(done);
  }
});

function requireAdmin(req, res, next) {
  // Check simple cookie approach
  if (req.headers.cookie && req.headers.cookie.includes('user_session=')) {
    try {
      const cookieValue = req.headers.cookie.split('user_session=')[1].split(';')[0];
      const sessionData = JSON.parse(decodeURIComponent(cookieValue));
      
      if (sessionData.role === 'admin') {
        return next();
      }
    } catch (e) {
      // Error parsing session
    }
  }
  
  return res.status(403).json({ success: false, message: 'Not authorized' });
}

function requireAuth(req, res, next){
  console.log('requireAuth called');
  console.log('Cookies:', req.headers.cookie);
  
  // Check simple cookie approach
  if (req.headers.cookie && req.headers.cookie.includes('user_session=')) {
    try {
      const userCookie = req.headers.cookie
        .split(';')
        .find(c => c.trim().startsWith('user_session='))
        .split('=')[1];
      
      if (userCookie) {
        const user = JSON.parse(decodeURIComponent(userCookie));
        console.log('Authenticated via cookie:', user.email);
        req.user = user;
        return next();
      }
    } catch (e) {
      console.log('Error parsing user cookie:', e);
    }
  }
  
  console.log('Not authenticated');
  return res.status(401).json({ success:false, message:'Unauthorized' });
}

// --------------------
// Local email/password auth
// --------------------

// Register local account and send verification email
app.post('/api/register', async (req, res) => {
  try{
    const { email, password, name } = req.body || {};
    if(!email || !password) return res.status(400).json({ success:false, message:'Email and password required' });
    const existing = findUserByEmail(email);
    if(existing) return res.status(409).json({ success:false, message:'Email already registered' });
    const passwordHash = await bcrypt.hash(password, 10);
    const verifyToken = randomToken();
    const user = {
      email,
      name: name || email.split('@')[0],
      passwordHash,
      provider: 'local',
      emailVerified: false,
      verifyToken,
      resetToken: null,
      resetExpires: null,
      role: 'admin',
      picture: '',
      createdAt: Date.now()
    };
    saveUser(user);

    const verifyUrl = `${req.protocol}://${req.get('host')}/auth/verify?token=${encodeURIComponent(verifyToken)}&email=${encodeURIComponent(email)}`;
    await sendMail(email, 'Verify your email — Hall of Fame', `
      <p>Hi ${user.name},</p>
      <p>Click to verify your email:</p>
      <p><a href="${verifyUrl}">${verifyUrl}</a></p>
    `);
    res.json({ success:true });
  }catch(e){
    console.error(e);
    res.status(500).json({ success:false, message:'Registration failed' });
  }
});

// Verify email link
app.get('/auth/verify', (req, res) => {
  const { token, email } = req.query;
  if(!token || !email) return res.status(400).send('Invalid verification link');
  const users = readUsers();
  const idx = users.findIndex(u => (u.email||'').toLowerCase() === String(email).toLowerCase() && u.verifyToken === token);
  if(idx === -1) return res.status(400).send('Invalid or expired token');
  users[idx].emailVerified = true;
  users[idx].verifyToken = null;
  writeUsers(users);
  // Sign user into session
  req.login?.(users[idx], (err) => {
    return res.redirect('/admin.html?verified=1');
  });
});

// Local login
app.post('/api/login', async (req, res) => {
  try{
    const { email, password } = req.body || {};
    const user = findUserByEmail(email);
    if(!user || user.provider !== 'local' || !user.passwordHash) return res.status(401).json({ success:false, message:'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if(!ok) return res.status(401).json({ success:false, message:'Invalid credentials' });
    if(!user.emailVerified) return res.status(403).json({ success:false, message:'Email not verified' });
    
    // Set session manually for local auth
    console.log('Setting session for user:', user.email);
    req.session.user = user;
    req.session.save((err) => {
      if(err) {
        console.error('Session save error:', err);
        return res.status(500).json({ success:false });
      }
      console.log('Session saved successfully');
      res.json({ success:true });
    });
  }catch(e){
    console.error(e);
    res.status(500).json({ success:false });
  }
});

// Forgot password: send reset link
app.post('/api/password/forgot', async (req, res) => {
  const { email } = req.body || {};
  const users = readUsers();
  const idx = users.findIndex(u => (u.email||'').toLowerCase() === (email||'').toLowerCase());
  if(idx === -1) return res.json({ success:true }); // do not reveal existence
  const token = randomToken();
  users[idx].resetToken = token;
  users[idx].resetExpires = Date.now() + 60*60*1000; // 1 hour
  writeUsers(users);
  const resetUrl = `${req.protocol}://${req.get('host')}/reset.html?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`;
  await sendMail(email, 'Reset your password — Hall of Fame', `
    <p>Click to reset your password (valid 1 hour):</p>
    <p><a href="${resetUrl}">${resetUrl}</a></p>
  `);
  res.json({ success:true });
});

// Reset password
app.post('/api/password/reset', async (req, res) => {
  try{
    const { token, email, password } = req.body || {};
    if(!token || !email || !password) return res.status(400).json({ success:false });
    const users = readUsers();
    const idx = users.findIndex(u => (u.email||'').toLowerCase() === (email||'').toLowerCase() && u.resetToken === token);
    if(idx === -1) return res.status(400).json({ success:false, message:'Invalid token' });
    if(!users[idx].resetExpires || users[idx].resetExpires < Date.now()) return res.status(400).json({ success:false, message:'Token expired' });
    users[idx].passwordHash = await bcrypt.hash(password, 10);
    users[idx].resetToken = null;
    users[idx].resetExpires = null;
    writeUsers(users);
    res.json({ success:true });
  }catch(e){
    console.error(e);
    res.status(500).json({ success:false });
  }
});

// --------------------
// Winners CRUD
// --------------------

// Get all winners for current user
app.get('/api/winners', requireAuth, async (req, res) => {
  try {
    const userEmail = req.user.email;
    const winners = await getUserWinners(userEmail);
    res.json(winners);
  } catch (error) {
    console.error('Error getting winners:', error);
    res.status(500).json({ success: false, message: 'Failed to load winners' });
  }
});

// Add winner
app.post('/api/winners', requireAuth, upload.single('photo'), async (req, res) => {
  try {
    const userEmail = req.user.email;
    const id = Date.now();
    const winner = {
      id,
      name: req.body.name,
      wa: req.body.wa,
      title: req.body.title,
      rank: req.body.rank,
      score: req.body.score,
      date: req.body.date,
      photo: req.file ? `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}` : ''
    };
    await saveWinner(userEmail, winner);
    res.json({ success: true, winner });
  } catch (error) {
    console.error('Error adding winner:', error);
    res.status(500).json({ success: false, message: 'Failed to add winner' });
  }
});

app.put('/api/winners/:id', requireAuth, upload.single('photo'), async (req, res) => {
  try {
    const userEmail = req.user.email;
    const winnerId = req.params.id;
    
    const winner = {
      name: req.body.name,
      wa: req.body.wa,
      title: req.body.title,
      rank: req.body.rank,
      score: req.body.score,
      date: req.body.date,
    };
    
    if (req.file) {
      winner.photo = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
    }
    
    await updateWinner(winnerId, winner);
    res.json({ success: true, winner });
  } catch (error) {
    console.error('Error updating winner:', error);
    res.status(500).json({ success: false, message: 'Failed to update winner' });
  }
});

// Delete winner
app.delete('/api/winners/:id', requireAuth, async (req, res) => {
  try {
    const winnerId = req.params.id;
    await deleteWinner(winnerId);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting winner:', error);
    res.status(500).json({ success: false, message: 'Failed to delete winner' });
  }
});

// Public winners route - no authentication required (for shareable links)
app.get('/public/winners', async (req, res) => {
  try {
    // Get user from query param for shareable links
    const userEmail = req.query.user;
    if (userEmail) {
      const winners = await getUserWinners(userEmail);
      res.json({ success: true, winners });
    } else {
      res.json({ success: true, winners: [] });
    }
  } catch (error) {
    console.error('Error getting public winners:', error);
    res.json({ success: true, winners: [] });
  }
});

// --------------------  
// Social Features
// --------------------

// List all users (for discovery)
app.get('/api/users', requireAuth, async (req, res) => {
  try {
    const users = await readUsers();
    // Return basic user info without sensitive data
    const publicUsers = users.map(u => ({
      email: u.email,
      name: u.name,
      username: u.username,
      picture: u.picture,
      followers: u.followers || [],
      following: u.following || [],
      createdAt: u.createdAt
    }));
    res.json({ success: true, users: publicUsers });
  } catch (error) {
    console.error('Error getting users:', error);
    res.status(500).json({ success: false, message: 'Failed to load users' });
  }
});

// Follow a user
app.post('/api/users/:email/follow', requireAuth, async (req, res) => {
  try {
    const targetEmail = req.params.email;
    const currentUser = req.user;
    
    console.log('Follow request:', { targetEmail, currentUser: currentUser.email });
    
    if (currentUser.email === targetEmail) {
      return res.status(400).json({ success: false, message: 'Cannot follow yourself' });
    }
    
    const targetUser = await findUserByEmail(targetEmail);
    const current = await findUserByEmail(currentUser.email);
    
    if (!targetUser) {
      return res.status(404).json({ success: false, message: 'User not found: ' + targetEmail });
    }
    
    if (!current) {
      return res.status(404).json({ success: false, message: 'Current user not found' });
    }
    
    // Initialize arrays if they don't exist
    if (!current.following) current.following = [];
    if (!targetUser.followers) targetUser.followers = [];
    
    // Add to following list
    if (!current.following.includes(targetEmail)) {
      current.following.push(targetEmail);
    }
    
    // Add to target's followers list
    if (!targetUser.followers.includes(currentUser.email)) {
      targetUser.followers.push(currentUser.email);
    }
    
    await saveUser(current);
    await saveUser(targetUser);
    res.json({ success: true, message: `Now following ${targetEmail}` });
  } catch (error) {
    console.error('Error following user:', error);
    res.status(500).json({ success: false, message: 'Failed to follow user' });
  }
});

// Unfollow a user
app.post('/api/users/:email/unfollow', requireAuth, async (req, res) => {
  try {
    const targetEmail = req.params.email;
    const currentUser = req.user;
    
    const targetUser = await findUserByEmail(targetEmail);
    const current = await findUserByEmail(currentUser.email);
    
    if (!targetUser || !current) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Remove from following list
    current.following = current.following.filter(email => email !== targetEmail);
    
    // Remove from target's followers list
    targetUser.followers = targetUser.followers.filter(email => email !== currentUser.email);
    
    await saveUser(current);
    await saveUser(targetUser);
    res.json({ success: true });
  } catch (error) {
    console.error('Error unfollowing user:', error);
    res.status(500).json({ success: false, message: 'Failed to unfollow user' });
  }
});

// Grant admin access to a follower
app.post('/api/users/:email/grant-admin', requireAuth, async (req, res) => {
  try {
    const targetEmail = req.params.email;
    const currentUser = req.user;
    
    // Only account owners can grant admin access
    if (currentUser.role !== 'user') {
      return res.status(403).json({ success: false, message: 'Only account owners can grant admin access' });
    }
    
    const targetUser = await findUserByEmail(targetEmail);
    const current = await findUserByEmail(currentUser.email);
    
    if (!targetUser) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Check if target user follows current user
    if (!current.followers.includes(targetEmail)) {
      return res.status(403).json({ success: false, message: 'Can only grant admin to followers' });
    }
    
    // Grant admin access
    targetUser.role = 'admin';
    current.admins.push(targetEmail);
    
    await saveUser(targetUser);
    await saveUser(current);
    res.json({ success: true });
  } catch (error) {
    console.error('Error granting admin:', error);
    res.status(500).json({ success: false, message: 'Failed to grant admin' });
  }
});

// Get user profile with followers/following
app.get('/api/users/:email', requireAuth, async (req, res) => {
  try {
    const targetEmail = req.params.email;
    const user = await findUserByEmail(targetEmail);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({
      success: true,
      user: {
        email: user.email,
        name: user.name,
        username: user.username,
        picture: user.picture,
        followers: user.followers,
        following: user.following,
        admins: user.admins,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Error getting user profile:', error);
    res.status(500).json({ success: false, message: 'Failed to load user profile' });
  }
});

// Find user by username
app.get('/api/user/by-username/:username', async (req, res) => {
  try {
    const username = req.params.username;
    const users = await readUsers();
    const user = users.find(u => u.username === username);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({
      success: true,
      user: {
        email: user.email,
        name: user.name,
        username: user.username,
        picture: user.picture,
        followers: user.followers,
        following: user.following,
        admins: user.admins,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Error finding user by username:', error);
    res.status(500).json({ success: false, message: 'Failed to find user' });
  }
});

// Start server with MongoDB connection
if (process.env.NODE_ENV !== 'production') {
  connectToMongoDB().then(() => {
    app.listen(PORT, () => console.log(`Backend running at http://localhost:${PORT}`));
  }).catch(error => {
    console.error('Failed to start server:', error);
  });
} else {
  // For Vercel serverless functions
  connectToMongoDB().catch(error => {
    console.error('MongoDB connection failed:', error);
  });
}

// Export for Vercel
export default app;

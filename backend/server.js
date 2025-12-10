import express from 'express';
import cors from 'cors';
import multer from 'multer';
import fs from 'fs';
import session from 'express-session';
import path from 'path';
import dotenv from 'dotenv';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';
import FileStoreFactory from 'session-file-store';
dotenv.config();
const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

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

// Users store (file-based)
const USERS_FILE = 'users.json';
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
function readUsers(){ return JSON.parse(fs.readFileSync(USERS_FILE)); }
function writeUsers(arr){ fs.writeFileSync(USERS_FILE, JSON.stringify(arr, null, 2)); }

function findUserByEmail(email){
  const users = readUsers();
  return users.find(u => (u.email||'').toLowerCase() === (email||'').toLowerCase()) || null;
}
function saveUser(user){
  const users = readUsers();
  const i = users.findIndex(u => u.email === user.email);
  if(i>=0) users[i] = user; else users.push(user);
  writeUsers(users);
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

// Passport serialization
passport.serializeUser((user, done) => {
  console.log('Serializing user:', user.email);
  done(null, user.email);
});

passport.deserializeUser((email, done) => {
  console.log('Deserializing user:', email);
  const user = findUserByEmail(email);
  done(null, user);
});

// Serve frontend static files
app.use(express.static('../frontend'));

// Serve uploads directory
app.use('/uploads', express.static('uploads'));

// Winners storage
const WINNERS_FILE = 'winners.json';
if (!fs.existsSync(WINNERS_FILE)) fs.writeFileSync(WINNERS_FILE, '[]');

// --------------------
// Auth (Google OAuth)
// --------------------
passport.serializeUser((user, done) => done(null, user.email));
passport.deserializeUser((email, done) => {
  const user = readUsers().find(u => u.email === email) || null;
  done(null, user);
});

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID || '',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
  callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback',
}, (accessToken, refreshToken, profile, done) => {
  const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
  if (!email) return done(null, false);
  const users = readUsers();
  let user = users.find(u => u.email === email);
  if (!user) {
    user = {
      email,
      name: profile.displayName,
      picture: profile.photos && profile.photos[0] ? profile.photos[0].value : '',
      role: 'admin',
      createdAt: Date.now()
    };
    users.push(user);
    writeUsers(users);
  }
  return done(null, user);
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

// Get all winners
app.get('/api/winners', (req, res) => {
  const winners = JSON.parse(fs.readFileSync(WINNERS_FILE));
  res.json(winners);
});

// Add winner
app.post('/api/winners', requireAdmin, upload.single('photo'), (req, res) => {
  const winners = JSON.parse(fs.readFileSync(WINNERS_FILE));
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
  winners.push(winner);
  fs.writeFileSync(WINNERS_FILE, JSON.stringify(winners, null, 2));
  res.json({ success: true, winner });
});

app.put('/api/winners/:id', requireAdmin, upload.single('photo'), (req, res) => {
  const winners = JSON.parse(fs.readFileSync(WINNERS_FILE));
  const idx = winners.findIndex(w => w.id == req.params.id);
  if (idx === -1) return res.status(404).json({ success: false, message: 'Winner not found' });
  const winner = winners[idx];
  Object.assign(winner, req.body);
  if (req.file) {
    winner.photo = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
  }
  fs.writeFileSync(WINNERS_FILE, JSON.stringify(winners, null, 2));
  res.json({ success: true, winner });
});

// Delete winner
app.delete('/api/winners/:id', requireAdmin, (req, res) => {
  let winners = JSON.parse(fs.readFileSync(WINNERS_FILE));
  winners = winners.filter(w => w.id != req.params.id);
  fs.writeFileSync(WINNERS_FILE, JSON.stringify(winners, null, 2));
  res.json({ success: true });
});

// Public winners route - no authentication required
app.get('/public/winners', (req, res) => {
  try {
    const winners = JSON.parse(fs.readFileSync(WINNERS_FILE));
    res.json({ success: true, winners });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to load winners' });
  }
});

app.listen(PORT, () => console.log(`Backend running at http://localhost:${PORT}`));

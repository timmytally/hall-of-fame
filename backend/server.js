import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" })); // allow base64 images

// Fake in-memory DB (Railway restarts sometimes)
let users = [];
let winners = [];

// SECRET for JWT
const SECRET = "mysecretkey_efb_2025";

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(403).json({ error: "Invalid token" });
  }
}

// -----------------------------
// USER SIGNUP (email login)
// -----------------------------
app.post("/signup", (req, res) => {
  const { email, password } = req.body;

  if (users.find(u => u.email === email))
    return res.status(400).json({ error: "Email already exists" });

  users.push({ email, password });
  res.json({ message: "Signup successful" });
});

// LOGIN
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const user = users.find(
    u => u.email === email && u.password === password
  );

  if (!user) return res.status(401).json({ error: "Invalid login" });

  const token = jwt.sign({ email }, SECRET, { expiresIn: "7d" });
  res.json({ token });
});

// -----------------------------
// WINNERS CRUD
// -----------------------------

// GET all winners
app.get("/winners", (req, res) => {
  res.json(winners);
});

// ADD winner
app.post("/winners", auth, (req, res) => {
  const win = { id: Date.now().toString(), ...req.body };
  winners.push(win);
  res.json({ message: "Winner added", win });
});

// UPDATE winner
app.put("/winners/:id", auth, (req, res) => {
  const id = req.params.id;
  const idx = winners.findIndex(w => w.id === id);
  if (idx === -1) return res.status(404).json({ error: "Not found" });

  winners[idx] = { ...winners[idx], ...req.body };
  res.json({ message: "Winner updated" });
});

// DELETE winner
app.delete("/winners/:id", auth, (req, res) => {
  const id = req.params.id;
  winners = winners.filter(w => w.id !== id);
  res.json({ message: "Winner removed" });
});

// -----------------------------

app.get("/", (req, res) => {
  res.send("E-Football Backend Running");
});

app.listen(process.env.PORT || 3000, () =>
  console.log("Backend is running")
);

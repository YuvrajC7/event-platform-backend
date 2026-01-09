const express = require("express");
const mysql = require("mysql2");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const { z } = require("zod");

const app = express();
app.use(express.json());
app.use(cors());

app.get("/", (req, res) => {
  res.send("🚀 Event Platform Backend is Running");
});

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "1234",
  database: "event_platform"
});

db.connect(err => {
  if (err) {
    console.error("❌ MySQL Error:", err);
    return;
  }
  console.log("✅ MySQL Connected");
});

db.query(`
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100),
  email VARCHAR(100) UNIQUE,
  password VARCHAR(255),
  role VARCHAR(10)
)`);

db.query(`
CREATE TABLE IF NOT EXISTS events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(100),
  description TEXT,
  date VARCHAR(50),
  created_by INT
)`);

db.query(`
CREATE TABLE IF NOT EXISTS tickets (
  id INT AUTO_INCREMENT PRIMARY KEY,
  event_id INT,
  user_id INT,
  ticket_code VARCHAR(50)
)`);

const signupSchema = z.object({
  name: z.string(),
  email: z.string().email(),
  password: z.string().min(6),
  role: z.string().optional()
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string()
});

const eventSchema = z.object({
  title: z.string(),
  description: z.string(),
  date: z.string()
});

function auth(req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    req.user = jwt.verify(token, "SECRET_KEY");
    next();
  } catch {
    res.status(401).json({ message: "Unauthorized" });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin only" });
  }
  next();
}

app.post("/signup", async (req, res) => {
  try {
    const data = signupSchema.parse(req.body);
    const hashedPassword = await bcrypt.hash(data.password, 10);

    db.query(
      "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
      [data.name, data.email, hashedPassword, data.role || "user"],
      (err) => {
        if (err) {
          return res.status(400).json({ error: "Email already exists" });
        }
        res.json({ message: "User registered successfully" });
      }
    );
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/login", (req, res) => {
  try {
    const data = loginSchema.parse(req.body);

    db.query(
      "SELECT * FROM users WHERE email = ?",
      [data.email],
      async (err, result) => {
        if (err || result.length === 0) {
          return res.status(400).json({ message: "Invalid credentials" });
        }

        const user = result[0];
        const valid = await bcrypt.compare(data.password, user.password);

        if (!valid) {
          return res.status(400).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign(
          { id: user.id, role: user.role },
          "SECRET_KEY"
        );

        res.json({ token });
      }
    );
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/events", auth, adminOnly, (req, res) => {
  try {
    const data = eventSchema.parse(req.body);

    db.query(
      "INSERT INTO events (title, description, date, created_by) VALUES (?, ?, ?, ?)",
      [data.title, data.description, data.date, req.user.id],
      () => res.json({ message: "Event created" })
    );
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/events", (req, res) => {
  db.query("SELECT * FROM events", (err, results) => {
    res.json(results);
  });
});

app.put("/events/:id", auth, adminOnly, (req, res) => {
  db.query(
    "UPDATE events SET title=?, description=?, date=? WHERE id=?",
    [req.body.title, req.body.description, req.body.date, req.params.id],
    () => res.json({ message: "Event updated" })
  );
});

app.delete("/events/:id", auth, adminOnly, (req, res) => {
  db.query(
    "DELETE FROM events WHERE id=?",
    [req.params.id],
    () => res.json({ message: "Event deleted" })
  );
});

app.post("/events/:id/register", auth, (req, res) => {
  const ticketCode = "TICKET-" + Math.random().toString(36).substring(2, 8);

  db.query(
    "INSERT INTO tickets (event_id, user_id, ticket_code) VALUES (?, ?, ?)",
    [req.params.id, req.user.id, ticketCode],
    () => res.json({ message: "Registered successfully", ticketCode })
  );
});

app.listen(3000, () => {
  console.log("🚀 Server running at http://localhost:3000");
});

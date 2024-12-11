import express from "express";
import pg from "pg";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;
const SECRET_KEY =
  process.env.SECRET_KEY ||
  (() => {
    console.warn(
      "Using default SECRET_KEY. This should not happen in production."
    );
    return "secret-key";
  })();

// Middleware
app.use(cors());
app.use(express.json());

// PostgreSQL connection
const db = new pg.Client({
  host: process.env.PG_HOST,
  port: process.env.PG_PORT,
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  database: process.env.PG_DATABASE,
});

db.connect((err) => {
  if (err) {
    console.error("Database connection error", err.stack);
  } else {
    console.log("Database connected successfully");
  }
});

// Register a new user
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.query(
      "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *",
      [username, hashedPassword]
    );
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Error registering user");
  }
});

// Login a user
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await db.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);

    if (result.rowCount === 0) {
      return res.status(401).json({
        message: "Invalid username or password: there are no users in db",
      });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({
        message: "Invalid username or password: no matching user found",
      });
    }

    const token = jwt.sign({ userId: user.id }, SECRET_KEY, {
      expiresIn: "1h",
    });
    res.json({ token });
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Error logging in user");
  }
});

const authenticateToken = (req, res, next) => {
  // const token = req.headers["authorization"];
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Get data
app.get("/api/data", authenticateToken, async (req, res) => {
  const userId = req.user.userId; // Extracted from the token

  try {
    const result = await db.query("SELECT * FROM notes WHERE user_id = $1", [
      userId,
    ]);
    res.json(result.rows);
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Server Error when fetching data");
  }
});

// Create a new note
app.post("/api/data", authenticateToken, async (req, res) => {
  const { title, content } = req.body;
  const userId = req.user.userId; // Extracting from the token

  try {
    const result = await db.query(
      "INSERT INTO notes (title, content, user_id) VALUES ($1, $2, $3) RETURNING *",
      [title, content, userId]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Server Error when creating a new note");
  }
});

// Delete a note
app.delete("/api/data/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.userId; // Extracted from the token

  try {
    const result = await db.query(
      "DELETE FROM notes WHERE id = $1 AND user_id = $2",
      [id, userId]
    );
    if (result.rowCount === 0) {
      return res.status(404).send("Note not found or not authorized to delete");
    }
    res.send("Note deleted successfully");
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Server Error when deleting a note");
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});

import express from "express";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Bejelentkezés — ellenőriz egy kulcsot, majd visszaad egy JWT-t
app.post("/login", (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: "Missing key" });

  if (key !== process.env.AUTH_KEY) {
    return res.status(401).json({ error: "Invalid key" });
  }
  const token = jwt.sign({ access: true }, process.env.JWT_SECRET, { expiresIn: "2h"});
    res.json({ token });
});

// Middleware — ellenőrzi a JWT-t
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Missing Authorization header" });

  const token = auth.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
}

// Védett végpont
app.get("/protected", requireAuth, (req, res) => {
  res.json({ message: "Sikeresen beléptél!", user: req.user });
});

app.listen(process.env.PORT, () =>
  console.log(`API running on port ${process.env.PORT}`)
);

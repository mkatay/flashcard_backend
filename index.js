import express from "express";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";

dotenv.config();

const app = express();
app.use(cors({
  origin: process.env.FRONTEND_URL, // frontend címe
  credentials: true,               // fontos!!
}));

app.use(express.json());
app.use(cookieParser());



//token  csak a backend és a browser között él, nem kerül kliens oldalra
app.post("/login", (req, res) => {
  const { key } = req.body;
  if (key !== process.env.AUTH_KEY) return res.status(401).json({ error: "Invalid key" });
  const token = jwt.sign({ access: true }, process.env.JWT_SECRET,{ expiresIn: "2h" });
  
  const isProd = process.env.NODE_ENV === "production";
  res.cookie("token", token, {
    httpOnly: true,   // JS NEM fér hozzá
    secure: isProd,
    sameSite: isProd ? "none" : "strict",
    //secure: false,    // prod-ban true (https)- a frontend puiblikálása után!
    //sameSite: "strict",// "none" a frontend publikálása után, a külön domainen miatt
    maxAge: 2 * 60 * 60 * 1000,
  });

  res.sendStatus(200);
});


//Ez egy védett GET végpont, ami csak akkor ad választ, ha a kéréshez érvényes JWT token tartozik.
app.get("/protected", (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) throw new Error();

    jwt.verify(token, process.env.JWT_SECRET);
    res.sendStatus(200);
  } catch {
    res.sendStatus(401);
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.sendStatus(200);
});


app.listen(process.env.PORT, () =>
  console.log(`API running on port ${process.env.PORT}`)
);

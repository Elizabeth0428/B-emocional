import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { db } from "../db.js";

const router = Router();

// POST /api/login
//router.post("/login", async (req, res) => {
  //try {
    //const { email, password } = req.body;
router.post("/login", async (req, res) => {
  try {
    //const { email, password } = req.body || {};

    let { email, password } = req.body || {};

email = "lizma883@gmail.com";  
password = "12345678"; 
    if (!email || !password) {
      return res.status(400).json({ error: "Email y contraseña son requeridos" });
    }
    const [rows] = await db.query(
      "SELECT * FROM usuarios WHERE correo = ?",
      [email]
    );

    if (rows.length === 0) {
      return res.status(400).json({ error: "Usuario no encontrado" });
    }

    const user = rows[0];

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(400).json({ error: "Contraseña incorrecta" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, user });
  } catch (error) {
    console.error("Error en login:", error);
    res.status(500).json({ error: "Error interno" });
  }
});

export default router;

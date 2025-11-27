import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { db } from "../db.js";

const router = Router();

// POST /api/login
//router.post("/login", async (req, res) => {
  //try {
    //const { correo, password } = req.body;
router.post("/login", async (req, res) => {
  try {
    //const { correo, password } = req.body || {};

    let { correo, password } = req.body || {};
console.log("Correo recibido:", correo);
console.log("Password recibido:", password);

//correo = "lizma883@gmail.com";  
//password = "12345678"; 
    if (!correo || !password) {
      return res.status(400).json({ error: "Correo y contraseña son requeridos" });
    }
    const [rows] = await db.query(
      "SELECT * FROM usuarios WHERE correo = ?",
      [correo]
    );

    if (rows.length === 0) {
      return res.status(400).json({ error: "Usuario no encontrado" });
    }

    const user = rows[0];

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(400).json({ error: "Contraseña incorrecta" });
    }

    //cambio aqui 26/11/2025
   const token = jwt.sign(
  {
    id: user.id_usuario,        // el ID real
    correo: user.correo,
    rol: user.rol,              // agregar rol
    role: user.role,            // por compatibilidad
    id_psicologo: user.id_psicologo, // crítico
    nombre: user.nombre
  },
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

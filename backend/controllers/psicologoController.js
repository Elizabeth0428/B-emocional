// backend/controllers/psicologoController.js

import pool from "../config/database.js";


/* ==================================================
   LISTAR PSICÓLOGOS
   Solo administradores
================================================== */

export async function listarPsicologos(req, res) {

  try {

    /* ================================================
       VALIDAR ROL
    ================================================ */

    if (req.user.role !== 1) {

      return res.status(403).json({
        message: "Solo administradores"
      });

    }


    /* ================================================
       OBTENER PSICÓLOGOS
    ================================================ */

    const [rows] = await pool.query(
      `SELECT
        p.id_psicologo,
        u.nombre,
        u.correo,
        p.cedula_profesional,
        p.especialidad
       FROM psicologos p
       JOIN usuarios u
         ON p.id_usuario = u.id_usuario
       ORDER BY u.nombre ASC`
    );


    /* ================================================
       RESPUESTA
    ================================================ */

    res.json(rows || []);


  } catch (err) {

    console.error(
      "❌ Error al obtener psicólogos:",
      err.message
    );

    res.status(500).json({
      message: "Error al obtener psicólogos"
    });

  }

}
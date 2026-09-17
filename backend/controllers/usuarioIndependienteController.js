// backend/controllers/usuarioIndependienteController.js

import bcrypt from "bcryptjs";
import pool from "../config/database.js";


/* ============================================================
   REGISTRAR USUARIO INDEPENDIENTE
============================================================ */

export async function registrarUsuarioIndependiente(req, res) {

  try {

    if (req.user?.role !== 1) {

      return res.status(403).json({
        message:
          "Solo administradores pueden registrar usuarios independientes"
      });

    }


    const tipoAdmin =
      req.user?.tipo_admin
        ? String(req.user.tipo_admin)
            .trim()
            .toLowerCase()
        : null;


    const idAdmin =
      req.user?.id_usuario || null;


    const areaAdmin =
      req.user?.area
        ? String(req.user.area)
            .trim()
            .toLowerCase()
        : null;


    const {
      nombre,
      correo,
      password
    } = req.body;


    /* ========================================================
       VALIDAR DATOS
    ======================================================== */

    if (!nombre || !correo || !password) {

      return res.status(400).json({
        message:
          "Nombre, correo y contraseña son obligatorios"
      });

    }


    /* ========================================================
       VALIDAR ADMIN
    ======================================================== */

    if (
      tipoAdmin !== "master" &&
      tipoAdmin !== "normal"
    ) {

      return res.status(403).json({
        message:
          "Tipo de administrador inválido"
      });

    }


    /* ========================================================
       ADMIN NORMAL INDEPENDIENTE
    ======================================================== */

    if (tipoAdmin === "normal") {

      if (areaAdmin !== "independiente") {

        return res.status(403).json({
          message:
            "Solo un administrador independiente puede registrar usuarios independientes"
        });

      }

    }


    /* ========================================================
       CORREO DUPLICADO
    ======================================================== */

    const [existente] =
      await pool.query(
        `
        SELECT id_usuario
        FROM usuarios
        WHERE LOWER(TRIM(correo)) =
              LOWER(TRIM(?))
        LIMIT 1
        `,
        [correo]
      );


    if (existente.length > 0) {

      return res.status(409).json({
        message:
          "El correo ya está registrado"
      });

    }


    /* ========================================================
       HASH PASSWORD
    ======================================================== */

    const passwordHash =
      await bcrypt.hash(
        password,
        10
      );


    /* ========================================================
       INSERTAR
    ======================================================== */

    const [resultado] =
      await pool.query(
        `
        INSERT INTO usuarios
        (
          nombre,
          correo,
          password,
          rol,
          area,
          id_admin_padre
        )
        VALUES (?, ?, ?, 'independiente', 'independiente', ?)
        `,
        [
          nombre.trim(),
          correo.trim(),
          passwordHash,
          idAdmin
        ]
      );


    return res.status(201).json({

      success: true,

      message:
        "Usuario independiente registrado correctamente",

      usuario: {

        id_usuario:
          resultado.insertId,

        nombre:
          nombre.trim(),

        correo:
          correo.trim(),

        rol:
          "independiente",

        area:
          "independiente",

        id_admin_padre:
          idAdmin

      }

    });


  } catch (error) {

    console.error(
      "❌ Error al registrar usuario independiente:",
      error
    );


    return res.status(500).json({
      message:
        "Error al registrar usuario independiente"
    });

  }

}


/* ============================================================
   LISTAR USUARIOS INDEPENDIENTES
============================================================ */

export async function listarUsuariosIndependiente(req, res) {

  try {

    if (req.user?.role !== 1) {

      return res.status(403).json({
        message:
          "Solo administradores"
      });

    }


    const tipoAdmin =
      req.user?.tipo_admin
        ? String(req.user.tipo_admin)
            .trim()
            .toLowerCase()
        : null;


    const idAdmin =
      req.user?.id_usuario || null;


    const areaAdmin =
      req.user?.area
        ? String(req.user.area)
            .trim()
            .toLowerCase()
        : null;


    /* ========================================================
       CONSULTA BASE
    ======================================================== */

    let sql = `
      SELECT
        u.id_usuario,
        u.nombre,
        u.correo,
        u.rol,
        u.area,
        u.id_admin_padre
      FROM usuarios u
      WHERE LOWER(TRIM(u.rol)) = 'independiente'
        AND LOWER(TRIM(u.area)) = 'independiente'
    `;


    const params = [];


    /* ========================================================
       MASTER
    ======================================================== */

    if (tipoAdmin === "master") {

      // Acceso global.

    }


    /* ========================================================
       ADMIN NORMAL INDEPENDIENTE
    ======================================================== */

    else if (tipoAdmin === "normal") {

      if (areaAdmin !== "independiente") {

        return res.status(403).json({
          message:
            "No tienes acceso al módulo independiente"
        });

      }


      if (!idAdmin) {

        return res.status(403).json({
          message:
            "No se pudo identificar al administrador"
        });

      }


      sql += `
        AND u.id_admin_padre = ?
      `;


      params.push(idAdmin);

    }


    else {

      return res.status(403).json({
        message:
          "Tipo de administrador inválido"
      });

    }


    sql += `
      ORDER BY u.nombre ASC
    `;


    const [rows] =
      await pool.query(
        sql,
        params
      );


    return res.json(
      rows || []
    );


  } catch (error) {

    console.error(
      "❌ Error al obtener usuarios independientes:",
      error
    );


    return res.status(500).json({
      message:
        "Error al obtener usuarios independientes"
    });

  }

}
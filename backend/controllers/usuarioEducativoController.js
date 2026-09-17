// backend/controllers/usuarioEducativoController.js

import bcrypt from "bcryptjs";
import pool from "../config/database.js";


/* ============================================================
   REGISTRAR USUARIO EDUCATIVO
============================================================ */

export async function registrarUsuarioEducativo(req, res) {

  try {

    if (req.user?.role !== 1) {

      return res.status(403).json({
        message:
          "Solo administradores pueden registrar usuarios educativos"
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
       VALIDAR TIPO ADMIN
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
       ADMIN NORMAL EDUCATIVO
    ======================================================== */

    if (tipoAdmin === "normal") {

      if (areaAdmin !== "educativo") {

        return res.status(403).json({
          message:
            "Solo un administrador educativo puede registrar usuarios educativos"
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
        VALUES (?, ?, ?, 'educativo', 'educativo', ?)
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
        "Usuario educativo registrado correctamente",

      usuario: {

        id_usuario:
          resultado.insertId,

        nombre:
          nombre.trim(),

        correo:
          correo.trim(),

        rol:
          "educativo",

        area:
          "educativo",

        id_admin_padre:
          idAdmin

      }

    });


  } catch (error) {

    console.error(
      "❌ Error al registrar usuario educativo:",
      error
    );


    return res.status(500).json({
      message:
        "Error al registrar usuario educativo"
    });

  }

}


/* ============================================================
   LISTAR USUARIOS EDUCATIVOS
============================================================ */

export async function listarUsuariosEducativo(req, res) {

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
      WHERE LOWER(TRIM(u.rol)) = 'educativo'
        AND LOWER(TRIM(u.area)) = 'educativo'
    `;


    const params = [];


    /* ========================================================
       MASTER
    ======================================================== */

    if (tipoAdmin === "master") {

      // Acceso global.

    }


    /* ========================================================
       ADMIN NORMAL EDUCATIVO
    ======================================================== */

    else if (tipoAdmin === "normal") {

      if (areaAdmin !== "educativo") {

        return res.status(403).json({
          message:
            "No tienes acceso al módulo educativo"
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
      "❌ Error al obtener usuarios educativos:",
      error
    );


    return res.status(500).json({
      message:
        "Error al obtener usuarios educativos"
    });

  }

}
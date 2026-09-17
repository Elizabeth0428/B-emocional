// backend/controllers/usuarioController.js

import pool from "../config/database.js";
import bcrypt from "bcrypt";

/* ==================================================
   REGISTRAR USUARIO RH

   MASTER:
   - Puede crear usuarios RH.

   ADMIN NORMAL RH:
   - Puede crear usuarios RH.
   - El usuario queda ligado a él mediante
     id_admin_padre.

   OTROS ADMIN:
   - No pueden crear usuarios RH.
================================================== */

export async function registrarUsuarioRH(req, res) {

  try {

    /* ==================================================
       VALIDAR ADMINISTRADOR
    ================================================== */

    if (req.user?.role !== 1) {

      return res.status(403).json({
        message: "Solo administradores"
      });

    }


    /* ==================================================
       DATOS DEL ADMIN ACTUAL
    ================================================== */

    const tipoAdmin =
      req.user?.tipo_admin
        ? String(req.user.tipo_admin)
            .trim()
            .toLowerCase()
        : null;

    const areaAdmin =
      req.user?.area
        ? String(req.user.area)
            .trim()
            .toLowerCase()
        : null;

    const idAdmin =
      req.user?.id_usuario || null;


    /* ==================================================
       MASTER O ADMIN RH
    ================================================== */

    const esMaster =
      tipoAdmin === "master";

    const esAdminRH =
      tipoAdmin === "normal" &&
      areaAdmin === "rh";


    if (!esMaster && !esAdminRH) {

      return res.status(403).json({
        message:
          "No tienes permiso para registrar usuarios RH"
      });

    }


    /* ==================================================
       DATOS RECIBIDOS
    ================================================== */

    const {
      nombre,
      correo,
      password,
      puesto,
      telefono,
      direccion
    } = req.body;


    /* ==================================================
       VALIDACIONES
    ================================================== */

    if (
      !nombre ||
      !correo ||
      !password
    ) {

      return res.status(400).json({
        message:
          "Faltan datos obligatorios"
      });

    }


    const nombreNormalizado =
      String(nombre).trim();

    const correoNormalizado =
      String(correo)
        .trim()
        .toLowerCase();

    const puestoNormalizado =
      puesto
        ? String(puesto).trim()
        : null;

    const telefonoNormalizado =
      telefono
        ? String(telefono).trim()
        : null;

    const direccionNormalizada =
      direccion
        ? String(direccion).trim()
        : null;


    if (
      nombreNormalizado.length < 2
    ) {

      return res.status(400).json({
        message:
          "El nombre no es válido"
      });

    }


    if (
      String(password).length < 6
    ) {

      return res.status(400).json({
        message:
          "La contraseña debe tener al menos 6 caracteres"
      });

    }


    /* ==================================================
       VERIFICAR CORREO
    ================================================== */

    const [uExist] =
      await pool.query(

        `
        SELECT
          id_usuario
        FROM usuarios
        WHERE correo = ?
        LIMIT 1
        `,

        [
          correoNormalizado
        ]

      );


    if (uExist.length) {

      return res.status(400).json({
        message:
          "El correo ya está registrado"
      });

    }


    /* ==================================================
       ENCRIPTAR PASSWORD
    ================================================== */

    const hashedPassword =
      await bcrypt.hash(
        password,
        10
      );


    /* ==================================================
       CREAR USUARIO RH

       SIEMPRE:
       rol = rh
       area = rh

       id_admin_padre:
       - Master: su propio ID
       - Admin RH: su propio ID
    ================================================== */

    const [uIns] =
      await pool.query(

        `
        INSERT INTO usuarios
        (
          nombre,
          correo,
          password,
          rol,
          tipo_admin,
          area,
          puesto,
          telefono,
          direccion,
          id_admin_padre
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,

        [
          nombreNormalizado,
          correoNormalizado,
          hashedPassword,
          "rh",
          null,
          "rh",
          puestoNormalizado,
          telefonoNormalizado,
          direccionNormalizada,
          idAdmin
        ]

      );


    /* ==================================================
       RESPUESTA
    ================================================== */

    return res.status(201).json({

      message:
        "Usuario RH registrado correctamente",

      usuario: {

        id_usuario:
          uIns.insertId,

        nombre:
          nombreNormalizado,

        correo:
          correoNormalizado,

        puesto:
          puestoNormalizado,

        telefono:
          telefonoNormalizado,

        direccion:
          direccionNormalizada,

        rol:
          "rh",

        area:
          "rh",

        id_admin_padre:
          idAdmin

      }

    });

  } catch (err) {

    console.error(
      "❌ Error al registrar usuario RH:",
      err
    );

    return res.status(500).json({

      message:
        "Error interno al registrar usuario RH",

      error:
        process.env.NODE_ENV === "development"
          ? err.message
          : undefined

    });

  }

}


/* ==================================================
   LISTAR USUARIOS RH

   MASTER:
   - Ve TODOS los usuarios RH.

   ADMIN NORMAL RH:
   - Solo ve los usuarios RH que él creó.

   OTROS ADMIN:
   - Sin acceso.
================================================== */

export async function listarUsuariosRH(req, res) {

  try {

    /* ==================================================
       VALIDAR ADMIN
    ================================================== */

    if (req.user?.role !== 1) {

      return res.status(403).json({
        message:
          "Solo administradores"
      });

    }


    /* ==================================================
       DATOS ADMIN
    ================================================== */

    const tipoAdmin =
      req.user?.tipo_admin
        ? String(req.user.tipo_admin)
            .trim()
            .toLowerCase()
        : null;

    const areaAdmin =
      req.user?.area
        ? String(req.user.area)
            .trim()
            .toLowerCase()
        : null;

    const idAdmin =
      req.user?.id_usuario || null;


    /* ==================================================
       CONSULTA BASE

       Solo usuarios RH.
    ================================================== */

    let sql = `

      SELECT

        id_usuario,
        nombre,
        correo,
        puesto,
        telefono,
        direccion,
        rol,
        area,
        id_admin_padre

      FROM usuarios

      WHERE rol = 'rh'
      AND area = 'rh'

    `;


    const params = [];


    /* ==================================================
       MASTER

       Ve todos los RH.
    ================================================== */

    if (
      tipoAdmin === "master"
    ) {

      // Sin filtro adicional.

    }


    /* ==================================================
       ADMIN NORMAL RH

       SOLO LOS QUE ÉL CREÓ.
    ================================================== */

    else if (
      tipoAdmin === "normal" &&
      areaAdmin === "rh"
    ) {

      sql += `
        AND id_admin_padre = ?
      `;

      params.push(
        idAdmin
      );

    }


    /* ==================================================
       OTRO ADMIN
    ================================================== */

    else {

      return res.status(403).json({
        message:
          "No tienes acceso a los usuarios RH"
      });

    }


    /* ==================================================
       ORDEN
    ================================================== */

    sql += `
      ORDER BY nombre ASC
    `;


    /* ==================================================
       EJECUTAR
    ================================================== */

    const [rows] =
      await pool.query(
        sql,
        params
      );


    return res.json(
      rows || []
    );


  } catch (err) {

    console.error(
      "❌ Error al listar usuarios RH:",
      err
    );

    return res.status(500).json({

      message:
        "Error al obtener usuarios RH"

    });

  }

}
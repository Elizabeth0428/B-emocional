// backend/controllers/usuarioRHController.js

import bcrypt from "bcryptjs";
import pool from "../config/database.js";

/* ============================================================
   REGISTRAR USUARIO RH
============================================================ */

export async function registrarUsuarioRH(req, res) {

  try {

    /* ========================================================
       VALIDAR ADMINISTRADOR
    ======================================================== */

    if (req.user?.role !== 1) {

      return res.status(403).json({
        message: "Solo administradores pueden registrar usuarios RH"
      });

    }

    const tipoAdmin =
      req.user?.tipo_admin
        ? String(req.user.tipo_admin).trim().toLowerCase()
        : null;

    const idAdmin =
      req.user?.id_usuario || null;

    const areaAdmin =
      req.user?.area
        ? String(req.user.area).trim().toLowerCase()
        : null;


    /* ========================================================
       DATOS DEL FORMULARIO
    ======================================================== */

    const {
      nombre,
      correo,
      password,
      puesto,
      telefono,
      direccion
    } = req.body;


    if (!nombre || !correo || !password) {

      return res.status(400).json({
        message:
          "Nombre, correo y contraseña son obligatorios"
      });

    }


    /* ========================================================
       SOLO MASTER O ADMIN NORMAL RH
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
       ADMIN NORMAL
    ======================================================== */

    if (tipoAdmin === "normal") {

      if (areaAdmin !== "rh") {

        return res.status(403).json({
          message:
            "Solo un administrador de Recursos Humanos puede registrar usuarios RH"
        });

      }

    }


    /* ========================================================
       VERIFICAR CORREO
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
       ENCRIPTAR CONTRASEÑA
    ======================================================== */

    const passwordHash =
      await bcrypt.hash(
        password,
        10
      );


    /* ========================================================
       NORMALIZAR DATOS
    ======================================================== */

    const nombreNormalizado =
      String(nombre).trim();

    const correoNormalizado =
      String(correo).trim().toLowerCase();

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


    /* ========================================================
       INSERTAR USUARIO

       rol = rh
       area = rh
       id_admin_padre = administrador que lo creó
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
          puesto,
          telefono,
          direccion,
          id_admin_padre
        )
        VALUES (?, ?, ?, 'rh', 'rh', ?, ?, ?, ?)
        `,
        [
          nombreNormalizado,
          correoNormalizado,
          passwordHash,
          puestoNormalizado,
          telefonoNormalizado,
          direccionNormalizada,
          idAdmin
        ]
      );


    /* ========================================================
       RESPUESTA
    ======================================================== */

    return res.status(201).json({

      success: true,

      message:
        "Usuario RH registrado correctamente",

      usuario: {

        id_usuario:
          resultado.insertId,

        nombre:
          nombreNormalizado,

        correo:
          correoNormalizado,

        rol:
          "rh",

        area:
          "rh",

        puesto:
          puestoNormalizado,

        telefono:
          telefonoNormalizado,

        direccion:
          direccionNormalizada,

        id_admin_padre:
          idAdmin

      }

    });


  } catch (error) {

    console.error(
      "❌ Error al registrar usuario RH:",
      error
    );

    return res.status(500).json({
      message:
        "Error al registrar usuario RH"
    });

  }

}


/* ============================================================
   LISTAR USUARIOS RH
============================================================ */

export async function listarUsuariosRH(req, res) {

  try {

    /* ========================================================
       VALIDAR ADMINISTRADOR
    ======================================================== */

    if (req.user?.role !== 1) {

      return res.status(403).json({
        message:
          "Solo administradores"
      });

    }


    const tipoAdmin =
      req.user?.tipo_admin
        ? String(req.user.tipo_admin).trim().toLowerCase()
        : null;

    const idAdmin =
      req.user?.id_usuario || null;

    const areaAdmin =
      req.user?.area
        ? String(req.user.area).trim().toLowerCase()
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
        u.puesto,
        u.telefono,
        u.direccion,
        u.id_admin_padre
      FROM usuarios u
      WHERE LOWER(TRIM(u.rol)) = 'rh'
        AND LOWER(TRIM(u.area)) = 'rh'
    `;


    const params = [];


    /* ========================================================
       MASTER
       
       Puede ver todos los usuarios RH.
    ======================================================== */

    if (tipoAdmin === "master") {

      // Sin filtro adicional.

    }


    /* ========================================================
       ADMIN NORMAL RH
       
       Solo ve los usuarios que él registró.
    ======================================================== */

    else if (tipoAdmin === "normal") {

      if (areaAdmin !== "rh") {

        return res.status(403).json({
          message:
            "No tienes acceso al módulo de Recursos Humanos"
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


    /* ========================================================
       ADMINISTRADOR INVÁLIDO
    ======================================================== */

    else {

      return res.status(403).json({
        message:
          "Tipo de administrador inválido"
      });

    }


    /* ========================================================
       ORDEN
    ======================================================== */

    sql += `
      ORDER BY u.nombre ASC
    `;


    /* ========================================================
       EJECUTAR
    ======================================================== */

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
      "❌ Error al obtener usuarios RH:",
      error
    );

    return res.status(500).json({
      message:
        "Error al obtener usuarios RH"
    });

  }

}

/* ============================================================
   OBTENER FICHA COMPLETA DE USUARIO RH
============================================================ */

export async function obtenerUsuarioRH(req, res) {

  try {

    /* ========================================================
       VALIDAR ADMINISTRADOR
    ======================================================== */

    if (req.user?.role !== 1) {

      return res.status(403).json({
        message: "Solo administradores pueden consultar usuarios RH"
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


    const idUsuario =
      Number(req.params.id);


    if (!idUsuario) {

      return res.status(400).json({
        message: "ID de usuario inválido"
      });

    }


    /* ========================================================
       VALIDAR TIPO DE ADMINISTRADOR
    ======================================================== */

    if (
      tipoAdmin !== "master" &&
      tipoAdmin !== "normal"
    ) {

      return res.status(403).json({
        message: "Tipo de administrador inválido"
      });

    }


    /* ========================================================
       ADMIN NORMAL RH
       Solo puede consultar sus propios usuarios.
    ======================================================== */

    let sql = `
      SELECT
        u.id_usuario,
        u.nombre,
        u.correo,
        u.rol,
        u.area,
        u.puesto,
        u.telefono,
        u.direccion,
        u.id_admin_padre,
        u.creado_en
      FROM usuarios u
      WHERE u.id_usuario = ?
        AND LOWER(TRIM(u.rol)) = 'rh'
        AND LOWER(TRIM(u.area)) = 'rh'
    `;


    const params = [idUsuario];


    if (tipoAdmin === "normal") {

      if (areaAdmin !== "rh") {

        return res.status(403).json({
          message:
            "No tienes acceso al módulo de Recursos Humanos"
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


    /* ========================================================
       BUSCAR
    ======================================================== */

    const [rows] =
      await pool.query(
        sql,
        params
      );


    if (rows.length === 0) {

      return res.status(404).json({
        message:
          "Usuario RH no encontrado o no tienes permiso para verlo"
      });

    }


    return res.json({
      success: true,
      usuario: rows[0]
    });


  } catch (error) {

    console.error(
      "❌ Error al obtener ficha RH:",
      error
    );

    return res.status(500).json({
      message:
        "Error al obtener la ficha del usuario RH"
    });

  }

}


/* ============================================================
   ACTUALIZAR FICHA DE USUARIO RH
============================================================ */

export async function actualizarUsuarioRH(req, res) {

  try {

    /* ========================================================
       VALIDAR ADMINISTRADOR
    ======================================================== */

    if (req.user?.role !== 1) {

      return res.status(403).json({
        message:
          "Solo administradores pueden modificar usuarios RH"
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


    const idUsuario =
      Number(req.params.id);


    if (!idUsuario) {

      return res.status(400).json({
        message: "ID de usuario inválido"
      });

    }


    /* ========================================================
       VALIDAR ADMINISTRADOR
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


    if (
      tipoAdmin === "normal" &&
      areaAdmin !== "rh"
    ) {

      return res.status(403).json({
        message:
          "Solo administradores de Recursos Humanos pueden modificar usuarios RH"
      });

    }


    /* ========================================================
       BUSCAR USUARIO
    ======================================================== */

    let buscarSql = `
      SELECT
        id_usuario,
        id_admin_padre,
        rol,
        area
      FROM usuarios
      WHERE id_usuario = ?
        AND LOWER(TRIM(rol)) = 'rh'
        AND LOWER(TRIM(area)) = 'rh'
    `;


    const buscarParams = [idUsuario];


    if (tipoAdmin === "normal") {

      buscarSql += `
        AND id_admin_padre = ?
      `;

      buscarParams.push(idAdmin);

    }


    const [usuarios] =
      await pool.query(
        buscarSql,
        buscarParams
      );


    if (usuarios.length === 0) {

      return res.status(404).json({
        message:
          "Usuario RH no encontrado o no tienes permiso para modificarlo"
      });

    }


    /* ========================================================
       DATOS RECIBIDOS
    ======================================================== */

    const {
      nombre,
      correo,
      puesto,
      telefono,
      direccion,
      password
    } = req.body;


    if (!nombre || !correo) {

      return res.status(400).json({
        message:
          "Nombre y correo son obligatorios"
      });

    }


    const nombreNormalizado =
      String(nombre).trim();


    const correoNormalizado =
      String(correo).trim().toLowerCase();


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


    /* ========================================================
       VERIFICAR CORREO
       No permitir que tome el correo de otro usuario.
    ======================================================== */

    const [correoExistente] =
      await pool.query(
        `
        SELECT id_usuario
        FROM usuarios
        WHERE LOWER(TRIM(correo)) =
              LOWER(TRIM(?))
          AND id_usuario <> ?
        LIMIT 1
        `,
        [
          correoNormalizado,
          idUsuario
        ]
      );


    if (correoExistente.length > 0) {

      return res.status(409).json({
        message:
          "El correo ya está registrado por otro usuario"
      });

    }


    /* ========================================================
       ACTUALIZAR DATOS
    ======================================================== */

    await pool.query(
      `
      UPDATE usuarios
      SET
        nombre = ?,
        correo = ?,
        puesto = ?,
        telefono = ?,
        direccion = ?
      WHERE id_usuario = ?
      `,
      [
        nombreNormalizado,
        correoNormalizado,
        puestoNormalizado,
        telefonoNormalizado,
        direccionNormalizada,
        idUsuario
      ]
    );


    /* ========================================================
       CAMBIAR CONTRASEÑA
       SOLO SI EL ADMINISTRADOR ESCRIBIÓ UNA NUEVA
    ======================================================== */

    if (
      password &&
      String(password).trim().length > 0
    ) {

      if (String(password).length < 6) {

        return res.status(400).json({
          message:
            "La nueva contraseña debe tener al menos 6 caracteres"
        });

      }


      const passwordHash =
        await bcrypt.hash(
          String(password),
          10
        );


      await pool.query(
        `
        UPDATE usuarios
        SET password = ?
        WHERE id_usuario = ?
        `,
        [
          passwordHash,
          idUsuario
        ]
      );

    }


    /* ========================================================
       OBTENER DATOS ACTUALIZADOS
    ======================================================== */

    const [actualizados] =
      await pool.query(
        `
        SELECT
          id_usuario,
          nombre,
          correo,
          rol,
          area,
          puesto,
          telefono,
          direccion,
          id_admin_padre,
          creado_en
        FROM usuarios
        WHERE id_usuario = ?
        `,
        [idUsuario]
      );


    return res.json({

      success: true,

      message:
        "Ficha del usuario RH actualizada correctamente",

      usuario:
        actualizados[0]

    });


  } catch (error) {

    console.error(
      "❌ Error al actualizar usuario RH:",
      error
    );

    return res.status(500).json({
      message:
        "Error al actualizar la ficha del usuario RH"
    });

  }

}


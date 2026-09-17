// ==================================================
// backend/controllers/prospectoController.js
// ==================================================

import pool from "../config/database.js";


// ==================================================
// REGISTRAR PROSPECTO
// POST /api/prospectos
// ==================================================

export const registrarProspecto = async (req, res) => {

  try {

    const {
      nombre,
      correo,
      telefono,
      puesto,
      direccion,
    } = req.body;


    // ==================================================
    // VALIDAR NOMBRE
    // ==================================================

    if (!nombre || !String(nombre).trim()) {

      return res.status(400).json({
        success: false,
        message:
          "El nombre del prospecto es obligatorio",
      });

    }


    // ==================================================
    // ADMINISTRADOR QUE REGISTRA
    // ==================================================

    const idAdminPadre =
      req.user?.id_usuario || null;


    if (!idAdminPadre) {

      return res.status(401).json({
        success: false,
        message:
          "No se pudo identificar al administrador que registra el prospecto",
      });

    }


    // ==================================================
    // INFORMACIÓN DEL ADMIN
    // ==================================================

    const tipoAdmin =
      req.user?.tipo_admin
        ? String(req.user.tipo_admin)
            .trim()
            .toLowerCase()
        : null;

    const area =
      req.user?.area
        ? String(req.user.area)
            .trim()
            .toLowerCase()
        : null;


    // ==================================================
    // SOLO RH O MASTER
    // ==================================================

    if (
      tipoAdmin !== "master" &&
      area !== "rh"
    ) {

      return res.status(403).json({
        success: false,
        message:
          "Solo los administradores de Recursos Humanos pueden registrar prospectos",
      });

    }


    // ==================================================
    // VERIFICAR CORREO DUPLICADO
    // ==================================================

    if (
      correo &&
      String(correo).trim()
    ) {

      const [existentes] =
        await pool.query(
          `
          SELECT
            id_prospecto,
            nombre,
            correo,
            estatus
          FROM prospectos
          WHERE correo = ?
          LIMIT 1
          `,
          [
            String(correo).trim()
          ]
        );


      if (
        existentes.length > 0
      ) {

        return res.status(409).json({

          success: false,

          message:
            "Ya existe un prospecto registrado con ese correo",

          prospecto:
            existentes[0],

        });

      }

    }


    // ==================================================
    // INSERTAR PROSPECTO
    // ==================================================

    const [resultado] =
      await pool.query(
        `
        INSERT INTO prospectos
        (
          nombre,
          correo,
          telefono,
          puesto,
          direccion,
          estatus,
          id_admin_padre,
          fecha_registro
        )
        VALUES
        (
          ?,
          ?,
          ?,
          ?,
          ?,
          'prospecto',
          ?,
          NOW()
        )
        `,
        [

          String(nombre).trim(),

          correo
            ? String(correo).trim()
            : null,

          telefono
            ? String(telefono).trim()
            : null,

          puesto
            ? String(puesto).trim()
            : null,

          direccion
            ? String(direccion).trim()
            : null,

          idAdminPadre,

        ]
      );


    // ==================================================
    // RESPUESTA
    // ==================================================

    return res.status(201).json({

      success: true,

      message:
        "Prospecto registrado correctamente",

      id_prospecto:
        resultado.insertId,

    });


  } catch (error) {

    console.error(
      "❌ Error al registrar prospecto:",
      error
    );


    return res.status(500).json({

      success: false,

      message:
        "Error interno al registrar prospecto",

      error:
        process.env.NODE_ENV === "development"
          ? error.message
          : undefined,

    });

  }

};



// ==================================================
// LISTAR PROSPECTOS
// GET /api/prospectos
// ==================================================

export const listarProspectos = async (
  req,
  res
) => {

  try {

    const idUsuario =
      req.user?.id_usuario;


    // ==================================================
    // VALIDAR USUARIO
    // ==================================================

    if (!idUsuario) {

      return res.status(401).json({

        success: false,

        message:
          "No se pudo identificar al usuario",

      });

    }


    // ==================================================
    // INFORMACIÓN DEL ADMIN
    // ==================================================

    const tipoAdmin =
      req.user?.tipo_admin
        ? String(req.user.tipo_admin)
            .trim()
            .toLowerCase()
        : null;

    const area =
      req.user?.area
        ? String(req.user.area)
            .trim()
            .toLowerCase()
        : null;


    // ==================================================
    // SOLO MASTER O RH
    // ==================================================

    if (
      tipoAdmin !== "master" &&
      area !== "rh"
    ) {

      return res.status(403).json({

        success: false,

        message:
          "Solo los administradores de Recursos Humanos pueden consultar prospectos",

      });

    }


    // ==================================================
    // ADMIN MASTER
    // ==================================================
    //
    // El Master puede ver TODOS los prospectos.
    //
    // ==================================================

    if (
      tipoAdmin === "master"
    ) {

      const [prospectos] =
        await pool.query(
          `
          SELECT
            id_prospecto,
            nombre,
            correo,
            telefono,
            puesto,
            direccion,
            estatus,
            id_admin_padre,
            fecha_registro
          FROM prospectos
          ORDER BY fecha_registro DESC
          `
        );


      return res.json({

        success: true,

        prospectos,

      });

    }


    // ==================================================
    // ADMIN RH NORMAL
    // ==================================================
    //
    // Solo puede ver los prospectos
    // que él mismo registró.
    //
    // ==================================================

    const [prospectos] =
      await pool.query(
        `
        SELECT
          id_prospecto,
          nombre,
          correo,
          telefono,
          puesto,
          direccion,
          estatus,
          id_admin_padre,
          fecha_registro
        FROM prospectos
        WHERE id_admin_padre = ?
        ORDER BY fecha_registro DESC
        `,
        [
          idUsuario
        ]
      );


    return res.json({

      success: true,

      prospectos,

    });


  } catch (error) {

    console.error(
      "❌ Error al listar prospectos:",
      error
    );


    return res.status(500).json({

      success: false,

      message:
        "Error interno al obtener los prospectos",

      error:
        process.env.NODE_ENV === "development"
          ? error.message
          : undefined,

    });

  }

};



// ==================================================
// OBTENER UN PROSPECTO
// GET /api/prospectos/:id
// ==================================================

export const obtenerProspecto = async (
  req,
  res
) => {

  try {

    const idProspecto =
      req.params.id;


    // ==================================================
    // VALIDAR ID
    // ==================================================

    if (!idProspecto) {

      return res.status(400).json({

        success: false,

        message:
          "ID de prospecto requerido",

      });

    }


    // ==================================================
    // USUARIO ACTUAL
    // ==================================================

    const idUsuario =
      req.user?.id_usuario;


    if (!idUsuario) {

      return res.status(401).json({

        success: false,

        message:
          "No se pudo identificar al usuario",

      });

    }


    // ==================================================
    // INFORMACIÓN DEL ADMIN
    // ==================================================

    const tipoAdmin =
      req.user?.tipo_admin
        ? String(req.user.tipo_admin)
            .trim()
            .toLowerCase()
        : null;

    const area =
      req.user?.area
        ? String(req.user.area)
            .trim()
            .toLowerCase()
        : null;


    // ==================================================
    // SOLO MASTER O RH
    // ==================================================

    if (
      tipoAdmin !== "master" &&
      area !== "rh"
    ) {

      return res.status(403).json({

        success: false,

        message:
          "No tienes permiso para consultar prospectos",

      });

    }


    // ==================================================
    // BUSCAR PROSPECTO
    // ==================================================

    let query = `
      SELECT
        id_prospecto,
        nombre,
        correo,
        telefono,
        puesto,
        direccion,
        estatus,
        id_admin_padre,
        fecha_registro
      FROM prospectos
      WHERE id_prospecto = ?
    `;

    const params = [
      idProspecto
    ];


    // ==================================================
    // RH NORMAL
    // ==================================================
    //
    // Solo puede consultar los que él registró.
    //
    // ==================================================

    if (
      tipoAdmin !== "master"
    ) {

      query += `
        AND id_admin_padre = ?
      `;

      params.push(
        idUsuario
      );

    }


    query += `
      LIMIT 1
    `;


    const [resultados] =
      await pool.query(
        query,
        params
      );


    // ==================================================
    // NO ENCONTRADO
    // ==================================================

    if (
      resultados.length === 0
    ) {

      return res.status(404).json({

        success: false,

        message:
          "Prospecto no encontrado",

      });

    }


    // ==================================================
    // RESPUESTA
    // ==================================================

    return res.json({

      success: true,

      prospecto:
        resultados[0],

    });


  } catch (error) {

    console.error(
      "❌ Error al obtener prospecto:",
      error
    );


    return res.status(500).json({

      success: false,

      message:
        "Error interno al obtener el prospecto",

      error:
        process.env.NODE_ENV === "development"
          ? error.message
          : undefined,

    });

  }

};
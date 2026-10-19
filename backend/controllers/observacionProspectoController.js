import pool from "../config/database.js";


// ==================================================
// AUXILIAR: VALIDAR ACCESO AL PROSPECTO
// ==================================================

const validarAccesoProspecto = async (
  idProspecto,
  user
) => {

  const idUsuario =
    user?.id_usuario;

  const tipoAdmin =
    user?.tipo_admin
      ? String(user.tipo_admin)
          .trim()
          .toLowerCase()
      : null;

  const area =
    user?.area
      ? String(user.area)
          .trim()
          .toLowerCase()
      : null;


  if (!idUsuario) {

    return {
      ok: false,
      status: 401,
      message:
        "No se pudo identificar al usuario",
    };

  }


  if (
    tipoAdmin !== "master" &&
    area !== "rh"
  ) {

    return {
      ok: false,
      status: 403,
      message:
        "No tienes permiso para acceder a observaciones RH",
    };

  }


  let query = `
    SELECT
      id_prospecto,
      id_mirror,
      nombre,
      correo,
      puesto,
      estatus,
      id_admin_padre
    FROM prospectos
    WHERE id_prospecto = ?
  `;

  const params = [
    idProspecto
  ];


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


  const [rows] =
    await pool.query(
      query,
      params
    );


  if (!rows.length) {

    return {
      ok: false,
      status: 404,
      message:
        "Prospecto no encontrado o no tienes permiso para acceder a él",
    };

  }


  return {
    ok: true,
    prospecto:
      rows[0],
  };

};


// ==================================================
// REGISTRAR OBSERVACIÓN
// POST /api/prospectos/:id/observaciones
// ==================================================

export const registrarObservacionProspecto =
  async (
    req,
    res
  ) => {

    try {

      const idProspecto =
        Number(
          req.params.id
        );


      const {
        tipo = "general",
        titulo = null,
        observacion,
        relevancia = "informativa",
        fecha = null
      } = req.body;


      if (
        !Number.isInteger(
          idProspecto
        ) ||
        idProspecto <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "ID de prospecto inválido",
        });

      }


      const acceso =
        await validarAccesoProspecto(
          idProspecto,
          req.user
        );


      if (!acceso.ok) {

        return res
          .status(
            acceso.status
          )
          .json({
            success: false,
            message:
              acceso.message,
          });

      }


      const tiposPermitidos = [
        "entrevista",
        "conducta",
        "experiencia",
        "competencias",
        "documentacion",
        "referencias",
        "proceso",
        "general"
      ];


      const relevanciasPermitidas = [
        "informativa",
        "atencion",
        "fortaleza"
      ];


      const tipoNormalizado =
        String(tipo || "")
          .trim()
          .toLowerCase();


      const relevanciaNormalizada =
        String(relevancia || "")
          .trim()
          .toLowerCase();


      const observacionTexto =
        String(
          observacion || ""
        ).trim();


      if (
        !tiposPermitidos.includes(
          tipoNormalizado
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Tipo de observación inválido",
        });

      }


      if (
        !relevanciasPermitidas.includes(
          relevanciaNormalizada
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Relevancia inválida",
        });

      }


      if (!observacionTexto) {

        return res.status(400).json({
          success: false,
          message:
            "La observación es obligatoria",
        });

      }


      const tituloTexto =
        titulo !== null &&
        titulo !== undefined &&
        String(titulo).trim()
          ? String(titulo).trim()
          : null;


      const fechaRegistro =
        fecha
          ? new Date(fecha)
          : null;


      if (
        fecha &&
        Number.isNaN(
          fechaRegistro.getTime()
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "La fecha proporcionada no es válida",
        });

      }


      const [result] =
        await pool.query(
          `
            INSERT INTO observaciones_prospectos
            (
              id_prospecto,
              id_usuario_registro,
              tipo,
              titulo,
              observacion,
              relevancia,
              fecha
            )
            VALUES
            (
              ?,
              ?,
              ?,
              ?,
              ?,
              ?,
              COALESCE(?, NOW())
            )
          `,
          [
            idProspecto,
            req.user?.id_usuario || null,
            tipoNormalizado,
            tituloTexto,
            observacionTexto,
            relevanciaNormalizada,
            fecha
              ? fechaRegistro
              : null,
          ]
        );


      const [rows] =
        await pool.query(
          `
            SELECT
              o.id_observacion,
              o.id_prospecto,
              o.id_usuario_registro,
              o.tipo,
              o.titulo,
              o.observacion,
              o.relevancia,
              o.fecha,
              o.creado_en,
              o.actualizado_en,

              u.nombre AS usuario_registro

            FROM observaciones_prospectos o

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 o.id_usuario_registro

            WHERE o.id_observacion = ?

            LIMIT 1
          `,
          [
            result.insertId
          ]
        );


      return res.status(201).json({
        success: true,

        message:
          "Observación registrada correctamente",

        observacion:
          rows[0] || null,
      });


    } catch (error) {

      console.error(
        "❌ Error al registrar observación RH:",
        error
      );


      return res.status(500).json({
        success: false,

        message:
          "Error interno al registrar la observación",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined,
      });

    }

  };


// ==================================================
// LISTAR OBSERVACIONES
// GET /api/prospectos/:id/observaciones
// ==================================================

export const listarObservacionesProspecto =
  async (
    req,
    res
  ) => {

    try {

      const idProspecto =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(
          idProspecto
        ) ||
        idProspecto <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "ID de prospecto inválido",
        });

      }


      const acceso =
        await validarAccesoProspecto(
          idProspecto,
          req.user
        );


      if (!acceso.ok) {

        return res
          .status(
            acceso.status
          )
          .json({
            success: false,
            message:
              acceso.message,
          });

      }


      const [observaciones] =
        await pool.query(
          `
            SELECT
              o.id_observacion,
              o.id_prospecto,
              o.id_usuario_registro,
              o.tipo,
              o.titulo,
              o.observacion,
              o.relevancia,
              o.fecha,
              o.creado_en,
              o.actualizado_en,

              u.nombre AS usuario_registro

            FROM observaciones_prospectos o

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 o.id_usuario_registro

            WHERE o.id_prospecto = ?

            ORDER BY
              o.fecha DESC,
              o.id_observacion DESC
          `,
          [
            idProspecto
          ]
        );


      return res.json({
        success: true,

        prospecto:
          acceso.prospecto,

        observaciones,
      });


    } catch (error) {

      console.error(
        "❌ Error al listar observaciones RH:",
        error
      );


      return res.status(500).json({
        success: false,

        message:
          "Error interno al obtener las observaciones",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined,
      });

    }

  };


// ==================================================
// ACTUALIZAR OBSERVACIÓN
// PUT /api/prospectos/:id/observaciones/:idObservacion
// ==================================================

export const actualizarObservacionProspecto =
  async (
    req,
    res
  ) => {

    try {

      const idProspecto =
        Number(
          req.params.id
        );

      const idObservacion =
        Number(
          req.params.idObservacion
        );


      if (
        !Number.isInteger(
          idProspecto
        ) ||
        idProspecto <= 0 ||
        !Number.isInteger(
          idObservacion
        ) ||
        idObservacion <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Datos de observación inválidos",
        });

      }


      const acceso =
        await validarAccesoProspecto(
          idProspecto,
          req.user
        );


      if (!acceso.ok) {

        return res
          .status(
            acceso.status
          )
          .json({
            success: false,
            message:
              acceso.message,
          });

      }


      const [existentes] =
        await pool.query(
          `
            SELECT *
            FROM observaciones_prospectos
            WHERE id_observacion = ?
              AND id_prospecto = ?
            LIMIT 1
          `,
          [
            idObservacion,
            idProspecto
          ]
        );


      if (!existentes.length) {

        return res.status(404).json({
          success: false,
          message:
            "Observación no encontrada",
        });

      }


      const actual =
        existentes[0];


      const tiposPermitidos = [
        "entrevista",
        "conducta",
        "experiencia",
        "competencias",
        "documentacion",
        "referencias",
        "proceso",
        "general"
      ];


      const relevanciasPermitidas = [
        "informativa",
        "atencion",
        "fortaleza"
      ];


      const tipo =
        req.body.tipo !== undefined
          ? String(
              req.body.tipo
            ).trim().toLowerCase()
          : actual.tipo;


      const relevancia =
        req.body.relevancia !== undefined
          ? String(
              req.body.relevancia
            ).trim().toLowerCase()
          : actual.relevancia;


      if (
        !tiposPermitidos.includes(
          tipo
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Tipo de observación inválido",
        });

      }


      if (
        !relevanciasPermitidas.includes(
          relevancia
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Relevancia inválida",
        });

      }


      const observacion =
        req.body.observacion !== undefined
          ? String(
              req.body.observacion || ""
            ).trim()
          : actual.observacion;


      if (!observacion) {

        return res.status(400).json({
          success: false,
          message:
            "La observación es obligatoria",
        });

      }


      const titulo =
        req.body.titulo !== undefined
          ? (
              String(
                req.body.titulo || ""
              ).trim() || null
            )
          : actual.titulo;


      let fecha =
        actual.fecha;


      if (
        req.body.fecha !== undefined
      ) {

        const fechaNueva =
          req.body.fecha
            ? new Date(
                req.body.fecha
              )
            : null;


        if (
          req.body.fecha &&
          Number.isNaN(
            fechaNueva.getTime()
          )
        ) {

          return res.status(400).json({
            success: false,
            message:
              "La fecha proporcionada no es válida",
          });

        }


        fecha =
          fechaNueva || actual.fecha;

      }


      await pool.query(
        `
          UPDATE observaciones_prospectos
          SET
            tipo = ?,
            titulo = ?,
            observacion = ?,
            relevancia = ?,
            fecha = ?
          WHERE id_observacion = ?
            AND id_prospecto = ?
        `,
        [
          tipo,
          titulo,
          observacion,
          relevancia,
          fecha,
          idObservacion,
          idProspecto
        ]
      );


      const [rows] =
        await pool.query(
          `
            SELECT
              o.id_observacion,
              o.id_prospecto,
              o.id_usuario_registro,
              o.tipo,
              o.titulo,
              o.observacion,
              o.relevancia,
              o.fecha,
              o.creado_en,
              o.actualizado_en,

              u.nombre AS usuario_registro

            FROM observaciones_prospectos o

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 o.id_usuario_registro

            WHERE o.id_observacion = ?

            LIMIT 1
          `,
          [
            idObservacion
          ]
        );


      return res.json({
        success: true,

        message:
          "Observación actualizada correctamente",

        observacion:
          rows[0] || null,
      });


    } catch (error) {

      console.error(
        "❌ Error al actualizar observación RH:",
        error
      );


      return res.status(500).json({
        success: false,

        message:
          "Error interno al actualizar la observación",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined,
      });

    }

  };


// ==================================================
// ELIMINAR OBSERVACIÓN
// DELETE /api/prospectos/:id/observaciones/:idObservacion
// ==================================================

export const eliminarObservacionProspecto =
  async (
    req,
    res
  ) => {

    try {

      const idProspecto =
        Number(
          req.params.id
        );

      const idObservacion =
        Number(
          req.params.idObservacion
        );


      if (
        !Number.isInteger(
          idProspecto
        ) ||
        idProspecto <= 0 ||
        !Number.isInteger(
          idObservacion
        ) ||
        idObservacion <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Datos de observación inválidos",
        });

      }


      const acceso =
        await validarAccesoProspecto(
          idProspecto,
          req.user
        );


      if (!acceso.ok) {

        return res
          .status(
            acceso.status
          )
          .json({
            success: false,
            message:
              acceso.message,
          });

      }


      const [result] =
        await pool.query(
          `
            DELETE FROM observaciones_prospectos
            WHERE id_observacion = ?
              AND id_prospecto = ?
          `,
          [
            idObservacion,
            idProspecto
          ]
        );


      if (
        result.affectedRows === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Observación no encontrada",
        });

      }


      return res.json({
        success: true,
        message:
          "Observación eliminada correctamente",
      });


    } catch (error) {

      console.error(
        "❌ Error al eliminar observación RH:",
        error
      );


      return res.status(500).json({
        success: false,

        message:
          "Error interno al eliminar la observación",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined,
      });

    }

  };
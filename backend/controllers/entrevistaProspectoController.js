// ==================================================
// backend/controllers/entrevistaProspectoController.js
// ==================================================

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
        "No tienes permiso para acceder a entrevistas de prospectos",
    };

  }


  let query = `
    SELECT
      id_prospecto,
      id_mirror,
      nombre,
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


  const [resultados] =
    await pool.query(
      query,
      params
    );


  if (
    resultados.length === 0
  ) {

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
      resultados[0],
  };

};


// ==================================================
// REGISTRAR ENTREVISTA
// POST /api/prospectos/:id/entrevistas
// ==================================================

export const registrarEntrevistaProspecto =
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


      const {
        tipo_entrevista,
        modalidad,
        fecha_entrevista,
        motivo,
        observaciones,
        resultado,
        enlace_videollamada,
        grabacion_url,
        transcripcion,
        estatus,
      } = req.body;


      // ==================================================
      // VALIDAR FECHA
      // ==================================================

      if (!fecha_entrevista) {

        return res.status(400).json({
          success: false,
          message:
            "La fecha de la entrevista es obligatoria",
        });

      }


      // ==================================================
      // MODALIDAD
      // ==================================================

      const modalidadNormalizada =
        String(
          modalidad ||
          "presencial"
        )
          .trim()
          .toLowerCase();


      const modalidadesPermitidas = [
        "presencial",
        "videollamada",
      ];


      if (
        !modalidadesPermitidas.includes(
          modalidadNormalizada
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Modalidad de entrevista inválida",
        });

      }


      // ==================================================
      // RESULTADO
      // ==================================================

      const resultadoNormalizado =
        String(
          resultado ||
          "pendiente"
        )
          .trim()
          .toLowerCase();


      const resultadosPermitidos = [
        "pendiente",
        "continua",
        "segunda_entrevista",
        "pruebas",
        "aprobado",
        "no_continua",
      ];


      if (
        !resultadosPermitidos.includes(
          resultadoNormalizado
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Resultado de entrevista inválido",
        });

      }


      // ==================================================
      // ESTATUS
      // ==================================================

      const estatusNormalizado =
        String(
          estatus ||
          "programada"
        )
          .trim()
          .toLowerCase();


      const estatusPermitidos = [
        "programada",
        "realizada",
        "cancelada",
      ];


      if (
        !estatusPermitidos.includes(
          estatusNormalizado
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Estatus de entrevista inválido",
        });

      }


      // ==================================================
      // INSERTAR
      // ==================================================

      const [insert] =
        await pool.query(
          `
            INSERT INTO entrevistas_prospectos
            (
              id_prospecto,
              id_usuario_registro,
              tipo_entrevista,
              modalidad,
              fecha_entrevista,
              motivo,
              observaciones,
              resultado,
              enlace_videollamada,
              grabacion_url,
              transcripcion,
              estatus,
              creado_en
            )
            VALUES
            (
              ?,
              ?,
              ?,
              ?,
              ?,
              ?,
              ?,
              ?,
              ?,
              ?,
              ?,
              ?,
              NOW()
            )
          `,
          [
            idProspecto,

            req.user?.id_usuario ||
              null,

            tipo_entrevista
              ? String(
                  tipo_entrevista
                ).trim()
              : null,

            modalidadNormalizada,

            fecha_entrevista,

            motivo
              ? String(
                  motivo
                ).trim()
              : null,

            observaciones
              ? String(
                  observaciones
                ).trim()
              : null,

            resultadoNormalizado,

            modalidadNormalizada ===
            "videollamada"
              ? (
                  enlace_videollamada
                    ? String(
                        enlace_videollamada
                      ).trim()
                    : null
                )
              : null,

            modalidadNormalizada ===
            "videollamada"
              ? (
                  grabacion_url
                    ? String(
                        grabacion_url
                      ).trim()
                    : null
                )
              : null,

            modalidadNormalizada ===
            "videollamada"
              ? (
                  transcripcion
                    ? String(
                        transcripcion
                      )
                    : null
                )
              : null,

            estatusNormalizado,
          ]
        );


      // ==================================================
      // ACTUALIZAR ESTATUS DEL PROSPECTO
      // ==================================================

      let nuevoEstatus =
        null;


      if (
        estatusNormalizado ===
        "realizada"
      ) {

        nuevoEstatus =
          "en_proceso";

      }


      if (
        resultadoNormalizado ===
        "pruebas"
      ) {

        nuevoEstatus =
          "evaluacion";

      }


      if (
        resultadoNormalizado ===
        "aprobado"
      ) {

        nuevoEstatus =
          "aprobado";

      }


      if (
        resultadoNormalizado ===
        "no_continua"
      ) {

        nuevoEstatus =
          "no_contratado";

      }


      if (
        nuevoEstatus
      ) {

        await pool.query(
          `
            UPDATE prospectos
            SET estatus = ?
            WHERE id_prospecto = ?
          `,
          [
            nuevoEstatus,
            idProspecto,
          ]
        );

      }


      return res.status(201).json({
        success: true,

        message:
          "Entrevista registrada correctamente",

        id_entrevista:
          insert.insertId,

        nuevo_estatus:
          nuevoEstatus,
      });


    } catch (error) {

      console.error(
        "❌ Error al registrar entrevista:",
        error
      );


      return res.status(500).json({
        success: false,

        message:
          "Error interno al registrar la entrevista",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined,
      });

    }

  };


// ==================================================
// LISTAR ENTREVISTAS
// GET /api/prospectos/:id/entrevistas
// ==================================================

export const listarEntrevistasProspecto =
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


      const [entrevistas] =
        await pool.query(
          `
            SELECT
              ep.id_entrevista,
              ep.id_prospecto,
              ep.id_usuario_registro,
              ep.tipo_entrevista,
              ep.modalidad,
              ep.fecha_entrevista,
              ep.motivo,
              ep.observaciones,
              ep.resultado,
              ep.enlace_videollamada,
              ep.grabacion_url,
              ep.transcripcion,
              ep.estatus,
              ep.creado_en,
              ep.actualizado_en,

              u.nombre AS usuario_registro

            FROM entrevistas_prospectos ep

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 ep.id_usuario_registro

            WHERE ep.id_prospecto = ?

            ORDER BY
              ep.fecha_entrevista DESC,
              ep.id_entrevista DESC
          `,
          [
            idProspecto
          ]
        );


      return res.json({
        success: true,

        prospecto:
          acceso.prospecto,

        entrevistas,
      });


    } catch (error) {

      console.error(
        "❌ Error al obtener entrevistas:",
        error
      );


      return res.status(500).json({
        success: false,

        message:
          "Error interno al obtener las entrevistas",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined,
      });

    }

  };


// ==================================================
// ACTUALIZAR ENTREVISTA
// PUT /api/prospectos/:id/entrevistas/:idEntrevista
// ==================================================

export const actualizarEntrevistaProspecto =
  async (
    req,
    res
  ) => {

    try {

      const idProspecto =
        Number(
          req.params.id
        );

      const idEntrevista =
        Number(
          req.params.idEntrevista
        );


      if (
        !Number.isInteger(
          idProspecto
        ) ||
        idProspecto <= 0 ||
        !Number.isInteger(
          idEntrevista
        ) ||
        idEntrevista <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Identificador inválido",
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


      const [existente] =
        await pool.query(
          `
            SELECT *
            FROM entrevistas_prospectos
            WHERE id_entrevista = ?
              AND id_prospecto = ?
            LIMIT 1
          `,
          [
            idEntrevista,
            idProspecto,
          ]
        );


      if (
        existente.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Entrevista no encontrada",
        });

      }


      const actual =
        existente[0];


      const {
        tipo_entrevista,
        modalidad,
        fecha_entrevista,
        motivo,
        observaciones,
        resultado,
        enlace_videollamada,
        grabacion_url,
        transcripcion,
        estatus,
      } = req.body;


      const modalidadFinal =
        String(
          modalidad ??
          actual.modalidad
        )
          .trim()
          .toLowerCase();


      if (
        ![
          "presencial",
          "videollamada",
        ].includes(
          modalidadFinal
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Modalidad de entrevista inválida",
        });

      }


      const resultadoFinal =
        String(
          resultado ??
          actual.resultado
        )
          .trim()
          .toLowerCase();


      if (
        ![
          "pendiente",
          "continua",
          "segunda_entrevista",
          "pruebas",
          "aprobado",
          "no_continua",
        ].includes(
          resultadoFinal
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Resultado de entrevista inválido",
        });

      }


      const estatusFinal =
        String(
          estatus ??
          actual.estatus
        )
          .trim()
          .toLowerCase();


      if (
        ![
          "programada",
          "realizada",
          "cancelada",
        ].includes(
          estatusFinal
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Estatus de entrevista inválido",
        });

      }


      await pool.query(
        `
          UPDATE entrevistas_prospectos
          SET
            tipo_entrevista = ?,
            modalidad = ?,
            fecha_entrevista = ?,
            motivo = ?,
            observaciones = ?,
            resultado = ?,
            enlace_videollamada = ?,
            grabacion_url = ?,
            transcripcion = ?,
            estatus = ?
          WHERE id_entrevista = ?
            AND id_prospecto = ?
        `,
        [
          tipo_entrevista !==
          undefined
            ? (
                tipo_entrevista
                  ? String(
                      tipo_entrevista
                    ).trim()
                  : null
              )
            : actual.tipo_entrevista,

          modalidadFinal,

          fecha_entrevista ||
            actual.fecha_entrevista,

          motivo !==
          undefined
            ? (
                motivo
                  ? String(
                      motivo
                    ).trim()
                  : null
              )
            : actual.motivo,

          observaciones !==
          undefined
            ? (
                observaciones
                  ? String(
                      observaciones
                    ).trim()
                  : null
              )
            : actual.observaciones,

          resultadoFinal,

          modalidadFinal ===
          "videollamada"
            ? (
                enlace_videollamada !==
                undefined
                  ? (
                      enlace_videollamada
                        ? String(
                            enlace_videollamada
                          ).trim()
                        : null
                    )
                  : actual.enlace_videollamada
              )
            : null,

          modalidadFinal ===
          "videollamada"
            ? (
                grabacion_url !==
                undefined
                  ? (
                      grabacion_url
                        ? String(
                            grabacion_url
                          ).trim()
                        : null
                    )
                  : actual.grabacion_url
              )
            : null,

          modalidadFinal ===
          "videollamada"
            ? (
                transcripcion !==
                undefined
                  ? (
                      transcripcion
                        ? String(
                            transcripcion
                          )
                        : null
                    )
                  : actual.transcripcion
              )
            : null,

          estatusFinal,

          idEntrevista,
          idProspecto,
        ]
      );


      // ==================================================
      // ACTUALIZAR ESTATUS DEL PROSPECTO
      // ==================================================

      let nuevoEstatus =
        null;


      if (
        estatusFinal ===
        "realizada"
      ) {

        nuevoEstatus =
          "en_proceso";

      }


      if (
        resultadoFinal ===
        "pruebas"
      ) {

        nuevoEstatus =
          "evaluacion";

      }


      if (
        resultadoFinal ===
        "aprobado"
      ) {

        nuevoEstatus =
          "aprobado";

      }


      if (
        resultadoFinal ===
        "no_continua"
      ) {

        nuevoEstatus =
          "no_contratado";

      }


      if (
        nuevoEstatus
      ) {

        await pool.query(
          `
            UPDATE prospectos
            SET estatus = ?
            WHERE id_prospecto = ?
          `,
          [
            nuevoEstatus,
            idProspecto,
          ]
        );

      }


      return res.json({
        success: true,

        message:
          "Entrevista actualizada correctamente",

        nuevo_estatus:
          nuevoEstatus,
      });


    } catch (error) {

      console.error(
        "❌ Error al actualizar entrevista:",
        error
      );


      return res.status(500).json({
        success: false,

        message:
          "Error interno al actualizar la entrevista",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined,
      });

    }

  };


// ==================================================
// CREAR / REUTILIZAR VIDEOLLAMADA RH
// POST /api/prospectos/:id/entrevistas/:idEntrevista/videollamada
//
// IMPORTANTE:
// Esta sala pertenece al proceso RH.
// No crea sesiones clínicas ni usa id_paciente.
// ==================================================

export const crearVideollamadaEntrevistaProspecto =
  async (
    req,
    res
  ) => {

    try {

      const idProspecto =
        Number(
          req.params.id
        );

      const idEntrevista =
        Number(
          req.params.idEntrevista
        );


      if (
        !Number.isInteger(
          idProspecto
        ) ||
        idProspecto <= 0 ||
        !Number.isInteger(
          idEntrevista
        ) ||
        idEntrevista <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Identificador inválido",
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


      const [entrevistas] =
        await pool.query(
          `
            SELECT
              id_entrevista,
              id_prospecto,
              modalidad,
              enlace_videollamada,
              estatus
            FROM entrevistas_prospectos
            WHERE id_entrevista = ?
              AND id_prospecto = ?
            LIMIT 1
          `,
          [
            idEntrevista,
            idProspecto,
          ]
        );


      if (
        entrevistas.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Entrevista no encontrada",
        });

      }


      const entrevista =
        entrevistas[0];


      if (
        String(
          entrevista.modalidad || ""
        )
          .trim()
          .toLowerCase() !==
        "videollamada"
      ) {

        return res.status(400).json({
          success: false,
          message:
            "La entrevista no está configurada como videollamada",
        });

      }


      // ==================================================
      // REUTILIZAR SALA EXISTENTE
      // ==================================================

      if (
        entrevista.enlace_videollamada &&
        String(
          entrevista.enlace_videollamada
        ).includes(
          "/SalaVideollamadaRH/"
        )
      ) {

        const enlaceExistente =
          String(
            entrevista.enlace_videollamada
          ).trim();

        const salaExistente =
          enlaceExistente
            .split(
              "/SalaVideollamadaRH/"
            )[1] ||
          null;


        return res.json({
          success: true,
          message:
            "Videollamada RH existente",

          reutilizada:
            true,

          sala:
            salaExistente,

          enlace_videollamada:
            enlaceExistente,

          ruta:
            salaExistente
              ? `/SalaVideollamadaRH/${salaExistente}`
              : null,
        });

      }


      // ==================================================
      // GENERAR SALA RH
      // ==================================================

      const sala =
        `rh-${idProspecto}-${idEntrevista}-${Date.now()}`;


      const ruta =
        `/SalaVideollamadaRH/${sala}`;


      // ==================================================
      // URL DEL FRONTEND
      // ==================================================

      const originRequest =
        String(
          req.get("origin") ||
          ""
        )
          .trim()
          .replace(
            /\/+$/,
            ""
          );


      const frontendBase =
        originRequest ||
        String(
          process.env.FRONTEND_URL ||
          "http://localhost:5175"
        )
          .trim()
          .replace(
            /\/+$/,
            ""
          );


      const enlaceVideollamada =
        `${frontendBase}${ruta}`;


      // ==================================================
      // GUARDAR SALA EN LA ENTREVISTA
      // ==================================================

      await pool.query(
        `
          UPDATE entrevistas_prospectos
          SET
            enlace_videollamada = ?,
            actualizado_en = NOW()
          WHERE id_entrevista = ?
            AND id_prospecto = ?
        `,
        [
          enlaceVideollamada,
          idEntrevista,
          idProspecto,
        ]
      );


      // ==================================================
      // RESPUESTA
      // ==================================================

      return res.status(201).json({
        success: true,

        message:
          "Videollamada RH creada correctamente",

        reutilizada:
          false,

        sala,

        ruta,

        enlace_videollamada:
          enlaceVideollamada,

        id_prospecto:
          idProspecto,

        id_entrevista:
          idEntrevista,
      });


    } catch (error) {

      console.error(
        "❌ Error al crear videollamada RH:",
        error
      );


      return res.status(500).json({
        success: false,

        message:
          "Error interno al crear la videollamada RH",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined,
      });

    }

  };
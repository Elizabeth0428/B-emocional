import pool from "../config/database.js";

import fs from "fs/promises";

import path from "path";


// ==================================================
// AUXILIAR: VALIDAR ACCESO AL PROSPECTO
// ==================================================

const validarAccesoProspecto = async (
  idProspecto,
  user,
  connection = pool
) => {

  const idUsuario =
    Number(user?.id_usuario) || null;

  if (!idUsuario) {
    return {
      ok: false,
      status: 401,
      message:
        "No se pudo identificar al usuario",
    };
  }

  // ==================================================
  // CONTEXTO REAL DEL USUARIO RH
  //
  // Permite:
  // - Master
  // - Admin RH
  // - Usuario RH
  // - Independiente con perfil RH
  // ==================================================

  const [usuarios] =
    await connection.query(
      `
        SELECT
          u.id_usuario,
          u.tipo_admin,
          u.area,
          u.rol,
          u.id_admin_padre,
          u.id_organizacion,
          o.tipo AS tipo_organizacion,
          o.perfil_independiente,
          o.estado AS estado_organizacion
        FROM usuarios u
        LEFT JOIN organizaciones o
          ON o.id_organizacion =
             u.id_organizacion
        WHERE u.id_usuario = ?
        LIMIT 1
      `,
      [idUsuario]
    );

  if (!usuarios.length) {
    return {
      ok: false,
      status: 401,
      message:
        "No se pudo identificar al usuario",
    };
  }

  const usuario =
    usuarios[0];

  const tipoAdmin =
    String(
      usuario.tipo_admin || ""
    )
      .trim()
      .toLowerCase();

  const area =
    String(
      usuario.area || ""
    )
      .trim()
      .toLowerCase();

  const rol =
    String(
      usuario.rol || ""
    )
      .trim()
      .toLowerCase();

  const perfilIndependiente =
    String(
      usuario.perfil_independiente || ""
    )
      .trim()
      .toLowerCase();

  const estadoOrganizacion =
    String(
      usuario.estado_organizacion || ""
    )
      .trim()
      .toLowerCase();

  const esMaster =
    tipoAdmin === "master";

  const esAdminRH =
    tipoAdmin === "normal" &&
    area === "rh";

  const esUsuarioRH =
    rol === "rh" &&
    area === "rh";

  const esIndependienteRH =
    rol === "independiente" &&
    area === "independiente" &&
    perfilIndependiente === "rh" &&
    estadoOrganizacion === "activa";

  const tienePermiso =
    esMaster ||
    esAdminRH ||
    esUsuarioRH ||
    esIndependienteRH;

  if (!tienePermiso) {
    return {
      ok: false,
      status: 403,
      message:
        "No tienes permiso para tomar decisiones sobre prospectos",
    };
  }

  let query = `
    SELECT
      *
    FROM prospectos
    WHERE id_prospecto = ?
  `;

  const params = [
    idProspecto
  ];

  // Todo usuario RH no-master,
  // incluido Independiente RH,
  // solo puede acceder a sus propios prospectos.
  if (!esMaster) {
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
    await connection.query(
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
    contexto: {
      idUsuario,
      tipoAdmin,
      area,
      rol,
      idOrganizacion:
        Number(
          usuario.id_organizacion
        ) || null,
      perfilIndependiente,
      esMaster,
      esAdminRH,
      esUsuarioRH,
      esIndependienteRH,
    },
  };
};


// ==================================================
// AUXILIAR: CREAR RESUMEN DE PRUEBAS
// ==================================================

const crearResumenPruebasProspecto = async (
  idProspecto,
  connection
) => {

  const [resultados] =
    await connection.query(
      `
        SELECT
          r.id_resultado,
          r.id_prueba_rh,
          p.nombre AS prueba,
          r.puntaje_total,
          r.resultado_texto,
          r.interpretacion,
          r.interpretacion_laboral,
          r.fortalezas,
          r.areas_atencion,
          r.compatibilidad_puesto,
          r.recomendaciones,
          r.fecha_resultado

        FROM resultados_prueba_prospecto r

        LEFT JOIN pruebas_rh p
          ON p.id_prueba_rh =
             r.id_prueba_rh

        WHERE r.id_prospecto = ?

        ORDER BY
          r.fecha_resultado ASC,
          r.id_resultado ASC
      `,
      [
        idProspecto
      ]
    );

  if (!resultados.length) {
    return JSON.stringify([]);
  }

  return JSON.stringify(
    resultados.map(
      item => ({
        prueba:
          item.prueba ||
          `Prueba #${item.id_prueba_rh}`,

        puntaje_total:
          item.puntaje_total,

        resultado:
          item.resultado_texto,

        interpretacion:
          item.interpretacion,

        interpretacion_laboral:
          item.interpretacion_laboral,

        fortalezas:
          item.fortalezas,

        areas_atencion:
          item.areas_atencion,

        compatibilidad_puesto:
          item.compatibilidad_puesto,

        recomendaciones:
          item.recomendaciones,

        fecha_resultado:
          item.fecha_resultado,
      })
    )
  );
};


// ==================================================
// AUXILIAR: COPIAR DOCUMENTOS AL EMPLEADO
// ==================================================

const copiarDocumentosAEmpleado = async (
  idProspecto,
  idEmpleado,
  connection
) => {

  await connection.query(
    `
      INSERT INTO documentos_empleados
      (
        id_empleado,
        tipo_documento,
        nombre_original,
        nombre_archivo,
        ruta_archivo,
        mime_type,
        descripcion,
        fecha_subida
      )

      SELECT
        ?,
        tipo_documento,
        nombre_original,
        nombre_archivo,
        ruta_archivo,
        mime_type,
        descripcion,
        fecha_subida

      FROM documentos_prospectos

      WHERE id_prospecto = ?
    `,
    [
      idEmpleado,
      idProspecto
    ]
  );
};


// ==================================================
// AUXILIAR: OBTENER ARCHIVOS FÍSICOS A ELIMINAR
//
// CONTRATADO:
// - eliminamos grabaciones de entrevistas.
// - NO eliminamos físicamente documentos porque ahora
//   documentos_empleados utiliza esos mismos archivos.
//
// NO CONTRATADO:
// - eliminamos grabaciones y documentos físicos.
// ==================================================

const obtenerArchivosParaEliminar = async (
  idProspecto,
  connection,
  incluirDocumentos = false
) => {

  const rutas = [];

  const [grabaciones] =
    await connection.query(
      `
        SELECT ruta_video
        FROM videos_entrevista_rh
        WHERE id_prospecto = ?
      `,
      [
        idProspecto
      ]
    );

  for (
    const archivo of
    grabaciones
  ) {
    if (
      archivo?.ruta_video
    ) {
      rutas.push(
        archivo.ruta_video
      );
    }
  }

  if (
    incluirDocumentos
  ) {

    const [documentos] =
      await connection.query(
        `
          SELECT ruta_archivo
          FROM documentos_prospectos
          WHERE id_prospecto = ?
        `,
        [
          idProspecto
        ]
      );

    for (
      const documento of
      documentos
    ) {
      if (
        documento?.ruta_archivo
      ) {
        rutas.push(
          documento.ruta_archivo
        );
      }
    }
  }

  return [
    ...new Set(rutas)
  ];
};


// ==================================================
// AUXILIAR: ELIMINAR ARCHIVOS FÍSICOS
//
// Se ejecuta DESPUÉS del COMMIT.
// Si un archivo ya no existe, no rompe el proceso.
// ==================================================

const eliminarArchivosFisicos = async (
  rutas = []
) => {

  for (
    const rutaOriginal of
    rutas
  ) {

    try {

      const ruta =
        String(
          rutaOriginal || ""
        ).trim();

      if (
        !ruta ||
        /^https?:\/\//i.test(
          ruta
        )
      ) {
        continue;
      }

      const rutaRelativa =
        ruta
          .replace(
            /^[\/\\]+/,
            ""
          )
          .replace(
            /\\/g,
            "/"
          );

      const rutaAbsoluta =
        path.resolve(
          process.cwd(),
          rutaRelativa
        );

      await fs.unlink(
        rutaAbsoluta
      );

      console.log(
        "🗑️ Archivo eliminado:",
        rutaAbsoluta
      );

    } catch (error) {

      if (
        error?.code !==
        "ENOENT"
      ) {

        console.warn(
          "⚠️ No se pudo eliminar archivo físico:",
          rutaOriginal,
          error.message
        );
      }
    }
  }
};


// ==================================================
// AUXILIAR: LIMPIAR PRUEBAS DEL PROSPECTO
//
// IMPORTANTE:
// El resumen de resultados debe haberse guardado
// ANTES de ejecutar esta función.
//
// Se eliminan únicamente aplicaciones, respuestas
// y resultados del prospecto.
//
// NO se eliminan catálogos, preguntas, reactivos,
// baremos ni configuraciones de las pruebas.
// ==================================================

const limpiarPruebasProspecto = async (
  idProspecto,
  connection
) => {

  // ==================================================
  // RAVEN
  // ==================================================

  await connection.query(
    `
      DELETE FROM resultados_raven
      WHERE id_prospecto = ?
    `,
    [
      idProspecto
    ]
  );

  await connection.query(
    `
      DELETE FROM respuestas_raven
      WHERE id_prospecto = ?
    `,
    [
      idProspecto
    ]
  );

  // ==================================================
  // BETA III
  // ==================================================

  await connection.query(
    `
      DELETE FROM resultados_beta3
      WHERE id_prospecto = ?
    `,
    [
      idProspecto
    ]
  );

  await connection.query(
    `
      DELETE FROM respuestas_beta3
      WHERE id_prospecto = ?
    `,
    [
      idProspecto
    ]
  );

  // ==================================================
  // RESULTADOS GENERALES
  //
  // Aquí están también los resultados resumidos
  // de IPIP-50, ORVIS, Raven y Beta III.
  //
  // Ya fueron copiados previamente a resumen_pruebas.
  // ==================================================

  await connection.query(
    `
      DELETE FROM resultados_prueba_prospecto
      WHERE id_prospecto = ?
    `,
    [
      idProspecto
    ]
  );

  // ==================================================
  // RESPUESTAS GENERALES
  //
  // IPIP-50
  // ORVIS
  // pruebas RH genéricas
  // ==================================================

  await connection.query(
    `
      DELETE FROM respuestas_prueba_prospecto
      WHERE id_prospecto = ?
    `,
    [
      idProspecto
    ]
  );

  // ==================================================
  // HABILITACIONES / TOKENS PÚBLICOS
  //
  // Se hace al final porque las respuestas y
  // resultados dependen de id_habilitacion.
  // ==================================================

  await connection.query(
    `
      DELETE FROM pruebas_prospectos_habilitadas
      WHERE id_prospecto = ?
    `,
    [
      idProspecto
    ]
  );

  console.log(
    `🧹 Pruebas del prospecto ${idProspecto} limpiadas correctamente`
  );
};


// ==================================================
// AUXILIAR: LIMPIAR INFORMACIÓN TEMPORAL
//
// Esta función se ejecuta SOLAMENTE después de que:
//
// 1. Se creó el resumen de pruebas.
// 2. Se creó el resumen de selección o cierre.
// 3. Se transfirieron documentos si fue contratado.
//
// Todo ocurre dentro de la misma transacción.
// ==================================================

const limpiarProcesoProspecto = async (
  idProspecto,
  connection
) => {

  // ==================================================
  // MULTIMEDIA DE ENTREVISTAS
  // ==================================================

  await connection.query(
    `
      DELETE FROM videos_entrevista_rh
      WHERE id_prospecto = ?
    `,
    [
      idProspecto
    ]
  );

  // ==================================================
  // ENTREVISTAS
  //
  // Al eliminar la entrevista se elimina también
  // la información/transcripción asociada a ella.
  // ==================================================

  await connection.query(
    `
      DELETE FROM entrevistas_prospectos
      WHERE id_prospecto = ?
    `,
    [
      idProspecto
    ]
  );

  // ==================================================
  // SEGUIMIENTO DE SELECCIÓN
  // ==================================================

  await connection.query(
    `
      DELETE FROM seguimiento_prospectos
      WHERE id_prospecto = ?
    `,
    [
      idProspecto
    ]
  );

  // ==================================================
  // OBSERVACIONES INTERNAS RH
  // ==================================================

  await connection.query(
    `
      DELETE FROM observaciones_prospectos
      WHERE id_prospecto = ?
    `,
    [
      idProspecto
    ]
  );

  // ==================================================
  // REPORTES COMPLETOS DE IA
  // ==================================================

  await connection.query(
    `
      DELETE FROM reportes_ia_prospectos
      WHERE id_prospecto = ?
    `,
    [
      idProspecto
    ]
  );

  // ==================================================
  // DOCUMENTOS DEL PROCESO
  //
  // CONTRATADO:
  // ya fueron registrados en documentos_empleados.
  //
  // NO CONTRATADO:
  // los archivos físicos se eliminarán después
  // del COMMIT.
  // ==================================================

  await connection.query(
    `
      DELETE FROM documentos_prospectos
      WHERE id_prospecto = ?
    `,
    [
      idProspecto
    ]
  );

  // ==================================================
  // PRUEBAS PSICOMÉTRICAS
  //
  // Se dejan para el final porque primero necesitábamos
  // crear resumen_pruebas.
  // ==================================================

  await limpiarPruebasProspecto(
    idProspecto,
    connection
  );

  console.log(
    `✅ Proceso temporal del prospecto ${idProspecto} limpiado`
  );
};


// ==================================================
// REGISTRAR DECISIÓN DEL PROSPECTO
//
// POST
// /api/prospectos/:id/decision
//
// BODY:
// {
//   decision: "contratar" | "no_contratar",
//   motivo: "...",
//   observaciones: "...",
//   departamento: "...",
//   fecha_contratacion: "2026-09-16"
// }
// ==================================================

export const registrarDecisionProspecto =
  async (
    req,
    res
  ) => {

    let connection;

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

      const decision =
        String(
          req.body?.decision || ""
        )
          .trim()
          .toLowerCase();

      const decisionesPermitidas = [
        "contratar",
        "no_contratar"
      ];

      if (
        !decisionesPermitidas.includes(
          decision
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "La decisión seleccionada es inválida",
        });
      }

      const motivo =
        req.body?.motivo
          ? String(
              req.body.motivo
            ).trim()
          : null;

      const observaciones =
        req.body?.observaciones
          ? String(
              req.body.observaciones
            ).trim()
          : null;

      const departamento =
        req.body?.departamento
          ? String(
              req.body.departamento
            ).trim()
          : null;

      const fechaContratacion =
        req.body?.fecha_contratacion ||
        null;

      connection =
        await pool.getConnection();

      await connection.beginTransaction();

      // ==================================================
      // VALIDAR ACCESO
      // ==================================================

      const acceso =
        await validarAccesoProspecto(
          idProspecto,
          req.user,
          connection
        );

      if (!acceso.ok) {

        await connection.rollback();

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

      const prospecto =
        acceso.prospecto;

      // ==================================================
      // VALIDAR SI YA EXISTE UNA DECISIÓN FINAL
      // ==================================================

      const [decisionesPrevias] =
        await connection.query(
          `
            SELECT
              id_decision,
              decision,
              id_empleado,
              fecha_decision
            FROM decisiones_prospectos
            WHERE id_prospecto = ?
            ORDER BY id_decision DESC
            LIMIT 1
          `,
          [
            idProspecto
          ]
        );

      if (
        decisionesPrevias.length &&
        (
          prospecto.estatus ===
            "contratado" ||
          prospecto.estatus ===
            "no_contratado"
        )
      ) {

        await connection.rollback();

        return res.status(409).json({
          success: false,

          message:
            prospecto.estatus ===
            "contratado"
              ? "Este prospecto ya fue convertido en empleado"
              : "Este prospecto ya tiene una decisión de no contratación",

          decision:
            decisionesPrevias[0],
        });
      }

      // ==================================================
      // DECISIÓN: NO CONTRATAR
      // ==================================================

      if (
        decision ===
        "no_contratar"
      ) {

        const archivosParaEliminar =
          await obtenerArchivosParaEliminar(
            idProspecto,
            connection,
            true
          );

        const resumenPruebas =
          await crearResumenPruebasProspecto(
            idProspecto,
            connection
          );

        await connection.query(
          `
            INSERT INTO resumen_prospectos_cerrados
            (
              id_prospecto,
              id_admin_padre,
              id_mirror,
              nombre,
              puesto,
              decision,
              motivo,
              resumen_pruebas,
              observacion_final,
              fecha_decision
            )
            VALUES
            (
              ?,
              ?,
              ?,
              ?,
              ?,
              'no_contratar',
              ?,
              ?,
              ?,
              NOW()
            )

            ON DUPLICATE KEY UPDATE
              motivo =
                VALUES(motivo),

              resumen_pruebas =
                VALUES(resumen_pruebas),

              observacion_final =
                VALUES(observacion_final),

              fecha_decision =
                VALUES(fecha_decision)
          `,
          [
            idProspecto,
            prospecto.id_admin_padre,
            prospecto.id_mirror,
            prospecto.nombre,
            prospecto.puesto,
            motivo,
            resumenPruebas,
            observaciones,
          ]
        );

        const [insertDecision] =
          await connection.query(
            `
              INSERT INTO decisiones_prospectos
              (
                id_prospecto,
                id_usuario_registro,
                id_empleado,
                decision,
                motivo,
                observaciones,
                fecha_decision
              )
              VALUES
              (
                ?,
                ?,
                NULL,
                'no_contratar',
                ?,
                ?,
                NOW()
              )
            `,
            [
              idProspecto,

              req.user?.id_usuario ||
                null,

              motivo,
              observaciones,
            ]
          );

        await connection.query(
          `
            UPDATE prospectos
            SET estatus = 'no_contratado'
            WHERE id_prospecto = ?
          `,
          [
            idProspecto
          ]
        );

        await limpiarProcesoProspecto(
          idProspecto,
          connection
        );

        await connection.commit();

        await eliminarArchivosFisicos(
          archivosParaEliminar
        );

        return res.status(201).json({
          success: true,

          message:
            "Decisión registrada. Se guardó el resumen y el proceso fue cerrado.",

          decision: {
            id_decision:
              insertDecision.insertId,

            id_prospecto:
              idProspecto,

            decision:
              "no_contratar",

            motivo,

            observaciones,
          },

          empleado:
            null,
        });
      }

      // ==================================================
      // DECISIÓN: CONTRATAR
      // ==================================================

      if (
        !prospecto.id_mirror
      ) {

        await connection.rollback();

        return res.status(400).json({
          success: false,
          message:
            "El prospecto no tiene ID MirrorSoul y no puede convertirse en empleado",
        });
      }

      const [empleadosExistentes] =
        await connection.query(
          `
            SELECT
              id_empleado,
              id_prospecto,
              id_mirror,
              nombre,
              estatus
            FROM empleados
            WHERE id_prospecto = ?
               OR id_mirror = ?
            LIMIT 1
          `,
          [
            idProspecto,
            prospecto.id_mirror,
          ]
        );

      if (
        empleadosExistentes.length
      ) {

        await connection.rollback();

        return res.status(409).json({
          success: false,
          message:
            "Este prospecto ya existe como empleado",
          empleado:
            empleadosExistentes[0],
        });
      }

      // ==================================================
      // RESPONSABLE INICIAL
      // ==================================================

      const esUsuarioRHNormal =
        acceso.contexto.esUsuarioRH;

      const esIndependienteRH =
        acceso.contexto.esIndependienteRH;

      const idResponsableInicial =
        esUsuarioRHNormal ||
        esIndependienteRH
          ? Number(
              req.user?.id_usuario
            ) || null
          : null;

      const [insertEmpleado] =
        await connection.query(
          `
            INSERT INTO empleados
            (
              id_prospecto,
              id_admin_padre,
              id_usuario_responsable,
              id_mirror,
              nombre,
              edad,
              sexo,
              correo,
              telefono,
              direccion,
              puesto,
              departamento,
              fecha_contratacion,
              estatus
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
              COALESCE(?, CURDATE()),
              'activo'
            )
          `,
          [
            idProspecto,
            prospecto.id_admin_padre,
            idResponsableInicial,
            prospecto.id_mirror,
            prospecto.nombre,
            prospecto.edad,
            prospecto.sexo,
            prospecto.correo,
            prospecto.telefono,
            prospecto.direccion,
            prospecto.puesto,
            departamento,
            fechaContratacion,
          ]
        );

      const idEmpleado =
        insertEmpleado.insertId;

      const archivosParaEliminar =
        await obtenerArchivosParaEliminar(
          idProspecto,
          connection,
          false
        );

      const resumenPruebas =
        await crearResumenPruebasProspecto(
          idProspecto,
          connection
        );

      await copiarDocumentosAEmpleado(
        idProspecto,
        idEmpleado,
        connection
      );

      await connection.query(
        `
          INSERT INTO resumen_seleccion_empleados
          (
            id_empleado,
            id_prospecto_origen,
            decision,
            motivo,
            observacion_final,
            resumen_pruebas,
            fecha_decision
          )
          VALUES
          (
            ?,
            ?,
            'contratar',
            ?,
            ?,
            ?,
            NOW()
          )

          ON DUPLICATE KEY UPDATE
            motivo =
              VALUES(motivo),

            observacion_final =
              VALUES(observacion_final),

            resumen_pruebas =
              VALUES(resumen_pruebas),

            fecha_decision =
              VALUES(fecha_decision)
        `,
        [
          idEmpleado,
          idProspecto,
          motivo,
          observaciones,
          resumenPruebas,
        ]
      );

      await connection.query(
        `
          UPDATE prospectos
          SET estatus = 'contratado'
          WHERE id_prospecto = ?
        `,
        [
          idProspecto
        ]
      );

      await connection.query(
        `
          UPDATE mirror_ids
          SET
            tipo_persona = 'empleado',
            id_referencia = ?
          WHERE id_mirror = ?
        `,
        [
          idEmpleado,
          prospecto.id_mirror,
        ]
      );

      const [insertDecision] =
        await connection.query(
          `
            INSERT INTO decisiones_prospectos
            (
              id_prospecto,
              id_usuario_registro,
              id_empleado,
              decision,
              motivo,
              observaciones,
              fecha_decision
            )
            VALUES
            (
              ?,
              ?,
              ?,
              'contratar',
              ?,
              ?,
              NOW()
            )
          `,
          [
            idProspecto,

            req.user?.id_usuario ||
              null,

            idEmpleado,
            motivo,
            observaciones,
          ]
        );

      await limpiarProcesoProspecto(
        idProspecto,
        connection
      );

      await connection.commit();

      await eliminarArchivosFisicos(
        archivosParaEliminar
      );

      const [empleados] =
        await pool.query(
          `
            SELECT
              id_empleado,
              id_prospecto,
              id_admin_padre,
              id_usuario_responsable,
              id_mirror,
              nombre,
              edad,
              sexo,
              correo,
              telefono,
              direccion,
              puesto,
              departamento,
              fecha_contratacion,
              estatus,
              fecha_registro
            FROM empleados
            WHERE id_empleado = ?
            LIMIT 1
          `,
          [
            idEmpleado
          ]
        );

      return res.status(201).json({
        success: true,

        message:
          "Prospecto convertido en empleado correctamente",

        decision: {
          id_decision:
            insertDecision.insertId,

          decision:
            "contratar",

          motivo,

          observaciones,
        },

        empleado:
          empleados[0] ||
          null,
      });

    } catch (error) {

      if (connection) {
        try {
          await connection.rollback();
        } catch {}
      }

      console.error(
        "❌ Error registrando decisión del prospecto:",
        error
      );

      return res.status(500).json({
        success: false,

        message:
          "Error interno al registrar la decisión",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined,
      });

    } finally {

      if (connection) {
        connection.release();
      }
    }
  };


// ==================================================
// OBTENER DECISIÓN DEL PROSPECTO
//
// GET
// /api/prospectos/:id/decision
// ==================================================

export const obtenerDecisionProspecto =
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

      const [decisiones] =
        await pool.query(
          `
            SELECT
              d.id_decision,
              d.id_prospecto,
              d.id_usuario_registro,
              d.id_empleado,
              d.decision,
              d.motivo,
              d.observaciones,
              d.fecha_decision,
              d.creado_en,

              u.nombre AS usuario_registro,

              e.id_mirror AS empleado_id_mirror,
              e.nombre AS empleado_nombre,
              e.puesto AS empleado_puesto,
              e.departamento,
              e.fecha_contratacion,
              e.estatus AS empleado_estatus

            FROM decisiones_prospectos d

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 d.id_usuario_registro

            LEFT JOIN empleados e
              ON e.id_empleado =
                 d.id_empleado

            WHERE d.id_prospecto = ?

            ORDER BY
              d.fecha_decision DESC,
              d.id_decision DESC
          `,
          [
            idProspecto
          ]
        );

      return res.json({
        success: true,

        prospecto:
          acceso.prospecto,

        decision:
          decisiones.length
            ? decisiones[0]
            : null,

        historial:
          decisiones,
      });

    } catch (error) {

      console.error(
        "❌ Error obteniendo decisión RH:",
        error
      );

      return res.status(500).json({
        success: false,

        message:
          "Error interno al obtener la decisión",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined,
      });
    }
  };


// ==================================================
// LISTAR EMPLEADOS RH
//
// GET /api/prospectos/empleados/lista
//
// Permite:
// - Master
// - Admin RH
// - Usuario RH
// - Independiente RH
// ==================================================

export const listarEmpleadosRH =
  async (
    req,
    res
  ) => {

    try {

      const idUsuario =
        Number(
          req.user?.id_usuario
        ) || null;

      if (!idUsuario) {

        return res.status(401).json({
          success: false,
          message:
            "No se pudo identificar al usuario",
        });
      }

      const [usuarios] =
        await pool.query(
          `
            SELECT
              u.id_usuario,
              u.tipo_admin,
              u.area,
              u.rol,
              u.id_admin_padre,
              u.id_organizacion,

              o.perfil_independiente,
              o.estado AS estado_organizacion

            FROM usuarios u

            LEFT JOIN organizaciones o
              ON o.id_organizacion =
                 u.id_organizacion

            WHERE u.id_usuario = ?

            LIMIT 1
          `,
          [
            idUsuario
          ]
        );

      if (!usuarios.length) {

        return res.status(401).json({
          success: false,
          message:
            "No se pudo identificar al usuario",
        });
      }

      const usuario =
        usuarios[0];

      const tipoAdmin =
        String(
          usuario.tipo_admin ||
          ""
        )
          .trim()
          .toLowerCase();

      const area =
        String(
          usuario.area ||
          ""
        )
          .trim()
          .toLowerCase();

      const rol =
        String(
          usuario.rol ||
          ""
        )
          .trim()
          .toLowerCase();

      const perfilIndependiente =
        String(
          usuario.perfil_independiente ||
          ""
        )
          .trim()
          .toLowerCase();

      const estadoOrganizacion =
        String(
          usuario.estado_organizacion ||
          ""
        )
          .trim()
          .toLowerCase();

      const esMaster =
        tipoAdmin ===
        "master";

      const esAdminRH =
        tipoAdmin ===
          "normal" &&
        area ===
          "rh";

      const esUsuarioRH =
        rol ===
          "rh" &&
        area ===
          "rh";

      const esIndependienteRH =
        rol ===
          "independiente" &&
        area ===
          "independiente" &&
        perfilIndependiente ===
          "rh" &&
        estadoOrganizacion ===
          "activa";

      if (
        !esMaster &&
        !esAdminRH &&
        !esUsuarioRH &&
        !esIndependienteRH
      ) {

        return res.status(403).json({
          success: false,
          message:
            "No tienes permiso para consultar empleados",
        });
      }

      let query = `
        SELECT
          e.id_empleado,
          e.id_prospecto,
          e.id_admin_padre,
          e.id_usuario_responsable,
          e.id_mirror,
          e.nombre,
          e.edad,
          e.sexo,
          e.correo,
          e.telefono,
          e.direccion,
          e.puesto,
          e.departamento,
          e.fecha_contratacion,
          e.estatus,
          e.fecha_registro,
          e.fecha_actualizacion

        FROM empleados e
      `;

      const params = [];

      if (!esMaster) {

        query += `
          WHERE e.id_admin_padre = ?
        `;

        params.push(
          idUsuario
        );
      }

      query += `
        ORDER BY
          e.fecha_registro DESC,
          e.id_empleado DESC
      `;

      const [empleados] =
        await pool.query(
          query,
          params
        );

      return res.json({
        success: true,
        empleados,
      });

    } catch (error) {

      console.error(
        "❌ Error listando empleados RH:",
        error
      );

      return res.status(500).json({
        success: false,

        message:
          "Error interno al obtener los empleados",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined,
      });
    }
  };
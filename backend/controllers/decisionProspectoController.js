import pool from "../config/database.js";


// ==================================================
// AUXILIAR: VALIDAR ACCESO AL PROSPECTO
// ==================================================

const validarAccesoProspecto = async (
  idProspecto,
  user,
  connection = pool
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
        "No tienes permiso para tomar decisiones sobre prospectos",
    };
  }


  let query = `
    SELECT
      id_prospecto,
      id_admin_padre,
      id_mirror,
      nombre,
      edad,
      sexo,
      correo,
      telefono,
      puesto,
      direccion,
      estatus
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
  };
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


        await connection.commit();


        return res.status(201).json({
          success: true,

          message:
            "Decisión registrada. El prospecto fue marcado como no contratado.",

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


      // ==================================================
      // VALIDAR ID MIRRORSOUL
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


      // ==================================================
      // VALIDAR SI YA EXISTE EMPLEADO
      // ==================================================

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
      // CREAR EMPLEADO
      //
      // NO CREAMOS OTRO ID MIRRORSOUL.
      // SE CONSERVA EL MISMO DEL PROSPECTO.
      // ==================================================

      const [insertEmpleado] =
        await connection.query(
          `
            INSERT INTO empleados
            (
              id_prospecto,
              id_admin_padre,
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
              COALESCE(?, CURDATE()),
              'activo'
            )
          `,
          [
            idProspecto,
            prospecto.id_admin_padre,
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


      // ==================================================
      // ACTUALIZAR PROSPECTO
      // ==================================================

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


      // ==================================================
      // ACTUALIZAR TIPO EN mirror_ids
      //
      // IMPORTANTE:
      // NO INSERTAMOS OTRO REGISTRO.
      // SE CONSERVA EL MISMO id_mirror.
      // ==================================================

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


      // ==================================================
      // GUARDAR DECISIÓN
      // ==================================================

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


      await connection.commit();


      // ==================================================
      // DEVOLVER EMPLEADO
      // ==================================================

      const [empleados] =
        await pool.query(
          `
            SELECT
              id_empleado,
              id_prospecto,
              id_admin_padre,
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
// Luego podemos mover esto a employees.js si
// hacemos un módulo independiente de empleados.
// ==================================================

export const listarEmpleadosRH =
  async (
    req,
    res
  ) => {

    try {

      const idUsuario =
        req.user?.id_usuario;

      const tipoAdmin =
        req.user?.tipo_admin
          ? String(
              req.user.tipo_admin
            )
              .trim()
              .toLowerCase()
          : null;

      const area =
        req.user?.area
          ? String(
              req.user.area
            )
              .trim()
              .toLowerCase()
          : null;


      if (!idUsuario) {
        return res.status(401).json({
          success: false,
          message:
            "No se pudo identificar al usuario",
        });
      }


      if (
        tipoAdmin !== "master" &&
        area !== "rh"
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


      if (
        tipoAdmin !== "master"
      ) {

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
      });
    }
  };
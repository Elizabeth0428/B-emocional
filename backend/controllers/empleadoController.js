import pool from "../config/database.js";


// ==================================================
// AUXILIAR: DATOS DEL USUARIO RH
// ==================================================

const obtenerUsuarioRH = user => {

  const idUsuario =
    user?.id_usuario || null;

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

  return {
    idUsuario,
    tipoAdmin,
    area
  };

};


// ==================================================
// AUXILIAR: VALIDAR PERMISO RH
// ==================================================

const validarPermisoRH = user => {

  const {
    idUsuario,
    tipoAdmin,
    area
  } = obtenerUsuarioRH(user);


  if (!idUsuario) {

    return {
      ok: false,
      status: 401,
      message:
        "No se pudo identificar al usuario"
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
        "No tienes permiso para acceder al módulo de empleados"
    };

  }


  return {
    ok: true,
    idUsuario,
    tipoAdmin,
    area
  };

};


// ==================================================
// LISTAR EMPLEADOS RH
//
// GET /api/empleados
// ==================================================

export const listarEmpleados =
  async (
    req,
    res
  ) => {

    try {

      const permiso =
        validarPermisoRH(
          req.user
        );


      if (!permiso.ok) {

        return res
          .status(
            permiso.status
          )
          .json({
            success: false,
            message:
              permiso.message
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
          e.fecha_actualizacion,

          p.estatus
            AS estatus_prospecto

        FROM empleados e

        LEFT JOIN prospectos p
          ON p.id_prospecto =
             e.id_prospecto
      `;


      const params = [];


      // MASTER VE TODOS
      // RH NORMAL VE SOLO LOS SUYOS

      if (
        permiso.tipoAdmin !==
        "master"
      ) {

        query += `
          WHERE e.id_admin_padre = ?
        `;

        params.push(
          permiso.idUsuario
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
        total:
          empleados.length,
        empleados
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
            : undefined
      });

    }

  };


// ==================================================
// OBTENER UN EMPLEADO
//
// GET /api/empleados/:id
// ==================================================

export const obtenerEmpleado =
  async (
    req,
    res
  ) => {

    try {

      const permiso =
        validarPermisoRH(
          req.user
        );


      if (!permiso.ok) {

        return res
          .status(
            permiso.status
          )
          .json({
            success: false,
            message:
              permiso.message
          });

      }


      const idEmpleado =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "ID de empleado inválido"
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
          e.fecha_actualizacion,

          p.estatus
            AS estatus_prospecto,

          p.fecha_registro
            AS fecha_registro_prospecto

        FROM empleados e

        LEFT JOIN prospectos p
          ON p.id_prospecto =
             e.id_prospecto

        WHERE e.id_empleado = ?
      `;


      const params = [
        idEmpleado
      ];


      if (
        permiso.tipoAdmin !==
        "master"
      ) {

        query += `
          AND e.id_admin_padre = ?
        `;

        params.push(
          permiso.idUsuario
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

        return res.status(404).json({
          success: false,
          message:
            "Empleado no encontrado o no tienes permiso para acceder a él"
        });

      }


      return res.json({
        success: true,
        empleado:
          rows[0]
      });


    } catch (error) {

      console.error(
        "❌ Error obteniendo empleado RH:",
        error
      );


      return res.status(500).json({
        success: false,
        message:
          "Error interno al obtener el empleado",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined
      });

    }

  };


// ==================================================
// ACTUALIZAR INFORMACIÓN LABORAL
//
// PUT /api/empleados/:id
//
// BODY:
// {
//   puesto,
//   departamento,
//   fecha_contratacion,
//   estatus
// }
// ==================================================

export const actualizarEmpleado =
  async (
    req,
    res
  ) => {

    try {

      const permiso =
        validarPermisoRH(
          req.user
        );


      if (!permiso.ok) {

        return res
          .status(
            permiso.status
          )
          .json({
            success: false,
            message:
              permiso.message
          });

      }


      const idEmpleado =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "ID de empleado inválido"
        });

      }


      // ==================================================
      // VERIFICAR QUE PUEDE ACCEDER
      // ==================================================

      let queryEmpleado = `
        SELECT
          id_empleado
        FROM empleados
        WHERE id_empleado = ?
      `;

      const paramsEmpleado = [
        idEmpleado
      ];


      if (
        permiso.tipoAdmin !==
        "master"
      ) {

        queryEmpleado += `
          AND id_admin_padre = ?
        `;

        paramsEmpleado.push(
          permiso.idUsuario
        );

      }


      queryEmpleado += `
        LIMIT 1
      `;


      const [existentes] =
        await pool.query(
          queryEmpleado,
          paramsEmpleado
        );


      if (!existentes.length) {

        return res.status(404).json({
          success: false,
          message:
            "Empleado no encontrado o no tienes permiso para modificarlo"
        });

      }


      // ==================================================
      // CAMPOS
      // ==================================================

      const puesto =
        req.body?.puesto !== undefined
          ? String(
              req.body.puesto || ""
            ).trim() || null
          : undefined;


      const departamento =
        req.body?.departamento !==
        undefined
          ? String(
              req.body.departamento || ""
            ).trim() || null
          : undefined;


      const fechaContratacion =
        req.body?.fecha_contratacion !==
        undefined
          ? req.body.fecha_contratacion ||
            null
          : undefined;


      const estatus =
        req.body?.estatus !== undefined
          ? String(
              req.body.estatus || ""
            )
              .trim()
              .toLowerCase()
          : undefined;


      if (
        estatus !== undefined &&
        ![
          "activo",
          "inactivo",
          "baja"
        ].includes(
          estatus
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "El estado laboral seleccionado es inválido"
        });

      }


      // ==================================================
      // ARMAR UPDATE DINÁMICO
      // ==================================================

      const campos = [];
      const valores = [];


      if (
        puesto !== undefined
      ) {

        campos.push(
          "puesto = ?"
        );

        valores.push(
          puesto
        );

      }


      if (
        departamento !== undefined
      ) {

        campos.push(
          "departamento = ?"
        );

        valores.push(
          departamento
        );

      }


      if (
        fechaContratacion !==
        undefined
      ) {

        campos.push(
          "fecha_contratacion = ?"
        );

        valores.push(
          fechaContratacion
        );

      }


      if (
        estatus !== undefined
      ) {

        campos.push(
          "estatus = ?"
        );

        valores.push(
          estatus
        );

      }


      if (!campos.length) {

        return res.status(400).json({
          success: false,
          message:
            "No se enviaron datos para actualizar"
        });

      }


      valores.push(
        idEmpleado
      );


      await pool.query(
        `
          UPDATE empleados

          SET
            ${campos.join(", ")}

          WHERE id_empleado = ?
        `,
        valores
      );


      // ==================================================
      // DEVOLVER ACTUALIZADO
      // ==================================================

      const [rows] =
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
              fecha_registro,
              fecha_actualizacion

            FROM empleados

            WHERE id_empleado = ?

            LIMIT 1
          `,
          [
            idEmpleado
          ]
        );


      return res.json({
        success: true,
        message:
          "Información laboral actualizada correctamente",
        empleado:
          rows[0] || null
      });


    } catch (error) {

      console.error(
        "❌ Error actualizando empleado RH:",
        error
      );


      return res.status(500).json({
        success: false,
        message:
          "Error interno al actualizar el empleado",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined
      });

    }

  };
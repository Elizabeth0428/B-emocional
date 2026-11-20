// ==================================================
// backend/controllers/empleadoController.js
// ==================================================

import pool from "../config/database.js";

// ==================================================
// AUXILIAR: NORMALIZAR
// ==================================================

const normalizar = valor =>
  valor
    ? String(valor)
        .trim()
        .toLowerCase()
    : "";

// ==================================================
// AUXILIAR: DATOS DEL USUARIO RH
//
// Se consulta la BD para no depender únicamente
// de los datos guardados dentro del JWT.
// ==================================================

const obtenerUsuarioRH = async (
  user,
  connection = pool
) => {

  const idUsuario =
    Number(
      user?.id_usuario
    ) || null;

  if (!idUsuario) {
    return {
      idUsuario: null,
      tipoAdmin: "",
      area: "",
      rol: "",
      idAdminPadre: null,
      idOrganizacion: null,
      perfilIndependiente: "",
      estadoOrganizacion: ""
    };
  }

  const [rows] =
    await connection.query(
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

        WHERE
          u.id_usuario = ?

        LIMIT 1
      `,
      [
        idUsuario
      ]
    );

  if (!rows.length) {
    return {
      idUsuario,

      tipoAdmin:
        normalizar(
          user?.tipo_admin
        ),

      area:
        normalizar(
          user?.area
        ),

      rol:
        normalizar(
          user?.rol
        ),

      idAdminPadre:
        Number(
          user?.id_admin_padre
        ) || null,

      idOrganizacion:
        Number(
          user?.id_organizacion
        ) || null,

      perfilIndependiente:
        normalizar(
          user?.perfil_independiente
        ),

      estadoOrganizacion:
        normalizar(
          user?.estado_organizacion
        )
    };
  }

  const usuario =
    rows[0];

  return {
    idUsuario:
      Number(
        usuario.id_usuario
      ) || null,

    tipoAdmin:
      normalizar(
        usuario.tipo_admin
      ),

    area:
      normalizar(
        usuario.area
      ),

    rol:
      normalizar(
        usuario.rol
      ),

    idAdminPadre:
      Number(
        usuario.id_admin_padre
      ) || null,

    idOrganizacion:
      Number(
        usuario.id_organizacion
      ) || null,

    perfilIndependiente:
      normalizar(
        usuario.perfil_independiente
      ),

    estadoOrganizacion:
      normalizar(
        usuario.estado_organizacion
      )
  };
};

// ==================================================
// AUXILIAR: VALIDAR PERMISO RH
// ==================================================

const validarPermisoRH = async (
  user,
  connection = pool
) => {

  const contexto =
    await obtenerUsuarioRH(
      user,
      connection
    );

  if (!contexto.idUsuario) {
    return {
      ok: false,
      status: 401,
      message:
        "No se pudo identificar al usuario"
    };
  }

  const esMaster =
    contexto.tipoAdmin ===
    "master";

  const esAdminRH =
    contexto.tipoAdmin ===
      "normal" &&
    contexto.area ===
      "rh";

  const esUsuarioRH =
    contexto.rol ===
      "rh" &&
    contexto.area ===
      "rh";

  const esIndependienteRH =
    contexto.rol ===
      "independiente" &&
    contexto.area ===
      "independiente" &&
    contexto.perfilIndependiente ===
      "rh" &&
    contexto.estadoOrganizacion ===
      "activa";

  if (
    !esMaster &&
    !esAdminRH &&
    !esUsuarioRH &&
    !esIndependienteRH
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

    idUsuario:
      contexto.idUsuario,

    tipoAdmin:
      contexto.tipoAdmin,

    area:
      contexto.area,

    rol:
      contexto.rol,

    idAdminPadre:
      contexto.idAdminPadre,

    idOrganizacion:
      contexto.idOrganizacion,

    perfilIndependiente:
      contexto.perfilIndependiente,

    estadoOrganizacion:
      contexto.estadoOrganizacion,

    esMaster,
    esAdminRH,
    esUsuarioRH,
    esIndependienteRH
  };
};

// ==================================================
// AUXILIAR:
// CREAR FILTRO DE VISIBILIDAD DE EMPLEADOS
// ==================================================

const obtenerFiltroEmpleados = (
  permiso,
  alias = "e"
) => {

  // MASTER VE TODO
  if (
    permiso.esMaster
  ) {
    return {
      sql: "",
      params: []
    };
  }

  // ADMIN RH
  if (
    permiso.esAdminRH
  ) {
    return {
      sql: `
        (
          ${alias}.id_admin_padre = ?

          OR

          (
            ${alias}.id_usuario_responsable IS NULL

            AND ${alias}.id_admin_padre IN
            (
              SELECT
                u.id_usuario

              FROM usuarios u

              WHERE
                u.id_admin_padre = ?

                AND u.rol = 'rh'

                AND LOWER(
                  TRIM(
                    COALESCE(
                      u.area,
                      ''
                    )
                  )
                ) = 'rh'
            )
          )
        )
      `,

      params: [
        permiso.idUsuario,
        permiso.idUsuario
      ]
    };
  }

  // USUARIO RH E INDEPENDIENTE RH
  return {
    sql: `
      (
        ${alias}.id_usuario_responsable = ?

        OR

        (
          ${alias}.id_usuario_responsable IS NULL

          AND ${alias}.id_admin_padre = ?
        )
      )
    `,

    params: [
      permiso.idUsuario,
      permiso.idUsuario
    ]
  };
};

// ==================================================
// AUXILIAR: NORMALIZAR RESUMEN DE PRUEBAS
// ==================================================

const normalizarResumenPruebas =
  valor => {

    if (!valor) {
      return [];
    }

    if (
      Array.isArray(
        valor
      )
    ) {
      return valor;
    }

    try {

      const parsed =
        JSON.parse(
          valor
        );

      return Array.isArray(
        parsed
      )
        ? parsed
        : [];

    } catch {

      return [];

    }
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
        await validarPermisoRH(
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
          e.id_usuario_responsable,
          e.id_mirror,
          e.nombre,
          e.edad,
          e.sexo,
          e.correo,
          e.telefono,
          e.direccion,
          e.estado_residencia,
          e.municipio_residencia,
          e.colonia_residencia,
          e.codigo_postal_residencia,
          e.puesto,
          e.departamento,
          e.sueldo,
          e.periodicidad_sueldo,
          e.modalidad_trabajo,
          e.horario_laboral,
          e.fecha_contratacion,
          e.estatus,
          e.perfil_laboral_completo,
          e.fecha_registro,
          e.fecha_actualizacion,

          ur.nombre
            AS responsable_actual

        FROM empleados e

        LEFT JOIN usuarios ur
          ON ur.id_usuario =
             e.id_usuario_responsable
      `;

      const filtro =
        obtenerFiltroEmpleados(
          permiso,
          "e"
        );

      const params = [
        ...filtro.params
      ];

      if (
        filtro.sql
      ) {

        query += `
          WHERE
            ${filtro.sql}
        `;
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

      return res
        .status(500)
        .json({
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
        await validarPermisoRH(
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

        return res
          .status(400)
          .json({
            success: false,

            message:
              "ID de empleado inválido"
          });
      }

      let queryEmpleado = `
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
          e.estado_residencia,
          e.municipio_residencia,
          e.colonia_residencia,
          e.codigo_postal_residencia,
          e.puesto,
          e.departamento,
          e.sueldo,
          e.periodicidad_sueldo,
          e.modalidad_trabajo,
          e.horario_laboral,
          e.fecha_contratacion,
          e.estatus,
          e.perfil_laboral_completo,
          e.fecha_registro,
          e.fecha_actualizacion,

          ur.nombre
            AS responsable_actual

        FROM empleados e

        LEFT JOIN usuarios ur
          ON ur.id_usuario =
             e.id_usuario_responsable

        WHERE
          e.id_empleado = ?
      `;

      const paramsEmpleado = [
        idEmpleado
      ];

      const filtro =
        obtenerFiltroEmpleados(
          permiso,
          "e"
        );

      if (
        filtro.sql
      ) {

        queryEmpleado += `
          AND
            ${filtro.sql}
        `;

        paramsEmpleado.push(
          ...filtro.params
        );
      }

      queryEmpleado += `
        LIMIT 1
      `;

      const [empleados] =
        await pool.query(
          queryEmpleado,
          paramsEmpleado
        );

      if (
        !empleados.length
      ) {

        return res
          .status(404)
          .json({
            success: false,

            message:
              "Empleado no encontrado o no tienes permiso para acceder a él"
          });
      }

      const empleado =
        empleados[0];

      const [resumenRows] =
        await pool.query(
          `
            SELECT
              id_resumen,
              id_empleado,
              id_prospecto_origen,
              decision,
              motivo,
              observacion_final,
              resumen_pruebas,
              fecha_decision,
              creado_en

            FROM
              resumen_seleccion_empleados

            WHERE
              id_empleado = ?

            ORDER BY
              id_resumen DESC

            LIMIT 1
          `,
          [
            idEmpleado
          ]
        );

      let resumenSeleccion =
        resumenRows[0] ||
        null;

      if (
        resumenSeleccion
      ) {

        resumenSeleccion = {
          ...resumenSeleccion,

          resumen_pruebas:
            normalizarResumenPruebas(
              resumenSeleccion
                .resumen_pruebas
            )
        };
      }

      const [documentos] =
        await pool.query(
          `
            SELECT
              id_documento,
              id_empleado,
              tipo_documento,
              nombre_original,
              nombre_archivo,
              ruta_archivo,
              mime_type,
              descripcion,
              fecha_subida

            FROM
              documentos_empleados

            WHERE
              id_empleado = ?

            ORDER BY
              fecha_subida DESC,
              id_documento DESC
          `,
          [
            idEmpleado
          ]
        );

      return res.json({
        success: true,

        empleado,

        resumen_seleccion:
          resumenSeleccion,

        documentos:
          documentos || [],

        totales: {

          documentos:
            documentos.length,

          evaluaciones_seleccion:
            resumenSeleccion
              ?.resumen_pruebas
              ?.length || 0
        }
      });

    } catch (error) {

      console.error(
        "❌ Error obteniendo empleado RH:",
        error
      );

      return res
        .status(500)
        .json({
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
// ==================================================

export const actualizarEmpleado =
  async (
    req,
    res
  ) => {

    try {

      const permiso =
        await validarPermisoRH(
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

        return res
          .status(400)
          .json({
            success: false,

            message:
              "ID de empleado inválido"
          });
      }

      let queryEmpleado = `
        SELECT
          e.id_empleado

        FROM empleados e

        WHERE
          e.id_empleado = ?
      `;

      const paramsEmpleado = [
        idEmpleado
      ];

      const filtro =
        obtenerFiltroEmpleados(
          permiso,
          "e"
        );

      if (
        filtro.sql
      ) {

        queryEmpleado += `
          AND
            ${filtro.sql}
        `;

        paramsEmpleado.push(
          ...filtro.params
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

      if (
        !existentes.length
      ) {

        return res
          .status(404)
          .json({
            success: false,

            message:
              "Empleado no encontrado o no tienes permiso para modificarlo"
          });
      }

      const puesto =
        req.body?.puesto !==
        undefined
          ? String(
              req.body.puesto ||
              ""
            )
              .trim() ||
            null
          : undefined;

      const departamento =
        req.body
          ?.departamento !==
        undefined
          ? String(
              req.body
                .departamento ||
              ""
            )
              .trim() ||
            null
          : undefined;

      const sueldo =
        req.body?.sueldo !==
        undefined
          ? (
              req.body.sueldo === "" ||
              req.body.sueldo === null
                ? null
                : Number(
                    req.body.sueldo
                  )
            )
          : undefined;

      if (
        sueldo !== undefined &&
        sueldo !== null &&
        (
          !Number.isFinite(
            sueldo
          ) ||
          sueldo < 0
        )
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "El sueldo debe ser un número válido mayor o igual a 0"
          });
      }

      const periodicidadSueldo =
        req.body
          ?.periodicidad_sueldo !==
        undefined
          ? String(
              req.body
                .periodicidad_sueldo ||
              ""
            )
              .trim()
              .toLowerCase() ||
            null
          : undefined;

      if (
        periodicidadSueldo !==
          undefined &&
        periodicidadSueldo !==
          null &&
        ![
          "semanal",
          "quincenal",
          "mensual"
        ].includes(
          periodicidadSueldo
        )
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "La periodicidad del sueldo es inválida"
          });
      }

      const modalidadTrabajo =
        req.body
          ?.modalidad_trabajo !==
        undefined
          ? String(
              req.body
                .modalidad_trabajo ||
              ""
            )
              .trim()
              .toLowerCase() ||
            null
          : undefined;

      if (
        modalidadTrabajo !==
          undefined &&
        modalidadTrabajo !==
          null &&
        ![
          "presencial",
          "hibrido",
          "remoto"
        ].includes(
          modalidadTrabajo
        )
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "La modalidad de trabajo es inválida"
          });
      }

      const horarioLaboral =
        req.body
          ?.horario_laboral !==
        undefined
          ? String(
              req.body
                .horario_laboral ||
              ""
            )
              .trim() ||
            null
          : undefined;

      const estadoResidencia =
        req.body
          ?.estado_residencia !==
        undefined
          ? String(
              req.body
                .estado_residencia ||
              ""
            )
              .trim() ||
            null
          : undefined;

      const municipioResidencia =
        req.body
          ?.municipio_residencia !==
        undefined
          ? String(
              req.body
                .municipio_residencia ||
              ""
            )
              .trim() ||
            null
          : undefined;

      const coloniaResidencia =
        req.body
          ?.colonia_residencia !==
        undefined
          ? String(
              req.body
                .colonia_residencia ||
              ""
            )
              .trim() ||
            null
          : undefined;

      const codigoPostalResidencia =
        req.body
          ?.codigo_postal_residencia !==
        undefined
          ? String(
              req.body
                .codigo_postal_residencia ||
              ""
            )
              .trim() ||
            null
          : undefined;

      if (
        codigoPostalResidencia &&
        !/^\d{5}$/.test(
          codigoPostalResidencia
        )
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "El código postal debe contener 5 dígitos"
          });
      }

      const fechaContratacion =
        req.body
          ?.fecha_contratacion !==
        undefined
          ? req.body
              .fecha_contratacion ||
            null
          : undefined;

      const estatus =
        req.body?.estatus !==
        undefined
          ? String(
              req.body.estatus ||
              ""
            )
              .trim()
              .toLowerCase()
          : undefined;

      if (
        estatus !==
          undefined &&
        ![
          "activo",
          "inactivo",
          "baja"
        ].includes(
          estatus
        )
      ) {

        return res
          .status(400)
          .json({
            success: false,

            message:
              "El estado laboral seleccionado es inválido"
          });
      }

      const campos = [];
      const valores = [];

      if (
        puesto !==
        undefined
      ) {

        campos.push(
          "puesto = ?"
        );

        valores.push(
          puesto
        );
      }

      if (
        departamento !==
        undefined
      ) {

        campos.push(
          "departamento = ?"
        );

        valores.push(
          departamento
        );
      }

      if (
        sueldo !==
        undefined
      ) {

        campos.push(
          "sueldo = ?"
        );

        valores.push(
          sueldo
        );
      }

      if (
        periodicidadSueldo !==
        undefined
      ) {

        campos.push(
          "periodicidad_sueldo = ?"
        );

        valores.push(
          periodicidadSueldo
        );
      }

      if (
        modalidadTrabajo !==
        undefined
      ) {

        campos.push(
          "modalidad_trabajo = ?"
        );

        valores.push(
          modalidadTrabajo
        );
      }

      if (
        horarioLaboral !==
        undefined
      ) {

        campos.push(
          "horario_laboral = ?"
        );

        valores.push(
          horarioLaboral
        );
      }

      if (
        estadoResidencia !==
        undefined
      ) {

        campos.push(
          "estado_residencia = ?"
        );

        valores.push(
          estadoResidencia
        );
      }

      if (
        municipioResidencia !==
        undefined
      ) {

        campos.push(
          "municipio_residencia = ?"
        );

        valores.push(
          municipioResidencia
        );
      }

      if (
        coloniaResidencia !==
        undefined
      ) {

        campos.push(
          "colonia_residencia = ?"
        );

        valores.push(
          coloniaResidencia
        );
      }

      if (
        codigoPostalResidencia !==
        undefined
      ) {

        campos.push(
          "codigo_postal_residencia = ?"
        );

        valores.push(
          codigoPostalResidencia
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
        estatus !==
        undefined
      ) {

        campos.push(
          "estatus = ?"
        );

        valores.push(
          estatus
        );
      }

      if (!campos.length) {

        return res
          .status(400)
          .json({
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

          WHERE
            id_empleado = ?
        `,
        valores
      );

      await pool.query(
        `
          UPDATE empleados

          SET
            perfil_laboral_completo =
              CASE
                WHEN
                  NULLIF(
                    TRIM(
                      COALESCE(
                        puesto,
                        ''
                      )
                    ),
                    ''
                  ) IS NOT NULL

                  AND NULLIF(
                    TRIM(
                      COALESCE(
                        departamento,
                        ''
                      )
                    ),
                    ''
                  ) IS NOT NULL

                  AND fecha_contratacion
                    IS NOT NULL

                  AND sueldo
                    IS NOT NULL

                  AND sueldo > 0

                  AND periodicidad_sueldo
                    IS NOT NULL

                  AND modalidad_trabajo
                    IS NOT NULL

                  AND NULLIF(
                    TRIM(
                      COALESCE(
                        estado_residencia,
                        ''
                      )
                    ),
                    ''
                  ) IS NOT NULL

                  AND NULLIF(
                    TRIM(
                      COALESCE(
                        municipio_residencia,
                        ''
                      )
                    ),
                    ''
                  ) IS NOT NULL

                  AND NULLIF(
                    TRIM(
                      COALESCE(
                        colonia_residencia,
                        ''
                      )
                    ),
                    ''
                  ) IS NOT NULL

                  AND NULLIF(
                    TRIM(
                      COALESCE(
                        codigo_postal_residencia,
                        ''
                      )
                    ),
                    ''
                  ) IS NOT NULL

                THEN 1
                ELSE 0
              END

          WHERE
            id_empleado = ?
        `,
        [
          idEmpleado
        ]
      );

      const [rows] =
        await pool.query(
          `
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
              e.estado_residencia,
              e.municipio_residencia,
              e.colonia_residencia,
              e.codigo_postal_residencia,
              e.puesto,
              e.departamento,
              e.sueldo,
              e.periodicidad_sueldo,
              e.modalidad_trabajo,
              e.horario_laboral,
              e.fecha_contratacion,
              e.estatus,
              e.perfil_laboral_completo,
              e.fecha_registro,
              e.fecha_actualizacion,

              ur.nombre
                AS responsable_actual

            FROM empleados e

            LEFT JOIN usuarios ur
              ON ur.id_usuario =
                 e.id_usuario_responsable

            WHERE
              e.id_empleado = ?

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
          rows[0] ||
          null
      });

    } catch (error) {

      console.error(
        "❌ Error actualizando empleado RH:",
        error
      );

      return res
        .status(500)
        .json({
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
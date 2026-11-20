import pool from "../config/database.js";

// ==================================================
// AUXILIARES
// ==================================================

const normalizar = valor =>
  valor
    ? String(valor).trim().toLowerCase()
    : "";

const obtenerContextoUsuario = user => ({
  idUsuario:
    Number(user?.id_usuario) || null,

  tipoAdmin:
    normalizar(user?.tipo_admin),

  area:
    normalizar(user?.area),

  rol:
    normalizar(user?.rol),

  role:
    Number(user?.role) || null,

  idAdminPadre:
    Number(user?.id_admin_padre) || null,

  idPsicologo:
    Number(user?.id_psicologo) || null
});

// ==================================================
// OBTENER CONTEXTO REAL DESDE BD
// ==================================================

const obtenerContextoUsuarioBD = async (
  user,
  connection = pool
) => {
  const idUsuario =
    Number(user?.id_usuario) || null;

  if (!idUsuario) {
    return obtenerContextoUsuario(user);
  }

  const [rows] =
    await connection.query(
      `
        SELECT
          id_usuario,
          rol,
          tipo_admin,
          area,
          id_admin_padre
        FROM usuarios
        WHERE id_usuario = ?
        LIMIT 1
      `,
      [idUsuario]
    );

  if (!rows.length) {
    return obtenerContextoUsuario(user);
  }

  const usuarioBD =
    rows[0];

  return {
    idUsuario:
      Number(usuarioBD.id_usuario) || null,

    tipoAdmin:
      normalizar(usuarioBD.tipo_admin),

    area:
      normalizar(usuarioBD.area),

    rol:
      normalizar(usuarioBD.rol),

    role:
      Number(user?.role) || null,

    idAdminPadre:
      Number(usuarioBD.id_admin_padre) || null,

    idPsicologo:
      Number(user?.id_psicologo) || null
  };
};

const esMaster = contexto =>
  contexto.tipoAdmin === "master";

const esAdmin = contexto =>
  contexto.tipoAdmin === "normal" ||
  contexto.tipoAdmin === "master";

const esAreaClinica = contexto =>
  contexto.area === "clinica" ||
  contexto.area === "clínica";

const esAreaRH = contexto =>
  contexto.area === "rh";

// ==================================================
// OBTENER ID PSICÓLOGO DEL USUARIO
// ==================================================

const obtenerIdPsicologoUsuario = async (
  idUsuario,
  connection = pool
) => {
  if (!idUsuario) {
    return null;
  }

  const [rows] =
    await connection.query(
      `
        SELECT id_psicologo
        FROM psicologos
        WHERE id_usuario = ?
        LIMIT 1
      `,
      [idUsuario]
    );

  return rows.length
    ? Number(rows[0].id_psicologo)
    : null;
};

// ==================================================
// OBTENER PACIENTE
// ==================================================

const obtenerPaciente = async (
  idPaciente,
  connection = pool
) => {
  const [rows] =
    await connection.query(
      `
        SELECT
          p.id_paciente,
          p.id_mirror,
          p.nombre,
          p.id_psicologo,

          ps.id_usuario
            AS id_usuario_psicologo,

          ps.especialidad,

          u.nombre
            AS psicologo_actual,

          u.area
            AS area_psicologo,

          u.id_admin_padre

        FROM pacientes p

        INNER JOIN psicologos ps
          ON ps.id_psicologo =
             p.id_psicologo

        INNER JOIN usuarios u
          ON u.id_usuario =
             ps.id_usuario

        WHERE
          p.id_paciente = ?

        LIMIT 1
      `,
      [idPaciente]
    );

  return rows[0] || null;
};

// ==================================================
// OBTENER EMPLEADO
// ==================================================

const obtenerEmpleado = async (
  idEmpleado,
  connection = pool
) => {
  const [rows] =
    await connection.query(
      `
        SELECT
          e.id_empleado,
          e.id_mirror,
          e.nombre,
          e.id_admin_padre,
          e.id_usuario_responsable,

          u.nombre
            AS responsable_actual

        FROM empleados e

        LEFT JOIN usuarios u
          ON u.id_usuario =
             e.id_usuario_responsable

        WHERE
          e.id_empleado = ?

        LIMIT 1
      `,
      [idEmpleado]
    );

  return rows[0] || null;
};

// ==================================================
// VALIDAR PERMISO PACIENTE
// ==================================================

const validarPermisoPaciente = async (
  paciente,
  user,
  connection = pool
) => {
  const contexto =
    obtenerContextoUsuario(user);

  if (!contexto.idUsuario) {
    return {
      ok: false,
      status: 401,
      message:
        "No se pudo identificar al usuario."
    };
  }

  // MASTER

  if (esMaster(contexto)) {
    return {
      ok: true,
      contexto
    };
  }

  // ADMINISTRADOR CLÍNICO

  if (
    esAdmin(contexto) &&
    esAreaClinica(contexto) &&
    Number(
      paciente.id_admin_padre
    ) ===
    Number(
      contexto.idUsuario
    )
  ) {
    return {
      ok: true,
      contexto
    };
  }

  // PSICÓLOGO RESPONSABLE

  let idPsicologoUsuario =
    contexto.idPsicologo;

  if (!idPsicologoUsuario) {
    idPsicologoUsuario =
      await obtenerIdPsicologoUsuario(
        contexto.idUsuario,
        connection
      );
  }

  if (
    idPsicologoUsuario &&
    Number(
      paciente.id_psicologo
    ) ===
    Number(
      idPsicologoUsuario
    )
  ) {
    return {
      ok: true,

      contexto: {
        ...contexto,

        idPsicologo:
          idPsicologoUsuario
      }
    };
  }

  return {
    ok: false,
    status: 403,
    message:
      "No tienes permiso para transferir este paciente."
  };
};

// ==================================================
// VALIDAR PERMISO EMPLEADO
//
// SOPORTA ESTRUCTURA NUEVA:
//
// empleados.id_admin_padre = administrador RH
// empleados.id_usuario_responsable = usuario RH
//
// Y ESTRUCTURA ANTIGUA:
//
// empleados.id_admin_padre = usuario RH creador
// empleados.id_usuario_responsable = NULL
// ==================================================

const validarPermisoEmpleado = async (
  empleado,
  user,
  connection = pool
) => {
  const contexto =
    await obtenerContextoUsuarioBD(
      user,
      connection
    );

  if (!contexto.idUsuario) {
    return {
      ok: false,
      status: 401,
      message:
        "No se pudo identificar al usuario."
    };
  }

  let idResponsableActual =
    Number(
      empleado.id_usuario_responsable
    ) || null;

  let idAdminEmpresa = null;

  // ==================================================
  // CASO NUEVO:
  // YA TIENE RESPONSABLE RH
  // ==================================================

  if (idResponsableActual) {
    const [responsables] =
      await connection.query(
        `
          SELECT
            id_usuario,
            rol,
            area,
            tipo_admin,
            id_admin_padre

          FROM usuarios

          WHERE
            id_usuario = ?

          LIMIT 1
        `,
        [idResponsableActual]
      );

    if (responsables.length) {
      const responsable =
        responsables[0];

      idAdminEmpresa =
        Number(
          responsable.id_admin_padre
        ) || null;
    }
  }

  // ==================================================
  // CASO ANTIGUO:
  //
  // id_usuario_responsable = NULL
  //
  // empleados.id_admin_padre puede apuntar
  // directamente al usuario RH que creó el empleado.
  // ==================================================

  if (
    !idResponsableActual &&
    empleado.id_admin_padre
  ) {
    const [usuariosPadre] =
      await connection.query(
        `
          SELECT
            id_usuario,
            rol,
            area,
            tipo_admin,
            id_admin_padre

          FROM usuarios

          WHERE
            id_usuario = ?

          LIMIT 1
        `,
        [
          empleado.id_admin_padre
        ]
      );

    if (usuariosPadre.length) {
      const propietario =
        usuariosPadre[0];

      const rolPropietario =
        normalizar(
          propietario.rol
        );

      const areaPropietario =
        normalizar(
          propietario.area
        );

      const tipoAdminPropietario =
        normalizar(
          propietario.tipo_admin
        );

      // ================================================
      // id_admin_padre apunta a un USUARIO RH
      //
      // Ejemplo real:
      //
      // empleado.id_admin_padre = 15
      // usuario 15.id_admin_padre = 14
      //
      // Responsable real = 15
      // Empresa real = 14
      // ================================================

      if (
        rolPropietario === "rh" &&
        areaPropietario === "rh"
      ) {
        idResponsableActual =
          Number(
            propietario.id_usuario
          ) || null;

        idAdminEmpresa =
          Number(
            propietario.id_admin_padre
          ) || null;
      }

      // ================================================
      // id_admin_padre apunta directamente
      // al ADMINISTRADOR RH
      // ================================================

      else if (
        tipoAdminPropietario ===
          "normal" &&
        areaPropietario ===
          "rh"
      ) {
        idAdminEmpresa =
          Number(
            propietario.id_usuario
          ) || null;
      }
    }
  }

  // ==================================================
  // RESPALDO
  // ==================================================

  if (!idAdminEmpresa) {
    idAdminEmpresa =
      Number(
        empleado.id_admin_padre
      ) || null;
  }

  console.log(
    "🔐 Validando transferencia RH:",
    {
      usuarioLogueado: {
        id_usuario:
          contexto.idUsuario,

        tipo_admin:
          contexto.tipoAdmin,

        area:
          contexto.area,

        rol:
          contexto.rol,

        id_admin_padre:
          contexto.idAdminPadre
      },

      empleado: {
        id_empleado:
          empleado.id_empleado,

        id_admin_padre_guardado:
          empleado.id_admin_padre,

        id_usuario_responsable_guardado:
          empleado.id_usuario_responsable,

        id_responsable_actual_real:
          idResponsableActual,

        id_admin_empresa_real:
          idAdminEmpresa
      }
    }
  );

  // ==================================================
  // MASTER
  // ==================================================

  if (esMaster(contexto)) {
    return {
      ok: true,
      contexto,
      idAdminEmpresa,
      idResponsableActual
    };
  }

  // ==================================================
  // ADMINISTRADOR RH
  // ==================================================

  if (
    contexto.tipoAdmin ===
      "normal" &&

    esAreaRH(contexto) &&

    Number(
      contexto.idUsuario
    ) ===
    Number(
      idAdminEmpresa
    )
  ) {
    return {
      ok: true,
      contexto,
      idAdminEmpresa,
      idResponsableActual
    };
  }

  // ==================================================
  // RESPONSABLE RH ACTUAL
  // ==================================================

  if (
    contexto.rol === "rh" &&

    esAreaRH(contexto) &&

    Number(
      contexto.idUsuario
    ) ===
    Number(
      idResponsableActual
    ) &&

    Number(
      contexto.idAdminPadre
    ) ===
    Number(
      idAdminEmpresa
    )
  ) {
    return {
      ok: true,
      contexto,
      idAdminEmpresa,
      idResponsableActual
    };
  }

  return {
    ok: false,
    status: 403,
    message:
      "No tienes permiso para transferir este empleado."
  };
};

// ==================================================
// DESTINOS AUTORIZADOS PARA PACIENTE
//
// GET
// /api/transferencias/pacientes/:id/destinos
// ==================================================

export const listarDestinosPaciente =
  async (
    req,
    res
  ) => {
    try {
      const idPaciente =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(
          idPaciente
        ) ||
        idPaciente <= 0
      ) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              "ID de paciente inválido."
          });
      }

      const paciente =
        await obtenerPaciente(
          idPaciente
        );

      if (!paciente) {
        return res
          .status(404)
          .json({
            success: false,

            message:
              "Paciente no encontrado."
          });
      }

      const permiso =
        await validarPermisoPaciente(
          paciente,
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

      if (!paciente.id_admin_padre) {
        return res
          .status(409)
          .json({
            success: false,

            message:
              "El psicólogo actual no está asociado a una administración clínica."
          });
      }

      const [destinos] =
        await pool.query(
          `
            SELECT
              ps.id_psicologo,
              ps.id_usuario,
              ps.especialidad,

              u.nombre,
              u.correo,
              u.area,
              u.id_admin_padre

            FROM psicologos ps

            INNER JOIN usuarios u
              ON u.id_usuario =
                 ps.id_usuario

            WHERE
              u.rol = 'psicologo'

              AND LOWER(
                TRIM(
                  COALESCE(
                    u.area,
                    ''
                  )
                )
              ) = 'clinica'

              AND u.id_admin_padre = ?

              AND ps.id_psicologo <> ?

            ORDER BY
              u.nombre ASC
          `,
          [
            paciente.id_admin_padre,

            paciente.id_psicologo ||
              0
          ]
        );

      return res.json({
        success: true,

        paciente: {
          id_paciente:
            paciente.id_paciente,

          id_mirror:
            paciente.id_mirror,

          nombre:
            paciente.nombre,

          id_psicologo_actual:
            paciente.id_psicologo,

          psicologo_actual:
            paciente.psicologo_actual,

          id_admin_padre:
            paciente.id_admin_padre
        },

        destinos
      });

    } catch (error) {
      console.error(
        "❌ Error listando destinos de paciente:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            "Error interno al obtener los destinos disponibles."
        });
    }
  };

// ==================================================
// TRANSFERIR PACIENTE
//
// POST
// /api/transferencias/pacientes/:id
// ==================================================

export const transferirPaciente =
  async (
    req,
    res
  ) => {
    let connection;

    try {
      const idPaciente =
        Number(
          req.params.id
        );

      const idDestino =
        Number(
          req.body
            ?.id_psicologo_destino
        );

      const motivo =
        String(
          req.body?.motivo ||
          ""
        ).trim();

      if (
        !Number.isInteger(
          idPaciente
        ) ||
        idPaciente <= 0
      ) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              "ID de paciente inválido."
          });
      }

      if (
        !Number.isInteger(
          idDestino
        ) ||
        idDestino <= 0
      ) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              "Selecciona un psicólogo destino válido."
          });
      }

      if (!motivo) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              "Debes indicar el motivo de la transferencia."
          });
      }

      connection =
        await pool.getConnection();

      await connection
        .beginTransaction();

      const paciente =
        await obtenerPaciente(
          idPaciente,
          connection
        );

      if (!paciente) {
        await connection
          .rollback();

        return res
          .status(404)
          .json({
            success: false,

            message:
              "Paciente no encontrado."
          });
      }

      const permiso =
        await validarPermisoPaciente(
          paciente,
          req.user,
          connection
        );

      if (!permiso.ok) {
        await connection
          .rollback();

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

      if (
        Number(
          paciente.id_psicologo
        ) ===
        idDestino
      ) {
        await connection
          .rollback();

        return res
          .status(409)
          .json({
            success: false,

            message:
              "El psicólogo seleccionado ya es responsable del paciente."
          });
      }

      const [destinos] =
        await connection.query(
          `
            SELECT
              ps.id_psicologo,
              ps.id_usuario,
              ps.especialidad,

              u.nombre,
              u.correo,
              u.area,
              u.id_admin_padre

            FROM psicologos ps

            INNER JOIN usuarios u
              ON u.id_usuario =
                 ps.id_usuario

            WHERE
              ps.id_psicologo = ?

              AND u.rol = 'psicologo'

              AND LOWER(
                TRIM(
                  COALESCE(
                    u.area,
                    ''
                  )
                )
              ) = 'clinica'

              AND u.id_admin_padre = ?

            LIMIT 1
          `,
          [
            idDestino,
            paciente.id_admin_padre
          ]
        );

      if (!destinos.length) {
        await connection
          .rollback();

        return res
          .status(403)
          .json({
            success: false,

            message:
              "La psicóloga seleccionada no pertenece a la misma administración clínica."
          });
      }

      const destino =
        destinos[0];

      const idAnterior =
        paciente.id_psicologo ||
        null;

      // ==================================================
      // CAMBIAR PSICÓLOGO
      // ==================================================

      await connection.query(
        `
          UPDATE pacientes
          SET
            id_psicologo = ?
          WHERE
            id_paciente = ?
        `,
        [
          idDestino,
          idPaciente
        ]
      );

      // ==================================================
      // TRANSFERIR CITAS FUTURAS ACTIVAS
      // ==================================================

      const [resultadoCitas] =
        await connection.query(
          `
            UPDATE citas
            SET
              id_psicologo = ?
            WHERE
              id_paciente = ?

              AND estado IN (
                'apartada',
                'pendiente'
              )

              AND fecha >= CURDATE()
          `,
          [
            idDestino,
            idPaciente
          ]
        );

      // ==================================================
      // HISTORIAL
      // ==================================================

      await connection.query(
        `
          INSERT INTO transferencias_pacientes
          (
            id_paciente,
            id_psicologo_anterior,
            id_psicologo_nuevo,
            id_usuario_autor,
            id_admin_padre,
            motivo,
            fecha_transferencia
          )

          VALUES
          (
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
          idPaciente,
          idAnterior,
          idDestino,

          req.user
            ?.id_usuario ||
            null,

          paciente.id_admin_padre,

          motivo
        ]
      );

      await connection.commit();

      return res.json({
        success: true,

        message:
          `Paciente transferido correctamente a ${destino.nombre}.`,

        transferencia: {
          id_paciente:
            idPaciente,

          paciente:
            paciente.nombre,

          id_psicologo_anterior:
            idAnterior,

          psicologo_anterior:
            paciente.psicologo_actual,

          id_psicologo_nuevo:
            idDestino,

          psicologo_nuevo:
            destino.nombre,

          id_admin_padre:
            paciente.id_admin_padre,

          motivo,

          citas_transferidas:
            resultadoCitas.affectedRows
        }
      });

    } catch (error) {
      if (connection) {
        try {
          await connection.rollback();
        } catch {}
      }

      console.error(
        "❌ Error transfiriendo paciente:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            "Error interno al transferir el paciente.",

          error:
            process.env.NODE_ENV ===
            "development"
              ? error.message
              : undefined
        });

    } finally {
      if (connection) {
        connection.release();
      }
    }
  };

// ==================================================
// HISTORIAL DE TRANSFERENCIAS PACIENTE
// ==================================================

export const obtenerHistorialPaciente =
  async (
    req,
    res
  ) => {
    try {
      const idPaciente =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(
          idPaciente
        ) ||
        idPaciente <= 0
      ) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              "ID de paciente inválido."
          });
      }

      const paciente =
        await obtenerPaciente(
          idPaciente
        );

      if (!paciente) {
        return res
          .status(404)
          .json({
            success: false,

            message:
              "Paciente no encontrado."
          });
      }

      const permiso =
        await validarPermisoPaciente(
          paciente,
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

      const [historial] =
        await pool.query(
          `
            SELECT
              t.id_transferencia,
              t.id_paciente,
              t.id_psicologo_anterior,
              t.id_psicologo_nuevo,
              t.id_usuario_autor,
              t.id_admin_padre,
              t.motivo,
              t.fecha_transferencia,

              ua.nombre
                AS psicologo_anterior,

              un.nombre
                AS psicologo_nuevo,

              autor.nombre
                AS usuario_autor

            FROM transferencias_pacientes t

            LEFT JOIN psicologos pa
              ON pa.id_psicologo =
                 t.id_psicologo_anterior

            LEFT JOIN usuarios ua
              ON ua.id_usuario =
                 pa.id_usuario

            LEFT JOIN psicologos pn
              ON pn.id_psicologo =
                 t.id_psicologo_nuevo

            LEFT JOIN usuarios un
              ON un.id_usuario =
                 pn.id_usuario

            LEFT JOIN usuarios autor
              ON autor.id_usuario =
                 t.id_usuario_autor

            WHERE
              t.id_paciente = ?

            ORDER BY
              t.fecha_transferencia DESC,
              t.id_transferencia DESC
          `,
          [idPaciente]
        );

      return res.json({
        success: true,

        paciente: {
          id_paciente:
            paciente.id_paciente,

          id_mirror:
            paciente.id_mirror,

          nombre:
            paciente.nombre,

          psicologo_actual:
            paciente.psicologo_actual
        },

        historial
      });

    } catch (error) {
      console.error(
        "❌ Error obteniendo historial de transferencias del paciente:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            "Error interno al obtener el historial."
        });
    }
  };

// ==================================================
// DESTINOS AUTORIZADOS PARA EMPLEADO
//
// GET
// /api/transferencias/empleados/:id/destinos
// ==================================================

export const listarDestinosEmpleado =
  async (
    req,
    res
  ) => {
    try {
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
              "ID de empleado inválido."
          });
      }

      const empleado =
        await obtenerEmpleado(
          idEmpleado
        );

      if (!empleado) {
        return res
          .status(404)
          .json({
            success: false,

            message:
              "Empleado no encontrado."
          });
      }

      const permiso =
        await validarPermisoEmpleado(
          empleado,
          req.user,
          pool
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

      // ==================================================
      // BUSCAR COLEGAS RH DE LA MISMA EMPRESA
      // ==================================================

      const [destinos] =
        await pool.query(
          `
            SELECT
              u.id_usuario,
              u.nombre,
              u.puesto,
              u.correo,
              u.rol,
              u.area,
              u.id_admin_padre

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

              AND u.id_usuario <> ?

            ORDER BY
              u.nombre ASC
          `,
          [
            permiso.idAdminEmpresa,

            permiso.idResponsableActual ||
              0
          ]
        );

      return res.json({
        success: true,

        empleado: {
          id_empleado:
            empleado.id_empleado,

          id_mirror:
            empleado.id_mirror,

          nombre:
            empleado.nombre,

          id_admin_padre:
            permiso.idAdminEmpresa,

          id_usuario_responsable:
            permiso.idResponsableActual,

          responsable_actual:
            empleado.responsable_actual
        },

        destinos
      });

    } catch (error) {
      console.error(
        "❌ Error listando destinos de empleado:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            "Error interno al obtener los responsables disponibles."
        });
    }
  };

// ==================================================
// TRANSFERIR EMPLEADO
//
// POST
// /api/transferencias/empleados/:id
// ==================================================

export const transferirEmpleado =
  async (
    req,
    res
  ) => {
    let connection;

    try {
      const idEmpleado =
        Number(
          req.params.id
        );

      const idDestino =
        Number(
          req.body
            ?.id_usuario_destino
        );

      const motivo =
        String(
          req.body?.motivo ||
          ""
        ).trim();

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
              "ID de empleado inválido."
          });
      }

      if (
        !Number.isInteger(
          idDestino
        ) ||
        idDestino <= 0
      ) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              "Selecciona un responsable destino válido."
          });
      }

      if (!motivo) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              "Debes indicar el motivo de la transferencia."
          });
      }

      connection =
        await pool.getConnection();

      await connection
        .beginTransaction();

      const empleado =
        await obtenerEmpleado(
          idEmpleado,
          connection
        );

      if (!empleado) {
        await connection
          .rollback();

        return res
          .status(404)
          .json({
            success: false,

            message:
              "Empleado no encontrado."
          });
      }

      const permiso =
        await validarPermisoEmpleado(
          empleado,
          req.user,
          connection
        );

      if (!permiso.ok) {
        await connection
          .rollback();

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

      // ==================================================
      // NO TRANSFERIR AL MISMO RESPONSABLE
      // ==================================================

      if (
        Number(
          permiso.idResponsableActual
        ) ===
        idDestino
      ) {
        await connection
          .rollback();

        return res
          .status(409)
          .json({
            success: false,

            message:
              "El usuario seleccionado ya es responsable del empleado."
          });
      }

      // ==================================================
      // VALIDAR DESTINO
      // ==================================================

      const [destinos] =
        await connection.query(
          `
            SELECT
              id_usuario,
              nombre,
              puesto,
              correo,
              rol,
              area,
              id_admin_padre

            FROM usuarios

            WHERE
              id_usuario = ?

              AND id_admin_padre = ?

              AND rol = 'rh'

              AND LOWER(
                TRIM(
                  COALESCE(
                    area,
                    ''
                  )
                )
              ) = 'rh'

            LIMIT 1
          `,
          [
            idDestino,

            permiso.idAdminEmpresa
          ]
        );

      if (!destinos.length) {
        await connection
          .rollback();

        return res
          .status(403)
          .json({
            success: false,

            message:
              "El usuario seleccionado no pertenece a la misma empresa o área RH."
          });
      }

      const destino =
        destinos[0];

      const idAnterior =
        permiso.idResponsableActual ||
        null;

      // ==================================================
      // ACTUALIZAR EMPLEADO
      //
      // Aquí además corregimos automáticamente
      // registros antiguos:
      //
      // ANTES:
      // id_admin_padre = usuario RH
      // id_usuario_responsable = NULL
      //
      // DESPUÉS:
      // id_admin_padre = administrador RH
      // id_usuario_responsable = nuevo RH
      // ==================================================

      await connection.query(
        `
          UPDATE empleados

          SET
            id_usuario_responsable = ?,
            id_admin_padre = ?

          WHERE
            id_empleado = ?
        `,
        [
          idDestino,
          permiso.idAdminEmpresa,
          idEmpleado
        ]
      );

      // ==================================================
      // HISTORIAL
      // ==================================================

      await connection.query(
        `
          INSERT INTO transferencias_empleados
          (
            id_empleado,
            id_usuario_responsable_anterior,
            id_usuario_responsable_nuevo,
            id_usuario_autor,
            id_admin_padre,
            motivo,
            fecha_transferencia
          )

          VALUES
          (
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
          idEmpleado,
          idAnterior,
          idDestino,

          req.user
            ?.id_usuario ||
            null,

          permiso.idAdminEmpresa,

          motivo
        ]
      );

      await connection.commit();

      return res.json({
        success: true,

        message:
          `Empleado transferido correctamente a ${destino.nombre}.`,

        transferencia: {
          id_empleado:
            idEmpleado,

          empleado:
            empleado.nombre,

          id_usuario_anterior:
            idAnterior,

          responsable_anterior:
            empleado.responsable_actual,

          id_usuario_nuevo:
            idDestino,

          responsable_nuevo:
            destino.nombre,

          id_admin_padre:
            permiso.idAdminEmpresa,

          motivo
        }
      });

    } catch (error) {
      if (connection) {
        try {
          await connection.rollback();
        } catch {}
      }

      console.error(
        "❌ Error transfiriendo empleado:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            "Error interno al transferir el empleado.",

          error:
            process.env.NODE_ENV ===
            "development"
              ? error.message
              : undefined
        });

    } finally {
      if (connection) {
        connection.release();
      }
    }
  };

// ==================================================
// HISTORIAL DE TRANSFERENCIAS DEL EMPLEADO
// ==================================================

export const obtenerHistorialEmpleado =
  async (
    req,
    res
  ) => {
    try {
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
              "ID de empleado inválido."
          });
      }

      const empleado =
        await obtenerEmpleado(
          idEmpleado
        );

      if (!empleado) {
        return res
          .status(404)
          .json({
            success: false,

            message:
              "Empleado no encontrado."
          });
      }

      const permiso =
        await validarPermisoEmpleado(
          empleado,
          req.user,
          pool
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

      const [historial] =
        await pool.query(
          `
            SELECT
              t.id_transferencia,
              t.id_empleado,
              t.id_usuario_responsable_anterior,
              t.id_usuario_responsable_nuevo,
              t.id_usuario_autor,
              t.id_admin_padre,
              t.motivo,
              t.fecha_transferencia,

              ua.nombre
                AS responsable_anterior,

              un.nombre
                AS responsable_nuevo,

              autor.nombre
                AS usuario_autor

            FROM transferencias_empleados t

            LEFT JOIN usuarios ua
              ON ua.id_usuario =
                 t.id_usuario_responsable_anterior

            LEFT JOIN usuarios un
              ON un.id_usuario =
                 t.id_usuario_responsable_nuevo

            LEFT JOIN usuarios autor
              ON autor.id_usuario =
                 t.id_usuario_autor

            WHERE
              t.id_empleado = ?

            ORDER BY
              t.fecha_transferencia DESC,
              t.id_transferencia DESC
          `,
          [idEmpleado]
        );

      return res.json({
        success: true,

        empleado: {
          id_empleado:
            empleado.id_empleado,

          id_mirror:
            empleado.id_mirror,

          nombre:
            empleado.nombre,

          responsable_actual:
            empleado.responsable_actual,

          id_admin_padre:
            permiso.idAdminEmpresa,

          id_usuario_responsable:
            permiso.idResponsableActual
        },

        historial
      });

    } catch (error) {
      console.error(
        "❌ Error obteniendo historial de transferencias del empleado:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            "Error interno al obtener el historial."
        });
    }
  };
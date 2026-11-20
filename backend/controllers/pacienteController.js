// ============================================================
// backend/controllers/pacienteController.js
// ============================================================

import pool from "../config/database.js";


// ============================================================
// NORMALIZAR TEXTO
// ============================================================

function normalizar(valor) {

  return valor
    ? String(valor)
        .trim()
        .toLowerCase()
    : "";
}


// ============================================================
// GENERAR ID MIRRORSOUL
//
// Formato:
//
// MS-2026-18-FE-001
//
// El consecutivo es GLOBAL y se obtiene de mirror_ids.
// ============================================================

async function generarIdMirror(
  edad,
  sexo,
  connection
) {

  const añoActual =
    new Date().getFullYear();


  const edadNormalizada =
    Number.isFinite(
      Number(edad)
    )
      ? Number(edad)
      : 0;


  const sexoNormalizado =
    String(
      sexo || ""
    )
      .toUpperCase()
      .trim();


  const codigoSexo =
    sexoNormalizado === "F"
      ? "FE"
      : sexoNormalizado === "M"
        ? "MA"
        : "XX";


  const [
    rows
  ] =
    await connection.query(
      `
        SELECT
          consecutivo

        FROM mirror_ids

        WHERE
          año = ?

        ORDER BY
          consecutivo DESC

        LIMIT 1

        FOR UPDATE
      `,
      [
        añoActual
      ]
    );


  let consecutivo =
    1;


  if (
    rows.length &&
    rows[0].consecutivo
  ) {

    consecutivo =
      Number(
        rows[0].consecutivo
      ) + 1;

  }


  const numero =
    String(
      consecutivo
    )
      .padStart(
        3,
        "0"
      );


  const id_mirror =
    `MS-${añoActual}-${edadNormalizada}-${codigoSexo}-${numero}`;


  return {

    id_mirror,

    consecutivo,

    año:
      añoActual

  };

}


// ============================================================
// DATOS DEL ADMINISTRADOR
// ============================================================

function obtenerDatosAdmin(
  req
) {

  const tipoAdmin =
    req.user?.tipo_admin
      ? String(
          req.user.tipo_admin
        )
          .trim()
          .toLowerCase()
      : null;


  const idAdmin =
    Number(
      req.user?.id_usuario
    ) || null;


  const areaAdmin =
    req.user?.area
      ? String(
          req.user.area
        )
          .trim()
          .toLowerCase()
      : null;


  return {

    tipoAdmin,

    idAdmin,

    areaAdmin

  };

}


// ============================================================
// OBTENER ID PSICÓLOGO DE LA SESIÓN
//
// PERMITE:
//
// 1. Psicólogo tradicional.
//
// 2. Independiente Clínica:
//
//    rol = independiente
//    area = independiente
//    perfil_independiente = clinica
//
// El Independiente NO cambia de rol.
// Se obtiene su id_psicologo desde la tabla psicologos.
// ============================================================

async function obtenerIdPsicologoSesion(
  req,
  connection = pool
) {

  if (
    !req.user ||
    Number(
      req.user.role
    ) !== 2
  ) {

    return null;

  }


  const rol =
    normalizar(
      req.user?.rol
    );


  const perfilIndependiente =
    normalizar(
      req.user
        ?.perfil_independiente
    );


  const esPsicologo =
    rol ===
    "psicologo";


  const esIndependienteClinica =
    rol ===
      "independiente" &&

    perfilIndependiente ===
      "clinica";


  if (
    !esPsicologo &&
    !esIndependienteClinica
  ) {

    return null;

  }


  const idPsicologoToken =
    Number(
      req.user
        ?.id_psicologo
    );


  if (
    esPsicologo &&
    Number.isInteger(
      idPsicologoToken
    ) &&
    idPsicologoToken > 0
  ) {

    return idPsicologoToken;

  }


  const idUsuario =
    Number(
      req.user
        ?.id_usuario
    );


  if (
    !Number.isInteger(
      idUsuario
    ) ||
    idUsuario <= 0
  ) {

    return null;

  }


  const [
    rows
  ] =
    await connection.query(
      `
        SELECT
          p.id_psicologo

        FROM psicologos p

        WHERE
          p.id_usuario = ?

        LIMIT 1
      `,
      [
        idUsuario
      ]
    );


  if (
    !rows.length
  ) {

    return null;

  }


  return Number(
    rows[0]
      .id_psicologo
  ) || null;

}


// ============================================================
// LISTAR PACIENTES
// ============================================================

export async function listarPacientes(
  req,
  res
) {

  try {

    if (
      !req.user
    ) {

      return res
        .status(401)
        .json({

          message:
            "Sesión no válida"

        });

    }


    if (
      Number(
        req.user.role
      ) === 2
    ) {

      const idPsicologoSesion =
        await obtenerIdPsicologoSesion(
          req
        );


      if (
        !idPsicologoSesion
      ) {

        return res
          .status(403)
          .json({

            message:
              "Tu cuenta no tiene configurado un perfil clínico válido. Completa primero Mi perfil profesional."

          });

      }


      const [
        rows
      ] =
        await pool.query(
          `
            SELECT

              p.id_paciente,
              p.id_mirror,
              p.nombre,
              p.sexo,
              p.fecha_nacimiento,
              p.edad,
              p.correo,
              p.telefono,
              p.direccion,
              p.antecedentes

            FROM pacientes p

            WHERE
              p.id_psicologo = ?

            ORDER BY
              p.id_paciente DESC
          `,
          [
            idPsicologoSesion
          ]
        );


      return res.json(
        rows || []
      );

    }


    if (
      Number(
        req.user.role
      ) === 1
    ) {

      const {

        tipoAdmin,

        idAdmin,

        areaAdmin

      } =
        obtenerDatosAdmin(
          req
        );


      if (
        tipoAdmin ===
        "master"
      ) {

        const [
          rows
        ] =
          await pool.query(
            `
              SELECT

                p.id_paciente,
                p.id_mirror,
                p.nombre,
                p.sexo,
                p.fecha_nacimiento,
                p.edad,
                p.correo,
                p.telefono,
                p.direccion,
                p.antecedentes,

                ps.id_psicologo,

                u.id_usuario
                  AS id_usuario_psicologo,

                u.nombre
                  AS nombre_psicologo,

                u.correo
                  AS correo_psicologo,

                u.area
                  AS area_psicologo,

                u.rol
                  AS rol_profesional,

                o.perfil_independiente

              FROM pacientes p

              INNER JOIN psicologos ps
                ON ps.id_psicologo =
                   p.id_psicologo

              INNER JOIN usuarios u
                ON u.id_usuario =
                   ps.id_usuario

              LEFT JOIN organizaciones o
                ON o.id_organizacion =
                   u.id_organizacion

              ORDER BY
                p.id_paciente DESC
            `
          );


        return res.json(
          rows || []
        );

      }


      if (
        tipoAdmin ===
        "normal"
      ) {

        if (
          !idAdmin ||
          !areaAdmin
        ) {

          return res
            .status(403)
            .json({

              message:
                "El administrador no tiene configurados correctamente su ID o área"

            });

        }


        const [
          rows
        ] =
          await pool.query(
            `
              SELECT

                p.id_paciente,
                p.id_mirror,
                p.nombre,
                p.sexo,
                p.fecha_nacimiento,
                p.edad,
                p.correo,
                p.telefono,
                p.direccion,
                p.antecedentes,

                ps.id_psicologo,

                u.id_usuario
                  AS id_usuario_psicologo,

                u.nombre
                  AS nombre_psicologo,

                u.correo
                  AS correo_psicologo,

                u.area
                  AS area_psicologo

              FROM pacientes p

              INNER JOIN psicologos ps
                ON ps.id_psicologo =
                   p.id_psicologo

              INNER JOIN usuarios u
                ON u.id_usuario =
                   ps.id_usuario

              WHERE

                u.rol =
                  'psicologo'

                AND

                u.id_admin_padre = ?

                AND

                LOWER(
                  TRIM(
                    u.area
                  )
                ) = ?

              ORDER BY
                p.id_paciente DESC
            `,
            [
              idAdmin,
              areaAdmin
            ]
          );


        return res.json(
          rows || []
        );

      }


      return res
        .status(403)
        .json({

          message:
            "Tipo de administrador inválido"

        });

    }


    return res
      .status(403)
      .json({

        message:
          "Acceso denegado"

      });


  } catch (
    err
  ) {

    console.error(
      "❌ Error al obtener pacientes:",
      err
    );


    return res
      .status(500)
      .json({

        message:
          "Error al obtener pacientes"

      });

  }

}


// ============================================================
// OBTENER PACIENTE POR ID
// ============================================================

export async function obtenerPaciente(
  req,
  res
) {

  const {
    id
  } =
    req.params;


  try {

    const [
      rows
    ] =
      await pool.query(
        `
          SELECT

            p.id_paciente,
            p.id_mirror,
            p.nombre,
            p.sexo,
            p.fecha_nacimiento,
            p.edad,
            p.correo,
            p.telefono,
            p.direccion,
            p.antecedentes,

            ps.id_psicologo,

            u.id_usuario
              AS id_usuario_psicologo,

            u.nombre
              AS nombre_psicologo,

            u.area
              AS area_psicologo,

            u.rol
              AS rol_profesional,

            u.id_admin_padre,

            o.perfil_independiente

          FROM pacientes p

          INNER JOIN psicologos ps
            ON ps.id_psicologo =
               p.id_psicologo

          INNER JOIN usuarios u
            ON u.id_usuario =
               ps.id_usuario

          LEFT JOIN organizaciones o
            ON o.id_organizacion =
               u.id_organizacion

          WHERE
            p.id_paciente = ?

          LIMIT 1
        `,
        [
          id
        ]
      );


    if (
      !rows.length
    ) {

      return res
        .status(404)
        .json({

          message:
            "Paciente no encontrado"

        });

    }


    const paciente =
      rows[0];


    if (
      Number(
        req.user?.role
      ) === 2
    ) {

      const idPsicologoSesion =
        await obtenerIdPsicologoSesion(
          req
        );


      if (
        !idPsicologoSesion ||

        Number(
          idPsicologoSesion
        ) !==
        Number(
          paciente.id_psicologo
        )
      ) {

        return res
          .status(403)
          .json({

            message:
              "No tienes acceso a este paciente"

          });

      }


      return res.json(
        paciente
      );

    }


    if (
      Number(
        req.user?.role
      ) === 1 &&

      normalizar(
        req.user
          ?.tipo_admin
      ) ===
        "master"
    ) {

      return res.json(
        paciente
      );

    }


    if (
      Number(
        req.user?.role
      ) === 1 &&

      normalizar(
        req.user
          ?.tipo_admin
      ) ===
        "normal"
    ) {

      const idAdmin =
        Number(
          req.user
            ?.id_usuario
        );


      const areaAdmin =
        normalizar(
          req.user
            ?.area
        );


      const areaPaciente =
        normalizar(
          paciente
            .area_psicologo
        );


      if (
        !idAdmin ||
        !areaAdmin
      ) {

        return res
          .status(403)
          .json({

            message:
              "El administrador no tiene configurados correctamente su ID o área"

          });

      }


      if (
        Number(
          paciente
            .id_admin_padre
        ) !==
        idAdmin
      ) {

        return res
          .status(403)
          .json({

            message:
              "No tienes acceso a este paciente"

          });

      }


      if (
        areaPaciente !==
        areaAdmin
      ) {

        return res
          .status(403)
          .json({

            message:
              "No tienes acceso a pacientes de otra área"

          });

      }


      return res.json(
        paciente
      );

    }


    return res
      .status(403)
      .json({

        message:
          "Acceso denegado"

      });


  } catch (
    err
  ) {

    console.error(
      "❌ Error al obtener paciente:",
      err
    );


    return res
      .status(500)
      .json({

        message:
          "Error al obtener paciente"

      });

  }

}


// ============================================================
// REGISTRAR PACIENTE
//
// También permite:
// CANALIZACIÓN ACEPTADA -> INICIAR ATENCIÓN
// ============================================================

export async function registrarPaciente(
  req,
  res
) {

  let connection;


  try {

    if (
      !req.user
    ) {

      return res
        .status(401)
        .json({

          message:
            "Sesión no válida"

        });

    }


    const desdeCanalizacion =
      req.body
        ?.desde_canalizacion === true ||

      req.body
        ?.desde_canalizacion === 1 ||

      req.body
        ?.desde_canalizacion === "1" ||

      normalizar(
        req.body
          ?.desde_canalizacion
      ) === "true";


    const idCanalizacion =
      Number(
        req.body
          ?.id_canalizacion
      );


    if (
      desdeCanalizacion
    ) {

      if (
        Number(
          req.user.role
        ) !== 2
      ) {

        return res
          .status(403)
          .json({

            success:
              false,

            message:
              "Solo el profesional que aceptó la canalización puede iniciar la atención"

          });

      }


      if (
        !Number.isInteger(
          idCanalizacion
        ) ||

        idCanalizacion <= 0
      ) {

        return res
          .status(400)
          .json({

            success:
              false,

            message:
              "La canalización no es válida"

          });

      }


      connection =
        await pool
          .getConnection();


      await connection
        .beginTransaction();


      const idPsicologoSesion =
        await obtenerIdPsicologoSesion(
          req,
          connection
        );


      if (
        !idPsicologoSesion
      ) {

        await connection
          .rollback();


        return res
          .status(403)
          .json({

            success:
              false,

            message:
              "Tu cuenta no tiene un perfil clínico válido"

          });

      }


      const [
        canalizacionRows
      ] =
        await connection.query(
          `
            SELECT

              c.id_canalizacion,
              c.id_empleado,
              c.id_opcion_elegida,
              c.estatus,
              c.motivo,

              cp.id_opcion,
              cp.id_psicologo,
              cp.estado_respuesta_profesional,

              e.nombre,
              e.correo,
              e.telefono

            FROM canalizaciones c

            INNER JOIN
              canalizacion_profesionales cp

              ON cp.id_opcion =
                 c.id_opcion_elegida

            INNER JOIN empleados e

              ON e.id_empleado =
                 c.id_empleado

            WHERE

              c.id_canalizacion = ?

              AND cp.id_psicologo = ?

              AND cp.tipo_profesional =
                'mirrorsoul'

              AND cp.estado_respuesta_profesional =
                'aceptada'

            LIMIT 1

            FOR UPDATE
          `,
          [
            idCanalizacion,
            idPsicologoSesion
          ]
        );


      if (
        !canalizacionRows.length
      ) {

        await connection
          .rollback();


        return res
          .status(409)
          .json({

            success:
              false,

            message:
              "Esta canalización no está aceptada por tu perfil profesional"

          });

      }


      const canalizacion =
        canalizacionRows[0];


      const nombreEmpleado =
        String(
          canalizacion.nombre ||
          ""
        ).trim();


      const correoEmpleado =
        String(
          canalizacion.correo ||
          ""
        )
          .trim()
          .toLowerCase();


      const telefonoEmpleado =
        String(
          canalizacion.telefono ||
          ""
        ).trim();


      // ======================================================
      // DATOS COMPLETADOS EN EL FORMULARIO CLÍNICO
      // ======================================================

      const sexoPaciente =
        String(
          req.body?.sexo ||
          ""
        )
          .trim()
          .toUpperCase();


      const fechaNacimientoPaciente =
        req.body?.fecha_nacimiento ||
        null;


      const edadNumero =
        Number(
          req.body?.edad
        );


      const edadPaciente =
        Number.isFinite(
          edadNumero
        ) &&
        edadNumero >= 0
          ? edadNumero
          : null;


      const direccionPaciente =
        String(
          req.body?.direccion ||
          ""
        ).trim() ||
        null;


      const antecedentesPaciente =
        String(
          req.body?.antecedentes ||
          ""
        ).trim() ||
        null;


      if (
        !sexoPaciente
      ) {

        await connection
          .rollback();


        return res
          .status(400)
          .json({

            success:
              false,

            message:
              "Debes seleccionar el sexo del paciente"

          });

      }


      if (
        ![
          "M",
          "F",
          "X"
        ].includes(
          sexoPaciente
        )
      ) {

        await connection
          .rollback();


        return res
          .status(400)
          .json({

            success:
              false,

            message:
              "El sexo seleccionado no es válido"

          });

      }


      if (
        !fechaNacimientoPaciente
      ) {

        await connection
          .rollback();


        return res
          .status(400)
          .json({

            success:
              false,

            message:
              "La fecha de nacimiento es obligatoria"

          });

      }


      if (
        edadPaciente === null
      ) {

        await connection
          .rollback();


        return res
          .status(400)
          .json({

            success:
              false,

            message:
              "La edad del paciente no es válida"

          });

      }


      if (
        !nombreEmpleado
      ) {

        await connection
          .rollback();


        return res
          .status(409)
          .json({

            success:
              false,

            message:
              "La persona canalizada no tiene un nombre válido registrado"

          });

      }


      let pacienteExistente =
        null;


      if (
        correoEmpleado
      ) {

        const [
          pacientesCorreo
        ] =
          await connection.query(
            `
              SELECT

                id_paciente,
                id_mirror,
                nombre,
                correo,
                telefono

              FROM pacientes

              WHERE

                id_psicologo = ?

                AND LOWER(
                  TRIM(
                    COALESCE(
                      correo,
                      ''
                    )
                  )
                ) = ?

              LIMIT 1

              FOR UPDATE
            `,
            [
              idPsicologoSesion,
              correoEmpleado
            ]
          );


        pacienteExistente =
          pacientesCorreo[0] ||
          null;

      }


      if (
        !pacienteExistente &&
        telefonoEmpleado
      ) {

        const [
          pacientesTelefono
        ] =
          await connection.query(
            `
              SELECT

                id_paciente,
                id_mirror,
                nombre,
                correo,
                telefono

              FROM pacientes

              WHERE

                id_psicologo = ?

                AND TRIM(
                  COALESCE(
                    telefono,
                    ''
                  )
                ) = ?

              LIMIT 1

              FOR UPDATE
            `,
            [
              idPsicologoSesion,
              telefonoEmpleado
            ]
          );


        pacienteExistente =
          pacientesTelefono[0] ||
          null;

      }


      if (
        pacienteExistente
      ) {

        await connection.query(
          `
            UPDATE pacientes

            SET
              nombre = ?,
              sexo = ?,
              fecha_nacimiento = ?,
              edad = ?,
              correo = ?,
              telefono = ?,
              direccion = ?,
              antecedentes = ?

            WHERE
              id_paciente = ?

              AND id_psicologo = ?
          `,
          [
            nombreEmpleado,
            sexoPaciente,
            fechaNacimientoPaciente,
            edadPaciente,
            correoEmpleado ||
              null,
            telefonoEmpleado ||
              null,
            direccionPaciente,
            antecedentesPaciente,
            pacienteExistente.id_paciente,
            idPsicologoSesion
          ]
        );


        await connection.query(
          `
            UPDATE canalizaciones

            SET
              estatus =
                'atencion_iniciada'

            WHERE
              id_canalizacion = ?
          `,
          [
            idCanalizacion
          ]
        );


        if (
          canalizacion.estatus !==
          "atencion_iniciada"
        ) {

          await connection.query(
            `
              INSERT INTO canalizacion_historial
              (
                id_canalizacion,
                id_usuario,
                evento,
                detalle,
                fecha_evento
              )

              VALUES
              (
                ?,
                ?,
                'Atención iniciada',
                ?,
                NOW()
              )
            `,
            [
              idCanalizacion,

              Number(
                req.user
                  ?.id_usuario
              ) ||
              null,

              `Paciente existente vinculado al expediente clínico ${pacienteExistente.id_paciente}`
            ]
          );

        }


        await connection
          .commit();


        return res
          .status(200)
          .json({

            success:
              true,

            reutilizado:
              true,

            message:
              "El paciente ya tenía un expediente contigo. Se abrió el expediente existente.",

            id_paciente:
              pacienteExistente.id_paciente

          });

      }


      const {

        id_mirror,

        consecutivo,

        año

      } =
        await generarIdMirror(
          edadPaciente,
          sexoPaciente,
          connection
        );


      const [
        resultPaciente
      ] =
        await connection.query(
          `
            INSERT INTO pacientes
            (
              id_psicologo,
              id_mirror,
              nombre,
              sexo,
              fecha_nacimiento,
              edad,
              correo,
              telefono,
              direccion,
              antecedentes
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
              ?
            )
          `,
          [
            idPsicologoSesion,

            id_mirror,

            nombreEmpleado,

            sexoPaciente,

            fechaNacimientoPaciente,

            edadPaciente,

            correoEmpleado ||
              null,

            telefonoEmpleado ||
              null,

            direccionPaciente,

            antecedentesPaciente
          ]
        );


      const idPaciente =
        resultPaciente.insertId;


      await connection.query(
        `
          INSERT INTO mirror_ids
          (
            id_mirror,
            consecutivo,
            año,
            tipo_persona,
            id_referencia
          )

          VALUES
          (
            ?,
            ?,
            ?,
            'paciente',
            ?
          )
        `,
        [
          id_mirror,
          consecutivo,
          año,
          idPaciente
        ]
      );


      await connection.query(
        `
          UPDATE canalizaciones

          SET
            estatus =
              'atencion_iniciada'

          WHERE
            id_canalizacion = ?
        `,
        [
          idCanalizacion
        ]
      );


      await connection.query(
        `
          INSERT INTO canalizacion_historial
          (
            id_canalizacion,
            id_usuario,
            evento,
            detalle,
            fecha_evento
          )

          VALUES
          (
            ?,
            ?,
            'Atención iniciada',
            ?,
            NOW()
          )
        `,
        [
          idCanalizacion,

          Number(
            req.user
              ?.id_usuario
          ) ||
          null,

          `Se creó el expediente clínico ${idPaciente} a partir de una canalización aceptada`
        ]
      );


      await connection
        .commit();


      return res
        .status(201)
        .json({

          success:
            true,

          reutilizado:
            false,

          message:
            "Paciente creado correctamente. La atención clínica ha iniciado.",

          id_paciente:
            idPaciente

        });

    }
        const {

      nombre,

      sexo,

      fecha_nacimiento,

      edad,

      correo,

      telefono,

      direccion,

      antecedentes,

      id_psicologo

    } =
      req.body;


    if (
      !nombre ||
      !String(
        nombre
      ).trim()
    ) {

      return res
        .status(400)
        .json({

          message:
            "El nombre del paciente es obligatorio"

        });

    }


    let idPsicologoFinal =
      null;


    if (
      Number(
        req.user.role
      ) === 2
    ) {

      idPsicologoFinal =
        await obtenerIdPsicologoSesion(
          req
        );


      if (
        !idPsicologoFinal
      ) {

        return res
          .status(403)
          .json({

            message:
              "Tu cuenta no tiene configurado un perfil clínico válido. Completa primero Mi perfil profesional."

          });

      }

    }


    else if (
      Number(
        req.user.role
      ) === 1
    ) {

      const {

        tipoAdmin,

        idAdmin,

        areaAdmin

      } =
        obtenerDatosAdmin(
          req
        );


      if (
        tipoAdmin ===
        "master"
      ) {

        if (
          !id_psicologo
        ) {

          return res
            .status(400)
            .json({

              message:
                "Debes seleccionar el psicólogo responsable del paciente"

            });

        }


        const [
          profesional
        ] =
          await pool.query(
            `
              SELECT
                p.id_psicologo

              FROM psicologos p

              WHERE
                p.id_psicologo = ?

              LIMIT 1
            `,
            [
              id_psicologo
            ]
          );


        if (
          !profesional.length
        ) {

          return res
            .status(404)
            .json({

              message:
                "El profesional seleccionado no existe"

            });

        }


        idPsicologoFinal =
          Number(
            id_psicologo
          );

      }


      else if (
        tipoAdmin ===
        "normal"
      ) {

        if (
          !idAdmin ||
          !areaAdmin
        ) {

          return res
            .status(403)
            .json({

              message:
                "El administrador no tiene configurados correctamente su ID o área"

            });

        }


        if (
          !id_psicologo
        ) {

          return res
            .status(400)
            .json({

              message:
                "Debes seleccionar el psicólogo responsable del paciente"

            });

        }


        const [
          psicologoRows
        ] =
          await pool.query(
            `
              SELECT
                p.id_psicologo

              FROM psicologos p

              INNER JOIN usuarios u
                ON u.id_usuario =
                   p.id_usuario

              WHERE

                p.id_psicologo = ?

                AND u.rol =
                  'psicologo'

                AND u.id_admin_padre = ?

                AND LOWER(
                  TRIM(
                    u.area
                  )
                ) = ?

              LIMIT 1
            `,
            [
              id_psicologo,
              idAdmin,
              areaAdmin
            ]
          );


        if (
          !psicologoRows.length
        ) {

          return res
            .status(403)
            .json({

              message:
                "No puedes asignar pacientes a un psicólogo que no pertenece a tu área o que no registraste"

            });

        }


        idPsicologoFinal =
          Number(
            id_psicologo
          );

      }


      else {

        return res
          .status(403)
          .json({

            message:
              "Tipo de administrador inválido"

          });

      }

    }


    else {

      return res
        .status(403)
        .json({

          message:
            "No tienes permisos para registrar pacientes"

        });

    }


    connection =
      await pool
        .getConnection();


    await connection
      .beginTransaction();


    const {

      id_mirror,

      consecutivo,

      año

    } =
      await generarIdMirror(
        edad,
        sexo,
        connection
      );


    const [
      result
    ] =
      await connection.query(
        `
          INSERT INTO pacientes
          (
            id_psicologo,
            id_mirror,
            nombre,
            sexo,
            fecha_nacimiento,
            edad,
            correo,
            telefono,
            direccion,
            antecedentes
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
            ?
          )
        `,
        [
          idPsicologoFinal,

          id_mirror,

          String(
            nombre
          ).trim(),

          sexo ||
            null,

          fecha_nacimiento ||
            null,

          edad ||
            null,

          correo ||
            null,

          telefono ||
            null,

          direccion ||
            null,

          antecedentes ||
            null
        ]
      );


    await connection.query(
      `
        INSERT INTO mirror_ids
        (
          id_mirror,
          consecutivo,
          año,
          tipo_persona,
          id_referencia
        )

        VALUES
        (
          ?,
          ?,
          ?,
          'paciente',
          ?
        )
      `,
      [
        id_mirror,
        consecutivo,
        año,
        result.insertId
      ]
    );


    await connection
      .commit();


    return res
      .status(201)
      .json({

        success:
          true,

        message:
          "✅ Paciente registrado correctamente",

        id_paciente:
          result.insertId,

        id_mirror,

        id_psicologo:
          idPsicologoFinal

      });


  } catch (
    err
  ) {

    if (
      connection
    ) {

      try {

        await connection
          .rollback();

      } catch (
        rollbackError
      ) {

        console.error(
          "❌ Error en rollback:",
          rollbackError
        );

      }

    }


    console.error(
      "❌ Error al registrar paciente:",
      err
    );


    if (
      err?.code ===
      "ER_DUP_ENTRY"
    ) {

      return res
        .status(409)
        .json({

          message:
            "El ID MirrorSoul generado ya existe. Intenta nuevamente."

        });

    }


    return res
      .status(500)
      .json({

        message:
          "Error al registrar paciente",

        error:
          process.env.NODE_ENV ===
          "development"
            ? err.message
            : undefined

      });


  } finally {

    if (
      connection
    ) {

      connection
        .release();

    }

  }

}


// ============================================================
// REPORTES COMPLETOS DE UN PACIENTE
// ============================================================

export async function obtenerReportesCompletos(
  req,
  res
) {

  const {
    id
  } =
    req.params;


  try {

    const [
      pacienteAccessRows
    ] =
      await pool.query(
        `
          SELECT

            p.id_paciente,
            p.id_mirror,
            p.nombre,
            p.sexo,
            p.fecha_nacimiento,
            p.edad,
            p.correo,
            p.telefono,
            p.direccion,
            p.antecedentes,

            ps.id_psicologo,

            u.id_usuario
              AS id_usuario_profesional,

            u.area
              AS area_psicologo,

            u.rol
              AS rol_profesional,

            u.id_admin_padre,

            o.perfil_independiente

          FROM pacientes p

          INNER JOIN psicologos ps
            ON ps.id_psicologo =
               p.id_psicologo

          INNER JOIN usuarios u
            ON u.id_usuario =
               ps.id_usuario

          LEFT JOIN organizaciones o
            ON o.id_organizacion =
               u.id_organizacion

          WHERE
            p.id_paciente = ?

          LIMIT 1
        `,
        [
          id
        ]
      );


    if (
      !pacienteAccessRows.length
    ) {

      return res
        .status(404)
        .json({

          message:
            "Paciente no encontrado"

        });

    }


    const paciente =
      pacienteAccessRows[0];


    let tieneAcceso =
      false;


    if (
      Number(
        req.user?.role
      ) === 2
    ) {

      const idPsicologoSesion =
        await obtenerIdPsicologoSesion(
          req
        );


      tieneAcceso =
        Boolean(
          idPsicologoSesion
        ) &&

        Number(
          idPsicologoSesion
        ) ===
        Number(
          paciente
            .id_psicologo
        );

    }


    else if (
      Number(
        req.user?.role
      ) === 1 &&

      normalizar(
        req.user
          ?.tipo_admin
      ) ===
        "master"
    ) {

      tieneAcceso =
        true;

    }


    else if (
      Number(
        req.user?.role
      ) === 1 &&

      normalizar(
        req.user
          ?.tipo_admin
      ) ===
        "normal"
    ) {

      const idAdmin =
        Number(
          req.user
            ?.id_usuario
        );


      const areaAdmin =
        normalizar(
          req.user
            ?.area
        );


      const areaPaciente =
        normalizar(
          paciente
            .area_psicologo
        );


      tieneAcceso =
        Number(
          paciente
            .id_admin_padre
        ) ===
        idAdmin &&

        areaPaciente ===
        areaAdmin;

    }


    if (
      !tieneAcceso
    ) {

      return res
        .status(403)
        .json({

          message:
            "No tienes autorización para consultar el expediente de este paciente"

        });

    }


    const [
      historialInicial
    ] =
      await pool.query(
        `
          SELECT *

          FROM historial_inicial

          WHERE
            id_paciente = ?

          LIMIT 1
        `,
        [
          id
        ]
      );


    const [
      resultados
    ] =
      await pool.query(
        `
          SELECT

            r.id_resultado,
            r.id_prueba,

            p.nombre
              AS prueba,

            r.puntaje_total,
            r.interpretacion,

            DATE_FORMAT(
              r.fecha,
              '%d/%m/%Y %H:%i'
            )
              AS fecha

          FROM resultados_prueba r

          JOIN pruebas p
            ON p.id_prueba =
               r.id_prueba

          WHERE
            r.id_paciente = ?

          ORDER BY
            r.fecha DESC
        `,
        [
          id
        ]
      );


    const [
      seguimiento
    ] =
      await pool.query(
        `
          SELECT

            id_seguimiento,
            fecha,
            diagnostico,
            tratamiento,
            evolucion,
            observaciones

          FROM historial_seguimiento

          WHERE
            id_paciente = ?

          ORDER BY
            fecha DESC
        `,
        [
          id
        ]
      );


    const [
      sesiones
    ] =
      await pool.query(
        `
          SELECT

            s.id_sesion,
            s.fecha,
            s.notas,

            GROUP_CONCAT(
              v.ruta_video
              SEPARATOR '||'
            )
              AS videos

          FROM sesiones s

          LEFT JOIN videos_sesion v
            ON v.id_sesion =
               s.id_sesion

          WHERE
            s.id_paciente = ?

          GROUP BY
            s.id_sesion

          ORDER BY
            s.fecha DESC
        `,
        [
          id
        ]
      );


    const sesionesFormateadas =
      sesiones.map(
        sesion => ({

          ...sesion,

          videos:
            sesion.videos
              ? sesion
                  .videos
                  .split(
                    "||"
                  )
              : []

        })
      );


    return res.json({

      paciente,

      historialInicial:
        historialInicial[0] ||
        null,

      resultados:
        resultados || [],

      seguimiento:
        seguimiento || [],

      sesiones:
        sesionesFormateadas

    });


  } catch (
    err
  ) {

    console.error(
      "❌ Error al obtener reportes completos:",
      err
    );


    return res
      .status(500)
      .json({

        message:
          "Error al obtener reportes completos",

        error:
          process.env.NODE_ENV ===
          "development"
            ? err.message
            : undefined

      });

  }

}

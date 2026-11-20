// ============================================================
// backend/controllers/usuarioRHController.js
// ============================================================

import bcrypt from "bcryptjs";
import crypto from "crypto";

import pool from "../config/database.js";

import generarMatricula
from "../utils/generarMatricula.js";


// ============================================================
// AUXILIAR: NORMALIZAR
// ============================================================

const normalizar = (
  valor
) => {

  return String(
    valor ?? ""
  )
    .trim()
    .toLowerCase();

};


// ============================================================
// AUXILIAR: NÚMERO POSITIVO
// ============================================================

const enteroPositivo = (
  valor
) => {

  const numero =
    Number(
      valor
    );


  return (
    Number.isInteger(
      numero
    ) &&
    numero > 0
  )
    ? numero
    : null;

};


// ============================================================
// AUXILIAR: CORREO OPCIONAL
// ============================================================

const normalizarCorreo = (
  correo
) => {

  if (
    correo === null ||
    correo === undefined ||
    String(
      correo
    ).trim() === ""
  ) {

    return null;

  }


  return String(
    correo
  )
    .trim()
    .toLowerCase();

};


// ============================================================
// AUXILIAR: GENERAR PASSWORD TEMPORAL
// ============================================================

const generarPasswordTemporal =
  () => {

    const aleatorio =
      crypto
        .randomBytes(
          4
        )
        .toString(
          "hex"
        )
        .toUpperCase();


    return (
      `Ms!${aleatorio}`
    );

  };


// ============================================================
// REGISTRAR USUARIO RH
//
// POST
// /api/usuario-rh
//
// ADMIN NORMAL RH:
// - registra dentro de su organización.
//
// MASTER:
// - debe indicar id_organizacion.
//
// USUARIO RH:
// - consume una licencia.
//
// LOGIN:
// - utilizará matrícula + contraseña.
// ============================================================

export async function registrarUsuarioRH(
  req,
  res
) {

  let connection;


  try {

    // ========================================================
    // VALIDAR ADMIN
    // ========================================================

    if (
      Number(
        req.user?.role
      ) !== 1
    ) {

      return res
        .status(
          403
        )
        .json({

          success:
            false,

          message:
            "Solo administradores pueden registrar usuarios RH"

        });

    }


    const idAdmin =
      enteroPositivo(
        req.user
          ?.id_usuario
      );


    const tipoAdmin =
      normalizar(
        req.user
          ?.tipo_admin
      );


    const areaAdmin =
      normalizar(
        req.user
          ?.area
      );


    if (
      !idAdmin
    ) {

      return res
        .status(
          403
        )
        .json({

          success:
            false,

          message:
            "No se pudo identificar al administrador"

        });

    }


    // ========================================================
    // VALIDAR TIPO ADMIN
    // ========================================================

    if (
      tipoAdmin !==
        "master" &&
      tipoAdmin !==
        "normal"
    ) {

      return res
        .status(
          403
        )
        .json({

          success:
            false,

          message:
            "Tipo de administrador inválido"

        });

    }


    // ========================================================
    // ADMIN NORMAL DEBE SER RH
    // ========================================================

    if (
      tipoAdmin ===
        "normal" &&
      areaAdmin !==
        "rh"
    ) {

      return res
        .status(
          403
        )
        .json({

          success:
            false,

          message:
            "Solo un administrador de Recursos Humanos puede registrar usuarios RH"

        });

    }


    // ========================================================
    // DATOS
    // ========================================================

    const {

      nombre,

      correo,

      puesto,

      telefono,

      direccion,

      // Solo Master
      id_organizacion

    } =
      req.body;


    // ========================================================
    // SOLO NOMBRE ES OBLIGATORIO
    // ========================================================

    if (
      !nombre ||
      String(
        nombre
      ).trim() ===
        ""
    ) {

      return res
        .status(
          400
        )
        .json({

          success:
            false,

          message:
            "El nombre es obligatorio"

        });

    }


    // ========================================================
    // NORMALIZAR DATOS
    // ========================================================

    const nombreNormalizado =
      String(
        nombre
      ).trim();


    const correoNormalizado =
      normalizarCorreo(
        correo
      );


    const puestoNormalizado =
      puesto &&
      String(
        puesto
      ).trim()
        ? String(
            puesto
          ).trim()
        : null;


    const telefonoNormalizado =
      telefono &&
      String(
        telefono
      ).trim()
        ? String(
            telefono
          ).trim()
        : null;


    const direccionNormalizada =
      direccion &&
      String(
        direccion
      ).trim()
        ? String(
            direccion
          ).trim()
        : null;


    // ========================================================
    // CONEXIÓN / TRANSACCIÓN
    // ========================================================

    connection =
      await pool
        .getConnection();


    await connection
      .beginTransaction();


    // ========================================================
    // CONSULTAR ADMIN REAL
    // ========================================================

    const [
      administradores
    ] =
      await connection
        .query(
          `
            SELECT
              id_usuario,
              rol,
              tipo_admin,
              area,
              id_organizacion,
              estado

            FROM usuarios

            WHERE
              id_usuario = ?

            LIMIT 1

            FOR UPDATE
          `,
          [
            idAdmin
          ]
        );


    if (
      !administradores
        .length
    ) {

      await connection
        .rollback();


      return res
        .status(
          403
        )
        .json({

          success:
            false,

          message:
            "No se encontró el administrador que realiza el registro"

        });

    }


    const adminBD =
      administradores[
        0
      ];


    // ========================================================
    // VALIDAR ADMIN ACTIVO
    // ========================================================

    if (
      normalizar(
        adminBD.estado
      ) !==
      "activo"
    ) {

      await connection
        .rollback();


      return res
        .status(
          403
        )
        .json({

          success:
            false,

          code:
            "USUARIO_INACTIVO",

          message:
            "La cuenta del administrador está inactiva"

        });

    }


    // ========================================================
    // DETERMINAR ORGANIZACIÓN
    // ========================================================

    let idOrganizacionFinal =
      null;


    // ========================================================
    // ADMIN NORMAL
    // ========================================================

    if (
      tipoAdmin ===
      "normal"
    ) {

      idOrganizacionFinal =
        enteroPositivo(
          adminBD
            .id_organizacion
        );


      if (
        !idOrganizacionFinal
      ) {

        await connection
          .rollback();


        return res
          .status(
            403
          )
          .json({

            success:
              false,

            message:
              "Tu cuenta de administrador no está asociada a una organización"

          });

      }

    }


    // ========================================================
    // MASTER
    // ========================================================

    else {

      idOrganizacionFinal =
        enteroPositivo(
          id_organizacion
        );


      if (
        !idOrganizacionFinal
      ) {

        await connection
          .rollback();


        return res
          .status(
            400
          )
          .json({

            success:
              false,

            message:
              "El Administrador Master debe indicar id_organizacion para registrar un usuario RH"

          });

      }

    }


    // ========================================================
    // VALIDAR ORGANIZACIÓN
    // ========================================================

    const [
      organizaciones
    ] =
      await connection
        .query(
          `
            SELECT
              id_organizacion,
              nombre,
              nombre_comercial,
              tipo,
              estado

            FROM organizaciones

            WHERE
              id_organizacion = ?

            LIMIT 1

            FOR UPDATE
          `,
          [
            idOrganizacionFinal
          ]
        );


    if (
      !organizaciones
        .length
    ) {

      await connection
        .rollback();


      return res
        .status(
          404
        )
        .json({

          success:
            false,

          message:
            "La organización no existe"

        });

    }


    const organizacion =
      organizaciones[
        0
      ];


    // ========================================================
    // ORGANIZACIÓN ACTIVA
    // ========================================================

    if (
      normalizar(
        organizacion.estado
      ) !==
      "activa"
    ) {

      await connection
        .rollback();


      return res
        .status(
          403
        )
        .json({

          success:
            false,

          code:
            "ORGANIZACION_NO_ACTIVA",

          message:
            "La organización no está activa"

        });

    }


    // ========================================================
    // DEBE SER ORGANIZACIÓN RH
    // ========================================================

    if (
      normalizar(
        organizacion.tipo
      ) !==
      "rh"
    ) {

      await connection
        .rollback();


      return res
        .status(
          403
        )
        .json({

          success:
            false,

          message:
            "La organización seleccionada no corresponde al área de Recursos Humanos"

        });

    }


    // ========================================================
    // CORREO OPCIONAL
    //
    // Solo verificar duplicado si fue enviado.
    // ========================================================

    if (
      correoNormalizado
    ) {

      const [
        usuariosExistentes
      ] =
        await connection
          .query(
            `
              SELECT
                id_usuario

              FROM usuarios

              WHERE
                LOWER(
                  TRIM(correo)
                ) =
                LOWER(
                  TRIM(?)
                )

              LIMIT 1

              FOR UPDATE
            `,
            [
              correoNormalizado
            ]
          );


      if (
        usuariosExistentes
          .length
      ) {

        await connection
          .rollback();


        return res
          .status(
            409
          )
          .json({

            success:
              false,

            code:
              "CORREO_EXISTENTE",

            message:
              "El correo ya está registrado"

          });

      }

    }


    // ========================================================
    // BUSCAR SUSCRIPCIÓN ACTIVA / PRUEBA
    // ========================================================

    const [
      suscripciones
    ] =
      await connection
        .query(
          `
            SELECT
              s.id_suscripcion,
              s.id_organizacion,
              s.id_plan,
              s.estado,
              s.fecha_inicio,
              s.fecha_fin,
              s.proxima_renovacion,
              s.licencias_totales

            FROM suscripciones s

            WHERE
              s.id_organizacion = ?

              AND s.estado IN (
                'activa',
                'prueba'
              )

              AND
              (
                s.proxima_renovacion
                  IS NULL

                OR

                CURDATE() <=
                DATE_ADD(
                  s.proxima_renovacion,
                  INTERVAL 3 DAY
                )
              )

            ORDER BY
              s.id_suscripcion DESC

            LIMIT 1

            FOR UPDATE
          `,
          [
            idOrganizacionFinal
          ]
        );


    if (
      !suscripciones
        .length
    ) {

      await connection
        .rollback();


      return res
        .status(
          403
        )
        .json({

          success:
            false,

          code:
            "SUSCRIPCION_NO_ACTIVA",

          message:
            "La organización no tiene una suscripción RH activa"

        });

    }


    const suscripcion =
      suscripciones[
        0
      ];


    // ========================================================
    // BUSCAR LICENCIA RH DISPONIBLE
    // ========================================================

    const [
      licencias
    ] =
      await connection
        .query(
          `
            SELECT
              id_licencia,
              id_suscripcion,
              id_usuario,
              tipo,
              estado

            FROM licencias

            WHERE
              id_suscripcion = ?

              AND tipo = 'rh'

              AND estado =
                  'disponible'

              AND id_usuario
                  IS NULL

            ORDER BY
              id_licencia ASC

            LIMIT 1

            FOR UPDATE
          `,
          [
            suscripcion
              .id_suscripcion
          ]
        );


    if (
      !licencias
        .length
    ) {

      await connection
        .rollback();


      return res
        .status(
          409
        )
        .json({

          success:
            false,

          code:
            "SIN_LICENCIAS",

          message:
            "Has utilizado todas las licencias de tu plan. Amplía tu paquete para agregar más usuarios."

        });

    }


    const licencia =
      licencias[
        0
      ];


    // ========================================================
    // GENERAR MATRÍCULA
    // ========================================================

    const matricula =
      await generarMatricula({

        idOrganizacion:
          idOrganizacionFinal,

        area:
          "rh",

        connection

      });


    // ========================================================
    // GENERAR CONTRASEÑA TEMPORAL
    // ========================================================

    const passwordTemporal =
      generarPasswordTemporal();


    const passwordHash =
      await bcrypt.hash(
        passwordTemporal,
        10
      );


    // ========================================================
    // CREAR USUARIO RH
    // ========================================================

    const [
      resultado
    ] =
      await connection
        .query(
          `
            INSERT INTO usuarios
            (
              nombre,
              puesto,
              telefono,
              direccion,
              correo,
              matricula,
              password,
              debe_cambiar_password,
              rol,
              tipo_admin,
              area,
              id_admin_padre,
              id_organizacion,
              estado
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
              1,
              'rh',
              NULL,
              'rh',
              ?,
              ?,
              'activo'
            )
          `,
          [
            nombreNormalizado,
            puestoNormalizado,
            telefonoNormalizado,
            direccionNormalizada,
            correoNormalizado,
            matricula,
            passwordHash,
            idAdmin,
            idOrganizacionFinal
          ]
        );


    const idUsuarioNuevo =
      resultado.insertId;


    // ========================================================
    // ASIGNAR LICENCIA
    // ========================================================

    const [
      resultadoLicencia
    ] =
      await connection
        .query(
          `
            UPDATE licencias

            SET
              id_usuario = ?,

              estado =
                'asignada',

              fecha_asignacion =
                NOW(),

              fecha_liberacion =
                NULL

            WHERE
              id_licencia = ?

              AND estado =
                  'disponible'

              AND id_usuario
                  IS NULL
          `,
          [
            idUsuarioNuevo,
            licencia
              .id_licencia
          ]
        );


    // ========================================================
    // PROTECCIÓN EXTRA LICENCIA
    // ========================================================

    if (
      resultadoLicencia
        .affectedRows !== 1
    ) {

      await connection
        .rollback();


      return res
        .status(
          409
        )
        .json({

          success:
            false,

          code:
            "LICENCIA_NO_DISPONIBLE",

          message:
            "La licencia seleccionada ya no está disponible. Intenta nuevamente."

        });

    }


    // ========================================================
    // COMMIT
    // ========================================================

    await connection
      .commit();


    // ========================================================
    // RESPUESTA
    //
    // IMPORTANTE:
    // password_temporal solo se devuelve ahora.
    // No se guarda en texto plano.
    // ========================================================

    return res
      .status(
        201
      )
      .json({

        success:
          true,

        message:
          "Usuario RH registrado correctamente y licencia asignada",

        usuario: {

          id_usuario:
            idUsuarioNuevo,

          nombre:
            nombreNormalizado,

          correo:
            correoNormalizado,

          matricula,

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
            idAdmin,

          id_organizacion:
            idOrganizacionFinal,

          estado:
            "activo",

          debe_cambiar_password:
            1,

          id_licencia:
            licencia
              .id_licencia

        },

        credenciales: {

          matricula,

          password_temporal:
            passwordTemporal

        }

      });


  } catch (
    error
  ) {

    // ========================================================
    // ROLLBACK
    // ========================================================

    if (
      connection
    ) {

      try {

        await connection
          .rollback();

      }

      catch (
        rollbackError
      ) {

        console.error(
          "❌ Error haciendo rollback RH:",
          rollbackError
        );

      }

    }


    console.error(
      "❌ Error al registrar usuario RH:",
      error
    );


    // ========================================================
    // MATRÍCULA DUPLICADA
    // ========================================================

    if (
      error?.code ===
      "ER_DUP_ENTRY"
    ) {

      return res
        .status(
          409
        )
        .json({

          success:
            false,

          message:
            "No fue posible generar una matrícula única. Intenta nuevamente."

        });

    }


    return res
      .status(
        500
      )
      .json({

        success:
          false,

        message:
          "Error al registrar usuario RH"

      });


  } finally {

    // ========================================================
    // LIBERAR CONEXIÓN
    // ========================================================

    if (
      connection
    ) {

      connection
        .release();

    }

  }

}


// ============================================================
// LISTAR USUARIOS RH
//
// GET
// /api/usuario-rh
// ============================================================

export async function listarUsuariosRH(
  req,
  res
) {

  try {

    // ========================================================
    // VALIDAR ADMIN
    // ========================================================

    if (
      Number(
        req.user?.role
      ) !== 1
    ) {

      return res
        .status(
          403
        )
        .json({

          success:
            false,

          message:
            "Solo administradores"

        });

    }


    const tipoAdmin =
      normalizar(
        req.user
          ?.tipo_admin
      );


    const idAdmin =
      enteroPositivo(
        req.user
          ?.id_usuario
      );


    const areaAdmin =
      normalizar(
        req.user
          ?.area
      );


    // ========================================================
    // CONSULTA
    // ========================================================

    let sql = `
      SELECT
        u.id_usuario,
        u.nombre,
        u.correo,
        u.matricula,
        u.rol,
        u.area,
        u.puesto,
        u.telefono,
        u.direccion,
        u.id_admin_padre,
        u.id_organizacion,
        u.estado,
        u.debe_cambiar_password,
        u.creado_en

      FROM usuarios u

      WHERE
        LOWER(
          TRIM(u.rol)
        ) = 'rh'

        AND LOWER(
          TRIM(u.area)
        ) = 'rh'
    `;


    const params =
      [];


    // ========================================================
    // MASTER
    // ========================================================

    if (
      tipoAdmin ===
      "master"
    ) {

      // Master ve todos.

    }


    // ========================================================
    // ADMIN NORMAL RH
    // ========================================================

    else if (
      tipoAdmin ===
      "normal"
    ) {

      if (
        areaAdmin !==
        "rh"
      ) {

        return res
          .status(
            403
          )
          .json({

            success:
              false,

            message:
              "No tienes acceso al módulo de Recursos Humanos"

          });

      }


      if (
        !idAdmin
      ) {

        return res
          .status(
            403
          )
          .json({

            success:
              false,

            message:
              "No se pudo identificar al administrador"

          });

      }


      sql += `
        AND u.id_admin_padre = ?
      `;


      params.push(
        idAdmin
      );

    }


    // ========================================================
    // INVÁLIDO
    // ========================================================

    else {

      return res
        .status(
          403
        )
        .json({

          success:
            false,

          message:
            "Tipo de administrador inválido"

        });

    }


    sql += `
      ORDER BY
        u.nombre ASC
    `;


    const [
      rows
    ] =
      await pool
        .query(
          sql,
          params
        );


    return res.json(
      rows || []
    );


  } catch (
    error
  ) {

    console.error(
      "❌ Error al obtener usuarios RH:",
      error
    );


    return res
      .status(
        500
      )
      .json({

        success:
          false,

        message:
          "Error al obtener usuarios RH"

      });

  }

}


// ============================================================
// OBTENER FICHA COMPLETA DE USUARIO RH
//
// GET
// /api/usuario-rh/:id
// ============================================================

export async function obtenerUsuarioRH(
  req,
  res
) {

  try {

    // ========================================================
    // VALIDAR ADMIN
    // ========================================================

    if (
      Number(
        req.user?.role
      ) !== 1
    ) {

      return res
        .status(
          403
        )
        .json({

          success:
            false,

          message:
            "Solo administradores pueden consultar usuarios RH"

        });

    }


    const tipoAdmin =
      normalizar(
        req.user
          ?.tipo_admin
      );


    const idAdmin =
      enteroPositivo(
        req.user
          ?.id_usuario
      );


    const areaAdmin =
      normalizar(
        req.user
          ?.area
      );


    const idUsuario =
      enteroPositivo(
        req.params
          .id
      );


    if (
      !idUsuario
    ) {

      return res
        .status(
          400
        )
        .json({

          success:
            false,

          message:
            "ID de usuario inválido"

        });

    }


    // ========================================================
    // VALIDAR TIPO ADMIN
    // ========================================================

    if (
      tipoAdmin !==
        "master" &&
      tipoAdmin !==
        "normal"
    ) {

      return res
        .status(
          403
        )
        .json({

          success:
            false,

          message:
            "Tipo de administrador inválido"

        });

    }


    // ========================================================
    // CONSULTA
    // ========================================================

    let sql = `
      SELECT
        u.id_usuario,
        u.nombre,
        u.correo,
        u.matricula,
        u.rol,
        u.area,
        u.puesto,
        u.telefono,
        u.direccion,
        u.id_admin_padre,
        u.id_organizacion,
        u.estado,
        u.debe_cambiar_password,
        u.creado_en

      FROM usuarios u

      WHERE
        u.id_usuario = ?

        AND LOWER(
          TRIM(u.rol)
        ) = 'rh'

        AND LOWER(
          TRIM(u.area)
        ) = 'rh'
    `;


    const params = [
      idUsuario
    ];


    // ========================================================
    // ADMIN NORMAL RH
    // ========================================================

    if (
      tipoAdmin ===
      "normal"
    ) {

      if (
        areaAdmin !==
        "rh"
      ) {

        return res
          .status(
            403
          )
          .json({

            success:
              false,

            message:
              "No tienes acceso al módulo de Recursos Humanos"

          });

      }


      if (
        !idAdmin
      ) {

        return res
          .status(
            403
          )
          .json({

            success:
              false,

            message:
              "No se pudo identificar al administrador"

          });

      }


      sql += `
        AND u.id_admin_padre = ?
      `;


      params.push(
        idAdmin
      );

    }


    const [
      rows
    ] =
      await pool
        .query(
          sql,
          params
        );


    if (
      !rows.length
    ) {

      return res
        .status(
          404
        )
        .json({

          success:
            false,

          message:
            "Usuario RH no encontrado o no tienes permiso para verlo"

        });

    }


    return res.json({

      success:
        true,

      usuario:
        rows[
          0
        ]

    });


  } catch (
    error
  ) {

    console.error(
      "❌ Error al obtener ficha RH:",
      error
    );


    return res
      .status(
        500
      )
      .json({

        success:
          false,

        message:
          "Error al obtener la ficha del usuario RH"

      });

  }

}


// ============================================================
// ACTUALIZAR FICHA DE USUARIO RH
//
// PUT
// /api/usuario-rh/:id
//
// correo:
// - opcional.
//
// matricula:
// - NO se modifica.
//
// password:
// - opcional.
// - si admin genera una nueva, se obliga a cambiarla.
// ============================================================

export async function actualizarUsuarioRH(
  req,
  res
) {

  try {

    // ========================================================
    // VALIDAR ADMIN
    // ========================================================

    if (
      Number(
        req.user?.role
      ) !== 1
    ) {

      return res
        .status(
          403
        )
        .json({

          success:
            false,

          message:
            "Solo administradores pueden modificar usuarios RH"

        });

    }


    const tipoAdmin =
      normalizar(
        req.user
          ?.tipo_admin
      );


    const idAdmin =
      enteroPositivo(
        req.user
          ?.id_usuario
      );


    const areaAdmin =
      normalizar(
        req.user
          ?.area
      );


    const idUsuario =
      enteroPositivo(
        req.params
          .id
      );


    if (
      !idUsuario
    ) {

      return res
        .status(
          400
        )
        .json({

          success:
            false,

          message:
            "ID de usuario inválido"

        });

    }


    // ========================================================
    // VALIDAR TIPO ADMIN
    // ========================================================

    if (
      tipoAdmin !==
        "master" &&
      tipoAdmin !==
        "normal"
    ) {

      return res
        .status(
          403
        )
        .json({

          success:
            false,

          message:
            "Tipo de administrador inválido"

        });

    }


    if (
      tipoAdmin ===
        "normal" &&
      areaAdmin !==
        "rh"
    ) {

      return res
        .status(
          403
        )
        .json({

          success:
            false,

          message:
            "Solo administradores de Recursos Humanos pueden modificar usuarios RH"

        });

    }


    // ========================================================
    // BUSCAR USUARIO
    // ========================================================

    let buscarSql = `
      SELECT
        id_usuario,
        id_admin_padre,
        id_organizacion,
        estado,
        rol,
        area,
        matricula

      FROM usuarios

      WHERE
        id_usuario = ?

        AND LOWER(
          TRIM(rol)
        ) = 'rh'

        AND LOWER(
          TRIM(area)
        ) = 'rh'
    `;


    const buscarParams = [
      idUsuario
    ];


    if (
      tipoAdmin ===
      "normal"
    ) {

      buscarSql += `
        AND id_admin_padre = ?
      `;


      buscarParams.push(
        idAdmin
      );

    }


    const [
      usuarios
    ] =
      await pool
        .query(
          buscarSql,
          buscarParams
        );


    if (
      !usuarios.length
    ) {

      return res
        .status(
          404
        )
        .json({

          success:
            false,

          message:
            "Usuario RH no encontrado o no tienes permiso para modificarlo"

        });

    }


    // ========================================================
    // DATOS
    // ========================================================

    const {

      nombre,

      correo,

      puesto,

      telefono,

      direccion,

      password

    } =
      req.body;


    // ========================================================
    // NOMBRE OBLIGATORIO
    // ========================================================

    if (
      !nombre ||
      String(
        nombre
      ).trim() ===
        ""
    ) {

      return res
        .status(
          400
        )
        .json({

          success:
            false,

          message:
            "El nombre es obligatorio"

        });

    }


    const nombreNormalizado =
      String(
        nombre
      ).trim();


    const correoNormalizado =
      normalizarCorreo(
        correo
      );


    const puestoNormalizado =
      puesto &&
      String(
        puesto
      ).trim()
        ? String(
            puesto
          ).trim()
        : null;


    const telefonoNormalizado =
      telefono &&
      String(
        telefono
      ).trim()
        ? String(
            telefono
          ).trim()
        : null;


    const direccionNormalizada =
      direccion &&
      String(
        direccion
      ).trim()
        ? String(
            direccion
          ).trim()
        : null;


    // ========================================================
    // CORREO DUPLICADO SOLO SI EXISTE
    // ========================================================

    if (
      correoNormalizado
    ) {

      const [
        correoExistente
      ] =
        await pool
          .query(
            `
              SELECT
                id_usuario

              FROM usuarios

              WHERE
                LOWER(
                  TRIM(correo)
                ) =
                LOWER(
                  TRIM(?)
                )

                AND id_usuario <> ?

              LIMIT 1
            `,
            [
              correoNormalizado,
              idUsuario
            ]
          );


      if (
        correoExistente
          .length
      ) {

        return res
          .status(
            409
          )
          .json({

            success:
              false,

            message:
              "El correo ya está registrado por otro usuario"

          });

      }

    }


    // ========================================================
    // ACTUALIZAR DATOS
    // ========================================================

    await pool
      .query(
        `
          UPDATE usuarios

          SET
            nombre = ?,
            correo = ?,
            puesto = ?,
            telefono = ?,
            direccion = ?

          WHERE
            id_usuario = ?
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


    // ========================================================
    // CAMBIAR CONTRASEÑA OPCIONAL
    //
    // Si admin la cambia, usuario deberá volver a cambiarla
    // al iniciar sesión.
    // ========================================================

    if (
      password &&
      String(
        password
      )
        .trim()
        .length >
        0
    ) {

      if (
        String(
          password
        ).length <
        6
      ) {

        return res
          .status(
            400
          )
          .json({

            success:
              false,

            message:
              "La nueva contraseña debe tener al menos 6 caracteres"

          });

      }


      const passwordHash =
        await bcrypt.hash(
          String(
            password
          ),
          10
        );


      await pool
        .query(
          `
            UPDATE usuarios

            SET
              password = ?,
              debe_cambiar_password = 1

            WHERE
              id_usuario = ?
          `,
          [
            passwordHash,
            idUsuario
          ]
        );

    }


    // ========================================================
    // OBTENER ACTUALIZADO
    // ========================================================

    const [
      actualizados
    ] =
      await pool
        .query(
          `
            SELECT
              id_usuario,
              nombre,
              correo,
              matricula,
              rol,
              area,
              puesto,
              telefono,
              direccion,
              id_admin_padre,
              id_organizacion,
              estado,
              debe_cambiar_password,
              creado_en

            FROM usuarios

            WHERE
              id_usuario = ?

            LIMIT 1
          `,
          [
            idUsuario
          ]
        );


    return res.json({

      success:
        true,

      message:
        "Ficha del usuario RH actualizada correctamente",

      usuario:
        actualizados[
          0
        ]

    });


  } catch (
    error
  ) {

    console.error(
      "❌ Error al actualizar usuario RH:",
      error
    );


    return res
      .status(
        500
      )
      .json({

        success:
          false,

        message:
          "Error al actualizar la ficha del usuario RH"

      });

  }

}
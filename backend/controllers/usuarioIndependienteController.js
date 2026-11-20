// ============================================================
// backend/controllers/usuarioIndependienteController.js
// ============================================================

import bcrypt from "bcryptjs";
import pool from "../config/database.js";


// ============================================================
// HELPERS
// ============================================================

function normalizarTexto(valor) {

  if (
    valor === undefined ||
    valor === null
  ) {
    return null;
  }

  const texto =
    String(valor).trim();

  return texto || null;
}


function normalizarCorreo(valor) {

  if (!valor) {
    return null;
  }

  return String(valor)
    .trim()
    .toLowerCase();
}


// ============================================================
// REGISTRAR TITULAR INDEPENDIENTE
//
// IMPORTANTE:
//
// - NO lo crea un administrador.
// - NO usa matrícula.
// - Entra con correo + contraseña.
// - NO tiene administrador padre.
// - Se crea su propia organización.
// - La organización queda suspendida hasta pago.
// - La suscripción y licencia se crearán en Checkout.
// - Debe elegir perfil independiente:
//   clinica | rh
// ============================================================

export async function registrarUsuarioIndependiente(
  req,
  res
) {

  let connection;

  try {

    // ========================================================
    // DATOS
    // ========================================================

    const {
      nombre,
      correo,
      password,
      telefono,
      direccion,
      nombre_practica,
      rfc,
      perfil_independiente
    } = req.body;


    // ========================================================
    // NORMALIZAR
    // ========================================================

    const nombreNormalizado =
      normalizarTexto(
        nombre
      );


    const correoNormalizado =
      normalizarCorreo(
        correo
      );


    const telefonoNormalizado =
      normalizarTexto(
        telefono
      );


    const direccionNormalizada =
      normalizarTexto(
        direccion
      );


    const rfcNormalizado =
      normalizarTexto(
        rfc
      );


    const nombrePracticaNormalizado =
      normalizarTexto(
        nombre_practica
      );


    const perfilIndependiente =
      String(
        perfil_independiente || ""
      )
        .trim()
        .toLowerCase();


    // ========================================================
    // VALIDAR PERFIL INDEPENDIENTE
    // ========================================================

    if (
      ![
        "clinica",
        "rh"
      ].includes(
        perfilIndependiente
      )
    ) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "Selecciona si utilizarás MirrorSoul como Clínica/Psicología o Recursos Humanos."

        });

    }


    // ========================================================
    // VALIDAR NOMBRE
    // ========================================================

    if (
      !nombreNormalizado ||
      nombreNormalizado.length < 2
    ) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "El nombre no es válido"

        });

    }


    // ========================================================
    // VALIDAR CORREO
    // ========================================================

    if (
      !correoNormalizado
    ) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "El correo electrónico es obligatorio"

        });

    }


    const correoRegex =
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/;


    if (
      !correoRegex.test(
        correoNormalizado
      )
    ) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "El correo electrónico no es válido"

        });

    }


    // ========================================================
    // VALIDAR CONTRASEÑA
    // ========================================================

    if (
      !password ||
      String(
        password
      ).length < 6
    ) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "La contraseña debe tener al menos 6 caracteres"

        });

    }


    // ========================================================
    // VALIDAR TELÉFONO
    // ========================================================

    if (
      telefonoNormalizado
    ) {

      const digitos =
        telefonoNormalizado
          .replace(
            /\D/g,
            ""
          );


      if (
        digitos.length < 10 ||
        digitos.length > 15
      ) {

        return res
          .status(400)
          .json({

            success: false,

            message:
              "El teléfono no es válido"

          });

      }

    }


    // ========================================================
    // TRANSACCIÓN
    // ========================================================

    connection =
      await pool
        .getConnection();


    await connection
      .beginTransaction();


    // ========================================================
    // CORREO DUPLICADO
    // ========================================================

    const [
      existente
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
      existente.length > 0
    ) {

      await connection
        .rollback();


      return res
        .status(409)
        .json({

          success: false,

          code:
            "CORREO_EXISTENTE",

          message:
            "El correo ya está registrado"

        });

    }


    // ========================================================
    // HASH CONTRASEÑA
    // ========================================================

    const passwordHash =
      await bcrypt.hash(
        password,
        10
      );


    // ========================================================
    // NOMBRE DE LA ORGANIZACIÓN
    //
    // Independiente sigue teniendo organización,
    // pero es una organización de una sola persona.
    // ========================================================

    const nombreOrganizacion =
      nombrePracticaNormalizado ||
      `Práctica de ${nombreNormalizado}`;


    // ========================================================
    // CREAR ORGANIZACIÓN INDEPENDIENTE
    //
    // Se crea SUSPENDIDA porque todavía no existe pago.
    //
    // El Checkout posteriormente:
    // - crea suscripción
    // - crea licencia
    // - asigna licencia
    // - activa organización
    // ========================================================

    const [
      organizacionInsertada
    ] =
      await connection
        .query(
          `
            INSERT INTO organizaciones
            (
              nombre,
              nombre_comercial,
              responsable,
              correo,
              telefono,
              rfc,
              direccion,
              tipo,
              perfil_independiente,
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
              'independiente',
              ?,
              'suspendida'
            )
          `,
          [
            nombreOrganizacion,
            nombrePracticaNormalizado,
            nombreNormalizado,
            correoNormalizado,
            telefonoNormalizado,
            rfcNormalizado,
            direccionNormalizada,
            perfilIndependiente
          ]
        );


    const idOrganizacion =
      organizacionInsertada
        .insertId;


    // ========================================================
    // CREAR TITULAR
    //
    // CORREO + PASSWORD
    //
    // NO matrícula
    // NO admin padre
    // NO contraseña temporal
    // ========================================================

    const [
      usuarioInsertado
    ] =
      await connection
        .query(
          `
            INSERT INTO usuarios
            (
              nombre,
              correo,
              matricula,
              password,
              debe_cambiar_password,
              rol,
              tipo_admin,
              area,
              id_admin_padre,
              id_organizacion,
              estado,
              telefono,
              direccion
            )

            VALUES
            (
              ?,
              ?,
              NULL,
              ?,
              0,
              'independiente',
              NULL,
              'independiente',
              NULL,
              ?,
              'activo',
              ?,
              ?
            )
          `,
          [
            nombreNormalizado,
            correoNormalizado,
            passwordHash,
            idOrganizacion,
            telefonoNormalizado,
            direccionNormalizada
          ]
        );


    const idUsuario =
      usuarioInsertado
        .insertId;


    // ========================================================
    // CONFIRMAR
    // ========================================================

    await connection
      .commit();


    // ========================================================
    // RESPUESTA
    // ========================================================

    return res
      .status(201)
      .json({

        success: true,

        message:
          "Cuenta independiente creada correctamente",

        requiere_pago:
          true,

        siguiente_paso:
          "checkout",

        usuario: {

          id_usuario:
            idUsuario,

          nombre:
            nombreNormalizado,

          correo:
            correoNormalizado,

          matricula:
            null,

          rol:
            "independiente",

          area:
            "independiente",

          tipo_admin:
            null,

          id_admin_padre:
            null,

          id_organizacion:
            idOrganizacion,

          estado:
            "activo",

          debe_cambiar_password:
            0

        },

        organizacion: {

          id_organizacion:
            idOrganizacion,

          nombre:
            nombreOrganizacion,

          nombre_comercial:
            nombrePracticaNormalizado,

          tipo:
            "independiente",

          perfil_independiente:
            perfilIndependiente,

          estado:
            "suspendida"

        }

      });


  } catch (
    error
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
          "❌ Error haciendo rollback independiente:",
          rollbackError
        );

      }

    }


    console.error(
      "❌ Error al registrar independiente:",
      error
    );


    if (
      error?.code ===
      "ER_DUP_ENTRY"
    ) {

      return res
        .status(409)
        .json({

          success: false,

          message:
            "El correo ya está registrado"

        });

    }


    return res
      .status(500)
      .json({

        success: false,

        message:
          "Error interno al crear la cuenta independiente",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
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
// LISTAR CUENTAS INDEPENDIENTES
//
// ÚNICAMENTE MASTER.
// ============================================================

export async function listarUsuariosIndependiente(
  req,
  res
) {

  try {

    // ========================================================
    // VALIDAR MASTER
    // ========================================================

    if (
      Number(
        req.user?.role
      ) !== 1 ||
      String(
        req.user?.tipo_admin ||
        ""
      )
        .trim()
        .toLowerCase() !==
      "master"
    ) {

      return res
        .status(403)
        .json({

          success: false,

          message:
            "Solo el Administrador Master puede consultar las cuentas independientes"

        });

    }


    // ========================================================
    // CONSULTAR
    // ========================================================

    const [
      rows
    ] =
      await pool
        .query(
          `
            SELECT

              u.id_usuario,
              u.nombre,
              u.correo,
              u.rol,
              u.area,
              u.estado
                AS estado_usuario,

              u.id_organizacion,

              o.nombre
                AS organizacion,

              o.nombre_comercial,

              o.tipo
                AS tipo_organizacion,

              o.perfil_independiente,

              o.estado
                AS estado_organizacion,

              s.id_suscripcion,

              s.estado
                AS estado_suscripcion,

              s.proxima_renovacion,

              l.id_licencia,

              l.estado
                AS estado_licencia

            FROM usuarios u

            LEFT JOIN organizaciones o
              ON o.id_organizacion =
                 u.id_organizacion

            LEFT JOIN suscripciones s
              ON s.id_suscripcion =
              (
                SELECT
                  s2.id_suscripcion

                FROM suscripciones s2

                WHERE
                  s2.id_organizacion =
                  u.id_organizacion

                ORDER BY
                  s2.id_suscripcion DESC

                LIMIT 1
              )

            LEFT JOIN licencias l
              ON l.id_usuario =
                 u.id_usuario

            WHERE

              LOWER(
                TRIM(u.rol)
              ) =
              'independiente'

              AND

              LOWER(
                TRIM(u.area)
              ) =
              'independiente'

            ORDER BY
              u.id_usuario DESC
          `
        );


    return res.json({

      success: true,

      total:
        rows.length,

      usuarios:
        rows

    });


  } catch (
    error
  ) {

    console.error(
      "❌ Error al obtener independientes:",
      error
    );


    return res
      .status(500)
      .json({

        success: false,

        message:
          "Error al obtener las cuentas independientes"

      });

  }

}
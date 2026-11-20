// ============================================================
// backend/controllers/passwordInicialController.js
// ============================================================

import {
  validarTokenPasswordInicial,
  establecerPasswordInicial,
} from "../svc/passwordInicialService.js";


// ============================================================
// VALIDAR TOKEN
// GET /api/auth/password-inicial/validar/:token
// ============================================================

export async function validarTokenInicial(
  req,
  res
) {

  try {

    const {
      token
    } =
      req.params;


    const resultado =
      await validarTokenPasswordInicial(
        token
      );


    if (
      !resultado.valido
    ) {

      let mensaje =
        "El enlace no es válido.";


      if (
        resultado.motivo ===
        "TOKEN_USADO"
      ) {

        mensaje =
          "Este enlace ya fue utilizado.";

      }


      if (
        resultado.motivo ===
        "TOKEN_EXPIRADO"
      ) {

        mensaje =
          "Este enlace ha expirado.";

      }


      if (
        resultado.motivo ===
        "PASSWORD_YA_CONFIGURADO"
      ) {

        mensaje =
          "La contraseña de esta cuenta ya fue configurada.";

      }


      return res
        .status(
          400
        )
        .json({

          ok:
            false,

          valido:
            false,

          motivo:
            resultado.motivo,

          message:
            mensaje,

        });

    }


    return res.json({

      ok:
        true,

      valido:
        true,

      usuario: {

        nombre:
          resultado.nombre,

        correo:
          resultado.correo,

      },

      expira_en:
        resultado.expira_en,

    });


  } catch (
    error
  ) {

    console.error(
      "❌ Error validando token inicial:",
      error
    );


    return res
      .status(
        500
      )
      .json({

        ok:
          false,

        message:
          "No fue posible validar el enlace.",

      });

  }

}


// ============================================================
// CREAR PASSWORD
// POST /api/auth/password-inicial/crear
// ============================================================

export async function crearPasswordInicial(
  req,
  res
) {

  try {

    const {
      token,
      password,
      confirmar_password,
    } =
      req.body;


    // ========================================================
    // VALIDAR TOKEN
    // ========================================================

    if (
      !token
    ) {

      return res
        .status(
          400
        )
        .json({

          ok:
            false,

          message:
            "El token es obligatorio.",

        });

    }


    // ========================================================
    // VALIDAR PASSWORD
    // ========================================================

    if (
      !password
    ) {

      return res
        .status(
          400
        )
        .json({

          ok:
            false,

          message:
            "La contraseña es obligatoria.",

        });

    }


    if (
      password !==
      confirmar_password
    ) {

      return res
        .status(
          400
        )
        .json({

          ok:
            false,

          message:
            "Las contraseñas no coinciden.",

        });

    }


    // ========================================================
    // ESTABLECER PASSWORD
    // ========================================================

    const resultado =
      await establecerPasswordInicial({

        token,

        password,

      });


    return res.json({

      ok:
        true,

      message:
        "Tu contraseña fue creada correctamente.",

      usuario: {

        id_usuario:
          resultado.id_usuario,

        nombre:
          resultado.nombre,

        correo:
          resultado.correo,

      },

    });


  } catch (
    error
  ) {

    console.error(
      "❌ Error creando contraseña inicial:",
      error
    );


    return res
      .status(
        error.status ||
        500
      )
      .json({

        ok:
          false,

        message:
          error.message ||
          "No fue posible crear la contraseña.",

      });

  }

}
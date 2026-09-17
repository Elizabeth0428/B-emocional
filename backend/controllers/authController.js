// backend/controllers/authController.js

import pool from "../config/database.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";


/* ==================================================
   REGISTRO DE USUARIO POR ADMINISTRADOR

   REGLAS:

   MASTER:
   - Puede registrar:
     psicologo
     rh
     educativo
     independiente

   ADMIN NORMAL:
   - Solamente puede registrar usuarios
     correspondientes a su propia área.
   - El usuario queda asociado mediante
     id_admin_padre.

   IMPORTANTE:
   id_admin_padre es la propiedad principal
   para saber quién creó al usuario.
================================================== */

export async function registerPsicologo(req, res) {

  try {

    /* ==================================================
       VERIFICAR QUE SEA ADMIN
    ================================================== */

    if (req.user?.role !== 1) {

      return res.status(403).json({
        message:
          "Acceso denegado: solo administradores"
      });

    }


    /* ==================================================
       DATOS RECIBIDOS
    ================================================== */

    const {
      rol,
      cedula_profesional,
      nombre,
      correo,
      password,
      especialidad,
      area
    } = req.body;


    /* ==================================================
       ADMIN QUE CREA AL USUARIO
    ================================================== */

    const id_admin_padre =
      req.user?.id_usuario || null;

    const tipoAdmin =
      req.user?.tipo_admin
        ? String(req.user.tipo_admin)
            .trim()
            .toLowerCase()
        : null;

    const areaAdmin =
      req.user?.area
        ? String(req.user.area)
            .trim()
            .toLowerCase()
        : null;


    /* ==================================================
       VALIDAR ID DEL ADMIN
    ================================================== */

    if (!id_admin_padre) {

      return res.status(403).json({
        message:
          "No se pudo identificar al administrador que realiza el registro"
      });

    }


    /* ==================================================
       NORMALIZAR ROL
    ================================================== */

    const rolSolicitado =
      rol
        ? String(rol)
            .trim()
            .toLowerCase()
        : "psicologo";


    const rolesPermitidos = [
      "psicologo",
      "rh",
      "educativo",
      "independiente"
    ];


    if (
      !rolesPermitidos.includes(
        rolSolicitado
      )
    ) {

      return res.status(400).json({
        message:
          "El tipo de usuario seleccionado no es válido"
      });

    }


    /* ==================================================
       ÁREAS PERMITIDAS
    ================================================== */

    const areasPermitidas = [
      "clinica",
      "rh",
      "educativo",
      "independiente"
    ];


    /* ==================================================
       DETERMINAR ROL Y ÁREA FINAL

       MASTER:
       - Puede seleccionar cualquier rol.
       - Puede seleccionar cualquier área.

       ADMIN NORMAL:
       - NO puede cambiar de área.
       - Su usuario queda ligado a su admin padre.
       - Clínica -> psicólogo
       - RH -> usuario RH
       - Educativo -> usuario educativo
       - Independiente -> usuario independiente
    ================================================== */

    let areaFinal = null;
    let rolFinal = rolSolicitado;


    /* ==================================================
       MASTER
    ================================================== */

    if (tipoAdmin === "master") {

      areaFinal =
        area
          ? String(area)
              .trim()
              .toLowerCase()
          : null;


      /* -----------------------------------------------
         SI ES PSICÓLOGO, SIEMPRE ES CLÍNICA
      ----------------------------------------------- */

      if (
        rolFinal === "psicologo"
      ) {

        areaFinal = "clinica";

      }

    }


    /* ==================================================
       ADMIN NORMAL
    ================================================== */

    else if (tipoAdmin === "normal") {

      /* -----------------------------------------------
         EL ADMIN NORMAL DEBE TENER ÁREA
      ----------------------------------------------- */

      if (!areaAdmin) {

        return res.status(403).json({
          message:
            "Tu administrador no tiene un área asignada"
        });

      }


      /* -----------------------------------------------
         EL ADMIN NORMAL NO PUEDE ELEGIR OTRA ÁREA

         LA FUENTE DE VERDAD ES SU PROPIA ÁREA.
      ----------------------------------------------- */

      areaFinal = areaAdmin;


      /* -----------------------------------------------
         EL ROL DEPENDE DE SU ÁREA
      ----------------------------------------------- */

      if (
        areaAdmin === "clinica"
      ) {

        rolFinal = "psicologo";

      }

      else if (
        areaAdmin === "rh"
      ) {

        rolFinal = "rh";

      }

      else if (
        areaAdmin === "educativo"
      ) {

        rolFinal = "educativo";

      }

      else if (
        areaAdmin === "independiente"
      ) {

        rolFinal = "independiente";

      }

      else {

        return res.status(403).json({
          message:
            "El área de tu administrador no es válida"
        });

      }

    }


    /* ==================================================
       TIPO DE ADMINISTRADOR INVÁLIDO
    ================================================== */

    else {

      return res.status(403).json({
        message:
          "Tipo de administrador inválido"
      });

    }


    /* ==================================================
       VALIDAR ÁREA FINAL
    ================================================== */

    if (
      !areaFinal ||
      !areasPermitidas.includes(
        areaFinal
      )
    ) {

      return res.status(400).json({
        message:
          "El área seleccionada no es válida"
      });

    }


    /* ==================================================
       REGLA DEFINITIVA:

       PSICÓLOGO = CLÍNICA
    ================================================== */

    if (
      rolFinal === "psicologo"
    ) {

      areaFinal = "clinica";

    }


    /* ==================================================
       VALIDACIONES BÁSICAS
    ================================================== */

    if (
      !nombre ||
      !correo ||
      !password
    ) {

      return res.status(400).json({
        message:
          "Faltan datos obligatorios"
      });

    }


    /* ==================================================
       VALIDAR NOMBRE
    ================================================== */

    if (
      String(nombre)
        .trim()
        .length < 2
    ) {

      return res.status(400).json({
        message:
          "El nombre no es válido"
      });

    }


    /* ==================================================
       VALIDAR PASSWORD
    ================================================== */

    if (
      String(password).length < 6
    ) {

      return res.status(400).json({
        message:
          "La contraseña debe tener al menos 6 caracteres"
      });

    }


    /* ==================================================
       CÉDULA
       SOLO PSICÓLOGOS
    ================================================== */

    if (
      rolFinal === "psicologo"
    ) {

      if (
        !cedula_profesional
      ) {

        return res.status(400).json({
          message:
            "La cédula profesional es obligatoria para los psicólogos"
        });

      }


      if (
        String(cedula_profesional)
          .trim()
          .length < 5
      ) {

        return res.status(400).json({
          message:
            "La cédula profesional no es válida"
        });

      }

    }


    /* ==================================================
       NORMALIZAR DATOS
    ================================================== */

    const nombreNormalizado =
      String(nombre).trim();


    const correoNormalizado =
      String(correo)
        .trim()
        .toLowerCase();


    const cedulaNormalizada =
      cedula_profesional
        ? String(
            cedula_profesional
          ).trim()
        : null;


    /* ==================================================
       VERIFICAR CORREO
    ================================================== */

    const [uExist] =
      await pool.query(

        `
        SELECT
          id_usuario
        FROM usuarios
        WHERE correo = ?
        LIMIT 1
        `,

        [
          correoNormalizado
        ]

      );


    if (
      uExist.length
    ) {

      return res.status(400).json({
        message:
          "El correo ya está registrado"
      });

    }


    /* ==================================================
       VERIFICAR CÉDULA
       SOLO PSICÓLOGOS
    ================================================== */

    if (
      rolFinal === "psicologo"
    ) {

      const [cExist] =
        await pool.query(

          `
          SELECT
            id_psicologo
          FROM psicologos
          WHERE cedula_profesional = ?
          LIMIT 1
          `,

          [
            cedulaNormalizada
          ]

        );


      if (
        cExist.length
      ) {

        return res.status(400).json({
          message:
            "La cédula ya está registrada"
        });

      }

    }


    /* ==================================================
       ENCRIPTAR CONTRASEÑA
    ================================================== */

    const hashedPassword =
      await bcrypt.hash(
        password,
        10
      );


    /* ==================================================
       CREAR USUARIO

       IMPORTANTE:

       id_admin_padre = ADMIN QUE LO CREÓ

       Esta columna será la base para controlar
       posteriormente qué usuarios puede ver cada
       administrador normal.
    ================================================== */

    const [uIns] =
      await pool.query(

        `
        INSERT INTO usuarios
        (
          nombre,
          correo,
          password,
          rol,
          tipo_admin,
          area,
          id_admin_padre
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        `,

        [
          nombreNormalizado,
          correoNormalizado,
          hashedPassword,
          rolFinal,
          null,
          areaFinal,
          id_admin_padre
        ]

      );


    /* ==================================================
       CREAR REGISTRO EN PSICÓLOGOS

       ÚNICAMENTE SI ES PSICÓLOGO
    ================================================== */

    let id_psicologo = null;


    if (
      rolFinal === "psicologo"
    ) {

      const [pIns] =
        await pool.query(

          `
          INSERT INTO psicologos
          (
            id_usuario,
            cedula_profesional,
            especialidad
          )
          VALUES (?, ?, ?)
          `,

          [
            uIns.insertId,

            cedulaNormalizada,

            especialidad
              ? String(
                  especialidad
                ).trim()
              : null
          ]

        );


      id_psicologo =
        pIns.insertId;

    }


    /* ==================================================
       RESPUESTA
    ================================================== */

    return res.status(201).json({

      message:
        "Usuario registrado correctamente",

      usuario: {

        id_usuario:
          uIns.insertId,

        id_psicologo,

        nombre:
          nombreNormalizado,

        correo:
          correoNormalizado,

        rol:
          rolFinal,

        area:
          areaFinal,

        especialidad:
          rolFinal === "psicologo"
            ? (
                especialidad
                  ? String(
                      especialidad
                    ).trim()
                  : null
              )
            : null,

        id_admin_padre

      }

    });


  } catch (err) {

    console.error(
      "❌ Error en registro de usuario:",
      err
    );


    return res.status(500).json({

      message:
        "Error interno en registro de usuario",

      error:
        process.env.NODE_ENV === "development"
          ? err.message
          : undefined

    });

  }

}


/* ==================================================
   REGISTRO DE ADMINISTRADOR NORMAL

   SOLO ADMIN MASTER

   El Master puede crear administradores de
   cualquier área.

   El administrador creado queda ligado al Master
   mediante id_admin_padre.
================================================== */

export async function registerAdmin(
  req,
  res
) {

  try {

    /* ==================================================
       VERIFICAR ADMIN
    ================================================== */

    if (
      req.user?.role !== 1
    ) {

      return res.status(403).json({
        message:
          "Acceso denegado: solo administradores"
      });

    }


    /* ==================================================
       VERIFICAR MASTER
    ================================================== */

    const tipoAdmin =
      req.user?.tipo_admin
        ? String(req.user.tipo_admin)
            .trim()
            .toLowerCase()
        : null;


    if (
      tipoAdmin !== "master"
    ) {

      return res.status(403).json({
        message:
          "Acceso denegado: solo el Administrador Master puede crear administradores"
      });

    }


    /* ==================================================
       DATOS
    ================================================== */

    const {
      nombre,
      correo,
      password,
      area
    } = req.body;


    /* ==================================================
       VALIDACIONES
    ================================================== */

    if (
      !nombre ||
      !correo ||
      !password
    ) {

      return res.status(400).json({
        message:
          "Faltan datos obligatorios"
      });

    }


    const nombreNormalizado =
      String(nombre).trim();


    const correoNormalizado =
      String(correo)
        .trim()
        .toLowerCase();


    if (
      nombreNormalizado.length < 2
    ) {

      return res.status(400).json({
        message:
          "El nombre no es válido"
      });

    }


    if (
      String(password).length < 6
    ) {

      return res.status(400).json({
        message:
          "La contraseña debe tener al menos 6 caracteres"
      });

    }


    /* ==================================================
       ÁREAS PERMITIDAS
    ================================================== */

    const areasPermitidas = [
      "clinica",
      "rh",
      "educativo",
      "independiente"
    ];


    const areaNormalizada =
      area
        ? String(area)
            .trim()
            .toLowerCase()
        : null;


    if (
      !areaNormalizada ||
      !areasPermitidas.includes(
        areaNormalizada
      )
    ) {

      return res.status(400).json({
        message:
          "El área seleccionada no es válida"
      });

    }


    /* ==================================================
       VERIFICAR CORREO
    ================================================== */

    const [uExist] =
      await pool.query(

        `
        SELECT
          id_usuario
        FROM usuarios
        WHERE correo = ?
        LIMIT 1
        `,

        [
          correoNormalizado
        ]

      );


    if (
      uExist.length
    ) {

      return res.status(400).json({
        message:
          "El correo ya está registrado"
      });

    }


    /* ==================================================
       ENCRIPTAR
    ================================================== */

    const hashedPassword =
      await bcrypt.hash(
        password,
        10
      );


    /* ==================================================
       CREAR ADMIN NORMAL

       id_admin_padre =
       ID DEL MASTER QUE LO CREÓ
    ================================================== */

    const [uIns] =
      await pool.query(

        `
        INSERT INTO usuarios
        (
          nombre,
          correo,
          password,
          rol,
          tipo_admin,
          area,
          id_admin_padre
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        `,

        [
          nombreNormalizado,
          correoNormalizado,
          hashedPassword,
          "admin",
          "normal",
          areaNormalizada,
          req.user.id_usuario
        ]

      );


    /* ==================================================
       RESPUESTA
    ================================================== */

    return res.status(201).json({

      message:
        "Administrador normal creado correctamente",

      administrador: {

        id_usuario:
          uIns.insertId,

        nombre:
          nombreNormalizado,

        correo:
          correoNormalizado,

        rol:
          "admin",

        tipo_admin:
          "normal",

        area:
          areaNormalizada,

        id_admin_padre:
          req.user.id_usuario

      }

    });


  } catch (err) {

    console.error(
      "❌ Error al registrar administrador:",
      err
    );


    return res.status(500).json({

      message:
        "Error interno al registrar administrador",

      error:
        process.env.NODE_ENV === "development"
          ? err.message
          : undefined

    });

  }

}


/* ==================================================
   LOGIN
================================================== */

export async function login(
  req,
  res
) {

  try {

    const {
      correo,
      password
    } = req.body;


    /* ==================================================
       VALIDAR DATOS
    ================================================== */

    if (
      !correo ||
      !password
    ) {

      return res.status(400).json({
        message:
          "Faltan correo y contraseña"
      });

    }


    /* ==================================================
       NORMALIZAR CORREO
    ================================================== */

    const correoNormalizado =
      String(correo)
        .trim()
        .toLowerCase();


    /* ==================================================
       BUSCAR USUARIO
    ================================================== */

    const [rows] =
      await pool.query(

        `
        SELECT
          id_usuario,
          nombre,
          correo,
          password,
          rol,
          tipo_admin,
          area,
          id_admin_padre
        FROM usuarios
        WHERE correo = ?
        LIMIT 1
        `,

        [
          correoNormalizado
        ]

      );


    /* ==================================================
       USUARIO NO EXISTE
    ================================================== */

    if (
      !rows.length
    ) {

      return res.status(401).json({
        message:
          "Credenciales inválidas"
      });

    }


    const user =
      rows[0];


    /* ==================================================
       VERIFICAR PASSWORD
    ================================================== */

    const passwordCorrecta =
      await bcrypt.compare(

        password,

        user.password

      );


    if (
      !passwordCorrecta
    ) {

      return res.status(401).json({
        message:
          "Credenciales inválidas"
      });

    }


    /* ==================================================
       BUSCAR PSICÓLOGO
    ================================================== */

    let id_psicologo = null;


    if (
      user.rol === "psicologo"
    ) {

      const [p] =
        await pool.query(

          `
          SELECT
            id_psicologo
          FROM psicologos
          WHERE id_usuario = ?
          LIMIT 1
          `,

          [
            user.id_usuario
          ]

        );


      id_psicologo =
        p[0]?.id_psicologo ||
        null;

    }


    /* ==================================================
       CONVERTIR ROL PARA FRONTEND

       admin = 1
       demás = 2
    ================================================== */

    const roleNumber =
      user.rol === "admin"
        ? 1
        : 2;


    /* ==================================================
       CREAR JWT

       SE INCLUYEN TODOS LOS DATOS NECESARIOS
       PARA CONTROLAR PROPIEDAD Y PERMISOS.
    ================================================== */

    const token =
      jwt.sign(

        {

          id_usuario:
            user.id_usuario,

          role:
            roleNumber,

          id_psicologo,

          rol:
            user.rol,

          tipo_admin:
            user.tipo_admin ||
            null,

          area:
            user.area ||
            null,

          id_admin_padre:
            user.id_admin_padre ||
            null

        },

        process.env.JWT_SECRET,

        {
          expiresIn:
            "2h"
        }

      );


    /* ==================================================
       RESPUESTA
    ================================================== */

    return res.json({

      message:
        "Login exitoso",

      user: {

        id_usuario:
          user.id_usuario,

        nombre:
          user.nombre,

        correo:
          user.correo,

        role:
          roleNumber,

        rol:
          user.rol,

        tipo_admin:
          user.tipo_admin ||
          null,

        area:
          user.area ||
          null,

        id_admin_padre:
          user.id_admin_padre ||
          null,

        id_psicologo

      },

      token

    });


  } catch (err) {

    console.error(
      "❌ Error en login:",
      err
    );


    return res.status(500).json({

      message:
        "Error en login"

    });

  }

}


/* ==================================================
   CAMBIAR CONTRASEÑA
================================================== */

export async function changePassword(
  req,
  res
) {

  try {

    const {
      oldPassword,
      newPassword
    } = req.body;


    const {
      id_usuario
    } = req.user;


    /* ==================================================
       VALIDAR DATOS
    ================================================== */

    if (
      !oldPassword ||
      !newPassword
    ) {

      return res.status(400).json({
        message:
          "Faltan datos"
      });

    }


    /* ==================================================
       VALIDAR NUEVA CONTRASEÑA
    ================================================== */

    if (
      String(newPassword).length < 6
    ) {

      return res.status(400).json({

        message:
          "La nueva contraseña debe tener al menos 6 caracteres"

      });

    }


    /* ==================================================
       BUSCAR USUARIO
    ================================================== */

    const [rows] =
      await pool.query(

        `
        SELECT
          password
        FROM usuarios
        WHERE id_usuario = ?
        LIMIT 1
        `,

        [
          id_usuario
        ]

      );


    if (
      !rows.length
    ) {

      return res.status(404).json({

        message:
          "Usuario no encontrado"

      });

    }


    /* ==================================================
       VERIFICAR PASSWORD ACTUAL
    ================================================== */

    const passwordCorrecta =
      await bcrypt.compare(

        oldPassword,

        rows[0].password

      );


    if (
      !passwordCorrecta
    ) {

      return res.status(401).json({

        message:
          "La contraseña actual es incorrecta"

      });

    }


    /* ==================================================
       ENCRIPTAR NUEVA PASSWORD
    ================================================== */

    const hashedPassword =
      await bcrypt.hash(

        newPassword,

        10

      );


    /* ==================================================
       ACTUALIZAR
    ================================================== */

    await pool.query(

      `
      UPDATE usuarios
      SET password = ?
      WHERE id_usuario = ?
      `,

      [
        hashedPassword,
        id_usuario
      ]

    );


    /* ==================================================
       RESPUESTA
    ================================================== */

    return res.json({

      message:
        "Contraseña actualizada"

    });


  } catch (err) {

    console.error(
      "❌ Error al cambiar contraseña:",
      err
    );


    return res.status(500).json({

      message:
        "Error interno al cambiar contraseña"

    });

  }

}
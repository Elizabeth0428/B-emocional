// ============================================================
// backend/controllers/authController.js
// ============================================================

import pool from "../config/database.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import generarMatricula from "../utils/generarMatricula.js";


// ============================================================
// REGISTRAR PSICÓLOGO
// ============================================================

export async function registerPsicologo(req, res) {

  let connection;

  try {

    // --------------------------------------------------------
    // SOLO ADMINISTRADORES
    // --------------------------------------------------------

    if (Number(req.user?.role) !== 1) {
      return res.status(403).json({
        success: false,
        message: "Acceso denegado: solo administradores"
      });
    }

    const idAdmin =
      Number(req.user?.id_usuario) || null;

    const tipoAdmin =
      req.user?.tipo_admin
        ? String(req.user.tipo_admin).trim().toLowerCase()
        : null;

    const areaAdmin =
      req.user?.area
        ? String(req.user.area).trim().toLowerCase()
        : null;


    if (!idAdmin) {
      return res.status(403).json({
        success: false,
        message: "No se pudo identificar al administrador"
      });
    }


    if (
      tipoAdmin !== "master" &&
      tipoAdmin !== "normal"
    ) {
      return res.status(403).json({
        success: false,
        message: "Tipo de administrador inválido"
      });
    }


    // Admin normal solo Clínica
    if (
      tipoAdmin === "normal" &&
      areaAdmin !== "clinica"
    ) {
      return res.status(403).json({
        success: false,
        message:
          "Solo un administrador de Clínica puede registrar psicólogos"
      });
    }


    // --------------------------------------------------------
    // DATOS
    // --------------------------------------------------------

    const {
      nombre,
      cedula_profesional,
      especialidad,
      telefono,
      direccion,
      fecha_nacimiento,
      id_organizacion
    } = req.body;


    if (
      !nombre ||
      String(nombre).trim().length < 2
    ) {
      return res.status(400).json({
        success: false,
        message: "El nombre no es válido"
      });
    }


    if (
      !cedula_profesional ||
      String(cedula_profesional).trim().length < 5
    ) {
      return res.status(400).json({
        success: false,
        message:
          "La cédula profesional es obligatoria y debe ser válida"
      });
    }


    // --------------------------------------------------------
    // NORMALIZAR
    // --------------------------------------------------------

    const nombreNormalizado =
      String(nombre).trim();

    const cedulaNormalizada =
      String(cedula_profesional).trim();

    const especialidadNormalizada =
      especialidad &&
      String(especialidad).trim()
        ? String(especialidad).trim()
        : null;

    const telefonoNormalizado =
      telefono &&
      String(telefono).trim()
        ? String(telefono).trim()
        : null;

    const direccionNormalizada =
      direccion &&
      String(direccion).trim()
        ? String(direccion).trim()
        : null;

    const fechaNacimientoNormalizada =
      fecha_nacimiento &&
      String(fecha_nacimiento).trim()
        ? String(fecha_nacimiento).trim()
        : null;


    // --------------------------------------------------------
    // TELÉFONO
    // --------------------------------------------------------

    if (telefonoNormalizado) {

      const telefonoDigitos =
        telefonoNormalizado.replace(/\D/g, "");

      if (
        telefonoDigitos.length < 10 ||
        telefonoDigitos.length > 15
      ) {
        return res.status(400).json({
          success: false,
          message: "El teléfono no es válido"
        });
      }

    }


    // --------------------------------------------------------
    // TRANSACCIÓN
    // --------------------------------------------------------

    connection =
      await pool.getConnection();

    await connection.beginTransaction();


    // --------------------------------------------------------
    // ADMINISTRADOR REAL
    // --------------------------------------------------------

    const [administradores] =
      await connection.query(
        `
          SELECT
            id_usuario,
            rol,
            tipo_admin,
            area,
            id_organizacion,
            estado
          FROM usuarios
          WHERE id_usuario = ?
          LIMIT 1
          FOR UPDATE
        `,
        [idAdmin]
      );


    if (!administradores.length) {

      await connection.rollback();

      return res.status(403).json({
        success: false,
        message:
          "No se encontró el administrador que realiza el registro"
      });
    }


    const adminBD =
      administradores[0];


    if (
      String(adminBD.estado || "")
        .trim()
        .toLowerCase() !== "activo"
    ) {

      await connection.rollback();

      return res.status(403).json({
        success: false,
        code: "USUARIO_INACTIVO",
        message:
          "La cuenta del administrador está inactiva"
      });
    }


    // Validación adicional del área real del admin
    if (
      tipoAdmin === "normal" &&
      String(adminBD.area || "")
        .trim()
        .toLowerCase() !== "clinica"
    ) {

      await connection.rollback();

      return res.status(403).json({
        success: false,
        message:
          "Solo un administrador de Clínica puede registrar psicólogos"
      });
    }


    // --------------------------------------------------------
    // ORGANIZACIÓN
    // --------------------------------------------------------

    let idOrganizacionFinal = null;


    if (tipoAdmin === "normal") {

      idOrganizacionFinal =
        Number(adminBD.id_organizacion) || null;


      if (!idOrganizacionFinal) {

        await connection.rollback();

        return res.status(403).json({
          success: false,
          message:
            "Tu cuenta de administrador no está asociada a una organización"
        });
      }

    } else {

      idOrganizacionFinal =
        Number(id_organizacion) || null;


      if (!idOrganizacionFinal) {

        await connection.rollback();

        return res.status(400).json({
          success: false,
          message:
            "El Administrador Master debe indicar id_organizacion para registrar un psicólogo"
        });
      }

    }


    // --------------------------------------------------------
    // VALIDAR ORGANIZACIÓN CLÍNICA
    // --------------------------------------------------------

    const [organizaciones] =
      await connection.query(
        `
          SELECT
            id_organizacion,
            nombre,
            nombre_comercial,
            tipo,
            estado
          FROM organizaciones
          WHERE id_organizacion = ?
          LIMIT 1
          FOR UPDATE
        `,
        [idOrganizacionFinal]
      );


    if (!organizaciones.length) {

      await connection.rollback();

      return res.status(404).json({
        success: false,
        message: "La organización no existe"
      });
    }


    const organizacion =
      organizaciones[0];


    if (
      String(organizacion.estado || "")
        .trim()
        .toLowerCase() !== "activa"
    ) {

      await connection.rollback();

      return res.status(403).json({
        success: false,
        code: "ORGANIZACION_NO_ACTIVA",
        message:
          "La organización no está activa"
      });
    }


    if (
      String(organizacion.tipo || "")
        .trim()
        .toLowerCase() !== "clinica"
    ) {

      await connection.rollback();

      return res.status(403).json({
        success: false,
        message:
          "La organización seleccionada no corresponde al área Clínica"
      });
    }


    // --------------------------------------------------------
    // CÉDULA DUPLICADA
    // --------------------------------------------------------

    const [cedulasExistentes] =
      await connection.query(
        `
          SELECT
            id_psicologo
          FROM psicologos
          WHERE cedula_profesional = ?
          LIMIT 1
          FOR UPDATE
        `,
        [cedulaNormalizada]
      );


    if (cedulasExistentes.length) {

      await connection.rollback();

      return res.status(409).json({
        success: false,
        code: "CEDULA_EXISTENTE",
        message:
          "La cédula profesional ya está registrada"
      });
    }


    // --------------------------------------------------------
    // SUSCRIPCIÓN
    // --------------------------------------------------------

    const [suscripciones] =
      await connection.query(
        `
          SELECT
            s.id_suscripcion,
            s.id_organizacion,
            s.id_plan,
            s.estado,
            s.proxima_renovacion,
            s.licencias_totales
          FROM suscripciones s
          WHERE
            s.id_organizacion = ?
            AND s.estado IN ('activa', 'prueba')
            AND (
              s.proxima_renovacion IS NULL
              OR CURDATE() <= DATE_ADD(
                s.proxima_renovacion,
                INTERVAL 3 DAY
              )
            )
          ORDER BY
            s.id_suscripcion DESC
          LIMIT 1
          FOR UPDATE
        `,
        [idOrganizacionFinal]
      );


    if (!suscripciones.length) {

      await connection.rollback();

      return res.status(403).json({
        success: false,
        code: "SUSCRIPCION_NO_ACTIVA",
        message:
          "La organización no tiene una suscripción Clínica activa"
      });
    }


    const suscripcion =
      suscripciones[0];


    // --------------------------------------------------------
    // LICENCIA PSICÓLOGO
    // --------------------------------------------------------

    const [licencias] =
      await connection.query(
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
            AND tipo = 'psicologo'
            AND estado = 'disponible'
            AND id_usuario IS NULL
          ORDER BY
            id_licencia ASC
          LIMIT 1
          FOR UPDATE
        `,
        [suscripcion.id_suscripcion]
      );


    if (!licencias.length) {

      await connection.rollback();

      return res.status(409).json({
        success: false,
        code: "SIN_LICENCIAS",
        message:
          "Has utilizado todas las licencias de tu plan. Amplía tu paquete para agregar más psicólogos."
      });
    }


    const licencia =
      licencias[0];


    // --------------------------------------------------------
    // MATRÍCULA
    // Ejemplo: MS-CLI-001-0001
    // --------------------------------------------------------

    const matricula =
      await generarMatricula({
        idOrganizacion:
          idOrganizacionFinal,
        area:
          "clinica",
        connection
      });


    // --------------------------------------------------------
    // CONTRASEÑA TEMPORAL
    // --------------------------------------------------------

    const passwordTemporal =
      `Ms!${
        crypto
          .randomBytes(4)
          .toString("hex")
          .toUpperCase()
      }`;


    const passwordHash =
      await bcrypt.hash(
        passwordTemporal,
        10
      );


    // --------------------------------------------------------
    // CREAR USUARIO
    // --------------------------------------------------------

    const [usuarioInsertado] =
      await connection.query(
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
            NULL,
            ?,
            ?,
            1,
            'psicologo',
            NULL,
            'clinica',
            ?,
            ?,
            'activo',
            ?,
            ?
          )
        `,
        [
          nombreNormalizado,
          matricula,
          passwordHash,
          idAdmin,
          idOrganizacionFinal,
          telefonoNormalizado,
          direccionNormalizada
        ]
      );


    const idUsuarioNuevo =
      usuarioInsertado.insertId;


    // --------------------------------------------------------
    // CREAR PSICÓLOGO
    // --------------------------------------------------------

    const [psicologoInsertado] =
      await connection.query(
        `
          INSERT INTO psicologos
          (
            id_usuario,
            cedula_profesional,
            especialidad,
            telefono,
            direccion,
            fecha_nacimiento
          )
          VALUES
          (
            ?,
            ?,
            ?,
            ?,
            ?,
            ?
          )
        `,
        [
          idUsuarioNuevo,
          cedulaNormalizada,
          especialidadNormalizada,
          telefonoNormalizado,
          direccionNormalizada,
          fechaNacimientoNormalizada
        ]
      );


    const idPsicologo =
      psicologoInsertado.insertId;


    // --------------------------------------------------------
    // ASIGNAR LICENCIA
    // --------------------------------------------------------

    const [licenciaActualizada] =
      await connection.query(
        `
          UPDATE licencias
          SET
            id_usuario = ?,
            estado = 'asignada',
            fecha_asignacion = NOW(),
            fecha_liberacion = NULL
          WHERE
            id_licencia = ?
            AND estado = 'disponible'
            AND id_usuario IS NULL
        `,
        [
          idUsuarioNuevo,
          licencia.id_licencia
        ]
      );


    if (
      licenciaActualizada.affectedRows !== 1
    ) {

      await connection.rollback();

      return res.status(409).json({
        success: false,
        code: "LICENCIA_NO_DISPONIBLE",
        message:
          "La licencia ya no está disponible. Intenta nuevamente."
      });
    }


    // --------------------------------------------------------
    // COMMIT
    // --------------------------------------------------------

    await connection.commit();


    return res.status(201).json({

      success: true,

      message:
        "Psicólogo registrado correctamente y licencia asignada",

      usuario: {

        id_usuario:
          idUsuarioNuevo,

        id_psicologo:
          idPsicologo,

        nombre:
          nombreNormalizado,

        correo:
          null,

        matricula,

        rol:
          "psicologo",

        area:
          "clinica",

        especialidad:
          especialidadNormalizada,

        cedula_profesional:
          cedulaNormalizada,

        telefono:
          telefonoNormalizado,

        direccion:
          direccionNormalizada,

        fecha_nacimiento:
          fechaNacimientoNormalizada,

        id_admin_padre:
          idAdmin,

        id_organizacion:
          idOrganizacionFinal,

        id_licencia:
          licencia.id_licencia,

        estado:
          "activo",

        debe_cambiar_password:
          1
      },

      credenciales: {

        matricula,

        password_temporal:
          passwordTemporal
      }

    });


  } catch (err) {

    if (connection) {

      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error(
          "❌ Error haciendo rollback psicólogo:",
          rollbackError
        );
      }

    }


    console.error(
      "❌ Error registrando psicólogo:",
      err
    );


    if (
      err?.code === "ER_DUP_ENTRY"
    ) {

      return res.status(409).json({
        success: false,
        message:
          "No fue posible generar una matrícula única. Intenta nuevamente."
      });
    }


    return res.status(500).json({

      success: false,

      message:
        "Error interno al registrar psicólogo",

      error:
        process.env.NODE_ENV === "development"
          ? err.message
          : undefined

    });


  } finally {

    if (connection) {
      connection.release();
    }

  }

}


// ============================================================
// REGISTRAR ADMINISTRADOR NORMAL
// ============================================================

export async function registerAdmin(
  req,
  res
) {

  try {

    // --------------------------------------------------------
    // SOLO ADMIN
    // --------------------------------------------------------

    if (
      Number(req.user?.role) !== 1
    ) {

      return res.status(403).json({
        success: false,
        message:
          "Acceso denegado: solo administradores"
      });
    }


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
        success: false,
        message:
          "Acceso denegado: solo el Administrador Master puede crear administradores"
      });
    }


    // --------------------------------------------------------
    // DATOS
    // --------------------------------------------------------

    const {
      nombre,
      correo,
      password,
      area,
      id_organizacion
    } = req.body;


    if (
      !nombre ||
      !correo ||
      !password
    ) {

      return res.status(400).json({
        success: false,
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

    const areaNormalizada =
      area
        ? String(area)
            .trim()
            .toLowerCase()
        : null;


    if (
      nombreNormalizado.length < 2
    ) {

      return res.status(400).json({
        success: false,
        message:
          "El nombre no es válido"
      });
    }


    if (
      String(password).length < 6
    ) {

      return res.status(400).json({
        success: false,
        message:
          "La contraseña debe tener al menos 6 caracteres"
      });
    }


    const areasPermitidas = [
      "clinica",
      "rh",
      "educativo"
    ];


    if (
      !areaNormalizada ||
      !areasPermitidas.includes(
        areaNormalizada
      )
    ) {

      return res.status(400).json({
        success: false,
        message:
          "El área seleccionada no es válida"
      });
    }


    // --------------------------------------------------------
    // CORREO DUPLICADO
    // --------------------------------------------------------

    const [usuariosExistentes] =
      await pool.query(
        `
          SELECT
            id_usuario
          FROM usuarios
          WHERE correo = ?
          LIMIT 1
        `,
        [correoNormalizado]
      );


    if (
      usuariosExistentes.length
    ) {

      return res.status(409).json({
        success: false,
        message:
          "El correo ya está registrado"
      });
    }


    // --------------------------------------------------------
    // ORGANIZACIÓN OPCIONAL
    //
    // Si se envía, verificamos que corresponda al área.
    // --------------------------------------------------------

    let idOrganizacionFinal =
      Number(id_organizacion) || null;


    if (
      idOrganizacionFinal
    ) {

      const [organizaciones] =
        await pool.query(
          `
            SELECT
              id_organizacion,
              tipo,
              estado
            FROM organizaciones
            WHERE id_organizacion = ?
            LIMIT 1
          `,
          [idOrganizacionFinal]
        );


      if (!organizaciones.length) {

        return res.status(404).json({
          success: false,
          message:
            "La organización no existe"
        });
      }


      const organizacion =
        organizaciones[0];


      if (
        String(organizacion.estado || "")
          .trim()
          .toLowerCase() !== "activa"
      ) {

        return res.status(403).json({
          success: false,
          message:
            "La organización no está activa"
        });
      }


      if (
        String(organizacion.tipo || "")
          .trim()
          .toLowerCase() !==
        areaNormalizada
      ) {

        return res.status(400).json({
          success: false,
          message:
            "El área del administrador no corresponde al tipo de organización"
        });
      }

    }


    // --------------------------------------------------------
    // PASSWORD
    // --------------------------------------------------------

    const passwordHash =
      await bcrypt.hash(
        password,
        10
      );


    // --------------------------------------------------------
    // INSERTAR ADMIN
    // --------------------------------------------------------

    const [resultado] =
      await pool.query(
        `
          INSERT INTO usuarios
          (
            nombre,
            correo,
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
            0,
            'admin',
            'normal',
            ?,
            ?,
            ?,
            'activo'
          )
        `,
        [
          nombreNormalizado,
          correoNormalizado,
          passwordHash,
          areaNormalizada,
          req.user.id_usuario,
          idOrganizacionFinal
        ]
      );


    return res.status(201).json({

      success: true,

      message:
        "Administrador normal creado correctamente",

      administrador: {

        id_usuario:
          resultado.insertId,

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
          req.user.id_usuario,

        id_organizacion:
          idOrganizacionFinal,

        estado:
          "activo"
      }

    });


  } catch (err) {

    console.error(
      "❌ Error al registrar administrador:",
      err
    );


    return res.status(500).json({

      success: false,

      message:
        "Error interno al registrar administrador",

      error:
        process.env.NODE_ENV === "development"
          ? err.message
          : undefined

    });

  }

}


// ============================================================
// LOGIN
//
// ADMINISTRADORES:
// correo + contraseña
//
// PSICÓLOGO / RH / EDUCATIVO:
// matrícula + contraseña
//
// INDEPENDIENTE:
// correo + contraseña
//
// COMPATIBILIDAD:
// todavía acepta "correo" desde frontend anterior.
// ============================================================

export async function login(
  req,
  res
) {

  try {

    const {
      identificador,
      correo,
      password
    } = req.body;


    const acceso =
      identificador ||
      correo;


    // --------------------------------------------------------
    // VALIDAR
    // --------------------------------------------------------

    if (
      !acceso ||
      !password
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Faltan correo o matrícula y contraseña"
      });

    }


    const accesoNormalizado =
      String(
        acceso
      ).trim();


    if (
      !accesoNormalizado
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Ingresa tu correo o matrícula"
      });

    }


    // --------------------------------------------------------
    // BUSCAR POR CORREO O MATRÍCULA
    //
    // AHORA TAMBIÉN LEEMOS LA ORGANIZACIÓN.
    // --------------------------------------------------------

    const [rows] =
      await pool.query(
        `
          SELECT

            u.id_usuario,
            u.nombre,
            u.correo,
            u.matricula,
            u.password,
            u.debe_cambiar_password,
            u.rol,
            u.tipo_admin,
            u.area,
            u.id_admin_padre,
            u.id_organizacion,
            u.estado,

            o.tipo AS tipo_organizacion,

            o.perfil_independiente,

            o.estado AS estado_organizacion

          FROM usuarios u

          LEFT JOIN organizaciones o
            ON o.id_organizacion =
               u.id_organizacion

          WHERE

            (
              u.correo IS NOT NULL

              AND LOWER(
                TRIM(
                  u.correo
                )
              ) =
              LOWER(
                TRIM(
                  ?
                )
              )
            )

            OR

            (
              u.matricula IS NOT NULL

              AND UPPER(
                TRIM(
                  u.matricula
                )
              ) =
              UPPER(
                TRIM(
                  ?
                )
              )
            )

          LIMIT 1
        `,
        [
          accesoNormalizado,
          accesoNormalizado
        ]
      );


    if (!rows.length) {

      return res.status(401).json({
        success: false,
        message:
          "Credenciales inválidas"
      });

    }


    const user =
      rows[0];


    // --------------------------------------------------------
    // NORMALIZACIONES
    // --------------------------------------------------------

    const rolNormalizado =
      String(
        user.rol ||
        ""
      )
        .trim()
        .toLowerCase();


    const areaNormalizada =
      user.area
        ? String(
            user.area
          )
            .trim()
            .toLowerCase()
        : null;


    const tipoAdminNormalizado =
      user.tipo_admin
        ? String(
            user.tipo_admin
          )
            .trim()
            .toLowerCase()
        : null;


    const tipoOrganizacion =
      user.tipo_organizacion
        ? String(
            user.tipo_organizacion
          )
            .trim()
            .toLowerCase()
        : null;


    const perfilIndependiente =
      user.perfil_independiente
        ? String(
            user.perfil_independiente
          )
            .trim()
            .toLowerCase()
        : null;


    const estadoOrganizacion =
      user.estado_organizacion
        ? String(
            user.estado_organizacion
          )
            .trim()
            .toLowerCase()
        : null;


    // --------------------------------------------------------
    // ESTADO
    // --------------------------------------------------------

    if (
      String(
        user.estado ||
        "activo"
      )
        .trim()
        .toLowerCase() !== "activo"
    ) {

      return res.status(403).json({
        success: false,
        code: "USUARIO_INACTIVO",
        message:
          "Tu cuenta está inactiva. Contacta al administrador de tu organización."
      });

    }


    // --------------------------------------------------------
    // PASSWORD
    // --------------------------------------------------------

    const passwordCorrecta =
      await bcrypt.compare(
        password,
        user.password
      );


    if (
      !passwordCorrecta
    ) {

      return res.status(401).json({
        success: false,
        message:
          "Credenciales inválidas"
      });

    }


    // --------------------------------------------------------
    // PSICÓLOGO
    // --------------------------------------------------------

    let id_psicologo =
      null;


    if (
      rolNormalizado ===
      "psicologo"
    ) {

      const [psicologos] =
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
        psicologos[0]
          ?.id_psicologo ||
        null;

    }


    // --------------------------------------------------------
    // ROLE NUMÉRICO
    // --------------------------------------------------------

    const roleNumber =
      rolNormalizado ===
      "admin"
        ? 1
        : 2;


    const debeCambiarPassword =
      Number(
        user.debe_cambiar_password ||
        0
      ) === 1;


    // --------------------------------------------------------
    // JWT
    //
    // IMPORTANTE:
    // perfil_independiente se guarda en el token.
    // --------------------------------------------------------

    const token =
      jwt.sign(
        {

          id_usuario:
            user.id_usuario,

          role:
            roleNumber,

          id_psicologo,

          rol:
            rolNormalizado,

          tipo_admin:
            tipoAdminNormalizado,

          area:
            areaNormalizada,

          id_admin_padre:
            user.id_admin_padre ||
            null,

          id_organizacion:
            user.id_organizacion ||
            null,

          perfil_independiente:
            perfilIndependiente,

          tipo_organizacion:
            tipoOrganizacion,

          estado_organizacion:
            estadoOrganizacion,

          estado:
            user.estado ||
            "activo",

          matricula:
            user.matricula ||
            null,

          debe_cambiar_password:
            debeCambiarPassword
              ? 1
              : 0

        },

        process.env.JWT_SECRET,

        {
          expiresIn:
            "8h"
        }
      );


    // --------------------------------------------------------
    // LOG LOGIN
    // --------------------------------------------------------

    console.log(
      "🔐 LOGIN:",
      {

        id_usuario:
          user.id_usuario,

        rol:
          rolNormalizado,

        area:
          areaNormalizada,

        id_organizacion:
          user.id_organizacion ||
          null,

        tipo_organizacion:
          tipoOrganizacion,

        perfil_independiente:
          perfilIndependiente,

        estado_organizacion:
          estadoOrganizacion

      }
    );


    // --------------------------------------------------------
    // RESPUESTA
    // --------------------------------------------------------

    return res.json({

      success: true,

      message:
        "Login exitoso",

      requiere_cambio_password:
        debeCambiarPassword,

      user: {

        id_usuario:
          user.id_usuario,

        nombre:
          user.nombre,

        correo:
          user.correo ||
          null,

        matricula:
          user.matricula ||
          null,

        role:
          roleNumber,

        rol:
          rolNormalizado,

        tipo_admin:
          tipoAdminNormalizado,

        area:
          areaNormalizada,

        id_admin_padre:
          user.id_admin_padre ||
          null,

        id_organizacion:
          user.id_organizacion ||
          null,

        perfil_independiente:
          perfilIndependiente,

        tipo_organizacion:
          tipoOrganizacion,

        estado_organizacion:
          estadoOrganizacion,

        estado:
          user.estado ||
          "activo",

        debe_cambiar_password:
          debeCambiarPassword
            ? 1
            : 0,

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

      success: false,

      message:
        "Error en login",

      error:
        process.env.NODE_ENV ===
        "development"
          ? err.message
          : undefined

    });

  }

}


// ============================================================
// CAMBIAR CONTRASEÑA
//
// Si era contraseña temporal:
// debe_cambiar_password pasa de 1 a 0.
// ============================================================

export async function changePassword(
  req,
  res
) {

  try {

    const {
      oldPassword,
      newPassword
    } = req.body;


    const id_usuario =
      req.user?.id_usuario;


    if (
      !id_usuario
    ) {

      return res.status(401).json({
        success: false,
        message:
          "Usuario no autenticado"
      });

    }


    // --------------------------------------------------------
    // VALIDAR
    // --------------------------------------------------------

    if (
      !oldPassword ||
      !newPassword
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Faltan datos"
      });

    }


    if (
      String(newPassword).length < 6
    ) {

      return res.status(400).json({
        success: false,
        message:
          "La nueva contraseña debe tener al menos 6 caracteres"
      });

    }


    if (
      String(oldPassword) ===
      String(newPassword)
    ) {

      return res.status(400).json({
        success: false,
        message:
          "La nueva contraseña debe ser diferente a la contraseña temporal o actual"
      });

    }


    // --------------------------------------------------------
    // USUARIO
    // --------------------------------------------------------

    const [rows] =
      await pool.query(
        `
          SELECT
            password,
            estado,
            debe_cambiar_password
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
        success: false,
        message:
          "Usuario no encontrado"
      });

    }


    const usuario =
      rows[0];


    if (
      String(
        usuario.estado ||
        "activo"
      )
        .trim()
        .toLowerCase() !== "activo"
    ) {

      return res.status(403).json({
        success: false,
        code:
          "USUARIO_INACTIVO",
        message:
          "La cuenta está inactiva"
      });

    }


    // --------------------------------------------------------
    // PASSWORD ACTUAL
    // --------------------------------------------------------

    const passwordCorrecta =
      await bcrypt.compare(
        oldPassword,
        usuario.password
      );


    if (
      !passwordCorrecta
    ) {

      return res.status(401).json({
        success: false,
        message:
          "La contraseña actual es incorrecta"
      });

    }


    // --------------------------------------------------------
    // NUEVA PASSWORD
    // --------------------------------------------------------

    const passwordHash =
      await bcrypt.hash(
        newPassword,
        10
      );


    await pool.query(
      `
        UPDATE usuarios
        SET
          password = ?,
          debe_cambiar_password = 0
        WHERE id_usuario = ?
      `,
      [
        passwordHash,
        id_usuario
      ]
    );


    return res.json({

      success: true,

      message:
        "Contraseña actualizada correctamente",

      debe_cambiar_password:
        0

    });


  } catch (err) {

    console.error(
      "❌ Error al cambiar contraseña:",
      err
    );


    return res.status(500).json({
      success: false,
      message:
        "Error interno al cambiar contraseña"
    });

  }

}
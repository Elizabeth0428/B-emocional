// backend/controllers/pacienteController.js

import pool from "../config/database.js";


/* ==================================================
   GENERAR ID MIRRORSOUL

   Formato:

   MS-2026-18-FE-001

   MS   = MirrorSoul
   2026 = año de registro
   18   = edad
   FE   = sexo femenino
   MA   = sexo masculino
   XX   = sexo no especificado
   001  = CONSECUTIVO GLOBAL

   IMPORTANTE:

   El consecutivo NO se obtiene de pacientes.

   Se obtiene de la tabla:

   mirror_ids

   Esto permite que el consecutivo sea global
   entre:

   - pacientes
   - prospectos
   - empleados
   - estudiantes

   Y NO se utiliza para:

   - psicólogos
   - administradores
   - RH
   - educativo
   - otros usuarios
================================================== */

async function generarIdMirror(
  edad,
  sexo,
  connection
) {

  const añoActual =
    new Date().getFullYear();


  const edadNormalizada =
    Number.isFinite(Number(edad))
      ? Number(edad)
      : 0;


  const sexoNormalizado =
    String(sexo || "")
      .toUpperCase()
      .trim();


  const codigoSexo =
    sexoNormalizado === "F"
      ? "FE"
      : sexoNormalizado === "M"
        ? "MA"
        : "XX";


  /* ==================================================
     BUSCAR SIGUIENTE CONSECUTIVO GLOBAL

     FOR UPDATE evita que dos registros reciban
     el mismo consecutivo al mismo tiempo.

     IMPORTANTE:
     Esta función debe ejecutarse dentro de una
     transacción.
  ================================================== */

  const [
    rows
  ] = await connection.query(
    `
    SELECT
      consecutivo
    FROM mirror_ids
    WHERE año = ?
    ORDER BY consecutivo DESC
    LIMIT 1
    FOR UPDATE
    `,
    [
      añoActual
    ]
  );


  let consecutivo = 1;


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
    String(consecutivo)
      .padStart(3, "0");


  const id_mirror =
    `MS-${añoActual}-${edadNormalizada}-${codigoSexo}-${numero}`;


  return {
    id_mirror,
    consecutivo,
    año: añoActual
  };

}


/* ==================================================
   OBTENER DATOS DEL ADMINISTRADOR
================================================== */

function obtenerDatosAdmin(req) {

  const tipoAdmin =
    req.user?.tipo_admin
      ? String(
          req.user.tipo_admin
        )
          .trim()
          .toLowerCase()
      : null;


  const idAdmin =
    req.user?.id_usuario || null;


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


/* ==================================================
   LISTAR PACIENTES

   PSICÓLOGO:
   - Solo sus propios pacientes.

   ADMIN MASTER:
   - Todos los pacientes.

   ADMIN NORMAL:
   - Pacientes de los psicólogos que él creó.
   - Solo de su propia área.

   Esto aplica para:
   - clínica
   - RH
   - educativo
   - independiente
================================================== */

export async function listarPacientes(
  req,
  res
) {

  try {

    /* ==================================================
       VALIDAR SESIÓN
    ================================================== */

    if (!req.user) {

      return res.status(401).json({
        message:
          "Sesión no válida"
      });

    }


    /* ==================================================
       PSICÓLOGO
    ================================================== */

    if (
      req.user.role === 2
    ) {

      if (
        !req.user.id_psicologo
      ) {

        return res.status(403).json({
          message:
            "El usuario no tiene configurado su psicólogo"
        });

      }


      const [
        rows
      ] = await pool.query(
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
          req.user.id_psicologo
        ]
      );


      return res.json(
        rows || []
      );

    }


    /* ==================================================
       ADMINISTRADORES
    ================================================== */

    if (
      req.user.role === 1
    ) {

      const {
        tipoAdmin,
        idAdmin,
        areaAdmin
      } =
        obtenerDatosAdmin(req);


      /* ================================================
         ADMIN MASTER
      ================================================ */

      if (
        tipoAdmin === "master"
      ) {

        const [
          rows
        ] = await pool.query(
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

            u.id_usuario AS id_usuario_psicologo,
            u.nombre AS nombre_psicologo,
            u.correo AS correo_psicologo,
            u.area AS area_psicologo

          FROM pacientes p

          INNER JOIN psicologos ps
            ON p.id_psicologo =
               ps.id_psicologo

          INNER JOIN usuarios u
            ON ps.id_usuario =
               u.id_usuario

          WHERE
            u.rol = 'psicologo'

          ORDER BY
            p.id_paciente DESC
          `
        );


        return res.json(
          rows || []
        );

      }


      /* ================================================
         ADMIN NORMAL
      ================================================ */

      if (
        tipoAdmin === "normal"
      ) {

        if (
          !idAdmin ||
          !areaAdmin
        ) {

          return res.status(403).json({
            message:
              "El administrador no tiene configurados correctamente su ID o área"
          });

        }


        const [
          rows
        ] = await pool.query(
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

            u.id_usuario AS id_usuario_psicologo,
            u.nombre AS nombre_psicologo,
            u.correo AS correo_psicologo,
            u.area AS area_psicologo

          FROM pacientes p

          INNER JOIN psicologos ps
            ON p.id_psicologo =
               ps.id_psicologo

          INNER JOIN usuarios u
            ON ps.id_usuario =
               u.id_usuario

          WHERE
            u.rol = 'psicologo'

            AND u.id_admin_padre = ?

            AND LOWER(
              TRIM(u.area)
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


      /* ================================================
         TIPO DE ADMINISTRADOR INVÁLIDO
      ================================================ */

      return res.status(403).json({
        message:
          "Tipo de administrador inválido"
      });

    }


    /* ==================================================
       OTROS ROLES
    ================================================== */

    return res.status(403).json({
      message:
        "Acceso denegado"
    });


  } catch (err) {

    console.error(
      "❌ Error al obtener pacientes:",
      err
    );


    return res.status(500).json({
      message:
        "Error al obtener pacientes"
    });

  }

}


/* ==================================================
   OBTENER PACIENTE POR ID

   PSICÓLOGO:
   - Solo sus pacientes.

   ADMIN MASTER:
   - Cualquier paciente.

   ADMIN NORMAL:
   - Pacientes de sus psicólogos.
================================================== */

export async function obtenerPaciente(
  req,
  res
) {

  const {
    id
  } = req.params;


  try {

    const [
      rows
    ] = await pool.query(
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

        u.id_usuario AS id_usuario_psicologo,
        u.nombre AS nombre_psicologo,
        u.area AS area_psicologo,
        u.id_admin_padre

      FROM pacientes p

      INNER JOIN psicologos ps
        ON p.id_psicologo =
           ps.id_psicologo

      INNER JOIN usuarios u
        ON ps.id_usuario =
           u.id_usuario

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

      return res.status(404).json({
        message:
          "Paciente no encontrado"
      });

    }


    const paciente =
      rows[0];


    /* ==================================================
       PSICÓLOGO
    ================================================== */

    if (
      req.user?.role === 2
    ) {

      if (
        Number(
          req.user.id_psicologo
        ) !==
        Number(
          paciente.id_psicologo
        )
      ) {

        return res.status(403).json({
          message:
            "No tienes acceso a este paciente"
        });

      }


      return res.json(
        paciente
      );

    }


    /* ==================================================
       ADMIN MASTER
    ================================================== */

    if (
      req.user?.role === 1 &&
      String(
        req.user?.tipo_admin || ""
      )
        .trim()
        .toLowerCase() ===
        "master"
    ) {

      return res.json(
        paciente
      );

    }


    /* ==================================================
       ADMIN NORMAL
    ================================================== */

    if (
      req.user?.role === 1 &&
      String(
        req.user?.tipo_admin || ""
      )
        .trim()
        .toLowerCase() ===
        "normal"
    ) {

      const idAdmin =
        req.user?.id_usuario;


      const areaAdmin =
        req.user?.area
          ? String(
              req.user.area
            )
              .trim()
              .toLowerCase()
          : null;


      const areaPaciente =
        paciente.area_psicologo
          ? String(
              paciente.area_psicologo
            )
              .trim()
              .toLowerCase()
          : null;


      if (
        !idAdmin ||
        !areaAdmin
      ) {

        return res.status(403).json({
          message:
            "El administrador no tiene configurados correctamente su ID o área"
        });

      }


      if (
        Number(
          paciente.id_admin_padre
        ) !==
        Number(
          idAdmin
        )
      ) {

        return res.status(403).json({
          message:
            "No tienes acceso a este paciente"
        });

      }


      if (
        areaPaciente !==
        areaAdmin
      ) {

        return res.status(403).json({
          message:
            "No tienes acceso a pacientes de otra área"
        });

      }


      return res.json(
        paciente
      );

    }


    return res.status(403).json({
      message:
        "Acceso denegado"
    });


  } catch (err) {

    console.error(
      "❌ Error al obtener paciente:",
      err
    );


    return res.status(500).json({
      message:
        "Error al obtener paciente"
    });

  }

}


/* ==================================================
   REGISTRAR PACIENTE

   PSICÓLOGO:
   - Puede registrar pacientes.

   ADMIN:
   - Puede registrar pacientes para un psicólogo
     de su propia área.

   GENERACIÓN DE ID:
   - Usa consecutivo GLOBAL.
   - Se registra en mirror_ids.
================================================== */

export async function registrarPaciente(
  req,
  res
) {

  let connection;


  try {

    /* ==================================================
       VALIDAR SESIÓN
    ================================================== */

    if (!req.user) {

      return res.status(401).json({
        message:
          "Sesión no válida"
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
    } = req.body;


    /* ==================================================
       VALIDAR NOMBRE
    ================================================== */

    if (
      !nombre ||
      !String(nombre).trim()
    ) {

      return res.status(400).json({
        message:
          "El nombre del paciente es obligatorio"
      });

    }


    let idPsicologoFinal =
      null;


    /* ==================================================
       PSICÓLOGO
    ================================================== */

    if (
      req.user.role === 2
    ) {

      idPsicologoFinal =
        req.user.id_psicologo;


      if (
        !idPsicologoFinal
      ) {

        return res.status(403).json({
          message:
            "El usuario no tiene configurado su psicólogo"
        });

      }

    }


    /* ==================================================
       ADMINISTRADOR
    ================================================== */

    else if (
      req.user.role === 1
    ) {

      const {
        tipoAdmin,
        idAdmin,
        areaAdmin
      } =
        obtenerDatosAdmin(req);


      /* ================================================
         MASTER
      ================================================ */

      if (
        tipoAdmin === "master"
      ) {

        if (
          !id_psicologo
        ) {

          return res.status(400).json({
            message:
              "Debes seleccionar el psicólogo responsable del paciente"
          });

        }


        idPsicologoFinal =
          Number(
            id_psicologo
          );

      }


      /* ================================================
         ADMIN NORMAL
      ================================================ */

      else if (
        tipoAdmin === "normal"
      ) {

        if (
          !idAdmin ||
          !areaAdmin
        ) {

          return res.status(403).json({
            message:
              "El administrador no tiene configurados correctamente su ID o área"
          });

        }


        if (
          !id_psicologo
        ) {

          return res.status(400).json({
            message:
              "Debes seleccionar el psicólogo responsable del paciente"
          });

        }


        const [
          psicologoRows
        ] = await pool.query(
          `
          SELECT
            p.id_psicologo

          FROM psicologos p

          INNER JOIN usuarios u
            ON p.id_usuario =
               u.id_usuario

          WHERE
            p.id_psicologo = ?

            AND u.rol = 'psicologo'

            AND u.id_admin_padre = ?

            AND LOWER(
              TRIM(u.area)
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

          return res.status(403).json({
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

        return res.status(403).json({
          message:
            "Tipo de administrador inválido"
        });

      }

    }


    /* ==================================================
       OTRO ROL
    ================================================== */

    else {

      return res.status(403).json({
        message:
          "No tienes permisos para registrar pacientes"
      });

    }


    /* ==================================================
       OBTENER CONEXIÓN

       Todo se hace dentro de una transacción:

       1. Generar consecutivo
       2. Insertar paciente
       3. Registrar ID en mirror_ids

       Si algo falla:
       ROLLBACK

       Así evitamos IDs duplicados.
    ================================================== */

    connection =
      await pool.getConnection();


    await connection.beginTransaction();


    /* ==================================================
       GENERAR ID GLOBAL
    ================================================== */

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


    /* ==================================================
       INSERTAR PACIENTE
    ================================================== */

    const [
      result
    ] = await connection.query(
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
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        idPsicologoFinal,
        id_mirror,
        nombre,
        sexo || null,
        fecha_nacimiento || null,
        edad || null,
        correo || null,
        telefono || null,
        direccion || null,
        antecedentes || null
      ]
    );


    /* ==================================================
       REGISTRAR ID EN TABLA CENTRAL

       Aquí queda reservado el consecutivo
       globalmente.
    ================================================== */

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
      (?, ?, ?, 'paciente', ?)
      `,
      [
        id_mirror,
        consecutivo,
        año,
        result.insertId
      ]
    );


    /* ==================================================
       CONFIRMAR TRANSACCIÓN
    ================================================== */

    await connection.commit();


    /* ==================================================
       RESPUESTA
    ================================================== */

    return res.status(201).json({

      message:
        "✅ Paciente registrado correctamente",

      id_paciente:
        result.insertId,

      id_mirror,

      id_psicologo:
        idPsicologoFinal

    });


  } catch (err) {

    /* ==================================================
       DESHACER TRANSACCIÓN
    ================================================== */

    if (connection) {

      try {

        await connection.rollback();

      } catch (rollbackError) {

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


    /* ==================================================
       DUPLICADO DE ID
    ================================================== */

    if (
      err?.code ===
      "ER_DUP_ENTRY"
    ) {

      return res.status(409).json({
        message:
          "El ID MirrorSoul generado ya existe. Intenta nuevamente."
      });

    }


    return res.status(500).json({
      message:
        "Error al registrar paciente"
    });


  } finally {

    if (connection) {

      connection.release();

    }

  }

}


/* ==================================================
   REPORTES COMPLETOS DE UN PACIENTE

   IMPORTANTE:
   Antes de entregar información clínica,
   verificamos que el usuario tenga acceso
   al paciente.
================================================== */

export async function obtenerReportesCompletos(
  req,
  res
) {

  const {
    id
  } = req.params;


  try {

    /* ==================================================
       VALIDAR ACCESO AL PACIENTE
    ================================================== */

    const [
      pacienteAccessRows
    ] = await pool.query(
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

        u.area AS area_psicologo,
        u.id_admin_padre

      FROM pacientes p

      INNER JOIN psicologos ps
        ON p.id_psicologo =
           ps.id_psicologo

      INNER JOIN usuarios u
        ON ps.id_usuario =
           u.id_usuario

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

      return res.status(404).json({
        message:
          "Paciente no encontrado"
      });

    }


    const paciente =
      pacienteAccessRows[0];


    /* ==================================================
       VALIDAR PERMISOS
    ================================================== */

    let tieneAcceso =
      false;


    /* ================================================
       PSICÓLOGO
    ================================================ */

    if (
      req.user?.role === 2
    ) {

      tieneAcceso =
        Number(
          req.user.id_psicologo
        ) ===
        Number(
          paciente.id_psicologo
        );

    }


    /* ================================================
       ADMIN MASTER
    ================================================ */

    else if (
      req.user?.role === 1 &&
      String(
        req.user?.tipo_admin || ""
      )
        .trim()
        .toLowerCase() ===
        "master"
    ) {

      tieneAcceso =
        true;

    }


    /* ================================================
       ADMIN NORMAL
    ================================================ */

    else if (
      req.user?.role === 1 &&
      String(
        req.user?.tipo_admin || ""
      )
        .trim()
        .toLowerCase() ===
        "normal"
    ) {

      const idAdmin =
        req.user?.id_usuario;


      const areaAdmin =
        req.user?.area
          ? String(
              req.user.area
            )
              .trim()
              .toLowerCase()
          : null;


      const areaPaciente =
        paciente.area_psicologo
          ? String(
              paciente.area_psicologo
            )
              .trim()
              .toLowerCase()
          : null;


      tieneAcceso =
        Number(
          paciente.id_admin_padre
        ) ===
        Number(
          idAdmin
        )

        &&

        areaPaciente ===
        areaAdmin;

    }


    if (
      !tieneAcceso
    ) {

      return res.status(403).json({
        message:
          "No tienes autorización para consultar el expediente de este paciente"
      });

    }


    /* ==================================================
       1. HISTORIAL INICIAL
    ================================================== */

    const [
      historialInicial
    ] = await pool.query(
      `
      SELECT *
      FROM historial_inicial
      WHERE id_paciente = ?
      LIMIT 1
      `,
      [
        id
      ]
    );


    /* ==================================================
       2. RESULTADOS DE PRUEBAS
    ================================================== */

    const [
      resultados
    ] = await pool.query(
      `
      SELECT
        r.id_resultado,
        r.id_prueba,
        p.nombre AS prueba,
        r.puntaje_total,
        r.interpretacion,

        DATE_FORMAT(
          r.fecha,
          '%d/%m/%Y %H:%i'
        ) AS fecha

      FROM resultados_prueba r

      JOIN pruebas p
        ON r.id_prueba =
           p.id_prueba

      WHERE
        r.id_paciente = ?

      ORDER BY
        r.fecha DESC
      `,
      [
        id
      ]
    );


    /* ==================================================
       3. HISTORIAL DE SEGUIMIENTO
    ================================================== */

    const [
      seguimiento
    ] = await pool.query(
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


    /* ==================================================
       4. SESIONES + VIDEOS
    ================================================== */

    const [
      sesiones
    ] = await pool.query(
      `
      SELECT
        s.id_sesion,
        s.fecha,
        s.notas,

        GROUP_CONCAT(
          v.ruta_video
          SEPARATOR '||'
        ) AS videos

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


    /* ==================================================
       5. FORMATEAR VIDEOS
    ================================================== */

    const sesionesFormateadas =
      sesiones.map(
        (s) => ({

          ...s,

          videos:
            s.videos
              ? s.videos.split("||")
              : []

        })
      );


    /* ==================================================
       RESPUESTA
    ================================================== */

    return res.json({

      paciente,

      historialInicial:
        historialInicial[0] ||
        null,

      resultados,

      seguimiento,

      sesiones:
        sesionesFormateadas

    });


  } catch (err) {

    console.error(
      "❌ Error al obtener reportes completos:",
      err
    );


    return res.status(500).json({
      message:
        "Error al obtener reportes completos"
    });

  }

}
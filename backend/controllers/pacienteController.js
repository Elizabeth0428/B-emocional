// backend/controllers/pacienteController.js

import pool from "../config/database.js";


/* ==================================================
   GENERAR ID MIRRORSOUL

   Formato:
   MS-2026-18-FE-001

   MS   = MirrorSoul
   2026 = año de registro
   18   = edad
   FE   = sexo
   001  = consecutivo
================================================== */

async function generarIdMirror(edad, sexo) {

  const añoActual = new Date().getFullYear();

  const edadNormalizada =
    Number.isFinite(Number(edad))
      ? Number(edad)
      : 0;


  const sexoNormalizado =
    String(sexo || "").toUpperCase();


  const codigoSexo =
    sexoNormalizado === "F"
      ? "FE"
      : sexoNormalizado === "M"
        ? "MA"
        : "XX";


  /* ==================================================
     BUSCAR ÚLTIMO CONSECUTIVO
  ================================================== */

  const [rows] = await pool.query(
    `
    SELECT id_mirror
    FROM pacientes
    WHERE id_mirror IS NOT NULL
    ORDER BY id_paciente DESC
    LIMIT 1
    `
  );


  let consecutivo = 1;


  if (rows.length && rows[0].id_mirror) {

    const partes =
      rows[0].id_mirror.split("-");


    const ultimo =
      parseInt(partes[4], 10);


    if (!isNaN(ultimo)) {

      consecutivo =
        ultimo + 1;

    }

  }


  const numero =
    String(consecutivo).padStart(3, "0");


  return `MS-${añoActual}-${edadNormalizada}-${codigoSexo}-${numero}`;

}


/* ==================================================
   LISTAR PACIENTES
   Solo pacientes del psicólogo logueado
================================================== */

export async function listarPacientes(req, res) {

  try {

    if (req.user.role !== 2) {

      return res.status(403).json({
        message:
          "Acceso denegado: solo psicólogos"
      });

    }


    const [rows] = await pool.query(
      `
      SELECT
        id_paciente,
        id_mirror,
        nombre,
        sexo,
        fecha_nacimiento,
        edad,
        correo,
        telefono,
        direccion,
        antecedentes
      FROM pacientes
      WHERE id_psicologo = ?
      ORDER BY id_paciente DESC
      `,
      [req.user.id_psicologo]
    );


    res.json(rows || []);


  } catch (err) {

    console.error(
      "❌ Error al obtener pacientes:",
      err.message
    );


    res.status(500).json({
      message:
        "Error al obtener pacientes"
    });

  }

}


/* ==================================================
   OBTENER PACIENTE POR ID
================================================== */

export async function obtenerPaciente(req, res) {

  const { id } = req.params;


  try {

    const [rows] = await pool.query(
      `
      SELECT
        id_paciente,
        id_mirror,
        nombre,
        sexo,
        fecha_nacimiento,
        edad,
        correo,
        telefono,
        direccion,
        antecedentes
      FROM pacientes
      WHERE id_paciente = ?
      `,
      [id]
    );


    if (!rows.length) {

      return res.status(404).json({
        message:
          "Paciente no encontrado"
      });

    }


    res.json(rows[0]);


  } catch (err) {

    console.error(
      "❌ Error al obtener paciente:",
      err.message
    );


    res.status(500).json({
      message:
        "Error al obtener paciente"
    });

  }

}


/* ==================================================
   REGISTRAR PACIENTE
   Solo psicólogos
================================================== */

export async function registrarPaciente(req, res) {

  try {

    if (req.user.role !== 2) {

      return res.status(403).json({
        message:
          "Acceso denegado: solo psicólogos pueden registrar pacientes"
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
      antecedentes
    } = req.body;


    const id_psicologo =
      req.user?.id_psicologo;


    if (!id_psicologo || !nombre) {

      return res.status(400).json({
        message:
          "Faltan datos obligatorios (id_psicologo o nombre)"
      });

    }


    /* ==================================================
       GENERAR ID MIRRORSOUL
    ================================================== */

    const id_mirror =
      await generarIdMirror(
        edad,
        sexo
      );


    /* ==================================================
       INSERTAR PACIENTE
    ================================================== */

    const [result] = await pool.query(
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
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        id_psicologo,
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


    res.status(201).json({

      message:
        "✅ Paciente registrado correctamente",

      id_paciente:
        result.insertId,

      id_mirror

    });


  } catch (err) {

    console.error(
      "❌ Error al registrar paciente:",
      err.message
    );


    res.status(500).json({
      message:
        "Error al registrar paciente"
    });

  }

}


/* ==================================================
   REPORTES COMPLETOS DE UN PACIENTE
================================================== */

export async function obtenerReportesCompletos(
  req,
  res
) {

  const { id } = req.params;


  try {

    /* ==================================================
       1. DATOS DEL PACIENTE
    ================================================== */

    const [pacienteRows] = await pool.query(
      `
      SELECT
        id_paciente,
        id_mirror,
        nombre,
        sexo,
        fecha_nacimiento,
        edad,
        correo,
        telefono,
        direccion,
        antecedentes
      FROM pacientes
      WHERE id_paciente = ?
      `,
      [id]
    );


    if (!pacienteRows.length) {

      return res.status(404).json({
        message:
          "Paciente no encontrado"
      });

    }


    const paciente =
      pacienteRows[0];


    /* ==================================================
       2. HISTORIAL INICIAL
    ================================================== */

    const [historialInicial] =
      await pool.query(
        `
        SELECT *
        FROM historial_inicial
        WHERE id_paciente = ?
        LIMIT 1
        `,
        [id]
      );


    /* ==================================================
       3. RESULTADOS DE PRUEBAS
    ================================================== */

    const [resultados] =
      await pool.query(
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
          ON r.id_prueba = p.id_prueba
        WHERE r.id_paciente = ?
        ORDER BY r.fecha DESC
        `,
        [id]
      );


    /* ==================================================
       4. HISTORIAL DE SEGUIMIENTO
    ================================================== */

    const [seguimiento] =
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
        WHERE id_paciente = ?
        ORDER BY fecha DESC
        `,
        [id]
      );


    /* ==================================================
       5. SESIONES + VIDEOS
    ================================================== */

    const [sesiones] =
      await pool.query(
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
          ON v.id_sesion = s.id_sesion
        WHERE s.id_paciente = ?
        GROUP BY
          s.id_sesion
        ORDER BY
          s.fecha DESC
        `,
        [id]
      );


    /* ==================================================
       FORMATEAR VIDEOS
    ================================================== */

    const sesionesFormateadas =
      sesiones.map((s) => ({

        ...s,

        videos: s.videos
          ? s.videos.split("||")
          : []

      }));


    /* ==================================================
       RESPUESTA
    ================================================== */

    res.json({

      paciente,

      historialInicial:
        historialInicial[0] || null,

      resultados,

      seguimiento,

      sesiones:
        sesionesFormateadas

    });


  } catch (err) {

    console.error(
      "❌ Error al obtener reportes completos:",
      err.message
    );


    res.status(500).json({
      message:
        "Error al obtener reportes completos"
    });

  }

}
import crypto from "crypto";
import pool from "../config/database.js";
import {
  generarReporteIAConMeta
} from "../svc/aiService.js";

// ==================================================
// AUXILIARES: CONTEXTO Y ACCESO NOM-035
// ==================================================


// ==================================================
// AUXILIARES: CALIFICACIÓN OFICIAL GUÍAS II Y III
// NOM-035-STPS-2018
// ==================================================

const clasificarPorCortes = (
  puntaje,
  cortes
) => {
  const valor =
    Number(puntaje) || 0;

  if (valor < cortes[0]) {
    return "nulo";
  }

  if (valor < cortes[1]) {
    return "bajo";
  }

  if (valor < cortes[2]) {
    return "medio";
  }

  if (valor < cortes[3]) {
    return "alto";
  }

  return "muy_alto";
};

const obtenerCortesNom035 = guia => {
  if (guia === "II") {
    return {
      final: [20, 45, 70, 90],

      categorias: {
        "Ambiente de trabajo":
          [3, 5, 7, 9],

        "Factores propios de la actividad":
          [10, 20, 30, 40],

        "Organización del tiempo de trabajo":
          [4, 6, 9, 12],

        "Liderazgo y relaciones en el trabajo":
          [10, 18, 28, 38]
      },

      dominios: {
        "Condiciones en el ambiente de trabajo":
          [3, 5, 7, 9],

        "Carga de trabajo":
          [12, 16, 20, 24],

        "Falta de control sobre el trabajo":
          [5, 8, 11, 14],

        "Jornada de trabajo":
          [1, 2, 4, 6],

        "Interferencia en la relación trabajo-familia":
          [1, 2, 4, 6],

        "Liderazgo":
          [3, 5, 8, 11],

        "Relaciones en el trabajo":
          [5, 8, 11, 14],

        "Violencia":
          [7, 10, 13, 16]
      }
    };
  }

  if (guia === "III") {
    return {
      final: [50, 75, 99, 140],

      categorias: {
        "Ambiente de trabajo":
          [5, 9, 11, 14],

        "Factores propios de la actividad":
          [15, 30, 45, 60],

        "Organización del tiempo de trabajo":
          [5, 7, 10, 13],

        "Liderazgo y relaciones en el trabajo":
          [14, 29, 42, 58],

        "Entorno organizacional":
          [10, 14, 18, 23]
      },

      dominios: {
        "Condiciones en el ambiente de trabajo":
          [5, 9, 11, 14],

        "Carga de trabajo":
          [15, 21, 27, 37],

        "Falta de control sobre el trabajo":
          [11, 16, 21, 25],

        "Jornada de trabajo":
          [1, 2, 4, 6],

        "Interferencia en la relación trabajo-familia":
          [4, 6, 8, 10],

        "Liderazgo":
          [9, 12, 16, 20],

        "Relaciones en el trabajo":
          [10, 13, 17, 21],

        "Violencia":
          [7, 10, 13, 16],

        "Reconocimiento del desempeño":
          [6, 10, 14, 18],

        "Insuficiente sentido de pertenencia e, inestabilidad":
          [4, 6, 8, 10]
      }
    };
  }

  return null;
};

const obtenerAccionNom035 = nivel => {
  const acciones = {
    muy_alto: {
      requiere_accion: true,

      resultado:
        "El resultado global se ubica en un nivel de riesgo muy alto.",

      recomendacion:
        "Se requiere analizar cada categoría y dominio para establecer acciones de intervención apropiadas mediante un Programa de intervención. Deben contemplarse evaluaciones específicas, campañas de sensibilización, revisión de la política de prevención de riesgos psicosociales y de los programas de prevención, promoción de un entorno organizacional favorable y prevención de la violencia laboral, reforzando su aplicación y difusión."
    },

    alto: {
      requiere_accion: true,

      resultado:
        "El resultado global se ubica en un nivel de riesgo alto.",

      recomendacion:
        "Se requiere analizar cada categoría y dominio para determinar acciones de intervención apropiadas mediante un Programa de intervención. Puede incluir una evaluación específica y debe considerar una campaña de sensibilización, revisión de la política y programas de prevención de riesgos psicosociales, promoción de un entorno organizacional favorable y prevención de la violencia laboral."
    },

    medio: {
      requiere_accion: true,

      resultado:
        "El resultado global se ubica en un nivel de riesgo medio.",

      recomendacion:
        "Se requiere revisar la política de prevención de riesgos psicosociales y los programas para prevenir estos factores, promover un entorno organizacional favorable y prevenir la violencia laboral, reforzando su aplicación y difusión mediante un Programa de intervención."
    },

    bajo: {
      requiere_accion: true,

      resultado:
        "El resultado global se ubica en un nivel de riesgo bajo.",

      recomendacion:
        "Es necesaria una mayor difusión de la política de prevención de riesgos psicosociales y de los programas para prevenir estos factores, promover un entorno organizacional favorable y prevenir la violencia laboral."
    },

    nulo: {
      requiere_accion: false,

      resultado:
        "El resultado global se ubica en un nivel de riesgo nulo o despreciable.",

      recomendacion:
        "El riesgo resulta despreciable, por lo que no se requieren medidas adicionales derivadas de esta calificación."
    }
  };

  return (
    acciones[nivel] ||
    acciones.nulo
  );
};

// ==================================================
// AUXILIAR: PRE-EVALUACIÓN IA NOM-035
//
// Se genera y guarda por cada aplicación terminada.
//
// IMPORTANTE:
// La pre-evaluación pertenece a la aplicación NOM-035.
// Canalización NO la genera.
//
// Si la IA falla, la NOM-035 sigue siendo válida.
// ==================================================

const generarYGuardarPreevaluacionNom035 =
  async ({
    idResultado,
    aplicacion,
    puntajeTotal = null,
    nivelRiesgo = null,
    resultadoGeneral,
    categorias = [],
    dominios = [],
    dimensiones = [],
    recomendaciones
  }) => {
    try {
      const systemPrompt = `
Eres un asistente de apoyo para Recursos Humanos.

Tu función es generar una PRE-EVALUACIÓN ORIENTATIVA
a partir exclusivamente de los resultados de una aplicación
NOM-035-STPS-2018.

REGLAS OBLIGATORIAS:

- No realices diagnósticos médicos ni psicológicos.
- No afirmes que la persona tiene un trastorno.
- No inventes síntomas, antecedentes, hechos ni resultados.
- No modifiques puntajes.
- No utilices información clínica.
- No recomiendes medicamentos ni tratamientos.
- No sustituyas una valoración profesional.
- No decidas por Recursos Humanos si debe canalizar o no.
- Explica únicamente lo que reflejan los resultados disponibles.
- Si la información es insuficiente, indícalo.
- La decisión administrativa final corresponde a Recursos Humanos.

La pre-evaluación debe ser clara, breve, prudente y útil para RH.
`;

      const prompt = `
Genera la pre-evaluación orientativa de esta aplicación NOM-035.

Guía:
${aplicacion.guia || "No especificada"}

Cuestionario:
${aplicacion.cuestionario_nombre || "NOM-035"}

Tipo de aplicación:
${aplicacion.tipo_aplicacion || "No especificado"}

Puntaje total:
${
  puntajeTotal === null ||
  puntajeTotal === undefined
    ? "No aplica"
    : puntajeTotal
}

Nivel de riesgo:
${nivelRiesgo || "No aplica"}

Resultado general:
${resultadoGeneral || "Sin resultado general"}

Categorías:
${JSON.stringify(
  categorias || [],
  null,
  2
)}

Dominios:
${JSON.stringify(
  dominios || [],
  null,
  2
)}

Dimensiones:
${JSON.stringify(
  dimensiones || [],
  null,
  2
)}

Recomendación oficial registrada:
${recomendaciones || "Sin recomendación registrada"}

FORMATO OBLIGATORIO:

PRE-EVALUACIÓN IA

Interpretación:
Resume en máximo 2 oraciones el resultado general y únicamente los factores más relevantes.

Atención sugerida:
En máximo 2 oraciones indica qué aspectos conviene que Recursos Humanos revise o atienda según el resultado.

Nota:
Escribe una sola oración indicando que la pre-evaluación es orientativa, no constituye diagnóstico médico o psicológico y que la decisión final corresponde a Recursos Humanos.

REGLAS DE EXTENSIÓN:

- Máximo 120 palabras en total.
- No repitas todos los puntajes.
- No enumeres todas las categorías, dominios o dimensiones.
- Menciona únicamente de 2 a 4 factores realmente relevantes.
- No repitas literalmente la recomendación oficial.
- Evita explicaciones largas.
- No uses más de tres apartados.
`;

      const resultadoIA =
        await generarReporteIAConMeta(
          prompt,
          220,
          systemPrompt
        );

      const texto =
        resultadoIA?.texto
          ? String(
              resultadoIA.texto
            ).trim()
          : "";

      if (!texto) {
        throw new Error(
          "La IA no devolvió contenido para la pre-evaluación NOM-035."
        );
      }

      await pool.query(
        `
          UPDATE nom035_resultados
          SET
            preevaluacion_ia = ?,
            ia_proveedor = ?,
            ia_modelo = ?,
            fecha_preevaluacion_ia = NOW()
          WHERE
            id_resultado = ?
        `,
        [
          texto,

          resultadoIA
            ?.proveedor ||
          null,

          resultadoIA
            ?.modelo ||
          null,

          idResultado
        ]
      );

      return {
        texto,

        proveedor:
          resultadoIA
            ?.proveedor ||
          null,

        modelo:
          resultadoIA
            ?.modelo ||
          null
      };

    } catch (error) {
      console.error(
        "⚠️ No fue posible generar la pre-evaluación IA NOM-035:",
        error
      );

      // MUY IMPORTANTE:
      // La NOM-035 ya fue calculada y guardada.
      // Un fallo de IA NO debe invalidarla.

      return null;
    }
  };

const normalizar = valor =>
  valor
    ? String(valor)
        .trim()
        .toLowerCase()
    : "";

// ==================================================
// CONTEXTO DEL USUARIO
// ==================================================

const obtenerContextoUsuario = async (
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
      perfilIndependiente: ""
    };
  }

  const [rows] =
    await connection.query(
      `
        SELECT
          id_usuario,
          tipo_admin,
          area,
          rol,
          id_admin_padre,
          id_organizacion,
          (
            SELECT
              o.perfil_independiente
            FROM organizaciones o
            WHERE o.id_organizacion = usuarios.id_organizacion
            LIMIT 1
          ) AS perfil_independiente
        FROM usuarios
        WHERE id_usuario = ?
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
      )
  };
};

// ==================================================
// VALIDAR ACCESO RH AL EMPLEADO
// ==================================================

const validarAccesoEmpleado = async (
  idEmpleado,
  user,
  connection = pool
) => {
  const contexto =
    await obtenerContextoUsuario(
      user,
      connection
    );

  console.log(
    "🔐 USUARIO NOM-035:",
    contexto
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
      "rh";

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
        "No tienes permiso para acceder al módulo NOM-035"
    };
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
      e.puesto,
      e.departamento,
      e.fecha_contratacion,
      e.estatus,

      ur.nombre
        AS responsable_actual

    FROM empleados e

    LEFT JOIN usuarios ur
      ON ur.id_usuario =
         e.id_usuario_responsable

    WHERE
      e.id_empleado = ?
  `;

  const params = [
    idEmpleado
  ];

  if (esAdminRH) {
    query += `
      AND
      (
        e.id_admin_padre = ?

        OR
        (
          e.id_usuario_responsable IS NULL

          AND e.id_admin_padre IN
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
    `;

    params.push(
      contexto.idUsuario,
      contexto.idUsuario
    );
  }

  else if (esUsuarioRH || esIndependienteRH) {
    query += `
      AND
      (
        e.id_usuario_responsable = ?

        OR
        (
          e.id_usuario_responsable IS NULL
          AND e.id_admin_padre = ?
        )
      )
    `;

    params.push(
      contexto.idUsuario,
      contexto.idUsuario
    );
  }

  query += `
    LIMIT 1
  `;

  const [rows] =
    await connection.query(
      query,
      params
    );

  if (!rows.length) {
    return {
      ok: false,
      status: 404,
      message:
        "Empleado no encontrado o no tienes permiso para acceder a él"
    };
  }

  return {
    ok: true,

    empleado:
      rows[0],

    contexto
  };
};

// ==================================================
// AUXILIAR: OBTENER APLICACIÓN POR TOKEN
// ==================================================

const obtenerAplicacionPorToken = async token => {
  const [rows] =
    await pool.query(
      `
        SELECT
          a.id_aplicacion,
          a.id_empleado,
          a.id_cuestionario,
          a.id_usuario_registro,
          a.token_publico,
          a.tipo_aplicacion,
          a.motivo,
          a.atiende_clientes,
          a.tiene_personal_cargo,
          a.estatus,
          a.fecha_habilitacion,
          a.fecha_inicio,
          a.fecha_completada,

          e.id_mirror,
          e.nombre
            AS empleado_nombre,
          e.puesto,
          e.departamento,
          e.estatus
            AS empleado_estatus,

          c.clave,
          c.nombre
            AS cuestionario_nombre,
          c.descripcion
            AS cuestionario_descripcion,
          c.guia,
          c.tipo,
          c.version,
          c.activo
            AS cuestionario_activo

        FROM nom035_aplicaciones a

        INNER JOIN empleados e
          ON e.id_empleado =
             a.id_empleado

        INNER JOIN nom035_cuestionarios c
          ON c.id_cuestionario =
             a.id_cuestionario

        WHERE
          a.token_publico = ?

        LIMIT 1
      `,
      [
        token
      ]
    );

  return rows.length
    ? rows[0]
    : null;
};

// ==================================================
// LISTAR CUESTIONARIOS
// ==================================================

export const listarCuestionariosNom035 =
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
        return res.status(400).json({
          success: false,
          message:
            "ID de empleado inválido"
        });
      }

      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
          req.user
        );

      if (!acceso.ok) {
        return res
          .status(
            acceso.status
          )
          .json({
            success: false,
            message:
              acceso.message
          });
      }

      const [cuestionarios] =
        await pool.query(
          `
            SELECT
              id_cuestionario,
              clave,
              nombre,
              descripcion,
              guia,
              tipo,
              version,
              activo
            FROM nom035_cuestionarios
            WHERE activo = 1
            ORDER BY
              guia ASC,
              nombre ASC
          `
        );

      return res.json({
        success: true,

        empleado:
          acceso.empleado,

        cuestionarios
      });

    } catch (error) {
      console.error(
        "❌ Error listando cuestionarios NOM-035:",
        error
      );

      return res.status(500).json({
        success: false,

        message:
          "Error interno al obtener los cuestionarios NOM-035"
      });
    }
  };

// ==================================================
// HABILITAR CUESTIONARIO
// ==================================================

export const habilitarNom035Empleado =
  async (
    req,
    res
  ) => {
    try {
      const idEmpleado =
        Number(
          req.params.id
        );

      const idCuestionario =
        Number(
          req.body?.id_cuestionario
        );

      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "ID de empleado inválido"
        });
      }

      if (
        !Number.isInteger(
          idCuestionario
        ) ||
        idCuestionario <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Selecciona un cuestionario válido"
        });
      }

      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
          req.user
        );

      if (!acceso.ok) {
        return res
          .status(
            acceso.status
          )
          .json({
            success: false,
            message:
              acceso.message
          });
      }

      const tiposPermitidos = [
        "inicial",
        "periodica",
        "seguimiento",
        "extraordinaria"
      ];

      const tipoAplicacion =
        String(
          req.body?.tipo_aplicacion ||
          "periodica"
        )
          .trim()
          .toLowerCase();

      if (
        !tiposPermitidos.includes(
          tipoAplicacion
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Tipo de aplicación inválido"
        });
      }

      const motivo =
        req.body?.motivo
          ? String(
              req.body.motivo
            ).trim()
          : null;

      const [cuestionarios] =
        await pool.query(
          `
            SELECT
              id_cuestionario,
              clave,
              nombre,
              descripcion,
              guia,
              tipo,
              version

            FROM nom035_cuestionarios

            WHERE
              id_cuestionario = ?
              AND activo = 1

            LIMIT 1
          `,
          [
            idCuestionario
          ]
        );

      if (!cuestionarios.length) {
        return res.status(404).json({
          success: false,

          message:
            "El cuestionario NOM-035 no existe o está inactivo"
        });
      }

      const [activas] =
        await pool.query(
          `
            SELECT
              id_aplicacion,
              estatus,
              fecha_habilitacion

            FROM nom035_aplicaciones

            WHERE
              id_empleado = ?
              AND id_cuestionario = ?

              AND estatus IN
              (
                'habilitada',
                'iniciada'
              )

            LIMIT 1
          `,
          [
            idEmpleado,
            idCuestionario
          ]
        );

      if (activas.length) {
        return res.status(409).json({
          success: false,

          message:
            "El empleado ya tiene este cuestionario pendiente o iniciado",

          aplicacion:
            activas[0]
        });
      }

      const tokenPublico =
        crypto
          .randomBytes(32)
          .toString("hex");

      const [result] =
        await pool.query(
          `
            INSERT INTO nom035_aplicaciones
            (
              id_empleado,
              id_cuestionario,
              id_usuario_registro,
              token_publico,
              tipo_aplicacion,
              motivo,
              estatus,
              fecha_habilitacion
            )
            VALUES
            (
              ?, ?, ?, ?, ?, ?,
              'habilitada',
              NOW()
            )
          `,
          [
            idEmpleado,

            idCuestionario,

            req.user
              ?.id_usuario ||
            null,

            tokenPublico,

            tipoAplicacion,

            motivo
          ]
        );

      return res
        .status(201)
        .json({
          success: true,

          message:
            "Cuestionario NOM-035 habilitado correctamente",

          aplicacion: {
            id_aplicacion:
              result.insertId,

            id_empleado:
              idEmpleado,

            id_cuestionario:
              idCuestionario,

            cuestionario:
              cuestionarios[0]
                .nombre,

            guia:
              cuestionarios[0]
                .guia,

            tipo_aplicacion:
              tipoAplicacion,

            motivo,

            token_publico:
              tokenPublico,

            estatus:
              "habilitada"
          }
        });

    } catch (error) {
      console.error(
        "❌ Error habilitando NOM-035:",
        error
      );

      return res.status(500).json({
        success: false,

        message:
          "Error interno al habilitar el cuestionario NOM-035",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined
      });
    }
  };

// ==================================================
// LISTAR APLICACIONES DEL EMPLEADO
// ==================================================

export const listarAplicacionesNom035Empleado =
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
        return res.status(400).json({
          success: false,
          message:
            "ID de empleado inválido"
        });
      }

      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
          req.user
        );

      if (!acceso.ok) {
        return res
          .status(
            acceso.status
          )
          .json({
            success: false,
            message:
              acceso.message
          });
      }

      const [aplicaciones] =
        await pool.query(
          `
            SELECT
              a.id_aplicacion,
              a.id_cuestionario,
              a.token_publico,
              a.tipo_aplicacion,
              a.motivo,
              a.atiende_clientes,
              a.tiene_personal_cargo,
              a.estatus,
              a.fecha_habilitacion,
              a.fecha_inicio,
              a.fecha_completada,

              c.clave,
              c.nombre
                AS cuestionario_nombre,

              c.descripcion
                AS cuestionario_descripcion,

              c.guia,

              c.tipo
                AS cuestionario_tipo,

              c.version,

              r.id_resultado,
              r.puntaje_total,
              r.nivel_riesgo,
              r.resultado_general,
              r.categorias,
              r.dominios,
              r.dimensiones,
              r.requiere_accion,
              r.recomendaciones,

              r.preevaluacion_ia,
              r.ia_proveedor,
              r.ia_modelo,
              r.fecha_preevaluacion_ia,

              r.fecha_resultado

            FROM nom035_aplicaciones a

            INNER JOIN nom035_cuestionarios c
              ON c.id_cuestionario =
                 a.id_cuestionario

            LEFT JOIN nom035_resultados r
              ON r.id_aplicacion =
                 a.id_aplicacion

            WHERE
              a.id_empleado = ?

            ORDER BY
              a.fecha_habilitacion DESC,
              a.id_aplicacion DESC
          `,
          [
            idEmpleado
          ]
        );

      return res.json({
        success: true,

        empleado:
          acceso.empleado,

        total:
          aplicaciones.length,

        aplicaciones
      });

    } catch (error) {
      console.error(
        "❌ Error listando aplicaciones NOM-035:",
        error
      );

      return res.status(500).json({
        success: false,

        message:
          "Error interno al obtener el historial NOM-035"
      });
    }
  };

// ==================================================
// OBTENER CUESTIONARIO PÚBLICO
// ==================================================

export const obtenerNom035Publica =
  async (
    req,
    res
  ) => {
    try {
      const token =
        String(
          req.params.token ||
          ""
        ).trim();

      if (!token) {
        return res.status(400).json({
          success: false,
          message:
            "Token inválido"
        });
      }

      const aplicacion =
        await obtenerAplicacionPorToken(
          token
        );

      if (!aplicacion) {
        return res.status(404).json({
          success: false,

          message:
            "Aplicación NOM-035 no encontrada"
        });
      }

      if (
        aplicacion.estatus ===
        "cancelada"
      ) {
        return res.status(410).json({
          success: false,
          message:
            "Esta aplicación fue cancelada"
        });
      }

      if (
        aplicacion.estatus ===
        "completada"
      ) {
        return res.status(409).json({
          success: false,

          message:
            "Este cuestionario ya fue completado"
        });
      }

      if (
        Number(
          aplicacion
            .cuestionario_activo
        ) !== 1
      ) {
        return res.status(410).json({
          success: false,

          message:
            "Este cuestionario ya no está disponible"
        });
      }

      if (
        aplicacion.estatus ===
        "habilitada"
      ) {
        await pool.query(
          `
            UPDATE nom035_aplicaciones

            SET
              estatus =
                'iniciada',

              fecha_inicio =
                COALESCE(
                  fecha_inicio,
                  NOW()
                )

            WHERE
              id_aplicacion = ?
          `,
          [
            aplicacion.id_aplicacion
          ]
        );
      }

      const [preguntas] =
        await pool.query(
          `
            SELECT
              id_pregunta,
              numero,
              seccion,
              categoria,
              dominio,
              dimension,
              texto_pregunta,
              tipo_respuesta,
              orden

            FROM nom035_preguntas

            WHERE
              id_cuestionario = ?
              AND activo = 1

            ORDER BY
              orden ASC,
              id_pregunta ASC
          `,
          [
            aplicacion.id_cuestionario
          ]
        );

      let opciones = [];

      if (
        preguntas.length
      ) {
        const ids =
          preguntas.map(
            item =>
              item.id_pregunta
          );

        const placeholders =
          ids
            .map(
              () => "?"
            )
            .join(",");

        const [rowsOpciones] =
          await pool.query(
            `
              SELECT
                id_opcion,
                id_pregunta,
                texto_opcion,
                valor,
                orden

              FROM nom035_opciones

              WHERE
                id_pregunta IN
                (
                  ${placeholders}
                )

                AND activo = 1

              ORDER BY
                id_pregunta ASC,
                orden ASC,
                id_opcion ASC
            `,
            ids
          );

        opciones =
          rowsOpciones;
      }

      const [respuestasGuardadas] =
        await pool.query(
          `
            SELECT
              id_pregunta,
              id_opcion,
              respuesta,
              valor

            FROM nom035_respuestas

            WHERE
              id_aplicacion = ?
          `,
          [
            aplicacion.id_aplicacion
          ]
        );

      const preguntasConOpciones =
        preguntas.map(
          pregunta => {
            const respuestaActual =
              respuestasGuardadas.find(
                respuesta =>
                  Number(
                    respuesta.id_pregunta
                  ) ===
                  Number(
                    pregunta.id_pregunta
                  )
              );

            return {
              ...pregunta,

              opciones:
                opciones.filter(
                  opcion =>
                    Number(
                      opcion.id_pregunta
                    ) ===
                    Number(
                      pregunta.id_pregunta
                    )
                ),

              respuesta_actual:
                respuestaActual
                  ? {
                      id_opcion:
                        respuestaActual.id_opcion,

                      respuesta:
                        respuestaActual.respuesta,

                      valor:
                        respuestaActual.valor
                    }
                  : null
            };
          }
        );

      return res.json({
        success: true,

        aplicacion: {
          id_aplicacion:
            aplicacion.id_aplicacion,

          tipo_aplicacion:
            aplicacion.tipo_aplicacion,

          motivo:
            aplicacion.motivo,

          atiende_clientes:
            aplicacion.atiende_clientes,

          tiene_personal_cargo:
            aplicacion.tiene_personal_cargo,

          cuestionario: {
            id_cuestionario:
              aplicacion.id_cuestionario,

            clave:
              aplicacion.clave,

            nombre:
              aplicacion
                .cuestionario_nombre,

            descripcion:
              aplicacion
                .cuestionario_descripcion,

            guia:
              aplicacion.guia,

            tipo:
              aplicacion.tipo,

            version:
              aplicacion.version
          },

          empleado: {
            nombre:
              aplicacion
                .empleado_nombre,

            id_mirror:
              aplicacion.id_mirror,

            puesto:
              aplicacion.puesto,

            departamento:
              aplicacion.departamento
          },

          preguntas:
            preguntasConOpciones
        }
      });

    } catch (error) {
      console.error(
        "❌ Error obteniendo NOM-035 pública:",
        error
      );

      return res.status(500).json({
        success: false,

        message:
          "Error interno al cargar el cuestionario NOM-035"
      });
    }
  };

// ==================================================
// GUARDAR RESPUESTAS
// ==================================================

export const guardarRespuestasNom035 =
  async (
    req,
    res
  ) => {
    let connection;

    try {
      const token =
        String(
          req.params.token ||
          ""
        ).trim();

      const respuestas =
        Array.isArray(
          req.body?.respuestas
        )
          ? req.body.respuestas
          : [];

      if (!token) {
        return res.status(400).json({
          success: false,
          message:
            "Token inválido"
        });
      }

      if (
        !respuestas.length
      ) {
        return res.status(400).json({
          success: false,

          message:
            "No se recibieron respuestas"
        });
      }

      const aplicacion =
        await obtenerAplicacionPorToken(
          token
        );

      if (!aplicacion) {
        return res.status(404).json({
          success: false,

          message:
            "Aplicación NOM-035 no encontrada"
        });
      }

      if (
        aplicacion.estatus ===
        "cancelada"
      ) {
        return res.status(410).json({
          success: false,

          message:
            "Esta aplicación fue cancelada"
        });
      }

      if (
        aplicacion.estatus ===
        "completada"
      ) {
        return res.status(409).json({
          success: false,

          message:
            "Este cuestionario ya fue completado"
        });
      }

      connection =
        await pool.getConnection();

      await connection
        .beginTransaction();

      await connection.query(
        `
          DELETE FROM nom035_respuestas

          WHERE
            id_aplicacion = ?
        `,
        [
          aplicacion.id_aplicacion
        ]
      );

      const preguntasProcesadas =
        new Set();

      for (
        const item
        of respuestas
      ) {
        const idPregunta =
          Number(
            item?.id_pregunta
          );

        const idOpcion =
          Number(
            item?.id_opcion
          );

        if (
          !Number.isInteger(
            idPregunta
          ) ||
          idPregunta <= 0
        ) {
          await connection.rollback();

          return res
            .status(400)
            .json({
              success: false,

              message:
                "Se recibió una pregunta inválida"
            });
        }

        if (
          preguntasProcesadas.has(
            idPregunta
          )
        ) {
          await connection.rollback();

          return res
            .status(400)
            .json({
              success: false,

              message:
                "Una misma pregunta fue enviada más de una vez"
            });
        }

        preguntasProcesadas.add(
          idPregunta
        );

        const [preguntas] =
          await connection.query(
            `
              SELECT
                id_pregunta,
                tipo_respuesta

              FROM nom035_preguntas

              WHERE
                id_pregunta = ?
                AND id_cuestionario = ?
                AND activo = 1

              LIMIT 1
            `,
            [
              idPregunta,
              aplicacion.id_cuestionario
            ]
          );

        if (!preguntas.length) {
          await connection.rollback();

          return res
            .status(400)
            .json({
              success: false,

              message:
                "Una de las preguntas no pertenece a este cuestionario"
            });
        }

        if (
          !Number.isInteger(
            idOpcion
          ) ||
          idOpcion <= 0
        ) {
          await connection.rollback();

          return res
            .status(400)
            .json({
              success: false,

              message:
                "Falta seleccionar una respuesta"
            });
        }

        const [opciones] =
          await connection.query(
            `
              SELECT
                id_opcion,
                texto_opcion,
                valor

              FROM nom035_opciones

              WHERE
                id_opcion = ?
                AND id_pregunta = ?
                AND activo = 1

              LIMIT 1
            `,
            [
              idOpcion,
              idPregunta
            ]
          );

        if (!opciones.length) {
          await connection.rollback();

          return res
            .status(400)
            .json({
              success: false,

              message:
                "Se recibió una opción de respuesta inválida"
            });
        }

        await connection.query(
          `
            INSERT INTO nom035_respuestas
            (
              id_aplicacion,
              id_empleado,
              id_pregunta,
              id_opcion,
              respuesta,
              valor
            )
            VALUES
            (
              ?, ?, ?, ?, ?, ?
            )
          `,
          [
            aplicacion.id_aplicacion,

            aplicacion.id_empleado,

            idPregunta,

            idOpcion,

            opciones[0]
              .texto_opcion,

            opciones[0]
              .valor
          ]
        );
      }

      await connection.query(
        `
          UPDATE nom035_aplicaciones

          SET
            estatus =
              'iniciada',

            fecha_inicio =
              COALESCE(
                fecha_inicio,
                NOW()
              )

          WHERE
            id_aplicacion = ?
        `,
        [
          aplicacion.id_aplicacion
        ]
      );

      await connection.commit();

      return res.json({
        success: true,

        message:
          "Respuestas NOM-035 guardadas correctamente"
      });

    } catch (error) {
      if (connection) {
        try {
          await connection.rollback();
        } catch {}
      }

      console.error(
        "❌ Error guardando respuestas NOM-035:",
        error
      );

      return res.status(500).json({
        success: false,

        message:
          "Error interno al guardar las respuestas NOM-035"
      });

    } finally {
      if (connection) {
        connection.release();
      }
    }
  };

// ==================================================
// FINALIZAR CUESTIONARIO NOM-035
// ==================================================

export const finalizarNom035 =
  async (
    req,
    res
  ) => {
    let connection;

    try {
      const token =
        String(
          req.params.token ||
          ""
        ).trim();

      if (!token) {
        return res.status(400).json({
          success: false,
          message:
            "Token inválido"
        });
      }

      const aplicacion =
        await obtenerAplicacionPorToken(
          token
        );

      if (!aplicacion) {
        return res.status(404).json({
          success: false,

          message:
            "Aplicación NOM-035 no encontrada"
        });
      }

      if (
        aplicacion.estatus ===
        "cancelada"
      ) {
        return res.status(410).json({
          success: false,

          message:
            "Esta aplicación fue cancelada"
        });
      }

      if (
        aplicacion.estatus ===
        "completada"
      ) {
        return res.status(409).json({
          success: false,

          message:
            "Este cuestionario ya fue completado"
        });
      }

      connection =
        await pool.getConnection();

      await connection
        .beginTransaction();

      const [preguntasRows] =
        await connection.query(
          `
            SELECT
              COUNT(*) AS total

            FROM nom035_preguntas

            WHERE
              id_cuestionario = ?
              AND activo = 1
          `,
          [
            aplicacion.id_cuestionario
          ]
        );

      const totalPreguntas =
        Number(
          preguntasRows[0]
            ?.total ||
          0
        );

      if (
        totalPreguntas ===
        0
      ) {
        await connection.rollback();

        return res
          .status(400)
          .json({
            success: false,

            message:
              "Este cuestionario no tiene preguntas activas"
          });
      }

      // ==================================================
      // GUÍA I
      // ==================================================

      if (
        String(
          aplicacion.guia
        ) === "I"
      ) {
        const [seccionIRows] =
          await connection.query(
            `
              SELECT
                COUNT(
                  DISTINCT r.id_pregunta
                ) AS total,

                COALESCE(
                  SUM(
                    CASE
                      WHEN
                        r.valor = 1
                      THEN 1
                      ELSE 0
                    END
                  ),
                  0
                ) AS respuestas_si

              FROM nom035_respuestas r

              INNER JOIN nom035_preguntas p
                ON p.id_pregunta =
                   r.id_pregunta

              WHERE
                r.id_aplicacion = ?
                AND p.orden
                  BETWEEN 1 AND 6
            `,
            [
              aplicacion.id_aplicacion
            ]
          );

        const totalSeccionI =
          Number(
            seccionIRows[0]
              ?.total ||
            0
          );

        const siSeccionI =
          Number(
            seccionIRows[0]
              ?.respuestas_si ||
            0
          );

        if (
          totalSeccionI <
          6
        ) {
          await connection.rollback();

          return res
            .status(400)
            .json({
              success: false,

              message:
                "Debes responder las seis preguntas de la Sección I."
            });
        }

        // ==================================================
        // GUÍA I:
        // SI TODAS LAS PRIMERAS 6 SON NO
        // ==================================================

        if (
          siSeccionI ===
          0
        ) {
          const resultadoGeneral =
            "No se identificó exposición al acontecimiento traumático severo en la Sección I, por lo que no se requiere continuar con las demás secciones de la Guía de Referencia I.";

          const recomendaciones =
            "No se requiere continuar con las secciones II, III y IV conforme a la lógica de la Guía de Referencia I.";

          const categorias = [
            {
              nombre:
                "Acontecimiento traumático severo",

              respuestas_si:
                0
            }
          ];

          const [existentes] =
            await connection.query(
              `
                SELECT
                  id_resultado

                FROM nom035_resultados

                WHERE
                  id_aplicacion = ?

                LIMIT 1
              `,
              [
                aplicacion.id_aplicacion
              ]
            );

          let idResultado;

          if (
            existentes.length
          ) {
            idResultado =
              existentes[0]
                .id_resultado;

            await connection.query(
              `
                UPDATE nom035_resultados

                SET
                  puntaje_total = 0,

                  nivel_riesgo =
                    'no_aplica',

                  resultado_general = ?,

                  categorias = ?,

                  dominios = ?,

                  dimensiones = ?,

                  requiere_accion = 0,

                  recomendaciones = ?,

                  fecha_resultado =
                    NOW()

                WHERE
                  id_resultado = ?
              `,
              [
                resultadoGeneral,

                JSON.stringify(
                  categorias
                ),

                JSON.stringify(
                  []
                ),

                JSON.stringify(
                  []
                ),

                recomendaciones,

                idResultado
              ]
            );

          } else {
            const [result] =
              await connection.query(
                `
                  INSERT INTO nom035_resultados
                  (
                    id_aplicacion,
                    id_empleado,
                    id_cuestionario,
                    puntaje_total,
                    nivel_riesgo,
                    resultado_general,
                    categorias,
                    dominios,
                    dimensiones,
                    requiere_accion,
                    recomendaciones,
                    fecha_resultado
                  )
                  VALUES
                  (
                    ?, ?, ?, 0,
                    'no_aplica',
                    ?, ?, ?, ?,
                    0,
                    ?,
                    NOW()
                  )
                `,
                [
                  aplicacion.id_aplicacion,

                  aplicacion.id_empleado,

                  aplicacion.id_cuestionario,

                  resultadoGeneral,

                  JSON.stringify(
                    categorias
                  ),

                  JSON.stringify(
                    []
                  ),

                  JSON.stringify(
                    []
                  ),

                  recomendaciones
                ]
              );

            idResultado =
              result.insertId;
          }

          await connection.query(
            `
              UPDATE nom035_aplicaciones

              SET
                estatus =
                  'completada',

                fecha_completada =
                  NOW()

              WHERE
                id_aplicacion = ?
            `,
            [
              aplicacion.id_aplicacion
            ]
          );

          // Primero guardamos oficialmente
          // la NOM-035.

          await connection.commit();

          // Después intentamos generar IA.
          // Si la IA falla, la evaluación
          // sigue completada correctamente.

          const preevaluacionIA =
            await generarYGuardarPreevaluacionNom035({
              idResultado,

              aplicacion,

              puntajeTotal:
                0,

              nivelRiesgo:
                "no_aplica",

              resultadoGeneral,

              categorias,

              dominios:
                [],

              dimensiones:
                [],

              recomendaciones
            });

          return res.json({
            success: true,

            message:
              "Guía I completada correctamente",

            resultado: {
              id_resultado:
                idResultado,

              guia:
                "I",

              respuestas_si: {
                seccion_i:
                  0,

                seccion_ii:
                  0,

                seccion_iii:
                  0,

                seccion_iv:
                  0
              },

              continuar_secciones:
                false,

              requiere_atencion_clinica:
                false,

              requiere_accion:
                false,

              resultado_general:
                resultadoGeneral,

              recomendaciones,

              preevaluacion_ia:
                preevaluacionIA
                  ?.texto ||
                null,

              ia_proveedor:
                preevaluacionIA
                  ?.proveedor ||
                null,

              ia_modelo:
                preevaluacionIA
                  ?.modelo ||
                null
            }
          });
        }

        // ==================================================
        // GUÍA I:
        // SI HUBO ALGÚN "SÍ" EN SECCIÓN I
        // ENTONCES DEBEN ESTAR CONTESTADAS LAS 20
        // ==================================================

        const [totalRespondidasRows] =
          await connection.query(
            `
              SELECT
                COUNT(
                  DISTINCT id_pregunta
                ) AS total

              FROM nom035_respuestas

              WHERE
                id_aplicacion = ?
            `,
            [
              aplicacion.id_aplicacion
            ]
          );

        const totalRespondidas =
          Number(
            totalRespondidasRows[0]
              ?.total ||
            0
          );

        if (
          totalRespondidas <
          totalPreguntas
        ) {
          await connection.rollback();

          return res
            .status(400)
            .json({
              success: false,

              message:
                `Al existir al menos una respuesta "Sí" en la Sección I, debes responder las secciones II, III y IV. Se respondieron ${totalRespondidas} de ${totalPreguntas} preguntas.`
            });
        }

        const [criteriosRows] =
          await connection.query(
            `
              SELECT

                COALESCE(
                  SUM(
                    CASE
                      WHEN
                        p.orden BETWEEN 7 AND 8
                        AND r.valor = 1
                      THEN 1
                      ELSE 0
                    END
                  ),
                  0
                ) AS seccion_ii,

                COALESCE(
                  SUM(
                    CASE
                      WHEN
                        p.orden BETWEEN 9 AND 15
                        AND r.valor = 1
                      THEN 1
                      ELSE 0
                    END
                  ),
                  0
                ) AS seccion_iii,

                COALESCE(
                  SUM(
                    CASE
                      WHEN
                        p.orden BETWEEN 16 AND 20
                        AND r.valor = 1
                      THEN 1
                      ELSE 0
                    END
                  ),
                  0
                ) AS seccion_iv,

                COALESCE(
                  SUM(
                    CASE
                      WHEN
                        r.valor = 1
                      THEN 1
                      ELSE 0
                    END
                  ),
                  0
                ) AS total_si

              FROM nom035_respuestas r

              INNER JOIN nom035_preguntas p
                ON p.id_pregunta =
                   r.id_pregunta

              WHERE
                r.id_aplicacion = ?
            `,
            [
              aplicacion.id_aplicacion
            ]
          );

        const siSeccionII =
          Number(
            criteriosRows[0]
              ?.seccion_ii ||
            0
          );

        const siSeccionIII =
          Number(
            criteriosRows[0]
              ?.seccion_iii ||
            0
          );

        const siSeccionIV =
          Number(
            criteriosRows[0]
              ?.seccion_iv ||
            0
          );

        const totalSi =
          Number(
            criteriosRows[0]
              ?.total_si ||
            0
          );

        const requiereAtencionClinica =
          (
            siSeccionII >= 1 ||
            siSeccionIII >= 3 ||
            siSeccionIV >= 2
          );

        const resultadoGeneral =
          requiereAtencionClinica
            ? "La aplicación cumple al menos uno de los criterios de la Guía de Referencia I para requerir atención clínica."
            : "La aplicación no alcanza los criterios de la Guía de Referencia I para requerir atención clínica.";

        const recomendaciones =
          requiereAtencionClinica
            ? "Corresponde realizar la canalización para valoración clínica conforme a la Guía de Referencia I."
            : "No se identifica criterio de atención clínica derivado de esta guía. Mantener las medidas preventivas y de seguimiento laboral que correspondan.";

        const categorias = [
          {
            nombre:
              "Acontecimiento traumático severo",

            respuestas_si:
              siSeccionI
          },

          {
            nombre:
              "Recuerdos persistentes",

            respuestas_si:
              siSeccionII
          },

          {
            nombre:
              "Evitación",

            respuestas_si:
              siSeccionIII
          },

          {
            nombre:
              "Afectación",

            respuestas_si:
              siSeccionIV
          }
        ];

        const [existentes] =
          await connection.query(
            `
              SELECT
                id_resultado

              FROM nom035_resultados

              WHERE
                id_aplicacion = ?

              LIMIT 1
            `,
            [
              aplicacion.id_aplicacion
            ]
          );

        let idResultado;

        if (
          existentes.length
        ) {
          idResultado =
            existentes[0]
              .id_resultado;

          await connection.query(
            `
              UPDATE nom035_resultados

              SET
                puntaje_total = ?,

                nivel_riesgo =
                  'no_aplica',

                resultado_general = ?,

                categorias = ?,

                dominios = ?,

                dimensiones = ?,

                requiere_accion = ?,

                recomendaciones = ?,

                fecha_resultado =
                  NOW()

              WHERE
                id_resultado = ?
            `,
            [
              totalSi,

              resultadoGeneral,

              JSON.stringify(
                categorias
              ),

              JSON.stringify(
                []
              ),

              JSON.stringify(
                []
              ),

              requiereAtencionClinica
                ? 1
                : 0,

              recomendaciones,

              idResultado
            ]
          );

        } else {
          const [result] =
            await connection.query(
              `
                INSERT INTO nom035_resultados
                (
                  id_aplicacion,
                  id_empleado,
                  id_cuestionario,
                  puntaje_total,
                  nivel_riesgo,
                  resultado_general,
                  categorias,
                  dominios,
                  dimensiones,
                  requiere_accion,
                  recomendaciones,
                  fecha_resultado
                )
                VALUES
                (
                  ?, ?, ?, ?,
                  'no_aplica',
                  ?, ?, ?, ?,
                  ?, ?,
                  NOW()
                )
              `,
              [
                aplicacion.id_aplicacion,

                aplicacion.id_empleado,

                aplicacion.id_cuestionario,

                totalSi,

                resultadoGeneral,

                JSON.stringify(
                  categorias
                ),

                JSON.stringify(
                  []
                ),

                JSON.stringify(
                  []
                ),

                requiereAtencionClinica
                  ? 1
                  : 0,

                recomendaciones
              ]
            );

          idResultado =
            result.insertId;
        }

        await connection.query(
          `
            UPDATE nom035_aplicaciones

            SET
              estatus =
                'completada',

              fecha_completada =
                NOW()

            WHERE
              id_aplicacion = ?
          `,
          [
            aplicacion.id_aplicacion
          ]
        );

        await connection.commit();

        const preevaluacionIA =
          await generarYGuardarPreevaluacionNom035({
            idResultado,

            aplicacion,

            puntajeTotal:
              totalSi,

            nivelRiesgo:
              "no_aplica",

            resultadoGeneral,

            categorias,

            dominios:
              [],

            dimensiones:
              [],

            recomendaciones
          });

        return res.json({
          success: true,

          message:
            "Guía I completada correctamente",

          resultado: {
            id_resultado:
              idResultado,

            guia:
              "I",

            respuestas_si: {
              seccion_i:
                siSeccionI,

              seccion_ii:
                siSeccionII,

              seccion_iii:
                siSeccionIII,

              seccion_iv:
                siSeccionIV
            },

            continuar_secciones:
              true,

            requiere_atencion_clinica:
              requiereAtencionClinica,

            requiere_accion:
              requiereAtencionClinica,

            resultado_general:
              resultadoGeneral,

            recomendaciones,

            preevaluacion_ia:
              preevaluacionIA
                ?.texto ||
              null,

            ia_proveedor:
              preevaluacionIA
                ?.proveedor ||
              null,

            ia_modelo:
              preevaluacionIA
                ?.modelo ||
              null
          }
        });
      }

      // ==================================================
      // GUÍAS II Y III
      // ==================================================

      const guiaActual =
        String(
          aplicacion.guia ||
          ""
        ).trim();

      if (
        guiaActual !== "II" &&
        guiaActual !== "III"
      ) {
        await connection.rollback();

        return res.status(400).json({
          success: false,

          message:
            "La guía del cuestionario no es válida para este proceso."
        });
      }

      const atiendeClientes =
        req.body?.atiende_clientes;

      const tienePersonalCargo =
        req.body?.tiene_personal_cargo;

      if (
        typeof atiendeClientes !==
          "boolean" ||

        typeof tienePersonalCargo !==
          "boolean"
      ) {
        await connection.rollback();

        return res.status(400).json({
          success: false,

          message:
            "Debes indicar si atiendes clientes o usuarios y si tienes personal a tu cargo."
        });
      }

      await connection.query(
        `
          UPDATE nom035_aplicaciones

          SET
            atiende_clientes = ?,

            tiene_personal_cargo = ?

          WHERE
            id_aplicacion = ?
        `,
        [
          atiendeClientes
            ? 1
            : 0,

          tienePersonalCargo
            ? 1
            : 0,

          aplicacion.id_aplicacion
        ]
      );

      const limiteBase =
        guiaActual === "II"
          ? 40
          : 64;

      const rangoClientes =
        guiaActual === "II"
          ? [41, 43]
          : [65, 68];

      const rangoPersonal =
        guiaActual === "II"
          ? [44, 46]
          : [69, 72];

      const rangosRequeridos = [
        [1, limiteBase]
      ];

      if (atiendeClientes) {
        rangosRequeridos.push(
          rangoClientes
        );
      }

      if (tienePersonalCargo) {
        rangosRequeridos.push(
          rangoPersonal
        );
      }

      const totalPreguntasRequeridas =
        rangosRequeridos.reduce(
          (
            total,
            [desde, hasta]
          ) =>
            total +
            (
              hasta -
              desde +
              1
            ),
          0
        );

      const filtroOrdenSQL =
        rangosRequeridos
          .map(
            () =>
              "(p.orden BETWEEN ? AND ?)"
          )
          .join(" OR ");

      const parametrosOrden =
        rangosRequeridos.flatMap(
          ([desde, hasta]) => [
            desde,
            hasta
          ]
        );

      const parametrosRequeridas = [
        aplicacion.id_aplicacion,
        aplicacion.id_cuestionario,
        ...parametrosOrden
      ];

      const [respuestasRows] =
        await connection.query(
          `
            SELECT
              COUNT(
                DISTINCT r.id_pregunta
              ) AS total

            FROM nom035_respuestas r

            INNER JOIN nom035_preguntas p
              ON p.id_pregunta =
                 r.id_pregunta

            WHERE
              r.id_aplicacion = ?
              AND p.id_cuestionario = ?
              AND p.activo = 1

              AND
              (
                ${filtroOrdenSQL}
              )
          `,
          parametrosRequeridas
        );

      const totalRespuestas =
        Number(
          respuestasRows[0]
            ?.total ||
          0
        );

      if (
        totalRespuestas <
        totalPreguntasRequeridas
      ) {
        await connection.rollback();

        return res
          .status(400)
          .json({
            success: false,

            message:
              `Faltan respuestas. Se respondieron ${totalRespuestas} de ${totalPreguntasRequeridas} preguntas requeridas.`
          });
      }

      const [puntajeRows] =
        await connection.query(
          `
            SELECT
              COALESCE(
                SUM(r.valor),
                0
              ) AS puntaje_total

            FROM nom035_respuestas r

            INNER JOIN nom035_preguntas p
              ON p.id_pregunta =
                 r.id_pregunta

            WHERE
              r.id_aplicacion = ?
              AND p.id_cuestionario = ?
              AND p.activo = 1

              AND
              (
                ${filtroOrdenSQL}
              )
          `,
          parametrosRequeridas
        );

      const puntajeTotal =
        Number(
          puntajeRows[0]
            ?.puntaje_total ||
          0
        );

      const cortes =
        obtenerCortesNom035(
          guiaActual
        );

      const nivelRiesgo =
        clasificarPorCortes(
          puntajeTotal,
          cortes.final
        );

      const accion =
        obtenerAccionNom035(
          nivelRiesgo
        );

      const [categoriasRows] =
        await connection.query(
          `
            SELECT
              p.categoria,

              COALESCE(
                SUM(r.valor),
                0
              ) AS puntaje

            FROM nom035_respuestas r

            INNER JOIN nom035_preguntas p
              ON p.id_pregunta =
                 r.id_pregunta

            WHERE
              r.id_aplicacion = ?
              AND p.id_cuestionario = ?
              AND p.activo = 1

              AND p.categoria IS NOT NULL
              AND TRIM(p.categoria) <> ''

              AND
              (
                ${filtroOrdenSQL}
              )

            GROUP BY
              p.categoria

            ORDER BY
              p.categoria ASC
          `,
          parametrosRequeridas
        );

      const [dominiosRows] =
        await connection.query(
          `
            SELECT
              p.dominio,

              COALESCE(
                SUM(r.valor),
                0
              ) AS puntaje

            FROM nom035_respuestas r

            INNER JOIN nom035_preguntas p
              ON p.id_pregunta =
                 r.id_pregunta

            WHERE
              r.id_aplicacion = ?
              AND p.id_cuestionario = ?
              AND p.activo = 1

              AND p.dominio IS NOT NULL
              AND TRIM(p.dominio) <> ''

              AND
              (
                ${filtroOrdenSQL}
              )

            GROUP BY
              p.dominio

            ORDER BY
              p.dominio ASC
          `,
          parametrosRequeridas
        );

      const [dimensionesRows] =
        await connection.query(
          `
            SELECT
              p.dimension,

              COALESCE(
                SUM(r.valor),
                0
              ) AS puntaje

            FROM nom035_respuestas r

            INNER JOIN nom035_preguntas p
              ON p.id_pregunta =
                 r.id_pregunta

            WHERE
              r.id_aplicacion = ?
              AND p.id_cuestionario = ?
              AND p.activo = 1

              AND p.dimension IS NOT NULL
              AND TRIM(p.dimension) <> ''

              AND
              (
                ${filtroOrdenSQL}
              )

            GROUP BY
              p.dimension

            ORDER BY
              p.dimension ASC
          `,
          parametrosRequeridas
        );

      const categorias =
        categoriasRows.map(
          item => {
            const puntaje =
              Number(
                item.puntaje ||
                0
              );

            const cortesCategoria =
              cortes.categorias[
                item.categoria
              ];

            return {
              nombre:
                item.categoria,

              puntaje,

              nivel_riesgo:
                cortesCategoria
                  ? clasificarPorCortes(
                      puntaje,
                      cortesCategoria
                    )
                  : null
            };
          }
        );

      const dominios =
        dominiosRows.map(
          item => {
            const puntaje =
              Number(
                item.puntaje ||
                0
              );

            const cortesDominio =
              cortes.dominios[
                item.dominio
              ];

            return {
              nombre:
                item.dominio,

              puntaje,

              nivel_riesgo:
                cortesDominio
                  ? clasificarPorCortes(
                      puntaje,
                      cortesDominio
                    )
                  : null
            };
          }
        );

      const dimensiones =
        dimensionesRows.map(
          item => ({
            nombre:
              item.dimension,

            puntaje:
              Number(
                item.puntaje ||
                0
              )
          })
        );

      const resultadoGeneral =
        accion.resultado;

      const recomendaciones =
        accion.recomendacion;

      const requiereAccion =
        accion.requiere_accion;

      const [existentes] =
        await connection.query(
          `
            SELECT
              id_resultado

            FROM nom035_resultados

            WHERE
              id_aplicacion = ?

            LIMIT 1
          `,
          [
            aplicacion.id_aplicacion
          ]
        );

      let idResultado;

      if (
        existentes.length
      ) {
        idResultado =
          existentes[0]
            .id_resultado;

        await connection.query(
          `
            UPDATE nom035_resultados

            SET
              puntaje_total = ?,

              nivel_riesgo = ?,

              resultado_general = ?,

              categorias = ?,

              dominios = ?,

              dimensiones = ?,

              requiere_accion = ?,

              recomendaciones = ?,

              fecha_resultado =
                NOW()

            WHERE
              id_resultado = ?
          `,
          [
            puntajeTotal,

            nivelRiesgo,

            resultadoGeneral,

            JSON.stringify(
              categorias
            ),

            JSON.stringify(
              dominios
            ),

            JSON.stringify(
              dimensiones
            ),

            requiereAccion
              ? 1
              : 0,

            recomendaciones,

            idResultado
          ]
        );

      } else {
        const [result] =
          await connection.query(
            `
              INSERT INTO nom035_resultados
              (
                id_aplicacion,
                id_empleado,
                id_cuestionario,
                puntaje_total,
                nivel_riesgo,
                resultado_general,
                categorias,
                dominios,
                dimensiones,
                requiere_accion,
                recomendaciones,
                fecha_resultado
              )
              VALUES
              (
                ?, ?, ?, ?,
                ?, ?,
                ?, ?, ?,
                ?, ?,
                NOW()
              )
            `,
            [
              aplicacion.id_aplicacion,

              aplicacion.id_empleado,

              aplicacion.id_cuestionario,

              puntajeTotal,

              nivelRiesgo,

              resultadoGeneral,

              JSON.stringify(
                categorias
              ),

              JSON.stringify(
                dominios
              ),

              JSON.stringify(
                dimensiones
              ),

              requiereAccion
                ? 1
                : 0,

              recomendaciones
            ]
          );

        idResultado =
          result.insertId;
      }

      await connection.query(
        `
          UPDATE nom035_aplicaciones

          SET
            estatus =
              'completada',

            fecha_completada =
              NOW(),

            atiende_clientes = ?,

            tiene_personal_cargo = ?

          WHERE
            id_aplicacion = ?
        `,
        [
          atiendeClientes
            ? 1
            : 0,

          tienePersonalCargo
            ? 1
            : 0,

          aplicacion.id_aplicacion
        ]
      );

      await connection.commit();

      const preevaluacionIA =
        await generarYGuardarPreevaluacionNom035({
          idResultado,

          aplicacion,

          puntajeTotal,

          nivelRiesgo,

          resultadoGeneral,

          categorias,

          dominios,

          dimensiones,

          recomendaciones
        });

      return res.json({
        success: true,

        message:
          `Guía ${guiaActual} completada correctamente`,

        resultado: {
          id_resultado:
            idResultado,

          guia:
            guiaActual,

          puntaje_total:
            puntajeTotal,

          atiende_clientes:
            atiendeClientes,

          tiene_personal_cargo:
            tienePersonalCargo,

          categorias,

          dominios,

          dimensiones,

          nivel_riesgo:
            nivelRiesgo,

          resultado_general:
            resultadoGeneral,

          recomendaciones,

          requiere_accion:
            requiereAccion,

          preevaluacion_ia:
            preevaluacionIA
              ?.texto ||
            null,

          ia_proveedor:
            preevaluacionIA
              ?.proveedor ||
            null,

          ia_modelo:
            preevaluacionIA
              ?.modelo ||
            null
        }
      });

    } catch (error) {
      if (connection) {
        try {
          await connection.rollback();
        } catch {}
      }

      console.error(
        "❌ Error finalizando NOM-035:",
        error
      );

      return res.status(500).json({
        success: false,

        message:
          "Error interno al finalizar el cuestionario NOM-035",

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
// CANCELAR APLICACIÓN
// ==================================================

export const cancelarNom035Empleado =
  async (
    req,
    res
  ) => {
    try {
      const idEmpleado =
        Number(
          req.params.id
        );

      const idAplicacion =
        Number(
          req.params.idAplicacion
        );

      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0 ||
        !Number.isInteger(
          idAplicacion
        ) ||
        idAplicacion <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Datos de aplicación inválidos"
        });
      }

      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
          req.user
        );

      if (!acceso.ok) {
        return res
          .status(
            acceso.status
          )
          .json({
            success: false,
            message:
              acceso.message
          });
      }

      const [rows] =
        await pool.query(
          `
            SELECT
              id_aplicacion,
              estatus
            FROM nom035_aplicaciones
            WHERE
              id_aplicacion = ?
              AND id_empleado = ?
            LIMIT 1
          `,
          [
            idAplicacion,
            idEmpleado
          ]
        );

      if (!rows.length) {
        return res.status(404).json({
          success: false,
          message:
            "Aplicación NOM-035 no encontrada"
        });
      }

      const estatusActual =
        String(
          rows[0].estatus || ""
        ).toLowerCase();

      if (
        ![
          "habilitada",
          "iniciada"
        ].includes(
          estatusActual
        )
      ) {
        return res.status(409).json({
          success: false,

          message:
            estatusActual ===
            "completada"
              ? "Una aplicación completada no puede cancelarse"
              : "Esta aplicación no puede cancelarse en su estado actual"
        });
      }

      await pool.query(
        `
          UPDATE nom035_aplicaciones

          SET
            estatus =
              'cancelada'

          WHERE
            id_aplicacion = ?
            AND id_empleado = ?
        `,
        [
          idAplicacion,
          idEmpleado
        ]
      );

      return res.json({
        success: true,

        message:
          "Aplicación NOM-035 cancelada correctamente"
      });

    } catch (error) {
      console.error(
        "❌ Error cancelando NOM-035:",
        error
      );

      return res.status(500).json({
        success: false,

        message:
          "Error interno al cancelar la aplicación NOM-035"
      });
    }
  };

// ==================================================
// ELIMINAR APLICACIÓN CANCELADA
// ==================================================

export const eliminarNom035Empleado =
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

      const idAplicacion =
        Number(
          req.params.idAplicacion
        );

      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0 ||
        !Number.isInteger(
          idAplicacion
        ) ||
        idAplicacion <= 0
      ) {
        return res.status(400).json({
          success: false,

          message:
            "Datos de aplicación inválidos"
        });
      }

      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
          req.user
        );

      if (!acceso.ok) {
        return res
          .status(
            acceso.status
          )
          .json({
            success: false,

            message:
              acceso.message
          });
      }

      connection =
        await pool.getConnection();

      await connection.beginTransaction();

      const [rows] =
        await connection.query(
          `
            SELECT
              id_aplicacion,
              estatus

            FROM nom035_aplicaciones

            WHERE
              id_aplicacion = ?
              AND id_empleado = ?

            LIMIT 1

            FOR UPDATE
          `,
          [
            idAplicacion,
            idEmpleado
          ]
        );

      if (!rows.length) {
        await connection.rollback();

        return res.status(404).json({
          success: false,

          message:
            "Aplicación NOM-035 no encontrada"
        });
      }

      const estatus =
        String(
          rows[0].estatus || ""
        ).toLowerCase();

      if (
        estatus ===
        "completada"
      ) {
        await connection.rollback();

        return res.status(409).json({
          success: false,

          message:
            "Una aplicación respondida y completada no puede eliminarse"
        });
      }

      if (
        estatus !==
        "cancelada"
      ) {
        await connection.rollback();

        return res.status(409).json({
          success: false,

          message:
            "Solo las aplicaciones canceladas pueden eliminarse"
        });
      }

      await connection.query(
        `
          DELETE FROM nom035_respuestas

          WHERE
            id_aplicacion = ?
        `,
        [
          idAplicacion
        ]
      );

      await connection.query(
        `
          DELETE FROM nom035_resultados

          WHERE
            id_aplicacion = ?
        `,
        [
          idAplicacion
        ]
      );

      await connection.query(
        `
          DELETE FROM nom035_aplicaciones

          WHERE
            id_aplicacion = ?
            AND id_empleado = ?
            AND estatus =
              'cancelada'
        `,
        [
          idAplicacion,
          idEmpleado
        ]
      );

      await connection.commit();

      return res.json({
        success: true,

        message:
          "Aplicación cancelada eliminada definitivamente"
      });

    } catch (error) {
      if (connection) {
        try {
          await connection.rollback();
        } catch {}
      }

      console.error(
        "❌ Error eliminando aplicación NOM-035:",
        error
      );

      return res.status(500).json({
        success: false,

        message:
          "Error interno al eliminar la aplicación NOM-035"
      });

    } finally {
      if (connection) {
        connection.release();
      }
    }
  };

// ==================================================
// OBTENER RESULTADOS NOM-035 DEL EMPLEADO
//
// GET /api/empleados/:id/nom035/resultados
//
// INCLUYE PRE-EVALUACIÓN IA
// ==================================================

export const obtenerResultadosNom035Empleado =
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
        return res.status(400).json({
          success: false,

          message:
            "ID de empleado inválido"
        });
      }

      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
          req.user
        );

      if (!acceso.ok) {
        return res
          .status(
            acceso.status
          )
          .json({
            success: false,

            message:
              acceso.message
          });
      }

      const [resultados] =
        await pool.query(
          `
            SELECT
              r.id_resultado,
              r.id_aplicacion,
              r.id_empleado,
              r.id_cuestionario,

              r.puntaje_total,
              r.nivel_riesgo,

              r.resultado_general,

              r.categorias,
              r.dominios,
              r.dimensiones,

              r.requiere_accion,

              r.recomendaciones,

              r.preevaluacion_ia,
              r.ia_proveedor,
              r.ia_modelo,
              r.fecha_preevaluacion_ia,

              r.fecha_resultado,

              c.clave,

              c.nombre
                AS cuestionario_nombre,

              c.descripcion
                AS cuestionario_descripcion,

              c.guia,

              c.tipo
                AS cuestionario_tipo,

              c.version,

              a.tipo_aplicacion,

              a.motivo,

              a.atiende_clientes,

              a.tiene_personal_cargo,

              a.fecha_habilitacion,

              a.fecha_inicio,

              a.fecha_completada

            FROM nom035_resultados r

            INNER JOIN nom035_cuestionarios c
              ON c.id_cuestionario =
                 r.id_cuestionario

            INNER JOIN nom035_aplicaciones a
              ON a.id_aplicacion =
                 r.id_aplicacion

            WHERE
              r.id_empleado = ?

            ORDER BY
              r.fecha_resultado DESC,
              r.id_resultado DESC
          `,
          [
            idEmpleado
          ]
        );

      return res.json({
        success: true,

        empleado:
          acceso.empleado,

        total:
          resultados.length,

        resultados
      });

    } catch (error) {
      console.error(
        "❌ Error obteniendo resultados NOM-035:",
        error
      );

      return res.status(500).json({
        success: false,

        message:
          "Error interno al obtener los resultados NOM-035",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined
      });
    }
  };
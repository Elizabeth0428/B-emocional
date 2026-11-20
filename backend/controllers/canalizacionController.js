import crypto from "crypto";
import pool from "../config/database.js";

// ==================================================
// AUXILIARES
// ==================================================

const normalizar = valor =>
  valor ? String(valor).trim().toLowerCase() : "";

const enteroPositivo = valor =>
  Number.isInteger(Number(valor)) && Number(valor) > 0
    ? Number(valor)
    : null;

const calcularIngresoMensualEstimado = (
  sueldo,
  periodicidad
) => {
  const monto = Number(sueldo);
  const tipo = normalizar(periodicidad);

  if (!Number.isFinite(monto) || monto <= 0) {
    return null;
  }

  if (tipo === "semanal") {
    return Number((monto * 4.33).toFixed(2));
  }

  if (tipo === "quincenal") {
    return Number((monto * 2).toFixed(2));
  }

  if (tipo === "mensual") {
    return Number(monto.toFixed(2));
  }

  return null;
};

// ==================================================
// CONTEXTO DEL USUARIO
// ==================================================

const obtenerContextoUsuario = async (
  user,
  connection = pool
) => {
  const idUsuario =
    enteroPositivo(user?.id_usuario);

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
      [idUsuario]
    );

  if (!rows.length) {
    return {
      idUsuario,
      tipoAdmin:
        normalizar(user?.tipo_admin),
      area:
        normalizar(user?.area),
      rol:
        normalizar(user?.rol),
      idAdminPadre:
        enteroPositivo(
          user?.id_admin_padre
        ),

      idOrganizacion:
        enteroPositivo(
          user?.id_organizacion
        ),

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
      enteroPositivo(
        usuario.id_usuario
      ),

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
      enteroPositivo(
        usuario.id_admin_padre
      ),

    idOrganizacion:
      enteroPositivo(
        usuario.id_organizacion
      ),

    perfilIndependiente:
      normalizar(
        usuario.perfil_independiente
      )
  };
};

// ==================================================
// VALIDAR ACCESO RH AL EMPLEADO
// ==================================================

const validarAccesoEmpleadoRH = async (
  idEmpleado,
  user,
  connection = pool
) => {
  const contexto =
    await obtenerContextoUsuario(
      user,
      connection
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
        "No tienes permiso para acceder al módulo de canalización"
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
      e.sueldo,
      e.periodicidad_sueldo,
      e.modalidad_trabajo,
      e.modalidad_atencion_preferida,
      e.horario_laboral,
      e.estado_residencia,
      e.municipio_residencia,
      e.colonia_residencia,
      e.codigo_postal_residencia,
      e.perfil_laboral_completo,
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
// ÁREAS AUTOMÁTICAS DE CANALIZACIÓN DEL SISTEMA
//
// La canalización automática NO pide a RH volver a
// elegir áreas. Las obtiene de la recomendación que
// originó la canalización.
//
// Ejemplos:
// - GAD-7 -> Ansiedad
// - WHO-5 -> Manejo emocional
// - Estrés laboral -> Estrés laboral
// - NOM-035 Guía I / evento traumático ->
//   Trauma + Estrés postraumático
// ==================================================

const parseJSONSeguro = valor => {

  if (!valor) {
    return null;
  }

  if (
    typeof valor ===
    "object"
  ) {
    return valor;
  }

  try {
    return JSON.parse(
      valor
    );
  } catch {
    return null;
  }
};


const normalizarListaAreas =
  valor => {

    if (!valor) {
      return [];
    }

    const lista =
      Array.isArray(valor)
        ? valor
        : parseJSONSeguro(
            valor
          );

    if (
      !Array.isArray(
        lista
      )
    ) {
      return [];
    }

    return [
      ...new Set(
        lista
          .map(Number)
          .filter(
            item =>
              Number.isInteger(
                item
              ) &&
              item > 0
          )
      )
    ];
  };


const obtenerClavesAreasSistema =
  recomendacion => {

    if (!recomendacion) {
      return [];
    }

    const factores =
      parseJSONSeguro(
        recomendacion
          .factores_detectados
      ) || {};

    const version =
      normalizar(
        factores.version ||
        factores.prueba_version ||
        ""
      );

    const textoDeteccion =
      normalizar(
        [
          recomendacion.origen,
          recomendacion.resultado_detectado,
          factores.prueba,
          factores.descripcion,
          factores.version,
          factores.categoria,
          factores.resultado_texto,
          factores.interpretacion,
          factores.interpretacion_laboral,
          factores.guia,
          factores.categorias
        ]
          .filter(Boolean)
          .join(" ")
      );

    const claves =
      new Set();

    // GAD-7 = ansiedad
    if (
      version ===
        "gad-7" ||
      textoDeteccion.includes(
        "gad-7"
      ) ||
      textoDeteccion.includes(
        "ansiedad"
      )
    ) {
      claves.add(
        "ansiedad"
      );
    }

    // WHO-5 = bienestar / manejo emocional
    if (
      version ===
        "who-5" ||
      textoDeteccion.includes(
        "who-5"
      )
    ) {
      claves.add(
        "manejo_emocional"
      );
    }

    // Estrés laboral
    if (
      recomendacion.origen ===
        "estres_laboral" ||
      textoDeteccion.includes(
        "estres laboral"
      )
    ) {
      claves.add(
        "estres_laboral"
      );
    }

    // Burnout
    if (
      textoDeteccion.includes(
        "burnout"
      )
    ) {
      claves.add(
        "burnout"
      );
    }

    // Violencia / acoso laboral
    if (
      textoDeteccion.includes(
        "violencia laboral"
      )
    ) {
      claves.add(
        "violencia_laboral"
      );
    }

    if (
      textoDeteccion.includes(
        "acoso laboral"
      )
    ) {
      claves.add(
        "acoso_laboral"
      );
    }

    // Evento traumático
    if (
      textoDeteccion.includes(
        "traumatic"
      ) ||
      textoDeteccion.includes(
        "trauma"
      )
    ) {
      claves.add(
        "trauma"
      );

      claves.add(
        "estres_postraumatico"
      );
    }

    // NOM-035:
    // si no se detectó una categoría más específica,
    // usamos estrés laboral como área laboral base.
    if (
      recomendacion.origen ===
        "nom035" &&
      claves.size === 0
    ) {
      claves.add(
        "estres_laboral"
      );
    }

    return [
      ...claves
    ];
  };


const resolverAreasSistema =
  async (
    canalizacion,
    connection = pool
  ) => {

    if (
      !canalizacion ||
      canalizacion
        .tipo_deteccion !==
        "sistema"
    ) {
      return [];
    }

    const areasActuales =
      normalizarListaAreas(
        canalizacion
          .areas_atencion_requeridas
      );

    if (
      areasActuales.length
    ) {
      return areasActuales;
    }

    const [recomendaciones] =
      await connection.query(
        `
          SELECT
            id_recomendacion,
            origen,
            id_referencia_origen,
            resultado_detectado,
            factores_detectados

          FROM recomendaciones_canalizacion

          WHERE
            id_empleado = ?
            AND origen = ?
            AND id_referencia_origen = ?

          ORDER BY
            id_recomendacion DESC

          LIMIT 1
        `,
        [
          canalizacion
            .id_empleado,

          canalizacion.origen,

          canalizacion
            .id_referencia_origen
        ]
      );

    if (
      !recomendaciones.length
    ) {
      return [];
    }

    const claves =
      obtenerClavesAreasSistema(
        recomendaciones[0]
      );

    if (
      !claves.length
    ) {
      return [];
    }

    const placeholders =
      claves
        .map(
          () => "?"
        )
        .join(",");

    const [areas] =
      await connection.query(
        `
          SELECT
            id_area,
            clave,
            nombre

          FROM catalogo_areas_atencion

          WHERE
            activo = 1
            AND clave IN
            (
              ${placeholders}
            )

          ORDER BY
            orden ASC,
            id_area ASC
        `,
        claves
      );

    return [
      ...new Set(
        areas.map(
          area =>
            Number(
              area.id_area
            )
        )
      )
    ];
  };


const asegurarAreasSistemaCanalizacion =
  async (
    canalizacion,
    connection = pool
  ) => {

    if (
      !canalizacion ||
      canalizacion
        .tipo_deteccion !==
        "sistema"
    ) {
      return canalizacion;
    }

    const areasActuales =
      normalizarListaAreas(
        canalizacion
          .areas_atencion_requeridas
      );

    if (
      areasActuales.length
    ) {
      return canalizacion;
    }

    const areasSistema =
      await resolverAreasSistema(
        canalizacion,
        connection
      );

    if (
      !areasSistema.length
    ) {
      return canalizacion;
    }

    await connection.query(
      `
        UPDATE canalizaciones

        SET
          areas_atencion_requeridas = ?

        WHERE
          id_canalizacion = ?
          AND id_empleado = ?
      `,
      [
        JSON.stringify(
          areasSistema
        ),

        canalizacion
          .id_canalizacion,

        canalizacion
          .id_empleado
      ]
    );

    return {
      ...canalizacion,

      areas_atencion_requeridas:
        JSON.stringify(
          areasSistema
        )
    };
  };


// ==================================================
// OBTENER CANALIZACIÓN
// ==================================================

const obtenerCanalizacionRH = async (
  idCanalizacion,
  idEmpleado,
  connection = pool,
  forUpdate = false
) => {
  const [rows] =
    await connection.query(
      `
        SELECT *
        FROM canalizaciones

        WHERE
          id_canalizacion = ?
          AND id_empleado = ?

        LIMIT 1

        ${
          forUpdate
            ? "FOR UPDATE"
            : ""
        }
      `,
      [
        idCanalizacion,
        idEmpleado
      ]
    );

  if (!rows.length) {
    return null;
  }

  return await asegurarAreasSistemaCanalizacion(
    rows[0],
    connection
  );
};

// ==================================================
// REGISTRAR HISTORIAL
// ==================================================

const registrarHistorial = async (
  connection,
  idCanalizacion,
  idUsuario,
  evento,
  detalle = null
) => {
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
        ?, ?, ?, ?, NOW()
      )
    `,
    [
      idCanalizacion,
      idUsuario || null,
      evento,
      detalle || null
    ]
  );
};

// ==================================================
// VALORES PERMITIDOS
// ==================================================

const origenesPermitidos = [
  "nom035",
  "estres_laboral",
  "otra_prueba",
  "entrevista_rh",
  "observacion_rh"
];

const tiposSeguimientoPermitidos = [
  "contacto",
  "recordatorio",
  "sin_respuesta",
  "nuevas_opciones",
  "rechazo",
  "seguimiento_general"
];

const motivosNoSeleccionPermitidos = [
  "costo",
  "ubicacion",
  "horario",
  "no_interesaron_opciones",
  "prefiere_otro_profesional",
  "no_desea_atencion",
  "no_respondio",
  "aun_valorando",
  "otro"
];

const nivelesRecomendacionPermitidos = [
  "no_requiere",
  "seguimiento",
  "canalizacion"
];

const decisionesRHPermitidas = [
  "canalizar",
  "seguimiento",
  "no_canalizar"
];

const origenesSistemaPermitidos = [
  "nom035",
  "estres_laboral",
  "otra_prueba"
];

// ==================================================
// LISTAR CANALIZACIONES DEL EMPLEADO
// ==================================================

export const listarCanalizacionesEmpleado =
async (req, res) => {
  try {
    const idEmpleado =
      enteroPositivo(
        req.params.id
      );

    if (!idEmpleado) {
      return res.status(400).json({
        success: false,
        message:
          "ID de empleado inválido"
      });
    }

    const acceso =
      await validarAccesoEmpleadoRH(
        idEmpleado,
        req.user
      );

    if (!acceso.ok) {
      return res
        .status(acceso.status)
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
            c.*,

            CASE
              WHEN
                c.id_opcion_elegida IS NULL

                AND c.fecha_limite_seguimiento
                    IS NOT NULL

                AND NOW() >=
                    c.fecha_limite_seguimiento

                AND c.estatus IN
                (
                  'opciones_enviadas',
                  'pendiente_eleccion',
                  'sin_seleccion',
                  'en_seguimiento'
                )

              THEN 1
              ELSE 0
            END
              AS seguimiento_requerido,

            (
              SELECT COUNT(*)

              FROM canalizacion_profesionales cp2

              WHERE
                cp2.id_canalizacion =
                c.id_canalizacion
            )
              AS total_opciones,

            (
              SELECT COUNT(*)

              FROM canalizacion_seguimientos cs

              WHERE
                cs.id_canalizacion =
                c.id_canalizacion
            )
              AS total_seguimientos,

            cp.tipo_profesional
              AS tipo_profesional_elegido,

            cp.id_psicologo
              AS id_psicologo_elegido,

            cp.id_profesional_externo
              AS id_profesional_externo_elegido,

            COALESCE(
              ui.nombre,
              pe.nombre
            )
              AS profesional_elegido

          FROM canalizaciones c

          LEFT JOIN canalizacion_profesionales cp
            ON cp.id_opcion =
               c.id_opcion_elegida

          LEFT JOIN psicologos p
            ON p.id_psicologo =
               cp.id_psicologo

          LEFT JOIN usuarios ui
            ON ui.id_usuario =
               p.id_usuario

          LEFT JOIN profesionales_externos pe
            ON pe.id_profesional_externo =
               cp.id_profesional_externo

          WHERE
            c.id_empleado = ?

          ORDER BY
            c.fecha_creacion DESC,
            c.id_canalizacion DESC
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
        rows.length,
      canalizaciones:
        rows
    });

  } catch (error) {
    console.error(
      "❌ Error listando canalizaciones:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Error interno al obtener las canalizaciones"
    });
  }
};

// ==================================================
// OBTENER DETALLE DE UNA CANALIZACIÓN
// ==================================================

export const obtenerCanalizacionEmpleado =
async (req, res) => {
  try {
    const idEmpleado =
      enteroPositivo(
        req.params.id
      );

    const idCanalizacion =
      enteroPositivo(
        req.params.idCanalizacion
      );

    if (
      !idEmpleado ||
      !idCanalizacion
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Datos de canalización inválidos"
      });
    }

    const acceso =
      await validarAccesoEmpleadoRH(
        idEmpleado,
        req.user
      );

    if (!acceso.ok) {
      return res
        .status(acceso.status)
        .json({
          success: false,
          message:
            acceso.message
        });
    }

    const canalizacion =
      await obtenerCanalizacionRH(
        idCanalizacion,
        idEmpleado
      );

    if (!canalizacion) {
      return res.status(404).json({
        success: false,
        message:
          "Canalización no encontrada"
      });
    }

    const [opciones] =
      await pool.query(
        `
          SELECT
            cp.*,

            COALESCE(
              ui.nombre,
              pe.nombre
            )
              AS nombre_profesional,

            COALESCE(
              p.especialidad,
              pe.especialidad
            )
              AS especialidad,

            p.cedula_profesional,

            COALESCE(
              p.telefono,
              ui.telefono,
              pe.telefono
            )
              AS telefono,

            COALESCE(
              p.direccion,
              ui.direccion,
              pe.direccion
            )
              AS direccion,

            COALESCE(
              p.descripcion_profesional,
              pe.descripcion
            ) AS descripcion,

            COALESCE(
              p.modalidad_presencial,
              pe.modalidad_presencial
            ) AS modalidad_presencial,

            COALESCE(
              p.modalidad_videollamada,
              pe.modalidad_videollamada
            ) AS modalidad_videollamada,

            COALESCE(
              p.precio_presencial,
              pe.precio_presencial
            ) AS precio_presencial,

            COALESCE(
              p.precio_videollamada,
              pe.precio_videollamada
            ) AS precio_videollamada,

            COALESCE(
              p.estado,
              pe.estado
            ) AS estado,

            COALESCE(
              p.municipio,
              pe.municipio
            ) AS municipio

          FROM canalizacion_profesionales cp

          LEFT JOIN psicologos p
            ON p.id_psicologo =
               cp.id_psicologo

          LEFT JOIN usuarios ui
            ON ui.id_usuario =
               p.id_usuario

          LEFT JOIN profesionales_externos pe
            ON pe.id_profesional_externo =
               cp.id_profesional_externo

          WHERE
            cp.id_canalizacion = ?

          ORDER BY
            cp.orden ASC,
            cp.id_opcion ASC
        `,
        [
          idCanalizacion
        ]
      );

    const [seguimientos] =
      await pool.query(
        `
          SELECT
            cs.*,

            u.nombre
              AS usuario_rh_nombre

          FROM canalizacion_seguimientos cs

          LEFT JOIN usuarios u
            ON u.id_usuario =
               cs.id_usuario_rh

          WHERE
            cs.id_canalizacion = ?

          ORDER BY
            cs.fecha_seguimiento DESC,
            cs.id_seguimiento DESC
        `,
        [
          idCanalizacion
        ]
      );

    const [historial] =
      await pool.query(
        `
          SELECT
            ch.*,

            u.nombre
              AS usuario_nombre

          FROM canalizacion_historial ch

          LEFT JOIN usuarios u
            ON u.id_usuario =
               ch.id_usuario

          WHERE
            ch.id_canalizacion = ?

          ORDER BY
            ch.fecha_evento DESC,
            ch.id_historial DESC
        `,
        [
          idCanalizacion
        ]
      );

    const seguimientoRequerido =
      !canalizacion.id_opcion_elegida &&

      canalizacion.fecha_limite_seguimiento &&

      new Date(
        canalizacion.fecha_limite_seguimiento
      ) <= new Date() &&

      [
        "opciones_enviadas",
        "pendiente_eleccion",
        "sin_seleccion",
        "en_seguimiento"
      ].includes(
        canalizacion.estatus
      );

    return res.json({
      success: true,

      empleado:
        acceso.empleado,

      canalizacion: {
        ...canalizacion,

        seguimiento_requerido:
          seguimientoRequerido
            ? 1
            : 0
      },

      opciones,
      seguimientos,
      historial
    });

  } catch (error) {
    console.error(
      "❌ Error obteniendo canalización:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Error interno al obtener la canalización"
    });
  }
};

// ==================================================
// CREAR CANALIZACIÓN MANUAL DESDE RH
// ==================================================

export const crearCanalizacion =
async (req, res) => {
  let connection;

  try {
    const idEmpleado =
      enteroPositivo(
        req.params.id
      );

    const origen =
      normalizar(
        req.body?.origen
      );

    const idReferenciaOrigen =
      enteroPositivo(
        req.body
          ?.id_referencia_origen
      );

    const motivo =
      String(
        req.body?.motivo ||
        ""
      ).trim();

    if (!idEmpleado) {
      return res.status(400).json({
        success: false,
        message:
          "ID de empleado inválido"
      });
    }

    if (
      !origenesPermitidos.includes(
        origen
      )
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Origen de canalización inválido"
      });
    }

    if (!motivo) {
      return res.status(400).json({
        success: false,
        message:
          "Debes indicar el motivo de la canalización"
      });
    }

    connection =
      await pool.getConnection();

    await connection.beginTransaction();

    const acceso =
      await validarAccesoEmpleadoRH(
        idEmpleado,
        req.user,
        connection
      );

    if (!acceso.ok) {
      await connection.rollback();

      return res
        .status(acceso.status)
        .json({
          success: false,
          message:
            acceso.message
        });
    }

    if (idReferenciaOrigen) {
      const [duplicadas] =
        await connection.query(
          `
            SELECT
              id_canalizacion,
              estatus

            FROM canalizaciones

            WHERE
              id_empleado = ?
              AND origen = ?
              AND id_referencia_origen = ?

              AND estatus NOT IN
              (
                'cerrada',
                'cancelada'
              )

            LIMIT 1
          `,
          [
            idEmpleado,
            origen,
            idReferenciaOrigen
          ]
        );

      if (duplicadas.length) {
        await connection.rollback();

        return res.status(409).json({
          success: false,

          message:
            "Ya existe una canalización activa para este origen y referencia",

          canalizacion:
            duplicadas[0]
        });
      }
    }

    const tokenPublico =
      crypto
        .randomBytes(32)
        .toString("hex");

    const [result] =
      await connection.query(
        `
          INSERT INTO canalizaciones
          (
            id_empleado,
            id_usuario_rh,
            tipo_deteccion,
            token_publico,
            origen,
            id_referencia_origen,
            recomendacion_sistema,
            preevaluacion_ia,
            decision_rh,
            motivo_decision_rh,
            motivo,
            estatus,
            fecha_creacion
          )
          VALUES
          (
            ?,
            ?,
            'rh',
            ?,
            ?,
            ?,
            NULL,
            NULL,
            'canalizar',
            ?,
            ?,
            'pendiente_revision',
            NOW()
          )
        `,
        [
          idEmpleado,
          acceso.contexto.idUsuario,
          tokenPublico,
          origen,
          idReferenciaOrigen,
          motivo,
          motivo
        ]
      );

    await registrarHistorial(
      connection,
      result.insertId,
      acceso.contexto.idUsuario,
      "Canalización creada por RH",
      `Origen: ${origen}. Motivo: ${motivo}`
    );

    await connection.commit();

    return res.status(201).json({
      success: true,

      message:
        "Canalización creada correctamente",

      canalizacion: {
        id_canalizacion:
          result.insertId,

        id_empleado:
          idEmpleado,

        tipo_deteccion:
          "rh",

        origen,

        id_referencia_origen:
          idReferenciaOrigen,

        recomendacion_sistema:
          null,

        preevaluacion_ia:
          null,

        decision_rh:
          "canalizar",

        motivo_decision_rh:
          motivo,

        motivo,

        estatus:
          "pendiente_revision",

        token_publico:
          tokenPublico
      }
    });

  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch {}
    }

    console.error(
      "❌ Error creando canalización:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Error interno al crear la canalización"
    });

  } finally {
    if (connection) {
      connection.release();
    }
  }
};

// ==================================================
// LISTAR RECOMENDACIONES DEL SISTEMA
//
// FUENTES CONECTADAS:
// - NOM-035
// - GAD-7
// - WHO-5
//
// IMPORTANTE:
// - CANALIZACIÓN NO GENERA IA.
// - SOLO LEE LA PREEVALUACIÓN IA YA GUARDADA
//   EN EL RESULTADO DE LA PRUEBA DE ORIGEN.
// - RH CONSERVA LA DECISIÓN FINAL.
// ==================================================

export const listarRecomendacionesCanalizacion =
async (req, res) => {

  let connection;

  try {

    const idEmpleado =
      enteroPositivo(
        req.params.id
      );


    if (!idEmpleado) {

      return res.status(400).json({
        success: false,

        message:
          "ID de empleado inválido"
      });

    }


    connection =
      await pool.getConnection();


    await connection.beginTransaction();


    const acceso =
      await validarAccesoEmpleadoRH(
        idEmpleado,
        req.user,
        connection
      );


    if (!acceso.ok) {

      await connection.rollback();


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


    // ==================================================
    // 1. NOM-035
    // ==================================================

    const [resultadosNom] =
      await connection.query(
        `
          SELECT

            a.id_aplicacion,

            a.id_empleado,

            a.id_cuestionario,

            a.tipo_aplicacion,

            a.fecha_completada,


            c.clave,

            c.nombre
              AS cuestionario_nombre,

            c.descripcion
              AS cuestionario_descripcion,

            c.guia,

            c.version,


            r.id_resultado,

            r.puntaje_total,

            r.nivel_riesgo,

            r.resultado_general,

            r.categorias,

            r.requiere_accion,

            r.recomendaciones,

            r.fecha_resultado


          FROM nom035_aplicaciones a


          INNER JOIN nom035_cuestionarios c

            ON c.id_cuestionario =
               a.id_cuestionario


          INNER JOIN nom035_resultados r

            ON r.id_aplicacion =
               a.id_aplicacion


          WHERE

            a.id_empleado = ?


            AND a.estatus =
              'completada'


            AND r.requiere_accion = 1


          ORDER BY

            r.fecha_resultado DESC,

            a.id_aplicacion DESC
        `,
        [
          idEmpleado
        ]
      );


    // ==================================================
    // CREAR RECOMENDACIÓN NOM-035
    // SI TODAVÍA NO EXISTE
    // ==================================================

    for (
      const resultado
      of resultadosNom
    ) {

      const [existente] =
        await connection.query(
          `
            SELECT

              id_recomendacion


            FROM recomendaciones_canalizacion


            WHERE

              id_empleado = ?


              AND origen =
                'nom035'


              AND id_referencia_origen = ?


            LIMIT 1
          `,
          [
            idEmpleado,

            resultado.id_aplicacion
          ]
        );


      if (
        !existente.length
      ) {

        const resultadoDetectado =
          resultado.resultado_general ||

          `La aplicación NOM-035 Guía ${resultado.guia} requiere atención.`;


        await connection.query(
          `
            INSERT INTO recomendaciones_canalizacion
            (
              id_empleado,

              origen,

              id_referencia_origen,

              nivel_recomendacion,

              resultado_detectado,

              preevaluacion_ia,

              factores_detectados,

              revisada_rh,

              decision_rh,

              fecha_deteccion,

              created_at,

              updated_at
            )

            VALUES
            (
              ?,

              'nom035',

              ?,

              'canalizacion',

              ?,

              NULL,

              ?,

              0,

              'pendiente',

              ?,

              NOW(),

              NOW()
            )
          `,
          [

            idEmpleado,


            resultado.id_aplicacion,


            resultadoDetectado,


            resultado.categorias ||
            null,


            resultado.fecha_resultado ||

            resultado.fecha_completada ||

            new Date()

          ]
        );

      }

    }


    // ==================================================
    // 2. RESULTADOS DE PRUEBAS RH
    //
    // IMPORTANTE:
    //
    // AQUÍ NO GENERAMOS IA.
    //
    // LA IA YA FUE GENERADA EN:
    // pruebaEmpleadoController.js
    //
    // Y ESTÁ GUARDADA EN:
    // resultados_prueba_empleado.preevaluacion_ia
    // ==================================================

    const [resultadosPruebasRH] =
      await connection.query(
        `
          SELECT

            r.id_resultado,

            r.id_habilitacion,

            r.id_empleado,

            r.id_prueba_rh,

            r.puntaje_total,

            r.resultado_texto,

            r.interpretacion,

            r.interpretacion_laboral,

            r.preevaluacion_ia,

            r.ia_proveedor,

            r.ia_modelo,

            r.fecha_preevaluacion_ia,

            r.fecha_resultado,


            p.nombre
              AS prueba_nombre,

            p.descripcion
              AS prueba_descripcion,

            p.categoria,

            p.version,


            h.tipo_evaluacion,

            h.motivo,

            h.fecha_habilitacion,

            h.fecha_completada


          FROM resultados_prueba_empleado r


          INNER JOIN pruebas_rh p

            ON p.id_prueba_rh =
               r.id_prueba_rh


          INNER JOIN pruebas_empleados_habilitadas h

            ON h.id_habilitacion =
               r.id_habilitacion


          WHERE

            r.id_empleado = ?


            AND h.estatus =
              'completada'


            AND LOWER(
              TRIM(
                COALESCE(
                  p.version,
                  ''
                )
              )
            )
            IN
            (
              'gad-7',
              'who-5'
            )


          ORDER BY

            r.fecha_resultado DESC,

            r.id_resultado DESC
        `,
        [
          idEmpleado
        ]
      );


    // ==================================================
    // CREAR / ACTUALIZAR RECOMENDACIONES
    // DE PRUEBAS RH
    // ==================================================

    for (
      const resultado
      of resultadosPruebasRH
    ) {

      const version =
        normalizar(
          resultado.version
        );


      const puntaje =
        Number(
          resultado.puntaje_total ||
          0
        );


      let nivelRecomendacion =
        "no_requiere";


      // ==================================================
      // GAD-7
      //
      // 0 - 4
      // NO REQUIERE
      //
      // 5 - 9
      // SEGUIMIENTO
      //
      // 10 O MÁS
      // RECOMENDACIÓN DE CANALIZACIÓN
      //
      // RH TODAVÍA DEBE DECIDIR.
      // ==================================================

      if (
        version ===
        "gad-7"
      ) {

        if (
          puntaje >= 10
        ) {

          nivelRecomendacion =
            "canalizacion";

        }

        else if (
          puntaje >= 5
        ) {

          nivelRecomendacion =
            "seguimiento";

        }

        else {

          nivelRecomendacion =
            "no_requiere";

        }

      }


      // ==================================================
      // WHO-5
      //
      // MENOR A 13
      // SEGUIMIENTO PREVENTIVO
      //
      // 13 O MÁS
      // NO ACTIVA REVISIÓN POR PUNTO DE REFERENCIA
      //
      // NO GENERAMOS CANALIZACIÓN AUTOMÁTICA.
      // ==================================================

      else if (
        version ===
        "who-5"
      ) {

        if (
          puntaje < 13
        ) {

          nivelRecomendacion =
            "seguimiento";

        }

        else {

          nivelRecomendacion =
            "no_requiere";

        }

      }


      // ==================================================
      // RESULTADO DETECTADO
      //
      // PRIORIZAMOS LA INTERPRETACIÓN LABORAL.
      // ==================================================

      const resultadoDetectado =

        resultado.interpretacion_laboral ||

        resultado.interpretacion ||

        resultado.resultado_texto ||

        `${resultado.prueba_nombre}: puntaje ${puntaje}.`;


      // ==================================================
      // INFORMACIÓN COMPLETA DEL RESULTADO
      //
      // SE GUARDA COMO JSON PARA QUE CANALIZACIÓN
      // PUEDA MOSTRAR LOS DATOS DE LA PRUEBA.
      // ==================================================

      const factoresDetectados =
        JSON.stringify({

          tipo_fuente:
            "evaluacion_rh",


          id_resultado:
            resultado.id_resultado,


          id_habilitacion:
            resultado.id_habilitacion,


          id_prueba_rh:
            resultado.id_prueba_rh,


          prueba:
            resultado.prueba_nombre,


          descripcion:
            resultado.prueba_descripcion ||
            null,


          version:
            resultado.version,


          categoria:
            resultado.categoria,


          puntaje_total:
            puntaje,


          resultado_texto:
            resultado.resultado_texto ||
            null,


          interpretacion:
            resultado.interpretacion ||
            null,


          interpretacion_laboral:
            resultado.interpretacion_laboral ||
            null,


          ia_proveedor:
            resultado.ia_proveedor ||
            null,


          ia_modelo:
            resultado.ia_modelo ||
            null,


          fecha_preevaluacion_ia:
            resultado.fecha_preevaluacion_ia ||
            null

        });


      // ==================================================
      // VERIFICAR SI YA EXISTE
      //
      // LA REFERENCIA ES EL id_resultado.
      // ==================================================

      const [existentePrueba] =
        await connection.query(
          `
            SELECT

              id_recomendacion,

              decision_rh


            FROM recomendaciones_canalizacion


            WHERE

              id_empleado = ?


              AND origen =
                'otra_prueba'


              AND id_referencia_origen = ?


            LIMIT 1


            FOR UPDATE
          `,
          [
            idEmpleado,

            resultado.id_resultado
          ]
        );


      // ==================================================
      // YA EXISTE
      //
      // SINCRONIZAMOS DATOS.
      //
      // NO CAMBIAMOS:
      // - decision_rh
      // - revisada_rh
      // - observacion_rh
      //
      // PORQUE ESAS SON DECISIONES HUMANAS.
      // ==================================================

      if (
        existentePrueba.length
      ) {

        await connection.query(
          `
            UPDATE recomendaciones_canalizacion


            SET

              nivel_recomendacion = ?,

              resultado_detectado = ?,

              preevaluacion_ia = ?,

              factores_detectados = ?,

              fecha_deteccion = ?,

              updated_at = NOW()


            WHERE

              id_recomendacion = ?
          `,
          [

            nivelRecomendacion,


            resultadoDetectado,


            resultado.preevaluacion_ia ||
            null,


            factoresDetectados,


            resultado.fecha_resultado ||

            resultado.fecha_completada ||

            new Date(),


            existentePrueba[0]
              .id_recomendacion

          ]
        );

      }


      // ==================================================
      // NO EXISTE
      //
      // CREAMOS RECOMENDACIÓN.
      // ==================================================

      else {

        await connection.query(
          `
            INSERT INTO recomendaciones_canalizacion
            (
              id_empleado,

              origen,

              id_referencia_origen,

              nivel_recomendacion,

              resultado_detectado,

              preevaluacion_ia,

              factores_detectados,

              revisada_rh,

              decision_rh,

              fecha_deteccion,

              created_at,

              updated_at
            )

            VALUES
            (
              ?,

              'otra_prueba',

              ?,

              ?,

              ?,

              ?,

              ?,

              0,

              'pendiente',

              ?,

              NOW(),

              NOW()
            )
          `,
          [

            idEmpleado,


            resultado.id_resultado,


            nivelRecomendacion,


            resultadoDetectado,


            resultado.preevaluacion_ia ||
            null,


            factoresDetectados,


            resultado.fecha_resultado ||

            resultado.fecha_completada ||

            new Date()

          ]
        );

      }

    }


    // ==================================================
    // 3. LISTAR RECOMENDACIONES
    //
    // AQUÍ UNIMOS:
    //
    // - NOM-035
    // - PRUEBAS RH
    //
    // SIN GENERAR NUEVA IA.
    // ==================================================

    const [rows] =
      await connection.query(
        `
          SELECT

            rc.id_recomendacion,

            rc.id_empleado,

            rc.origen,

            rc.id_referencia_origen,

            rc.nivel_recomendacion,

            rc.resultado_detectado,

            rc.preevaluacion_ia,

            rc.factores_detectados,

            rc.revisada_rh,

            rc.decision_rh,

            rc.id_usuario_revision,

            rc.observacion_rh,

            rc.fecha_deteccion,

            rc.fecha_revision,

            rc.created_at,

            rc.updated_at,


            u.nombre
              AS usuario_revision,


            can.id_canalizacion,


            can.estatus
              AS estatus_canalizacion,


            na.id_cuestionario
              AS nom_id_cuestionario,


            nc.nombre
              AS cuestionario_nombre,


            nc.descripcion
              AS cuestionario_descripcion,


            nc.guia,


            nc.clave
              AS cuestionario_clave,


            nc.version
              AS cuestionario_version,


            nr.id_resultado
              AS nom_id_resultado,


            nr.puntaje_total
              AS nom_puntaje_total,


            nr.nivel_riesgo
              AS nom_nivel_riesgo,


            nr.resultado_general
              AS nom_resultado_general,


            nr.recomendaciones
              AS nom_recomendaciones,


            nr.requiere_accion
              AS nom_requiere_accion,


            nr.fecha_resultado
              AS nom_fecha_resultado,


            rr.id_resultado
              AS prueba_id_resultado,


            rr.id_habilitacion
              AS prueba_id_habilitacion,


            rr.id_prueba_rh
              AS prueba_id_prueba_rh,


            rr.puntaje_total
              AS prueba_puntaje_total,


            rr.resultado_texto
              AS prueba_resultado_texto,


            rr.interpretacion
              AS prueba_interpretacion,


            rr.interpretacion_laboral
              AS prueba_interpretacion_laboral,


            rr.preevaluacion_ia
              AS prueba_preevaluacion_ia,


            rr.ia_proveedor
              AS prueba_ia_proveedor,


            rr.ia_modelo
              AS prueba_ia_modelo,


            rr.fecha_preevaluacion_ia
              AS prueba_fecha_preevaluacion_ia,


            rr.fecha_resultado
              AS prueba_fecha_resultado,


            pr.nombre
              AS prueba_nombre,


            pr.descripcion
              AS prueba_descripcion,


            pr.categoria
              AS prueba_categoria,


            pr.version
              AS prueba_version,


            ph.tipo_evaluacion
              AS prueba_tipo_evaluacion,


            ph.motivo
              AS prueba_motivo,


            ph.fecha_habilitacion
              AS prueba_fecha_habilitacion,


            ph.fecha_completada
              AS prueba_fecha_completada


          FROM recomendaciones_canalizacion rc


          LEFT JOIN usuarios u

            ON u.id_usuario =
               rc.id_usuario_revision


          LEFT JOIN canalizaciones can

            ON can.id_canalizacion =
            (
              SELECT

                c2.id_canalizacion


              FROM canalizaciones c2


              WHERE

                c2.id_empleado =
                  rc.id_empleado


                AND c2.tipo_deteccion =
                  'sistema'


                AND c2.origen =
                  rc.origen


                AND c2.id_referencia_origen =
                  rc.id_referencia_origen


              ORDER BY

                c2.id_canalizacion DESC


              LIMIT 1
            )


          LEFT JOIN nom035_aplicaciones na

            ON rc.origen =
               'nom035'


            AND na.id_aplicacion =
               rc.id_referencia_origen


          LEFT JOIN nom035_cuestionarios nc

            ON nc.id_cuestionario =
               na.id_cuestionario


          LEFT JOIN nom035_resultados nr

            ON nr.id_aplicacion =
               na.id_aplicacion


          LEFT JOIN resultados_prueba_empleado rr

            ON rc.origen =
               'otra_prueba'


            AND rr.id_resultado =
               rc.id_referencia_origen


          LEFT JOIN pruebas_rh pr

            ON pr.id_prueba_rh =
               rr.id_prueba_rh


          LEFT JOIN pruebas_empleados_habilitadas ph

            ON ph.id_habilitacion =
               rr.id_habilitacion


          WHERE

            rc.id_empleado = ?


          ORDER BY

            CASE

              WHEN
                rc.decision_rh =
                'pendiente'

              THEN 0

              ELSE 1

            END,


            rc.fecha_deteccion DESC,


            rc.id_recomendacion DESC
        `,
        [
          idEmpleado
        ]
      );


    // ==================================================
    // FINALIZAR TRANSACCIÓN
    // ==================================================

    await connection.commit();


    // ==================================================
    // RESPUESTA
    // ==================================================

    return res.json({

      success: true,


      empleado:
        acceso.empleado,


      total:
        rows.length,


      pendientes:
        rows.filter(
          item =>
            item.decision_rh ===
            "pendiente"
        ).length,


      recomendaciones:
        rows

    });


  } catch (error) {

    if (connection) {

      try {

        await connection.rollback();

      } catch {}

    }


    console.error(
      "❌ Error listando recomendaciones de canalización:",
      error
    );


    return res.status(500).json({

      success: false,


      message:
        "Error interno al obtener las recomendaciones de canalización",


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
// REGISTRAR / ACTUALIZAR RECOMENDACIÓN DEL SISTEMA
// ==================================================

export const registrarRecomendacionSistema =
async (req, res) => {
  let connection;

  try {
    const idEmpleado =
      enteroPositivo(
        req.params.id
      );

    const origen =
      normalizar(
        req.body?.origen
      );

    const idReferenciaOrigen =
      enteroPositivo(
        req.body?.id_referencia_origen
      );

    const nivelRecomendacion =
      normalizar(
        req.body?.nivel_recomendacion
      );

    const resultadoDetectado =
      String(
        req.body?.resultado_detectado ||
        ""
      ).trim() || null;

    const preevaluacionIA =
      String(
        req.body?.preevaluacion_ia ||
        ""
      ).trim() || null;

    const factoresDetectados =
      req.body?.factores_detectados ??
      null;

    if (!idEmpleado) {
      return res.status(400).json({
        success: false,
        message:
          "ID de empleado inválido"
      });
    }

    if (
      !origenesSistemaPermitidos.includes(
        origen
      )
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Origen de recomendación inválido"
      });
    }

    if (!idReferenciaOrigen) {
      return res.status(400).json({
        success: false,
        message:
          "La recomendación del sistema debe estar vinculada a una evaluación mediante su ID"
      });
    }

    if (
      !nivelesRecomendacionPermitidos.includes(
        nivelRecomendacion
      )
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Nivel de recomendación inválido"
      });
    }

    connection =
      await pool.getConnection();

    await connection.beginTransaction();

    const acceso =
      await validarAccesoEmpleadoRH(
        idEmpleado,
        req.user,
        connection
      );

    if (!acceso.ok) {
      await connection.rollback();

      return res
        .status(acceso.status)
        .json({
          success: false,
          message:
            acceso.message
        });
    }

    const [existentes] =
      await connection.query(
        `
          SELECT
            id_recomendacion

          FROM recomendaciones_canalizacion

          WHERE
            id_empleado = ?
            AND origen = ?
            AND id_referencia_origen = ?

          LIMIT 1

          FOR UPDATE
        `,
        [
          idEmpleado,
          origen,
          idReferenciaOrigen
        ]
      );

    let idRecomendacion;

    if (existentes.length) {
      idRecomendacion =
        existentes[0]
          .id_recomendacion;

      await connection.query(
        `
          UPDATE recomendaciones_canalizacion

          SET
            nivel_recomendacion = ?,
            resultado_detectado = ?,
            preevaluacion_ia = ?,
            factores_detectados = ?,
            updated_at = NOW()

          WHERE
            id_recomendacion = ?
        `,
        [
          nivelRecomendacion,
          resultadoDetectado,
          preevaluacionIA,

          factoresDetectados === null
            ? null
            : JSON.stringify(
                factoresDetectados
              ),

          idRecomendacion
        ]
      );

    } else {
      const [result] =
        await connection.query(
          `
            INSERT INTO recomendaciones_canalizacion
            (
              id_empleado,
              origen,
              id_referencia_origen,
              nivel_recomendacion,
              resultado_detectado,
              preevaluacion_ia,
              factores_detectados,
              revisada_rh,
              decision_rh,
              fecha_deteccion,
              created_at,
              updated_at
            )
            VALUES
            (
              ?, ?, ?, ?, ?, ?, ?,
              0,
              'pendiente',
              NOW(),
              NOW(),
              NOW()
            )
          `,
          [
            idEmpleado,
            origen,
            idReferenciaOrigen,
            nivelRecomendacion,
            resultadoDetectado,
            preevaluacionIA,

            factoresDetectados === null
              ? null
              : JSON.stringify(
                  factoresDetectados
                )
          ]
        );

      idRecomendacion =
        result.insertId;
    }

    await connection.commit();

    return res
      .status(
        existentes.length
          ? 200
          : 201
      )
      .json({
        success: true,

        message:
          existentes.length
            ? "Recomendación del sistema actualizada correctamente"
            : "Recomendación del sistema registrada correctamente",

        recomendacion: {
          id_recomendacion:
            idRecomendacion,

          id_empleado:
            idEmpleado,

          origen,

          id_referencia_origen:
            idReferenciaOrigen,

          nivel_recomendacion:
            nivelRecomendacion,

          resultado_detectado:
            resultadoDetectado,

          preevaluacion_ia:
            preevaluacionIA,

          factores_detectados:
            factoresDetectados,

          decision_rh:
            "pendiente"
        }
      });

  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch {}
    }

    console.error(
      "❌ Error registrando recomendación del sistema:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Error interno al registrar la recomendación del sistema"
    });

  } finally {
    if (connection) {
      connection.release();
    }
  }
};

// ==================================================
// DECISIÓN RH SOBRE RECOMENDACIÓN
// ==================================================

export const decidirRecomendacionRH =
async (req, res) => {
  let connection;

  try {
    const idEmpleado =
      enteroPositivo(
        req.params.id
      );

    const idRecomendacion =
      enteroPositivo(
        req.params.idRecomendacion
      );

    const decision =
      normalizar(
        req.body?.decision_rh
      );

    const observacion =
      String(
        req.body
          ?.observacion_rh ||
        ""
      ).trim() || null;

    if (
      !idEmpleado ||
      !idRecomendacion
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Datos de recomendación inválidos"
      });
    }

    if (
      !decisionesRHPermitidas.includes(
        decision
      )
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Decisión de RH inválida"
      });
    }

    if (
      [
        "seguimiento",
        "no_canalizar"
      ].includes(decision) &&
      !observacion
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Registra una observación para justificar la decisión de RH"
      });
    }

    connection =
      await pool.getConnection();

    await connection.beginTransaction();

    const acceso =
      await validarAccesoEmpleadoRH(
        idEmpleado,
        req.user,
        connection
      );

    if (!acceso.ok) {
      await connection.rollback();

      return res
        .status(acceso.status)
        .json({
          success: false,
          message:
            acceso.message
        });
    }

    const [rows] =
      await connection.query(
        `
          SELECT *

          FROM recomendaciones_canalizacion

          WHERE
            id_recomendacion = ?
            AND id_empleado = ?

          LIMIT 1

          FOR UPDATE
        `,
        [
          idRecomendacion,
          idEmpleado
        ]
      );

    if (!rows.length) {
      await connection.rollback();

      return res.status(404).json({
        success: false,
        message:
          "Recomendación no encontrada"
      });
    }

    const recomendacion =
      rows[0];

    if (
      recomendacion.decision_rh !==
      "pendiente"
    ) {
      await connection.rollback();

      return res.status(409).json({
        success: false,
        message:
          "Esta recomendación ya fue revisada por RH"
      });
    }

    let canalizacionCreada =
      null;

    if (
      decision ===
      "canalizar"
    ) {
      const [duplicadas] =
        await connection.query(
          `
            SELECT
              id_canalizacion,
              estatus

            FROM canalizaciones

            WHERE
              id_empleado = ?

              AND tipo_deteccion =
                'sistema'

              AND origen = ?

              AND id_referencia_origen = ?

              AND estatus NOT IN
              (
                'cerrada',
                'cancelada'
              )

            LIMIT 1
          `,
          [
            idEmpleado,
            recomendacion.origen,
            recomendacion
              .id_referencia_origen
          ]
        );

      if (duplicadas.length) {
        await connection.rollback();

        return res.status(409).json({
          success: false,

          message:
            "Ya existe una canalización activa para esta recomendación",

          canalizacion:
            duplicadas[0]
        });
      }

      const tokenPublico =
        crypto
          .randomBytes(32)
          .toString("hex");

      const motivo =
        observacion ||
        recomendacion
          .resultado_detectado ||
        "Canalización recomendada por el sistema y autorizada por RH.";

      const [result] =
        await connection.query(
          `
            INSERT INTO canalizaciones
            (
              id_empleado,
              id_usuario_rh,
              tipo_deteccion,
              token_publico,
              origen,
              id_referencia_origen,
              recomendacion_sistema,
              preevaluacion_ia,
              decision_rh,
              motivo_decision_rh,
              motivo,
              estatus,
              fecha_creacion
            )
            VALUES
            (
              ?,
              ?,
              'sistema',
              ?,
              ?,
              ?,
              ?,
              ?,
              'canalizar',
              ?,
              ?,
              'pendiente_revision',
              NOW()
            )
          `,
          [
            idEmpleado,
            acceso.contexto.idUsuario,
            tokenPublico,
            recomendacion.origen,
            recomendacion
              .id_referencia_origen,
            recomendacion
              .nivel_recomendacion,
            recomendacion
              .preevaluacion_ia,
            observacion,
            motivo
          ]
        );

      canalizacionCreada = {
        id_canalizacion:
          result.insertId,

        token_publico:
          tokenPublico,

        tipo_deteccion:
          "sistema",

        origen:
          recomendacion.origen,

        id_referencia_origen:
          recomendacion
            .id_referencia_origen,

        recomendacion_sistema:
          recomendacion
            .nivel_recomendacion,

        preevaluacion_ia:
          recomendacion
            .preevaluacion_ia,

        decision_rh:
          "canalizar",

        estatus:
          "pendiente_revision"
      };

      await registrarHistorial(
        connection,
        result.insertId,
        acceso.contexto.idUsuario,

        "Canalización creada desde recomendación del sistema",

        `Recomendación #${idRecomendacion}. Origen: ${recomendacion.origen}. Referencia: ${recomendacion.id_referencia_origen}.`
      );
    }

    await connection.query(
      `
        UPDATE recomendaciones_canalizacion

        SET
          revisada_rh = 1,
          decision_rh = ?,
          id_usuario_revision = ?,
          observacion_rh = ?,
          fecha_revision = NOW(),
          updated_at = NOW()

        WHERE
          id_recomendacion = ?
      `,
      [
        decision,
        acceso.contexto.idUsuario,
        observacion,
        idRecomendacion
      ]
    );

    await connection.commit();

    return res.json({
      success: true,

      message:
        decision ===
        "canalizar"

          ? "RH autorizó la canalización y se creó correctamente"

          : decision ===
            "seguimiento"

          ? "RH determinó dar seguimiento sin canalizar por ahora"

          : "RH determinó no canalizar y la decisión quedó registrada",

      decision_rh:
        decision,

      canalizacion:
        canalizacionCreada
    });

  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch {}
    }

    console.error(
      "❌ Error registrando decisión RH:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Error interno al registrar la decisión de RH"
    });

  } finally {
    if (connection) {
      connection.release();
    }
  }
};

// ==================================================
// RANKING DE CANALIZACIÓN
// ==================================================

const normalizarTextoRanking =
  valor =>
    String(
      valor || ""
    )
      .trim()
      .toLowerCase()
      .normalize("NFD")
      .replace(
        /[\u0300-\u036f]/g,
        ""
      );


// ==================================================
// CONVERTIR ÁREAS REQUERIDAS
// ==================================================

const normalizarAreasRequeridas =
  valor => {

    if (!valor) {
      return [];
    }


    if (
      Array.isArray(
        valor
      )
    ) {

      return valor
        .map(
          item =>
            Number(item)
        )
        .filter(
          item =>
            Number.isInteger(
              item
            ) &&
            item > 0
        );

    }


    try {

      const parsed =
        JSON.parse(
          valor
        );


      if (
        !Array.isArray(
          parsed
        )
      ) {
        return [];
      }


      return parsed
        .map(
          item =>
            Number(item)
        )
        .filter(
          item =>
            Number.isInteger(
              item
            ) &&
            item > 0
        );

    } catch {

      return [];

    }

  };


// ==================================================
// PUNTAJE NECESIDAD / ÁREAS
//
// Máximo: 45
// ==================================================

const calcularPuntajeAreas =
  (
    areasRequeridas,
    areasProfesional
  ) => {

    if (
      !Array.isArray(
        areasRequeridas
      ) ||
      areasRequeridas.length ===
        0
    ) {

      return {
        puntos: 0,
        coincidencias: [],
        total_requeridas: 0
      };

    }


    const areasPsicologo =
      new Set(
        (
          Array.isArray(
            areasProfesional
          )
            ? areasProfesional
            : []
        )
          .map(
            item =>
              Number(item)
          )
          .filter(
            item =>
              Number.isInteger(
                item
              ) &&
              item > 0
          )
      );


    const coincidencias =
      areasRequeridas.filter(
        idArea =>
          areasPsicologo.has(
            Number(
              idArea
            )
          )
      );


    const porcentaje =
      coincidencias.length /
      areasRequeridas.length;


    const puntos =
      Math.round(
        porcentaje * 45
      );


    return {
      puntos,
      coincidencias,
      total_requeridas:
        areasRequeridas.length
    };

  };


// ==================================================
// PRECIO MÁS ADECUADO SEGÚN MODALIDAD
// ==================================================

const obtenerPrecioCompatible =
  (
    profesional,
    modalidadPreferida
  ) => {

    const presencial =
      Number(
        profesional
          ?.precio_presencial
      ) > 0
        ? Number(
            profesional
              .precio_presencial
          )
        : null;


    const videollamada =
      Number(
        profesional
          ?.precio_videollamada
      ) > 0
        ? Number(
            profesional
              .precio_videollamada
          )
        : null;


    if (
      modalidadPreferida ===
      "presencial"
    ) {

      return presencial;

    }


    if (
      modalidadPreferida ===
      "videollamada"
    ) {

      return videollamada;

    }


    const disponibles =
      [
        presencial,
        videollamada
      ].filter(
        item =>
          Number(item) > 0
      );


    if (
      disponibles.length === 0
    ) {

      return null;

    }


    return Math.min(
      ...disponibles
    );

  };


// ==================================================
// PUNTAJE ECONÓMICO
//
// Máximo: 25
//
// Se calcula contra el ingreso mensual estimado.
// El sueldo nunca se manda al empleado ni al psicólogo.
// ==================================================

const calcularPuntajeEconomico =
  (
    profesional,
    modalidadPreferida,
    ingresoMensual
  ) => {

    const ingreso =
      Number(
        ingresoMensual
      );


    const precio =
      obtenerPrecioCompatible(
        profesional,
        modalidadPreferida
      );


    if (
      !precio ||
      !ingreso ||
      ingreso <= 0
    ) {

      return {
        puntos: 0,
        precio,
        porcentaje_ingreso:
          null
      };

    }


    const porcentaje =
      (
        precio /
        ingreso
      ) * 100;


    let puntos = 0;


    if (
      porcentaje <= 5
    ) {

      puntos = 25;

    } else if (
      porcentaje <= 7.5
    ) {

      puntos = 20;

    } else if (
      porcentaje <= 10
    ) {

      puntos = 15;

    } else if (
      porcentaje <= 15
    ) {

      puntos = 8;

    } else {

      puntos = 0;

    }


    return {
      puntos,

      precio,

      porcentaje_ingreso:
        Number(
          porcentaje.toFixed(
            2
          )
        )
    };

  };


// ==================================================
// PUNTAJE UBICACIÓN
//
// Máximo: 20
// ==================================================

const calcularPuntajeUbicacion =
  (
    empleado,
    profesional,
    modalidadPreferida
  ) => {

    // ==================================================
    // SI LA ATENCIÓN PREFERIDA ES VIDEOLLAMADA
    // LA DISTANCIA NO LIMITA LA ATENCIÓN.
    // ==================================================

    if (
      modalidadPreferida ===
      "videollamada"
    ) {

      return {
        puntos: 20,
        nivel:
          "Ubicación no limitante por videollamada"
      };

    }


    const cpEmpleado =
      normalizarTextoRanking(
        empleado
          ?.codigo_postal_residencia
      );


    const cpProfesional =
      normalizarTextoRanking(
        profesional
          ?.codigo_postal
      );


    const municipioEmpleado =
      normalizarTextoRanking(
        empleado
          ?.municipio_residencia
      );


    const municipioProfesional =
      normalizarTextoRanking(
        profesional
          ?.municipio
      );


    const estadoEmpleado =
      normalizarTextoRanking(
        empleado
          ?.estado_residencia
      );


    const estadoProfesional =
      normalizarTextoRanking(
        profesional
          ?.estado
      );


    if (
      cpEmpleado &&
      cpProfesional &&
      cpEmpleado ===
        cpProfesional
    ) {

      return {
        puntos: 20,
        nivel:
          "Mismo código postal"
      };

    }


    if (
      municipioEmpleado &&
      municipioProfesional &&
      municipioEmpleado ===
        municipioProfesional
    ) {

      return {
        puntos: 16,
        nivel:
          "Mismo municipio"
      };

    }


    if (
      estadoEmpleado &&
      estadoProfesional &&
      estadoEmpleado ===
        estadoProfesional
    ) {

      return {
        puntos: 10,
        nivel:
          "Mismo estado"
      };

    }


    return {
      puntos: 0,
      nivel:
        "Ubicación diferente"
    };

  };


// ==================================================
// PUNTAJE MODALIDAD
//
// Máximo: 10
// ==================================================

const calcularPuntajeModalidad =
  (
    profesional,
    modalidadPreferida
  ) => {

    const presencial =
      Number(
        profesional
          ?.modalidad_presencial
      ) === 1;


    const videollamada =
      Number(
        profesional
          ?.modalidad_videollamada
      ) === 1;


    if (
      modalidadPreferida ===
      "presencial"
    ) {

      return presencial
        ? 10
        : 0;

    }


    if (
      modalidadPreferida ===
      "videollamada"
    ) {

      return videollamada
        ? 10
        : 0;

    }


    if (
      modalidadPreferida ===
      "indistinta"
    ) {

      return (
        presencial ||
        videollamada
      )
        ? 10
        : 0;

    }


    return 0;

  };


// ==================================================
// NIVEL DE COMPATIBILIDAD
// ==================================================

const obtenerNivelCompatibilidad =
  total => {

    const puntos =
      Number(
        total
      ) || 0;


    if (
      puntos >= 90
    ) {

      return "Excelente coincidencia";

    }


    if (
      puntos >= 75
    ) {

      return "Muy buena opción";

    }


    if (
      puntos >= 60
    ) {

      return "Opción compatible";

    }


    return "Baja compatibilidad";

  };

// ==================================================
// LISTAR PSICÓLOGOS DISPONIBLES
//
// GET
// /api/empleados/:id/canalizaciones/
// :idCanalizacion/psicologos-disponibles
//
// RANKING:
// - Áreas de atención ........ 45
// - Economía ................. 25
// - Ubicación ................ 20
// - Modalidad ................ 10
//
// TOTAL ..................... 100
// ==================================================

export const listarPsicologosDisponibles =
async (req, res) => {

  try {

    // ==================================================
    // IDs
    // ==================================================

    const idEmpleado =
      enteroPositivo(
        req.params.id
      );

    const idCanalizacion =
      enteroPositivo(
        req.params.idCanalizacion
      );


    if (
      !idEmpleado ||
      !idCanalizacion
    ) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "Datos de canalización inválidos"

        });

    }


    // ==================================================
    // VALIDAR ACCESO RH
    // ==================================================

    const acceso =
      await validarAccesoEmpleadoRH(
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


    const empleado =
      acceso.empleado;


    // ==================================================
    // OBTENER CANALIZACIÓN
    // ==================================================

    const canalizacion =
      await obtenerCanalizacionRH(
        idCanalizacion,
        idEmpleado
      );


    if (!canalizacion) {

      return res
        .status(404)
        .json({

          success: false,

          message:
            "Canalización no encontrada"

        });

    }


    // ==================================================
    // NO PERMITIR RANKING EN CANALIZACIÓN CANCELADA
    // ==================================================

    if (
      canalizacion.estatus ===
      "cancelada"
    ) {

      return res
        .status(409)
        .json({

          success: false,

          message:
            "La canalización está cancelada"

        });

    }


    // ==================================================
    // MODALIDAD PREFERIDA
    //
    // PRIORIDAD:
    //
    // 1. Canalización
    // 2. Preferencia general del empleado
    //
    // NO usamos modalidad_trabajo.
    // ==================================================

    let modalidadPreferida =
      normalizarTextoRanking(
        canalizacion
          .modalidad_atencion_preferida
      );


    if (
      ![
        "presencial",
        "videollamada",
        "indistinta"
      ].includes(
        modalidadPreferida
      )
    ) {

      modalidadPreferida =
        normalizarTextoRanking(
          empleado
            .modalidad_atencion_preferida
        );

    }


    // ==================================================
    // VALIDAR MODALIDAD
    // ==================================================

    if (
      ![
        "presencial",
        "videollamada",
        "indistinta"
      ].includes(
        modalidadPreferida
      )
    ) {

      return res
        .status(409)
        .json({

          success: false,

          code:
            "MODALIDAD_ATENCION_REQUERIDA",

          message:
            "Debes indicar la modalidad de atención preferida antes de calcular el ranking.",

          opciones: [
            "presencial",
            "videollamada",
            "indistinta"
          ]

        });

    }


    // ==================================================
    // ÁREAS REQUERIDAS
    // ==================================================

    const areasRequeridas =
      normalizarAreasRequeridas(
        canalizacion
          .areas_atencion_requeridas
      );


    if (
      areasRequeridas.length ===
      0
    ) {

      return res
        .status(409)
        .json({

          success: false,

          code:
            "AREAS_ATENCION_REQUERIDAS",

          message:
            "Debes seleccionar al menos un área de atención para calcular el ranking."

        });

    }


    // ==================================================
    // VALIDAR QUE LAS ÁREAS EXISTAN
    // ==================================================

    const placeholdersAreas =
      areasRequeridas
        .map(
          () => "?"
        )
        .join(",");


    const [areasCatalogo] =
      await pool.query(
        `
          SELECT

            id_area,

            nombre,

            orden

          FROM catalogo_areas_atencion

          WHERE
            activo = 1

            AND id_area IN
            (
              ${placeholdersAreas}
            )

          ORDER BY
            orden ASC,
            nombre ASC
        `,
        areasRequeridas
      );


    const areasValidas =
      areasCatalogo.map(
        area =>
          Number(
            area.id_area
          )
      );


    if (
      areasValidas.length ===
      0
    ) {

      return res
        .status(409)
        .json({

          success: false,

          code:
            "AREAS_INVALIDAS",

          message:
            "Las áreas configuradas en la canalización no son válidas o ya no están activas."

        });

    }


    // ==================================================
    // INGRESO MENSUAL
    //
    // SOLO PARA CÁLCULO INTERNO.
    // NO SE ENVÍA AL EMPLEADO.
    // ==================================================

    const ingresoMensualEstimado =
      calcularIngresoMensualEstimado(

        empleado.sueldo,

        empleado
          .periodicidad_sueldo

      );


    // ==================================================
// PSICÓLOGOS INTERNOS MIRRORSOUL
//
// Solo entran al ranking:
// - Psicólogos con perfil completo.
// - Activos para canalización.
// - Estado "disponible".
// - Con cupo disponible.
// ==================================================

const [internos] =
  await pool.query(
    `
      SELECT

        'mirrorsoul'
          AS tipo_profesional,


        p.id_psicologo,

        NULL
          AS id_profesional_externo,

        p.id_usuario,


        u.nombre,

        u.correo,


        COALESCE(
          p.telefono,
          u.telefono
        )
          AS telefono,


        p.cedula_profesional,

        p.especialidad,


        p.foto_url,

        p.descripcion_profesional
          AS descripcion,

        p.anos_experiencia,


        p.modalidad_presencial,

        p.modalidad_videollamada,


        p.precio_presencial,

        p.precio_videollamada,


        p.estado,

        p.municipio,

        p.colonia,

        p.codigo_postal,

        p.direccion_consultorio,

        p.disponibilidad,


        p.perfil_profesional_completo,

        p.activo_canalizacion,

        p.estado_canalizacion,

        p.capacidad_maxima,


        (
          SELECT
            COUNT(*)

          FROM pacientes pa

          WHERE
            pa.id_psicologo =
              p.id_psicologo
        )
          AS pacientes_activos,


        CASE

          WHEN
            p.capacidad_maxima IS NULL

          THEN NULL


          ELSE

            GREATEST(
              p.capacidad_maxima -
              (
                SELECT
                  COUNT(*)

                FROM pacientes pa2

                WHERE
                  pa2.id_psicologo =
                    p.id_psicologo
              ),
              0
            )

        END
          AS cupos_disponibles,


        (
          SELECT

            GROUP_CONCAT(

              ca.nombre

              ORDER BY
                ca.orden ASC,
                ca.nombre ASC

              SEPARATOR '||'

            )

          FROM
            psicologo_areas_atencion paa

          INNER JOIN
            catalogo_areas_atencion ca

            ON ca.id_area =
               paa.id_area

          WHERE
            paa.id_psicologo =
              p.id_psicologo

            AND ca.activo = 1
        )
          AS areas_atencion_texto,


        (
          SELECT

            GROUP_CONCAT(

              ca.id_area

              ORDER BY
                ca.orden ASC,
                ca.id_area ASC

              SEPARATOR ','

            )

          FROM
            psicologo_areas_atencion paa

          INNER JOIN
            catalogo_areas_atencion ca

            ON ca.id_area =
               paa.id_area

          WHERE
            paa.id_psicologo =
              p.id_psicologo

            AND ca.activo = 1
        )
          AS areas_atencion_ids


      FROM psicologos p


      INNER JOIN usuarios u

        ON u.id_usuario =
           p.id_usuario


      WHERE

        LOWER(
          TRIM(
            COALESCE(
              u.rol,
              ''
            )
          )
        ) = 'psicologo'


        AND
          p.perfil_profesional_completo = 1


        AND
          p.activo_canalizacion = 1


        AND
          COALESCE(
            p.estado_canalizacion,
            'disponible'
          ) = 'disponible'


        AND
        (
          p.capacidad_maxima IS NULL

          OR

          (
            SELECT
              COUNT(*)

            FROM pacientes pa

            WHERE
              pa.id_psicologo =
                p.id_psicologo
          ) < p.capacidad_maxima
        )


      ORDER BY

        u.nombre ASC,

        p.id_psicologo ASC
    `
  );


    // ==================================================
    // PROFESIONALES EXTERNOS
    //
    // IMPORTANTE:
    //
    // Actualmente profesionales_externos NO tiene
    // relación con psicologo_areas_atencion.
    //
    // Por eso su puntaje de áreas será 0 mientras
    // no agreguemos áreas estructuradas al externo.
    // ==================================================

    const [externos] =
      await pool.query(
        `
          SELECT

            'externo'
              AS tipo_profesional,


            NULL
              AS id_psicologo,


            pe.id_profesional_externo,


            NULL
              AS id_usuario,


            pe.nombre,

            pe.correo,

            pe.telefono,


            NULL
              AS cedula_profesional,


            pe.especialidad,


            NULL
              AS foto_url,


            pe.descripcion,


            NULL
              AS anos_experiencia,


            pe.modalidad_presencial,

            pe.modalidad_videollamada,


            pe.precio_presencial,

            pe.precio_videollamada,


            pe.estado,

            pe.municipio,


            NULL
              AS colonia,


            NULL
              AS codigo_postal,


            pe.direccion
              AS direccion_consultorio,


            NULL
              AS disponibilidad,


            1
              AS perfil_profesional_completo,


            1
              AS activo_canalizacion,


            NULL
              AS areas_atencion_texto,


            NULL
              AS areas_atencion_ids


          FROM profesionales_externos pe


          WHERE
            pe.activo = 1


          ORDER BY
            pe.nombre ASC
        `
      );


    // ==================================================
    // PREPARAR Y CALCULAR RANKING
    // ==================================================

    const prepararProfesional =
      profesional => {


        // ==============================================
        // ÁREAS DEL PROFESIONAL
        // ==============================================

        const areasAtencion =
          String(
            profesional
              .areas_atencion_texto ||
            ""
          )
            .split(
              "||"
            )
            .map(
              item =>
                item.trim()
            )
            .filter(
              Boolean
            );


        const idsAreas =
          String(
            profesional
              .areas_atencion_ids ||
            ""
          )
            .split(
              ","
            )
            .map(
              item =>
                Number(item)
            )
            .filter(
              item =>
                Number.isInteger(
                  item
                ) &&
                item > 0
            );


        // ==============================================
        // 1. ÁREAS
        // MÁXIMO 45
        // ==============================================

        const compatibilidadAreas =
          calcularPuntajeAreas(
            areasValidas,
            idsAreas
          );


        // ==============================================
        // 2. ECONOMÍA
        // MÁXIMO 25
        // ==============================================

        const compatibilidadEconomica =
          calcularPuntajeEconomico(
            profesional,
            modalidadPreferida,
            ingresoMensualEstimado
          );


        // ==============================================
        // 3. UBICACIÓN
        // MÁXIMO 20
        // ==============================================

        const compatibilidadUbicacion =
          calcularPuntajeUbicacion(
            empleado,
            profesional,
            modalidadPreferida
          );


        // ==============================================
        // 4. MODALIDAD
        // MÁXIMO 10
        // ==============================================

        const compatibilidadModalidad =
          calcularPuntajeModalidad(
            profesional,
            modalidadPreferida
          );


        // ==============================================
        // TOTAL
        // ==============================================

        const total =
          Number(
            compatibilidadAreas
              .puntos || 0
          ) +

          Number(
            compatibilidadEconomica
              .puntos || 0
          ) +

          Number(
            compatibilidadUbicacion
              .puntos || 0
          ) +

          Number(
            compatibilidadModalidad || 0
          );


        const nivel =
          obtenerNivelCompatibilidad(
            total
          );


        // ==============================================
        // ÁREAS COINCIDENTES CON NOMBRE
        // ==============================================

        const areasCoincidentes =
          areasCatalogo
            .filter(
              area =>
                compatibilidadAreas
                  .coincidencias
                  .includes(
                    Number(
                      area.id_area
                    )
                  )
            )
            .map(
              area => ({
                id_area:
                  Number(
                    area.id_area
                  ),

                nombre:
                  area.nombre
              })
            );


        // ==============================================
        // DATOS DISPONIBLES
        // ==============================================

        const tieneEspecialidad =
          Boolean(
            String(
              profesional
                .especialidad ||
              ""
            ).trim()
          ) ||
          areasAtencion.length > 0;


        const tienePrecio =
          Number(
            profesional
              .precio_presencial
          ) > 0 ||

          Number(
            profesional
              .precio_videollamada
          ) > 0;


        const tieneUbicacion =
          Boolean(
            String(
              profesional
                .estado ||
              ""
            ).trim()
          ) &&

          Boolean(
            String(
              profesional
                .municipio ||
              ""
            ).trim()
          );


        const tieneModalidad =
          Number(
            profesional
              .modalidad_presencial
          ) === 1 ||

          Number(
            profesional
              .modalidad_videollamada
          ) === 1;


        return {

          ...profesional,


          // ============================================
          // ÁREAS
          // ============================================

          areas_atencion:
            areasAtencion,

          areas_atencion_ids:
            idsAreas,

          areas_atencion_texto:
            undefined,


          // ============================================
          // DATOS DISPONIBLES
          // ============================================

          datos_para_ranking: {

            especialidad:
              tieneEspecialidad,

            precio:
              tienePrecio,

            ubicacion:
              tieneUbicacion,

            modalidad:
              tieneModalidad

          },


          // ============================================
          // COMPATIBILIDAD
          // ============================================

          compatibilidad: {

            areas: {

              puntos:
                compatibilidadAreas
                  .puntos,

              maximo:
                45,

              coincidencias:
                compatibilidadAreas
                  .coincidencias,

              areas_coincidentes:
                areasCoincidentes,

              total_requeridas:
                compatibilidadAreas
                  .total_requeridas

            },


            economica: {

              puntos:
                compatibilidadEconomica
                  .puntos,

              maximo:
                25,

              precio_compatible:
                compatibilidadEconomica
                  .precio,

              porcentaje_ingreso:
                compatibilidadEconomica
                  .porcentaje_ingreso

            },


            ubicacion: {

              puntos:
                compatibilidadUbicacion
                  .puntos,

              maximo:
                20,

              nivel:
                compatibilidadUbicacion
                  .nivel

            },


            modalidad: {

              puntos:
                compatibilidadModalidad,

              maximo:
                10,

              preferida:
                modalidadPreferida

            },


            total,

            maximo:
              100,

            nivel,

            calculada:
              true

          }

        };

      };


    // ==================================================
    // PROFESIONALES RECHAZADOS EN ESTA CANALIZACIÓN
    //
    // Un rechazo pertenece únicamente a esta canalización.
    // El profesional puede seguir disponible para otras.
    // ==================================================

    const [rechazadosHistoricos] =
      await pool.query(
        `
          SELECT
            tipo_profesional,
            id_psicologo,
            id_profesional_externo,
            motivo_rechazo_profesional,
            observacion_respuesta_profesional,
            fecha_respuesta_profesional

          FROM canalizacion_profesionales

          WHERE
            id_canalizacion = ?

            AND LOWER(
              TRIM(
                COALESCE(
                  estado_respuesta_profesional,
                  ''
                )
              )
            ) IN (
              'rechazado',
              'rechazada'
            )
        `,
        [
          idCanalizacion
        ]
      );

    const clavesRechazadas =
      new Set(
        rechazadosHistoricos.map(
          item =>
            item.tipo_profesional ===
            "mirrorsoul"
              ? `m-${Number(item.id_psicologo)}`
              : `e-${Number(item.id_profesional_externo)}`
        )
      );


    // ==================================================
    // PREPARAR LISTA COMPLETA
    //
    // IMPORTANTE:
    // no volver a recomendar dentro de esta misma
    // canalización a un profesional que ya la rechazó.
    // ==================================================

    const profesionales =
      [
        ...internos,
        ...externos
      ]
        .filter(
          profesional => {
            const clave =
              profesional.tipo_profesional ===
              "mirrorsoul"
                ? `m-${Number(profesional.id_psicologo)}`
                : `e-${Number(profesional.id_profesional_externo)}`;

            return !clavesRechazadas.has(
              clave
            );
          }
        )
        .map(
          prepararProfesional
        );


    // ==================================================
    // ORDENAR DE MAYOR A MENOR COMPATIBILIDAD
    // ==================================================

    profesionales.sort(
      (a, b) => {

        const diferenciaTotal =
          Number(
            b.compatibilidad
              ?.total || 0
          ) -
          Number(
            a.compatibilidad
              ?.total || 0
          );


        if (
          diferenciaTotal !== 0
        ) {

          return diferenciaTotal;

        }


        // ==============================================
        // DESEMPATE 1:
        // MÁS COINCIDENCIA DE ÁREAS
        // ==============================================

        const diferenciaAreas =
          Number(
            b.compatibilidad
              ?.areas
              ?.puntos || 0
          ) -
          Number(
            a.compatibilidad
              ?.areas
              ?.puntos || 0
          );


        if (
          diferenciaAreas !== 0
        ) {

          return diferenciaAreas;

        }


        // ==============================================
        // DESEMPATE 2:
        // MEJOR ECONOMÍA
        // ==============================================

        const diferenciaEconomica =
          Number(
            b.compatibilidad
              ?.economica
              ?.puntos || 0
          ) -
          Number(
            a.compatibilidad
              ?.economica
              ?.puntos || 0
          );


        if (
          diferenciaEconomica !== 0
        ) {

          return diferenciaEconomica;

        }


        // ==============================================
        // DESEMPATE 3:
        // NOMBRE
        // ==============================================

        return String(
          a.nombre || ""
        ).localeCompare(
          String(
            b.nombre || ""
          ),
          "es"
        );

      }
    );


    // ==================================================
    // SEPARAR INTERNOS Y EXTERNOS
    // YA ORDENADOS
    // ==================================================

    const internosPreparados =
      profesionales.filter(
        profesional =>
          profesional
            .tipo_profesional ===
          "mirrorsoul"
      );


    const externosPreparados =
      profesionales.filter(
        profesional =>
          profesional
            .tipo_profesional ===
          "externo"
      );


    // ==================================================
    // RESPUESTA
    // ==================================================

    return res.json({

      success:
        true,


      empleado: {

        id_empleado:
          empleado.id_empleado,

        nombre:
          empleado.nombre,

        puesto:
          empleado.puesto,

        departamento:
          empleado.departamento,

        estado_residencia:
          empleado.estado_residencia,

        municipio_residencia:
          empleado.municipio_residencia,

        colonia_residencia:
          empleado.colonia_residencia,

        codigo_postal_residencia:
          empleado.codigo_postal_residencia,

        modalidad_atencion_preferida:
          modalidadPreferida

      },


      canalizacion: {

        id_canalizacion:
          canalizacion
            .id_canalizacion,

        origen:
          canalizacion.origen,

        motivo:
          canalizacion.motivo,

        estatus:
          canalizacion.estatus,

        modalidad_atencion_preferida:
          modalidadPreferida,

        areas_atencion_requeridas:
          areasValidas,

        areas_atencion_detalle:
          areasCatalogo

      },


      ranking: {

        activo:
          true,

        calculado:
          true,

        pesos: {

          areas:
            45,

          economica:
            25,

          ubicacion:
            20,

          modalidad:
            10

        },

        total:
          100

      },


      total:
        profesionales.length,

      internos:
        internosPreparados,

      externos:
        externosPreparados,

      profesionales

    });


  } catch (error) {

    console.error(
      "❌ Error calculando ranking de psicólogos disponibles:",
      error
    );


    return res
      .status(500)
      .json({

        success:
          false,

        message:
          "Error interno al obtener el ranking de profesionales",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined

      });

  }

};

// ==================================================
// ASIGNAR OPCIONES DE PSICÓLOGOS
// ==================================================

export const asignarOpcionesPsicologos =
async (req, res) => {
  let connection;

  try {
    const idEmpleado =
      enteroPositivo(
        req.params.id
      );

    const idCanalizacion =
      enteroPositivo(
        req.params.idCanalizacion
      );

    const opciones =
      Array.isArray(
        req.body?.opciones
      )
        ? req.body.opciones
        : [];

    if (
      !idEmpleado ||
      !idCanalizacion
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Datos de canalización inválidos"
      });
    }

    if (!opciones.length) {
      return res.status(400).json({
        success: false,
        message:
          "Selecciona al menos un profesional"
      });
    }

    if (opciones.length > 5) {
      return res.status(400).json({
        success: false,
        message:
          "Puedes enviar un máximo de 5 opciones por canalización"
      });
    }

    connection =
      await pool.getConnection();

    await connection.beginTransaction();

    const acceso =
      await validarAccesoEmpleadoRH(
        idEmpleado,
        req.user,
        connection
      );

    if (!acceso.ok) {
      await connection.rollback();

      return res
        .status(acceso.status)
        .json({
          success: false,
          message:
            acceso.message
        });
    }

    const canalizacion =
      await obtenerCanalizacionRH(
        idCanalizacion,
        idEmpleado,
        connection,
        true
      );

    if (!canalizacion) {
      await connection.rollback();

      return res.status(404).json({
        success: false,
        message:
          "Canalización no encontrada"
      });
    }

    if (
      [
        "cerrada",
        "cancelada",
        "seleccion_realizada"
      ].includes(
        canalizacion.estatus
      ) ||

      canalizacion
        .id_opcion_elegida
    ) {
      await connection.rollback();

      return res.status(409).json({
        success: false,
        message:
          "Esta canalización ya no permite cambiar las opciones"
      });
    }

    // ==================================================
    // CONSERVAR RECHAZOS PREVIOS
    //
    // Evita que RH vuelva a enviar, incluso desde una
    // pantalla desactualizada, a un profesional que ya
    // rechazó esta misma canalización.
    // ==================================================

    const [rechazadosPrevios] =
      await connection.query(
        `
          SELECT
            tipo_profesional,
            id_psicologo,
            id_profesional_externo

          FROM canalizacion_profesionales

          WHERE
            id_canalizacion = ?

            AND LOWER(
              TRIM(
                COALESCE(
                  estado_respuesta_profesional,
                  ''
                )
              )
            ) IN (
              'rechazado',
              'rechazada'
            )
        `,
        [
          idCanalizacion
        ]
      );

    const clavesRechazadas =
      new Set(
        rechazadosPrevios.map(
          item =>
            item.tipo_profesional ===
            "mirrorsoul"
              ? `m-${Number(item.id_psicologo)}`
              : `e-${Number(item.id_profesional_externo)}`
        )
      );

    const procesadas = [];
    const claves = new Set();

    for (
      let i = 0;
      i < opciones.length;
      i++
    ) {
      const tipo =
        normalizar(
          opciones[i]
            ?.tipo_profesional
        );

      if (
        ![
          "mirrorsoul",
          "externo"
        ].includes(tipo)
      ) {
        await connection.rollback();

        return res.status(400).json({
          success: false,
          message:
            "Tipo de profesional inválido"
        });
      }

      if (
        tipo ===
        "mirrorsoul"
      ) {
        const idPsicologo =
          enteroPositivo(
            opciones[i]
              ?.id_psicologo
          );

        if (!idPsicologo) {
          await connection.rollback();

          return res.status(400).json({
            success: false,
            message:
              "Psicólogo de MirrorSoul inválido"
          });
        }

        const clave =
          `m-${idPsicologo}`;

        if (
          clavesRechazadas.has(
            clave
          )
        ) {
          await connection.rollback();

          return res.status(409).json({
            success: false,
            message:
              "Ese psicólogo ya rechazó esta canalización. Selecciona otra opción."
          });
        }

        if (claves.has(clave)) {
          await connection.rollback();

          return res.status(400).json({
            success: false,
            message:
              "No puedes enviar el mismo profesional más de una vez"
          });
        }

        claves.add(clave);

        const [rows] =
          await connection.query(
            `
              SELECT
                p.id_psicologo,
                u.nombre

              FROM psicologos p

              INNER JOIN usuarios u
                ON u.id_usuario =
                   p.id_usuario

              WHERE
                p.id_psicologo = ?

                AND LOWER(
                  TRIM(
                    COALESCE(
                      u.rol,
                      ''
                    )
                  )
                ) = 'psicologo'

                AND p.perfil_profesional_completo = 1

                AND p.activo_canalizacion = 1

                AND COALESCE(
                  p.estado_canalizacion,
                  'disponible'
                ) = 'disponible'

                AND
                (
                  p.capacidad_maxima IS NULL

                  OR

                  (
                    SELECT COUNT(*)

                    FROM pacientes pa

                    WHERE
                      pa.id_psicologo =
                        p.id_psicologo
                  ) < p.capacidad_maxima
                )

              LIMIT 1
            `,
            [
              idPsicologo
            ]
          );

        if (!rows.length) {
          await connection.rollback();

          return res.status(400).json({
            success: false,
            message:
              `El psicólogo ${idPsicologo} no está disponible para canalización`
          });
        }

        procesadas.push({
          tipo_profesional:
            "mirrorsoul",

          id_psicologo:
            idPsicologo,

          id_profesional_externo:
            null,

          orden:
            i + 1,

          nombre:
            rows[0].nombre
        });

      } else {
        const idExterno =
          enteroPositivo(
            opciones[i]
              ?.id_profesional_externo
          );

        if (!idExterno) {
          await connection.rollback();

          return res.status(400).json({
            success: false,
            message:
              "Profesional externo inválido"
          });
        }

        const clave =
          `e-${idExterno}`;

        if (
          clavesRechazadas.has(
            clave
          )
        ) {
          await connection.rollback();

          return res.status(409).json({
            success: false,
            message:
              "Ese profesional ya rechazó esta canalización. Selecciona otra opción."
          });
        }

        if (claves.has(clave)) {
          await connection.rollback();

          return res.status(400).json({
            success: false,
            message:
              "No puedes enviar el mismo profesional más de una vez"
          });
        }

        claves.add(clave);

        const [rows] =
          await connection.query(
            `
              SELECT
                id_profesional_externo,
                nombre

              FROM profesionales_externos

              WHERE
                id_profesional_externo = ?
                AND activo = 1

              LIMIT 1
            `,
            [
              idExterno
            ]
          );

        if (!rows.length) {
          await connection.rollback();

          return res.status(400).json({
            success: false,
            message:
              `El profesional externo ${idExterno} no está disponible`
          });
        }

        procesadas.push({
          tipo_profesional:
            "externo",

          id_psicologo:
            null,

          id_profesional_externo:
            idExterno,

          orden:
            i + 1,

          nombre:
            rows[0].nombre
        });
      }
    }

    // ==================================================
    // NO BORRAR EL HISTORIAL DE OPCIONES
    //
    // Antes se hacía DELETE y con eso se perdían:
    // - rechazo del profesional
    // - motivo del rechazo
    // - observación
    // - fecha de respuesta
    //
    // Ahora solo retiramos las opciones anteriores de la
    // vista pública y conservamos su historial.
    // ==================================================

    await connection.query(
      `
        UPDATE canalizacion_profesionales

        SET
          enviado = 0,
          seleccionado = 0

        WHERE
          id_canalizacion = ?
      `,
      [
        idCanalizacion
      ]
    );

    for (
      const opcion
      of procesadas
    ) {
      await connection.query(
        `
          INSERT INTO canalizacion_profesionales
          (
            id_canalizacion,
            tipo_profesional,
            id_psicologo,
            id_profesional_externo,
            orden,
            enviado,
            seleccionado,
            fecha_envio
          )
          VALUES
          (
            ?, ?, ?, ?, ?,
            1,
            0,
            NOW()
          )
        `,
        [
          idCanalizacion,
          opcion.tipo_profesional,
          opcion.id_psicologo,
          opcion.id_profesional_externo,
          opcion.orden
        ]
      );
    }

    await connection.query(
      `
        UPDATE canalizaciones

        SET
          estatus =
            'pendiente_eleccion',

          fecha_envio_opciones =
            NOW(),

          fecha_limite_seguimiento =
            DATE_ADD(
              NOW(),
              INTERVAL 5 DAY
            ),

          fecha_eleccion =
            NULL,

          id_opcion_elegida =
            NULL

        WHERE
          id_canalizacion = ?
      `,
      [
        idCanalizacion
      ]
    );

    await registrarHistorial(
      connection,
      idCanalizacion,
      acceso.contexto.idUsuario,

      "Opciones enviadas al empleado",

      `Se enviaron ${procesadas.length} opciones: ${procesadas
        .map(
          item =>
            item.nombre
        )
        .join(", ")}`
    );

    await connection.commit();

    return res.json({
      success: true,

      message:
        "Opciones de profesionales enviadas correctamente",

      total_opciones:
        procesadas.length,

      seguimiento:
        "El sistema marcará seguimiento requerido si no hay selección después de 5 días."
    });

  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch {}
    }

    console.error(
      "❌ Error asignando opciones de psicólogos:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Error interno al enviar las opciones de profesionales"
    });

  } finally {
    if (connection) {
      connection.release();
    }
  }
};

// ==================================================
// OBTENER CANALIZACIÓN PÚBLICA
// ==================================================

export const obtenerCanalizacionPublica =
async (req, res) => {
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

    const [rows] =
      await pool.query(
        `
          SELECT
            c.id_canalizacion,
            c.id_empleado,
            c.tipo_deteccion,
            c.origen,
            c.motivo,
            c.estatus,
            c.fecha_envio_opciones,
            c.fecha_limite_seguimiento,
            c.fecha_eleccion,
            c.id_opcion_elegida,

            e.nombre
              AS empleado_nombre,

            e.id_mirror

          FROM canalizaciones c

          INNER JOIN empleados e
            ON e.id_empleado =
               c.id_empleado

          WHERE
            c.token_publico = ?

          LIMIT 1
        `,
        [
          token
        ]
      );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message:
          "Canalización no encontrada"
      });
    }

    const canalizacion =
      rows[0];

    if (
      canalizacion.estatus ===
      "cancelada"
    ) {
      return res.status(410).json({
        success: false,
        message:
          "Esta canalización fue cancelada"
      });
    }

    const [opciones] =
  await pool.query(
    `
      SELECT

        cp.id_opcion,
        cp.tipo_profesional,
        cp.orden,
        cp.seleccionado,
        cp.fecha_seleccion,


        COALESCE(
          ui.nombre,
          pe.nombre
        )
          AS nombre,


        COALESCE(
          p.especialidad,
          pe.especialidad
        )
          AS especialidad,


        p.cedula_profesional,


        CASE
          WHEN cp.tipo_profesional =
               'mirrorsoul'
          THEN p.foto_url
          ELSE NULL
        END
          AS foto_url,


        CASE
          WHEN cp.tipo_profesional =
               'mirrorsoul'
          THEN p.anos_experiencia
          ELSE NULL
        END
          AS anos_experiencia,


        CASE
          WHEN cp.tipo_profesional =
               'mirrorsoul'
          THEN p.descripcion_profesional
          ELSE pe.descripcion
        END
          AS descripcion,


        CASE
          WHEN cp.tipo_profesional =
               'mirrorsoul'
          THEN p.modalidad_presencial
          ELSE pe.modalidad_presencial
        END
          AS modalidad_presencial,


        CASE
          WHEN cp.tipo_profesional =
               'mirrorsoul'
          THEN p.modalidad_videollamada
          ELSE pe.modalidad_videollamada
        END
          AS modalidad_videollamada,


        CASE
          WHEN cp.tipo_profesional =
               'mirrorsoul'
          THEN p.precio_presencial
          ELSE pe.precio_presencial
        END
          AS precio_presencial,


        CASE
          WHEN cp.tipo_profesional =
               'mirrorsoul'
          THEN p.precio_videollamada
          ELSE pe.precio_videollamada
        END
          AS precio_videollamada,


        CASE
          WHEN cp.tipo_profesional =
               'mirrorsoul'
          THEN p.estado
          ELSE pe.estado
        END
          AS estado,


        CASE
          WHEN cp.tipo_profesional =
               'mirrorsoul'
          THEN p.municipio
          ELSE pe.municipio
        END
          AS municipio,


        CASE
          WHEN cp.tipo_profesional =
               'mirrorsoul'
          THEN p.colonia
          ELSE NULL
        END
          AS colonia,


        CASE
          WHEN cp.tipo_profesional =
               'mirrorsoul'
          THEN p.codigo_postal
          ELSE NULL
        END
          AS codigo_postal,


        CASE
          WHEN cp.tipo_profesional =
               'mirrorsoul'
          THEN p.direccion_consultorio
          ELSE pe.direccion
        END
          AS direccion,


        CASE
          WHEN cp.tipo_profesional =
               'mirrorsoul'
          THEN p.disponibilidad
          ELSE NULL
        END
          AS disponibilidad,


        COALESCE(
          p.telefono,
          ui.telefono,
          pe.telefono
        )
          AS telefono,

         COALESCE(
          ui.correo,
          pe.correo
        )
          AS correo,
      

        CASE
          WHEN cp.tipo_profesional =
               'mirrorsoul'
          THEN
          (
            SELECT
              GROUP_CONCAT(
                ca.nombre
                ORDER BY
                  ca.orden ASC,
                  ca.nombre ASC
                SEPARATOR '||'
              )

            FROM psicologo_areas_atencion paa

            INNER JOIN catalogo_areas_atencion ca
              ON ca.id_area =
                 paa.id_area

            WHERE
              paa.id_psicologo =
                p.id_psicologo

              AND ca.activo = 1
          )

          ELSE NULL
        END
          AS areas_atencion_texto


      FROM canalizacion_profesionales cp


      LEFT JOIN psicologos p
        ON p.id_psicologo =
           cp.id_psicologo


      LEFT JOIN usuarios ui
        ON ui.id_usuario =
           p.id_usuario


      LEFT JOIN profesionales_externos pe
        ON pe.id_profesional_externo =
           cp.id_profesional_externo


      WHERE
        cp.id_canalizacion = ?

        AND cp.enviado = 1

        AND LOWER(
          TRIM(
            COALESCE(
              cp.estado_respuesta_profesional,
              'pendiente'
            )
          )
        ) NOT IN (
          'rechazado',
          'rechazada'
        )

        AND
        (
          cp.tipo_profesional = 'externo'

          OR

          (
            cp.tipo_profesional = 'mirrorsoul'

            AND p.activo_canalizacion = 1

            AND COALESCE(
              p.estado_canalizacion,
              'disponible'
            ) = 'disponible'

            AND
            (
              p.capacidad_maxima IS NULL

              OR

              (
                SELECT COUNT(*)

                FROM pacientes pa

                WHERE
                  pa.id_psicologo =
                    p.id_psicologo
              ) < p.capacidad_maxima
            )
          )
        )


      ORDER BY
        cp.orden ASC,
        cp.id_opcion ASC
    `,
    [
      canalizacion
        .id_canalizacion
    ]
  );


const opcionesPreparadas =
  opciones.map(
    opcion => ({

      ...opcion,

      areas_atencion:
        String(
          opcion
            .areas_atencion_texto ||
          ""
        )
          .split(
            "||"
          )
          .map(
            item =>
              item.trim()
          )
          .filter(
            Boolean
          )

    })
  );

    const puedeSeleccionar =
      [
        "opciones_enviadas",
        "pendiente_eleccion",
        "sin_seleccion",
        "en_seguimiento"
      ].includes(
        canalizacion.estatus
      ) &&

      !canalizacion
        .id_opcion_elegida;

   return res.json({

  success: true,

  canalizacion: {

    ...canalizacion,

    puede_seleccionar:
      puedeSeleccionar

  },

  opciones:
    opcionesPreparadas

});

  } catch (error) {
    console.error(
      "❌ Error obteniendo canalización pública:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Error interno al cargar las opciones de canalización"
    });
  }
};

// ==================================================
// EMPLEADO SELECCIONA PSICÓLOGO
// ==================================================

export const seleccionarPsicologoEmpleado =
async (req, res) => {
  let connection;

  try {
    const token =
      String(
        req.params.token ||
        ""
      ).trim();

    const idOpcion =
      enteroPositivo(
        req.body?.id_opcion
      );

    if (!token) {
      return res.status(400).json({
        success: false,
        message:
          "Token inválido"
      });
    }

    if (!idOpcion) {
      return res.status(400).json({
        success: false,
        message:
          "Selecciona una opción válida"
      });
    }

    connection =
      await pool.getConnection();

    await connection.beginTransaction();

    const [rows] =
      await connection.query(
        `
          SELECT *

          FROM canalizaciones

          WHERE
            token_publico = ?

          LIMIT 1

          FOR UPDATE
        `,
        [
          token
        ]
      );

    if (!rows.length) {
      await connection.rollback();

      return res.status(404).json({
        success: false,
        message:
          "Canalización no encontrada"
      });
    }

    const canalizacion =
      rows[0];

    if (
      canalizacion.estatus ===
      "cancelada"
    ) {
      await connection.rollback();

      return res.status(410).json({
        success: false,
        message:
          "Esta canalización fue cancelada"
      });
    }

    if (
      canalizacion
        .id_opcion_elegida ||

      canalizacion.estatus ===
        "seleccion_realizada" ||

      canalizacion.estatus ===
        "cerrada"
    ) {
      await connection.rollback();

      return res.status(409).json({
        success: false,
        message:
          "Ya se realizó una selección para esta canalización"
      });
    }

    const [opciones] =
      await connection.query(
        `
          SELECT
            cp.id_opcion,
            cp.tipo_profesional,

            COALESCE(
              ui.nombre,
              pe.nombre
            )
              AS nombre_profesional

          FROM canalizacion_profesionales cp

          LEFT JOIN psicologos p
            ON p.id_psicologo =
               cp.id_psicologo

          LEFT JOIN usuarios ui
            ON ui.id_usuario =
               p.id_usuario

          LEFT JOIN profesionales_externos pe
            ON pe.id_profesional_externo =
               cp.id_profesional_externo

          WHERE
            cp.id_opcion = ?

            AND cp.id_canalizacion = ?

            AND cp.enviado = 1

            AND LOWER(
              TRIM(
                COALESCE(
                  cp.estado_respuesta_profesional,
                  'pendiente'
                )
              )
            ) NOT IN (
              'rechazado',
              'rechazada'
            )

            AND
            (
              cp.tipo_profesional = 'externo'

              OR

              (
                cp.tipo_profesional = 'mirrorsoul'

                AND p.activo_canalizacion = 1

                AND COALESCE(
                  p.estado_canalizacion,
                  'disponible'
                ) = 'disponible'

                AND
                (
                  p.capacidad_maxima IS NULL

                  OR

                  (
                    SELECT COUNT(*)

                    FROM pacientes pa

                    WHERE
                      pa.id_psicologo =
                        p.id_psicologo
                  ) < p.capacidad_maxima
                )
              )
            )

          LIMIT 1
        `,
        [
          idOpcion,
          canalizacion
            .id_canalizacion
        ]
      );

    if (!opciones.length) {
      await connection.rollback();

      return res.status(400).json({
        success: false,
        message:
          "La opción seleccionada no pertenece a esta canalización"
      });
    }

    await connection.query(
      `
        UPDATE canalizacion_profesionales

        SET
          seleccionado = 0,
          fecha_seleccion = NULL

        WHERE
          id_canalizacion = ?
      `,
      [
        canalizacion
          .id_canalizacion
      ]
    );

    await connection.query(
      `
        UPDATE canalizacion_profesionales

        SET
          seleccionado = 1,
          fecha_seleccion = NOW()

        WHERE
          id_opcion = ?
      `,
      [
        idOpcion
      ]
    );

    await connection.query(
      `
        UPDATE canalizaciones

        SET
          id_opcion_elegida = ?,
          fecha_eleccion = NOW(),
          estatus =
            'seleccion_realizada'

        WHERE
          id_canalizacion = ?
      `,
      [
        idOpcion,

        canalizacion
          .id_canalizacion
      ]
    );

    await registrarHistorial(
      connection,

      canalizacion
        .id_canalizacion,

      null,

      "Empleado seleccionó profesional",

      `Profesional seleccionado: ${opciones[0].nombre_profesional}`
    );

    await connection.commit();

    return res.json({
      success: true,

      message:
        "Profesional seleccionado correctamente",

      seleccion: {
        id_opcion:
          idOpcion,

        nombre_profesional:
          opciones[0]
            .nombre_profesional
      },

      notificar_rh:
        true
    });

  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch {}
    }

    console.error(
      "❌ Error seleccionando profesional:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Error interno al registrar la selección"
    });

  } finally {
    if (connection) {
      connection.release();
    }
  }
};

// ==================================================
// REGISTRAR SEGUIMIENTO RH
// ==================================================

export const registrarSeguimientoCanalizacion =
async (req, res) => {
  let connection;

  try {
    const idEmpleado =
      enteroPositivo(
        req.params.id
      );

    const idCanalizacion =
      enteroPositivo(
        req.params.idCanalizacion
      );

    const tipo =
      normalizar(
        req.body
          ?.tipo_seguimiento
      );

    const motivoRaw =
      req.body
        ?.motivo_no_seleccion;

    const motivoNoSeleccion =
      motivoRaw
        ? normalizar(motivoRaw)
        : null;

    const observacion =
      String(
        req.body
          ?.observacion ||
        ""
      ).trim() || null;

    if (
      !idEmpleado ||
      !idCanalizacion
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Datos de canalización inválidos"
      });
    }

    if (
      !tiposSeguimientoPermitidos.includes(
        tipo
      )
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Tipo de seguimiento inválido"
      });
    }

    if (
      motivoNoSeleccion &&

      !motivosNoSeleccionPermitidos.includes(
        motivoNoSeleccion
      )
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Motivo de no selección inválido"
      });
    }

    if (
      !observacion &&
      !motivoNoSeleccion
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Registra una observación o el motivo de no selección"
      });
    }

    connection =
      await pool.getConnection();

    await connection.beginTransaction();

    const acceso =
      await validarAccesoEmpleadoRH(
        idEmpleado,
        req.user,
        connection
      );

    if (!acceso.ok) {
      await connection.rollback();

      return res
        .status(acceso.status)
        .json({
          success: false,
          message:
            acceso.message
        });
    }

    const canalizacion =
      await obtenerCanalizacionRH(
        idCanalizacion,
        idEmpleado,
        connection,
        true
      );

    if (!canalizacion) {
      await connection.rollback();

      return res.status(404).json({
        success: false,
        message:
          "Canalización no encontrada"
      });
    }

    if (
      [
        "cerrada",
        "cancelada"
      ].includes(
        canalizacion.estatus
      )
    ) {
      await connection.rollback();

      return res.status(409).json({
        success: false,
        message:
          "Esta canalización ya no permite registrar seguimientos"
      });
    }

    const [result] =
      await connection.query(
        `
          INSERT INTO canalizacion_seguimientos
          (
            id_canalizacion,
            id_usuario_rh,
            tipo_seguimiento,
            motivo_no_seleccion,
            observacion,
            fecha_seguimiento
          )
          VALUES
          (
            ?, ?, ?, ?, ?, NOW()
          )
        `,
        [
          idCanalizacion,
          acceso.contexto.idUsuario,
          tipo,
          motivoNoSeleccion,
          observacion
        ]
      );

    let nuevoEstado =
      canalizacion.estatus;

    if (
      !canalizacion
        .id_opcion_elegida
    ) {
      nuevoEstado =
        motivoNoSeleccion ===
          "no_desea_atencion" ||

        tipo ===
          "rechazo"

          ? "sin_seleccion"
          : "en_seguimiento";
    }

    await connection.query(
      `
        UPDATE canalizaciones

        SET
          estatus = ?

        WHERE
          id_canalizacion = ?
      `,
      [
        nuevoEstado,
        idCanalizacion
      ]
    );

    await registrarHistorial(
      connection,
      idCanalizacion,
      acceso.contexto.idUsuario,

      "Seguimiento RH registrado",

      `Tipo: ${tipo}${
        motivoNoSeleccion
          ? `. Motivo: ${motivoNoSeleccion}`
          : ""
      }${
        observacion
          ? `. Observación: ${observacion}`
          : ""
      }`
    );

    await connection.commit();

    return res.status(201).json({
      success: true,

      message:
        "Seguimiento registrado correctamente",

      seguimiento: {
        id_seguimiento:
          result.insertId,

        tipo_seguimiento:
          tipo,

        motivo_no_seleccion:
          motivoNoSeleccion,

        observacion,

        estatus_canalizacion:
          nuevoEstado
      }
    });

  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch {}
    }

    console.error(
      "❌ Error registrando seguimiento:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Error interno al registrar el seguimiento"
    });

  } finally {
    if (connection) {
      connection.release();
    }
  }
};

// ==================================================
// CERRAR CANALIZACIÓN
// ==================================================

export const cerrarCanalizacion =
async (req, res) => {
  let connection;

  try {
    const idEmpleado =
      enteroPositivo(
        req.params.id
      );

    const idCanalizacion =
      enteroPositivo(
        req.params.idCanalizacion
      );

    const observacion =
      String(
        req.body
          ?.observacion ||
        ""
      ).trim() || null;

    if (
      !idEmpleado ||
      !idCanalizacion
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Datos de canalización inválidos"
      });
    }

    connection =
      await pool.getConnection();

    await connection.beginTransaction();

    const acceso =
      await validarAccesoEmpleadoRH(
        idEmpleado,
        req.user,
        connection
      );

    if (!acceso.ok) {
      await connection.rollback();

      return res
        .status(acceso.status)
        .json({
          success: false,
          message:
            acceso.message
        });
    }

    const canalizacion =
      await obtenerCanalizacionRH(
        idCanalizacion,
        idEmpleado,
        connection,
        true
      );

    if (!canalizacion) {
      await connection.rollback();

      return res.status(404).json({
        success: false,
        message:
          "Canalización no encontrada"
      });
    }

    if (
      canalizacion.estatus ===
      "cerrada"
    ) {
      await connection.rollback();

      return res.status(409).json({
        success: false,
        message:
          "La canalización ya está cerrada"
      });
    }

    if (
      canalizacion.estatus ===
      "cancelada"
    ) {
      await connection.rollback();

      return res.status(409).json({
        success: false,
        message:
          "Una canalización cancelada no puede cerrarse"
      });
    }

    await connection.query(
      `
        UPDATE canalizaciones

        SET
          estatus =
            'cerrada',

          fecha_cierre =
            NOW()

        WHERE
          id_canalizacion = ?
      `,
      [
        idCanalizacion
      ]
    );

    await registrarHistorial(
      connection,
      idCanalizacion,
      acceso.contexto.idUsuario,

      "Canalización cerrada",

      observacion ||
      "Cierre administrativo de la canalización"
    );

    await connection.commit();

    return res.json({
      success: true,
      message:
        "Canalización cerrada correctamente"
    });

  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch {}
    }

    console.error(
      "❌ Error cerrando canalización:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Error interno al cerrar la canalización"
    });

  } finally {
    if (connection) {
      connection.release();
    }
  }
};

// ==================================================
// CANCELAR CANALIZACIÓN
// ==================================================

export const cancelarCanalizacion =
async (req, res) => {
  let connection;

  try {
    const idEmpleado =
      enteroPositivo(
        req.params.id
      );

    const idCanalizacion =
      enteroPositivo(
        req.params.idCanalizacion
      );

    const motivo =
      String(
        req.body?.motivo ||
        ""
      ).trim();

    if (
      !idEmpleado ||
      !idCanalizacion
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Datos de canalización inválidos"
      });
    }

    if (!motivo) {
      return res.status(400).json({
        success: false,
        message:
          "Indica el motivo de cancelación"
      });
    }

    connection =
      await pool.getConnection();

    await connection.beginTransaction();

    const acceso =
      await validarAccesoEmpleadoRH(
        idEmpleado,
        req.user,
        connection
      );

    if (!acceso.ok) {
      await connection.rollback();

      return res
        .status(acceso.status)
        .json({
          success: false,
          message:
            acceso.message
        });
    }

    const canalizacion =
      await obtenerCanalizacionRH(
        idCanalizacion,
        idEmpleado,
        connection,
        true
      );

    if (!canalizacion) {
      await connection.rollback();

      return res.status(404).json({
        success: false,
        message:
          "Canalización no encontrada"
      });
    }

    if (
      [
        "cerrada",
        "cancelada"
      ].includes(
        canalizacion.estatus
      )
    ) {
      await connection.rollback();

      return res.status(409).json({
        success: false,
        message:
          "Esta canalización ya no puede cancelarse"
      });
    }

    if (
      canalizacion
        .id_opcion_elegida ||

      canalizacion.estatus ===
        "seleccion_realizada"
    ) {
      await connection.rollback();

      return res.status(409).json({
        success: false,

        message:
          "Una canalización con profesional ya seleccionado no puede cancelarse desde RH; debe cerrarse administrativamente"
      });
    }

    await connection.query(
      `
        UPDATE canalizaciones

        SET
          estatus =
            'cancelada',

          fecha_cierre =
            NOW()

        WHERE
          id_canalizacion = ?
      `,
      [
        idCanalizacion
      ]
    );

    await registrarHistorial(
      connection,
      idCanalizacion,
      acceso.contexto.idUsuario,
      "Canalización cancelada",
      motivo
    );

    await connection.commit();

    return res.json({
      success: true,
      message:
        "Canalización cancelada correctamente"
    });

  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch {}
    }

    console.error(
      "❌ Error cancelando canalización:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Error interno al cancelar la canalización"
    });

  } finally {
    if (connection) {
      connection.release();
    }
  }
};

// ==================================================
// ACTUALIZAR CRITERIOS PARA RANKING
// ==================================================

export const actualizarCriteriosRankingCanalizacion =
async (req, res) => {

  let connection;

  try {

    const idEmpleado =
      enteroPositivo(
        req.params.id
      );

    const idCanalizacion =
      enteroPositivo(
        req.params.idCanalizacion
      );

    const modalidad =
      normalizarTextoRanking(
        req.body
          ?.modalidad_atencion_preferida
      );

    const areas =
      normalizarAreasRequeridas(
        req.body
          ?.areas_atencion_requeridas
      );


    if (
      !idEmpleado ||
      !idCanalizacion
    ) {

      return res
        .status(400)
        .json({
          success: false,
          message:
            "Datos de canalización inválidos"
        });
    }


    if (
      ![
        "presencial",
        "videollamada",
        "indistinta"
      ].includes(
        modalidad
      )
    ) {

      return res
        .status(400)
        .json({
          success: false,
          message:
            "Selecciona una modalidad de atención válida"
        });
    }


    if (
      !areas.length
    ) {

      return res
        .status(400)
        .json({
          success: false,
          message:
            "Selecciona al menos un área de atención"
        });
    }


    connection =
      await pool.getConnection();


    await connection.beginTransaction();


    const acceso =
      await validarAccesoEmpleadoRH(
        idEmpleado,
        req.user,
        connection
      );


    if (!acceso.ok) {

      await connection.rollback();

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


    const canalizacion =
      await obtenerCanalizacionRH(
        idCanalizacion,
        idEmpleado,
        connection,
        true
      );


    if (!canalizacion) {

      await connection.rollback();

      return res
        .status(404)
        .json({
          success: false,
          message:
            "Canalización no encontrada"
        });
    }


    if (
      [
        "cerrada",
        "cancelada"
      ].includes(
        canalizacion.estatus
      )
    ) {

      await connection.rollback();

      return res
        .status(409)
        .json({
          success: false,
          message:
            "Esta canalización ya no permite modificar los criterios"
        });
    }


    // ==================================================
    // VALIDAR ÁREAS
    // ==================================================

    const placeholders =
      areas
        .map(
          () => "?"
        )
        .join(",");


    const [areasValidas] =
      await connection.query(
        `
          SELECT
            id_area,
            nombre

          FROM catalogo_areas_atencion

          WHERE
            activo = 1

            AND id_area IN
            (
              ${placeholders}
            )
        `,
        areas
      );


    if (
      areasValidas.length !==
      areas.length
    ) {

      await connection.rollback();

      return res
        .status(400)
        .json({
          success: false,
          message:
            "Una o más áreas seleccionadas no son válidas"
        });
    }


    // ==================================================
    // ACTUALIZAR CANALIZACIÓN
    // ==================================================

    await connection.query(
      `
        UPDATE canalizaciones

        SET
          modalidad_atencion_preferida = ?,
          areas_atencion_requeridas = ?

        WHERE
          id_canalizacion = ?
          AND id_empleado = ?
      `,
      [
        modalidad,
        JSON.stringify(
          areas
        ),
        idCanalizacion,
        idEmpleado
      ]
    );


    // ==================================================
    // GUARDAR TAMBIÉN PREFERENCIA GENERAL
    // DEL EMPLEADO
    // ==================================================

    await connection.query(
      `
        UPDATE empleados

        SET
          modalidad_atencion_preferida = ?

        WHERE
          id_empleado = ?
      `,
      [
        modalidad,
        idEmpleado
      ]
    );


    await registrarHistorial(
      connection,
      idCanalizacion,
      acceso.contexto.idUsuario,
      "Criterios de ranking actualizados",
      `Modalidad: ${modalidad}. Áreas: ${areas.join(", ")}`
    );


    await connection.commit();


    return res.json({

      success: true,

      message:
        "Criterios guardados correctamente",

      criterios: {

        modalidad_atencion_preferida:
          modalidad,

        areas_atencion_requeridas:
          areas

      }

    });


  } catch (error) {

    if (connection) {
      try {
        await connection.rollback();
      } catch {}
    }


    console.error(
      "❌ Error guardando criterios de ranking:",
      error
    );


    return res
      .status(500)
      .json({

        success: false,

        message:
          "Error interno al guardar los criterios del ranking"

      });


  } finally {

    if (connection) {
      connection.release();
    }

  }

};

// ==================================================
// LISTAR ÁREAS PARA CANALIZACIÓN
// ==================================================

export const listarAreasAtencionCanalizacion =
async (req, res) => {

  try {

    const idEmpleado =
      enteroPositivo(
        req.params.id
      );


    if (!idEmpleado) {

      return res
        .status(400)
        .json({
          success: false,
          message:
            "ID de empleado inválido"
        });

    }


    const acceso =
      await validarAccesoEmpleadoRH(
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


    const [areas] =
      await pool.query(
        `
          SELECT
            id_area,
            nombre

          FROM catalogo_areas_atencion

          WHERE
            activo = 1

          ORDER BY
            orden ASC,
            nombre ASC
        `
      );


    return res.json({

      success: true,

      total:
        areas.length,

      areas

    });


  } catch (error) {

    console.error(
      "❌ Error cargando áreas de atención:",
      error
    );


    return res
      .status(500)
      .json({

        success: false,

        message:
          "No fue posible obtener las áreas de atención"

      });

  }

};
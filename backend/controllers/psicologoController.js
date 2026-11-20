// ==================================================
// backend/controllers/psicologoController.js
// ==================================================

import pool from "../config/database.js";


// ==================================================
// AUXILIARES
// ==================================================

const normalizar =
  valor =>
    valor
      ? String(valor)
          .trim()
          .toLowerCase()
      : "";


const enteroPositivo =
  valor => {

    const numero =
      Number(valor);

    return Number.isInteger(numero) &&
      numero > 0
      ? numero
      : null;
  };


const textoONull =
  valor => {

    if (
      valor === undefined
    ) {
      return undefined;
    }

    const texto =
      String(
        valor || ""
      ).trim();

    return texto || null;
  };


const numeroONull =
  valor => {

    if (
      valor === undefined
    ) {
      return undefined;
    }

    if (
      valor === "" ||
      valor === null
    ) {
      return null;
    }

    const numero =
      Number(valor);

    return Number.isFinite(numero)
      ? numero
      : NaN;
  };


const booleano =
  valor => {

    return (
      valor === true ||
      valor === 1 ||
      valor === "1" ||
      normalizar(valor) === "true"
    )
      ? 1
      : 0;
  };


// ==================================================
// OBTENER CONTEXTO REAL DEL USUARIO
// ==================================================

const obtenerContextoUsuario =
  async (
    user,
    connection = pool
  ) => {

    const idUsuario =
      enteroPositivo(
        user?.id_usuario
      );


    if (
      !idUsuario
    ) {

      return {

        idUsuario:
          null,

        role:
          Number(
            user?.role
          ) || null,

        rol:
          normalizar(
            user?.rol
          ),

        tipoAdmin:
          normalizar(
            user?.tipo_admin
          ),

        area:
          normalizar(
            user?.area
          ),

        idAdminPadre:
          enteroPositivo(
            user?.id_admin_padre
          ),

        idOrganizacion:
          enteroPositivo(
            user?.id_organizacion
          ),

        tipoOrganizacion:
          normalizar(
            user?.tipo_organizacion
          ),

        perfilIndependiente:
          normalizar(
            user?.perfil_independiente
          )

      };

    }


    const [
      rows
    ] =
      await connection.query(
        `
          SELECT
            u.id_usuario,
            u.rol,
            u.tipo_admin,
            u.area,
            u.id_admin_padre,
            u.id_organizacion,

            o.tipo
              AS tipo_organizacion,

            o.perfil_independiente

          FROM usuarios u

          LEFT JOIN organizaciones o
            ON o.id_organizacion =
               u.id_organizacion

          WHERE
            u.id_usuario = ?

          LIMIT 1
        `,
        [
          idUsuario
        ]
      );


    if (
      !rows.length
    ) {

      return {

        idUsuario,

        role:
          Number(
            user?.role
          ) || null,

        rol:
          normalizar(
            user?.rol
          ),

        tipoAdmin:
          normalizar(
            user?.tipo_admin
          ),

        area:
          normalizar(
            user?.area
          ),

        idAdminPadre:
          enteroPositivo(
            user?.id_admin_padre
          ),

        idOrganizacion:
          enteroPositivo(
            user?.id_organizacion
          ),

        tipoOrganizacion:
          normalizar(
            user?.tipo_organizacion
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

      role:
        Number(
          user?.role
        ) || null,

      rol:
        normalizar(
          usuario.rol
        ),

      tipoAdmin:
        normalizar(
          usuario.tipo_admin
        ),

      area:
        normalizar(
          usuario.area
        ),

      idAdminPadre:
        enteroPositivo(
          usuario.id_admin_padre
        ),

      idOrganizacion:
        enteroPositivo(
          usuario.id_organizacion
        ),

      tipoOrganizacion:
        normalizar(
          usuario.tipo_organizacion
        ),

      perfilIndependiente:
        normalizar(
          usuario.perfil_independiente
        )

    };

  };


// ==================================================
// VALIDAR ACCESO A PERFIL CLÍNICO
// ==================================================

const puedeUsarPerfilClinico =
  contexto => {

    if (
      !contexto
    ) {
      return false;
    }


    const esPsicologo =
      contexto.rol ===
      "psicologo";


    const esIndependienteClinica =
      contexto.rol ===
        "independiente" &&

      contexto.perfilIndependiente ===
        "clinica";


    return (
      esPsicologo ||
      esIndependienteClinica
    );

  };


// ==================================================
// OBTENER ÁREAS DE UN PSICÓLOGO
// ==================================================

const obtenerAreasPsicologo =
  async (
    idPsicologo,
    connection = pool
  ) => {

    if (
      !idPsicologo
    ) {
      return [];
    }


    const [
      areas
    ] =
      await connection.query(
        `
          SELECT
            ca.id_area,
            ca.clave,
            ca.nombre

          FROM psicologo_areas_atencion paa

          INNER JOIN catalogo_areas_atencion ca
            ON ca.id_area =
               paa.id_area

          WHERE
            paa.id_psicologo = ?

            AND ca.activo = 1

          ORDER BY
            ca.orden ASC,
            ca.nombre ASC
        `,
        [
          idPsicologo
        ]
      );


    return areas || [];

  };


// ==================================================
// CALCULAR SI EL PERFIL ESTÁ COMPLETO
// ==================================================

const calcularPerfilCompleto =
  async (
    idPsicologo,
    connection = pool
  ) => {

    if (
      !idPsicologo
    ) {
      return 0;
    }


    const [
      rows
    ] =
      await connection.query(
        `
          SELECT
            p.*

          FROM psicologos p

          WHERE
            p.id_psicologo = ?

          LIMIT 1
        `,
        [
          idPsicologo
        ]
      );


    if (
      !rows.length
    ) {
      return 0;
    }


    const perfil =
      rows[0];


    const [
      areasRows
    ] =
      await connection.query(
        `
          SELECT
            COUNT(*) AS total

          FROM psicologo_areas_atencion

          WHERE
            id_psicologo = ?
        `,
        [
          idPsicologo
        ]
      );


    const totalAreas =
      Number(
        areasRows[0]?.total ||
        0
      );


    const datosProfesionales =
      Boolean(
        String(
          perfil.cedula_profesional ||
          ""
        ).trim()
      ) &&

      Boolean(
        String(
          perfil.especialidad ||
          ""
        ).trim()
      ) &&

      perfil.anos_experiencia !==
        null &&

      perfil.anos_experiencia !==
        undefined &&

      Number(
        perfil.anos_experiencia
      ) >= 0 &&

      Boolean(
        String(
          perfil.descripcion_profesional ||
          ""
        ).trim()
      ) &&

      totalAreas > 0;


    const presencial =
      Number(
        perfil.modalidad_presencial
      ) === 1;


    const videollamada =
      Number(
        perfil.modalidad_videollamada
      ) === 1;


    const tieneModalidad =
      presencial ||
      videollamada;


    let presencialCompleto =
      true;


    if (
      presencial
    ) {

      presencialCompleto =
        Number(
          perfil.precio_presencial
        ) > 0 &&

        Boolean(
          String(
            perfil.estado ||
            ""
          ).trim()
        ) &&

        Boolean(
          String(
            perfil.municipio ||
            ""
          ).trim()
        ) &&

        Boolean(
          String(
            perfil.colonia ||
            ""
          ).trim()
        ) &&

        /^\d{5}$/.test(
          String(
            perfil.codigo_postal ||
            ""
          ).trim()
        ) &&

        Boolean(
          String(
            perfil.direccion_consultorio ||
            ""
          ).trim()
        );

    }


    let videollamadaCompleta =
      true;


    if (
      videollamada
    ) {

      videollamadaCompleta =
        Number(
          perfil.precio_videollamada
        ) > 0;

    }


    const disponibilidadCompleta =
      Boolean(
        String(
          perfil.disponibilidad ||
          ""
        ).trim()
      );


    return (
      datosProfesionales &&
      tieneModalidad &&
      presencialCompleto &&
      videollamadaCompleta &&
      disponibilidadCompleta
    )
      ? 1
      : 0;

  };


// ==================================================
// ACTUALIZAR BANDERA PERFIL COMPLETO
// ==================================================

const actualizarEstadoPerfil =
  async (
    idPsicologo,
    connection = pool
  ) => {

    const completo =
      await calcularPerfilCompleto(
        idPsicologo,
        connection
      );


    await connection.query(
      `
        UPDATE psicologos

        SET
          perfil_profesional_completo = ?,

          activo_canalizacion =
            CASE
              WHEN ? = 1
                THEN activo_canalizacion
              ELSE 0
            END

        WHERE
          id_psicologo = ?
      `,
      [
        completo,
        completo,
        idPsicologo
      ]
    );


    return completo;

  };


// ==================================================
// LISTAR PSICÓLOGOS
// ==================================================

export async function listarPsicologos(
  req,
  res
) {

  try {

    const contexto =
      await obtenerContextoUsuario(
        req.user
      );


    if (
      contexto.role !== 1
    ) {

      return res
        .status(403)
        .json({
          message:
            "Solo administradores"
        });

    }


    let sql = `
      SELECT

        p.id_psicologo,
        p.id_usuario,

        u.nombre,
        u.correo,
        u.area,
        u.id_admin_padre,
        u.id_organizacion,

        p.cedula_profesional,
        p.especialidad,

        p.foto_url,
        p.descripcion_profesional,
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

        (
          SELECT COUNT(*)

          FROM psicologo_areas_atencion paa

          WHERE
            paa.id_psicologo =
            p.id_psicologo
        )
          AS total_areas_atencion

      FROM psicologos p

      INNER JOIN usuarios u
        ON p.id_usuario =
           u.id_usuario

      WHERE
        LOWER(
          TRIM(
            COALESCE(
              u.rol,
              ''
            )
          )
        ) = 'psicologo'
    `;


    const params = [];


    if (
      contexto.tipoAdmin ===
      "master"
    ) {

      // Master ve todo.

    }


    else if (
      contexto.tipoAdmin ===
      "normal"
    ) {

      if (
        !contexto.idUsuario
      ) {

        return res
          .status(403)
          .json({
            message:
              "El administrador no tiene un ID válido"
          });

      }


      if (
        contexto.area !==
        "clinica"
      ) {

        return res
          .status(403)
          .json({
            message:
              "No tienes acceso al módulo de psicólogos"
          });

      }


      if (
        !contexto.idOrganizacion
      ) {

        return res
          .status(403)
          .json({
            message:
              "El administrador no está asociado a una organización"
          });

      }


      sql += `
        AND u.id_organizacion = ?
      `;


      params.push(
        contexto.idOrganizacion
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


    sql += `
      ORDER BY
        u.nombre ASC,
        p.id_psicologo ASC
    `;


    const [
      rows
    ] =
      await pool.query(
        sql,
        params
      );


    return res.json(
      rows || []
    );


  } catch (err) {

    console.error(
      "❌ Error al obtener psicólogos:",
      err
    );


    return res
      .status(500)
      .json({
        message:
          "Error al obtener psicólogos"
      });

  }

}


// ==================================================
// CATÁLOGO DE ÁREAS DE ATENCIÓN
// ==================================================

export async function listarAreasAtencion(
  req,
  res
) {

  try {

    const contexto =
      await obtenerContextoUsuario(
        req.user
      );


    if (
      !contexto.idUsuario
    ) {

      return res
        .status(401)
        .json({
          success: false,

          message:
            "Sesión inválida"
        });

    }


    const [
      areas
    ] =
      await pool.query(
        `
          SELECT
            id_area,
            clave,
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

      success:
        true,

      areas:
        areas || []

    });


  } catch (error) {

    console.error(
      "❌ Error listando áreas de atención:",
      error
    );


    return res
      .status(500)
      .json({

        success:
          false,

        message:
          "Error al obtener las áreas de atención"

      });

  }

}


// ==================================================
// OBTENER MI PERFIL PROFESIONAL
// ==================================================

export async function obtenerMiPerfilPsicologo(
  req,
  res
) {

  try {

    const contexto =
      await obtenerContextoUsuario(
        req.user
      );


    if (
      !contexto.idUsuario
    ) {

      return res
        .status(401)
        .json({
          success: false,

          message:
            "No se pudo identificar al usuario"
        });

    }


    if (
      !puedeUsarPerfilClinico(
        contexto
      )
    ) {

      return res
        .status(403)
        .json({
          success: false,

          message:
            "Esta sección está disponible para psicólogos e Independientes con perfil Clínica"
        });

    }


    const [
      rows
    ] =
      await pool.query(
        `
          SELECT

            p.id_psicologo,
            p.id_usuario,

            u.nombre,
            u.correo,

            p.cedula_profesional,
            p.especialidad,

            p.foto_url,
            p.descripcion_profesional,
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
            p.activo_canalizacion

          FROM psicologos p

          INNER JOIN usuarios u
            ON u.id_usuario =
               p.id_usuario

          WHERE
            p.id_usuario = ?

          LIMIT 1
        `,
        [
          contexto.idUsuario
        ]
      );


    if (
      !rows.length
    ) {

      const esIndependienteClinica =
        contexto.rol ===
          "independiente" &&

        contexto.perfilIndependiente ===
          "clinica";


      if (
        esIndependienteClinica
      ) {

        const [
          usuarios
        ] =
          await pool.query(
            `
              SELECT
                id_usuario,
                nombre,
                correo

              FROM usuarios

              WHERE
                id_usuario = ?

              LIMIT 1
            `,
            [
              contexto.idUsuario
            ]
          );


        const usuario =
          usuarios[0] ||
          {};


        return res.json({

          success:
            true,

          requiere_crear_perfil:
            true,

          perfil: {

            id_psicologo:
              null,

            id_usuario:
              contexto.idUsuario,

            nombre:
              usuario.nombre ||
              null,

            correo:
              usuario.correo ||
              null,

            cedula_profesional:
              null,

            especialidad:
              null,

            foto_url:
              null,

            descripcion_profesional:
              null,

            anos_experiencia:
              null,

            modalidad_presencial:
              0,

            modalidad_videollamada:
              0,

            precio_presencial:
              null,

            precio_videollamada:
              null,

            estado:
              null,

            municipio:
              null,

            colonia:
              null,

            codigo_postal:
              null,

            direccion_consultorio:
              null,

            disponibilidad:
              null,

            perfil_profesional_completo:
              0,

            activo_canalizacion:
              0,

            areas_atencion:
              []

          }

        });

      }


      return res
        .status(404)
        .json({
          success: false,

          message:
            "No se encontró el perfil del psicólogo"
        });

    }


    const perfil =
      rows[0];


    const areas =
      await obtenerAreasPsicologo(
        perfil.id_psicologo
      );


    return res.json({

      success:
        true,

      perfil: {

        ...perfil,

        areas_atencion:
          areas

      }

    });


  } catch (error) {

    console.error(
      "❌ Error obteniendo perfil profesional:",
      error
    );


    return res
      .status(500)
      .json({

        success:
          false,

        message:
          "Error interno al obtener el perfil profesional"

      });

  }

}


// ==================================================
// ACTUALIZAR MI PERFIL PROFESIONAL
// ==================================================

export async function actualizarMiPerfilPsicologo(
  req,
  res
) {

  let connection;


  try {

    connection =
      await pool
        .getConnection();


    await connection
      .beginTransaction();


    const contexto =
      await obtenerContextoUsuario(
        req.user,
        connection
      );


    if (
      !contexto.idUsuario
    ) {

      await connection
        .rollback();


      return res
        .status(401)
        .json({
          success: false,

          message:
            "No se pudo identificar al usuario"
        });

    }


    if (
      !puedeUsarPerfilClinico(
        contexto
      )
    ) {

      await connection
        .rollback();


      return res
        .status(403)
        .json({
          success: false,

          message:
            "Esta sección está disponible para psicólogos e Independientes con perfil Clínica"
        });

    }


    const [
      psicologos
    ] =
      await connection.query(
        `
          SELECT *

          FROM psicologos

          WHERE
            id_usuario = ?

          LIMIT 1

          FOR UPDATE
        `,
        [
          contexto.idUsuario
        ]
      );


    let psicologo =
      psicologos[0] ||
      null;


    // ==================================================
    // CREAR PERFIL PARA INDEPENDIENTE CLÍNICA
    // ==================================================

    if (
      !psicologo
    ) {

      const esIndependienteClinica =
        contexto.rol ===
          "independiente" &&

        contexto.perfilIndependiente ===
          "clinica";


      if (
        !esIndependienteClinica
      ) {

        await connection
          .rollback();


        return res
          .status(404)
          .json({
            success: false,

            message:
              "No se encontró el registro del psicólogo"
          });

      }


      const cedulaInicial =
        textoONull(
          req.body
            ?.cedula_profesional
        );


      if (
        !cedulaInicial ||
        String(
          cedulaInicial
        )
          .trim()
          .length < 5
      ) {

        await connection
          .rollback();


        return res
          .status(400)
          .json({
            success: false,

            code:
              "CEDULA_REQUERIDA",

            message:
              "La cédula profesional es obligatoria para crear tu perfil clínico"
          });

      }


      const [
        cedulasExistentes
      ] =
        await connection.query(
          `
            SELECT
              id_psicologo

            FROM psicologos

            WHERE
              cedula_profesional = ?

            LIMIT 1

            FOR UPDATE
          `,
          [
            cedulaInicial
          ]
        );


      if (
        cedulasExistentes.length
      ) {

        await connection
          .rollback();


        return res
          .status(409)
          .json({
            success: false,

            code:
              "CEDULA_EXISTENTE",

            message:
              "La cédula profesional ya está registrada"
          });

      }


      const [
        usuarioRows
      ] =
        await connection.query(
          `
            SELECT
              telefono,
              direccion

            FROM usuarios

            WHERE
              id_usuario = ?

            LIMIT 1
          `,
          [
            contexto.idUsuario
          ]
        );


      const usuario =
        usuarioRows[0] ||
        {};


      const [
        perfilInsertado
      ] =
        await connection.query(
          `
            INSERT INTO psicologos
            (
              id_usuario,
              telefono,
              cedula_profesional,
              especialidad,
              direccion
            )

            VALUES
            (
              ?,
              ?,
              ?,
              ?,
              ?
            )
          `,
          [
            contexto.idUsuario,
            usuario.telefono ||
              null,
            cedulaInicial,
            textoONull(
              req.body
                ?.especialidad
            ) ||
              null,
            usuario.direccion ||
              null
          ]
        );


      const [
        perfilCreado
      ] =
        await connection.query(
          `
            SELECT *

            FROM psicologos

            WHERE
              id_psicologo = ?

            LIMIT 1

            FOR UPDATE
          `,
          [
            perfilInsertado
              .insertId
          ]
        );


      psicologo =
        perfilCreado[0] ||
        null;


      if (
        !psicologo
      ) {

        await connection
          .rollback();


        return res
          .status(500)
          .json({
            success: false,

            message:
              "No fue posible crear el perfil profesional"
          });

      }

    }


    // ==================================================
    // DATOS PROFESIONALES
    // ==================================================

    const cedulaProfesional =
      textoONull(
        req.body
          ?.cedula_profesional
      );


    const especialidad =
      textoONull(
        req.body
          ?.especialidad
      );


    const fotoUrl =
      textoONull(
        req.body
          ?.foto_url
      );


    const descripcionProfesional =
      textoONull(
        req.body
          ?.descripcion_profesional
      );


    const anosExperiencia =
      numeroONull(
        req.body
          ?.anos_experiencia
      );


    if (
      anosExperiencia !==
        undefined &&

      anosExperiencia !==
        null &&

      (
        !Number.isInteger(
          anosExperiencia
        ) ||

        anosExperiencia < 0 ||

        anosExperiencia > 80
      )
    ) {

      await connection
        .rollback();


      return res
        .status(400)
        .json({
          success: false,

          message:
            "Los años de experiencia deben ser un número entero válido"
        });

    }


    const modalidadPresencial =
      req.body
        ?.modalidad_presencial !==
      undefined
        ? booleano(
            req.body
              .modalidad_presencial
          )
        : undefined;


    const modalidadVideollamada =
      req.body
        ?.modalidad_videollamada !==
      undefined
        ? booleano(
            req.body
              .modalidad_videollamada
          )
        : undefined;


    const precioPresencial =
      numeroONull(
        req.body
          ?.precio_presencial
      );


    const precioVideollamada =
      numeroONull(
        req.body
          ?.precio_videollamada
      );


    if (
      precioPresencial !==
        undefined &&

      precioPresencial !==
        null &&

      (
        !Number.isFinite(
          precioPresencial
        ) ||

        precioPresencial < 0
      )
    ) {

      await connection
        .rollback();


      return res
        .status(400)
        .json({
          success: false,

          message:
            "El precio presencial es inválido"
        });

    }


    if (
      precioVideollamada !==
        undefined &&

      precioVideollamada !==
        null &&

      (
        !Number.isFinite(
          precioVideollamada
        ) ||

        precioVideollamada < 0
      )
    ) {

      await connection
        .rollback();


      return res
        .status(400)
        .json({
          success: false,

          message:
            "El precio de videollamada es inválido"
        });

    }


    const estado =
      textoONull(
        req.body?.estado
      );


    const municipio =
      textoONull(
        req.body?.municipio
      );


    const colonia =
      textoONull(
        req.body?.colonia
      );


    const codigoPostal =
      textoONull(
        req.body
          ?.codigo_postal
      );


    if (
      codigoPostal &&
      !/^\d{5}$/.test(
        codigoPostal
      )
    ) {

      await connection
        .rollback();


      return res
        .status(400)
        .json({
          success: false,

          message:
            "El código postal debe contener 5 dígitos"
        });

    }


    const direccionConsultorio =
      textoONull(
        req.body
          ?.direccion_consultorio
      );


    const disponibilidad =
      textoONull(
        req.body
          ?.disponibilidad
      );


    const activoCanalizacionSolicitado =
      req.body
        ?.activo_canalizacion !==
      undefined
        ? booleano(
            req.body
              .activo_canalizacion
          )
        : undefined;


    // ==================================================
    // UPDATE DINÁMICO
    // ==================================================

    const campos =
      [];

    const valores =
      [];


    const agregar =
      (
        nombreCampo,
        valor
      ) => {

        if (
          valor === undefined
        ) {
          return;
        }

        campos.push(
          `${nombreCampo} = ?`
        );

        valores.push(
          valor
        );

      };


    agregar(
      "cedula_profesional",
      cedulaProfesional
    );


    agregar(
      "especialidad",
      especialidad
    );


    agregar(
      "foto_url",
      fotoUrl
    );


    agregar(
      "descripcion_profesional",
      descripcionProfesional
    );


    agregar(
      "anos_experiencia",
      anosExperiencia
    );


    agregar(
      "modalidad_presencial",
      modalidadPresencial
    );


    agregar(
      "modalidad_videollamada",
      modalidadVideollamada
    );


    agregar(
      "precio_presencial",
      precioPresencial
    );


    agregar(
      "precio_videollamada",
      precioVideollamada
    );


    agregar(
      "estado",
      estado
    );


    agregar(
      "municipio",
      municipio
    );


    agregar(
      "colonia",
      colonia
    );


    agregar(
      "codigo_postal",
      codigoPostal
    );


    agregar(
      "direccion_consultorio",
      direccionConsultorio
    );


    agregar(
      "disponibilidad",
      disponibilidad
    );


    if (
      campos.length
    ) {

      valores.push(
        psicologo.id_psicologo
      );


      await connection.query(
        `
          UPDATE psicologos

          SET
            ${campos.join(", ")}

          WHERE
            id_psicologo = ?
        `,
        valores
      );

    }


    // ==================================================
    // ÁREAS DE ATENCIÓN
    // ==================================================

    if (
      req.body
        ?.areas_atencion !==
      undefined
    ) {

      if (
        !Array.isArray(
          req.body
            .areas_atencion
        )
      ) {

        await connection
          .rollback();


        return res
          .status(400)
          .json({
            success: false,

            message:
              "Las áreas de atención deben enviarse como una lista"
          });

      }


      const idsAreas =
        [
          ...new Set(
            req.body
              .areas_atencion
              .map(
                enteroPositivo
              )
              .filter(
                Boolean
              )
          )
        ];


      if (
        idsAreas.length
      ) {

        const placeholders =
          idsAreas
            .map(
              () => "?"
            )
            .join(",");


        const [
          areasValidas
        ] =
          await connection.query(
            `
              SELECT
                id_area

              FROM catalogo_areas_atencion

              WHERE
                activo = 1

                AND id_area IN
                (
                  ${placeholders}
                )
            `,
            idsAreas
          );


        if (
          areasValidas.length !==
          idsAreas.length
        ) {

          await connection
            .rollback();


          return res
            .status(400)
            .json({
              success: false,

              message:
                "Una o más áreas de atención no son válidas"
            });

        }

      }


      await connection.query(
        `
          DELETE FROM
            psicologo_areas_atencion

          WHERE
            id_psicologo = ?
        `,
        [
          psicologo
            .id_psicologo
        ]
      );


      for (
        const idArea
        of idsAreas
      ) {

        await connection.query(
          `
            INSERT INTO
              psicologo_areas_atencion
            (
              id_psicologo,
              id_area
            )

            VALUES
            (
              ?,
              ?
            )
          `,
          [
            psicologo
              .id_psicologo,

            idArea
          ]
        );

      }

    }


    // ==================================================
    // RECALCULAR PERFIL
    // ==================================================

    const perfilCompleto =
      await actualizarEstadoPerfil(
        psicologo.id_psicologo,
        connection
      );


    // ==================================================
    // ACTIVAR / DESACTIVAR CANALIZACIÓN
    // ==================================================

    if (
      activoCanalizacionSolicitado !==
      undefined
    ) {

      const activoFinal =
        perfilCompleto === 1
          ? activoCanalizacionSolicitado
          : 0;


      await connection.query(
        `
          UPDATE psicologos

          SET
            activo_canalizacion = ?

          WHERE
            id_psicologo = ?
        `,
        [
          activoFinal,
          psicologo
            .id_psicologo
        ]
      );

    }


    // ==================================================
    // OBTENER ACTUALIZADO
    // ==================================================

    const [
      rows
    ] =
      await connection.query(
        `
          SELECT

            p.id_psicologo,
            p.id_usuario,

            u.nombre,
            u.correo,

            p.cedula_profesional,
            p.especialidad,

            p.foto_url,
            p.descripcion_profesional,
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
            p.activo_canalizacion

          FROM psicologos p

          INNER JOIN usuarios u
            ON u.id_usuario =
               p.id_usuario

          WHERE
            p.id_psicologo = ?

          LIMIT 1
        `,
        [
          psicologo
            .id_psicologo
        ]
      );


    const areas =
      await obtenerAreasPsicologo(
        psicologo.id_psicologo,
        connection
      );


    await connection
      .commit();


    return res.json({

      success:
        true,

      message:
        perfilCompleto === 1
          ? "Perfil profesional actualizado y completo"
          : "Perfil profesional actualizado. Aún faltan datos para completarlo.",

      perfil: {

        ...rows[0],

        areas_atencion:
          areas

      }

    });


  } catch (error) {

    if (
      connection
    ) {

      try {

        await connection
          .rollback();

      } catch {}

    }


    console.error(
      "❌ Error actualizando perfil del psicólogo:",
      error
    );


    return res
      .status(500)
      .json({

        success:
          false,

        message:
          "Error interno al actualizar el perfil profesional",

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


// ==================================================
// SUBIR FOTO PROFESIONAL
//
// POST /api/psicologos/mi-perfil/foto
// ==================================================

export async function subirFotoPerfilPsicologo(
  req,
  res
) {

  try {

    const idUsuario =
      enteroPositivo(
        req.user?.id_usuario
      );


    if (
      !idUsuario
    ) {

      if (
        req.file?.path
      ) {

        try {

          const fs =
            await import(
              "fs/promises"
            );


          await fs.unlink(
            req.file.path
          );

        } catch {}

      }


      return res
        .status(401)
        .json({

          success:
            false,

          message:
            "No se pudo identificar al usuario"

        });

    }


    const contexto =
      await obtenerContextoUsuario(
        req.user
      );


    if (
      !contexto.idUsuario
    ) {

      if (
        req.file?.path
      ) {

        try {

          const fs =
            await import(
              "fs/promises"
            );


          await fs.unlink(
            req.file.path
          );

        } catch {}

      }


      return res
        .status(404)
        .json({

          success:
            false,

          message:
            "Usuario no encontrado"

        });

    }


    if (
      !puedeUsarPerfilClinico(
        contexto
      )
    ) {

      if (
        req.file?.path
      ) {

        try {

          const fs =
            await import(
              "fs/promises"
            );


          await fs.unlink(
            req.file.path
          );

        } catch {}

      }


      return res
        .status(403)
        .json({

          success:
            false,

          message:
            "Esta acción está disponible para psicólogos e Independientes con perfil Clínica"

        });

    }


    // ==================================================
    // VALIDAR ARCHIVO
    // ==================================================

    if (
      !req.file
    ) {

      return res
        .status(400)
        .json({

          success:
            false,

          message:
            "Debes seleccionar una imagen"

        });

    }


    // ==================================================
    // BUSCAR PERFIL
    // ==================================================

    const [
      psicologos
    ] =
      await pool.query(
        `
          SELECT
            id_psicologo,
            foto_url

          FROM psicologos

          WHERE
            id_usuario = ?

          LIMIT 1
        `,
        [
          idUsuario
        ]
      );


    if (
      !psicologos.length
    ) {

      try {

        const fs =
          await import(
            "fs/promises"
          );


        await fs.unlink(
          req.file.path
        );

      } catch {}


      return res
        .status(404)
        .json({

          success:
            false,

          message:
            contexto.rol === "independiente"
              ? "Primero completa y guarda tu perfil profesional antes de subir una foto"
              : "No se encontró el perfil del psicólogo"

        });

    }


    const psicologo =
      psicologos[0];


    const fotoUrl =
      `/uploads/imagenes/psicologos/${req.file.filename}`;


    // ==================================================
    // ACTUALIZAR FOTO
    // ==================================================

    await pool.query(
      `
        UPDATE psicologos

        SET
          foto_url = ?

        WHERE
          id_psicologo = ?
      `,
      [
        fotoUrl,
        psicologo.id_psicologo
      ]
    );


    // ==================================================
    // BORRAR FOTO ANTERIOR
    // ==================================================

    const fotoAnterior =
      String(
        psicologo.foto_url ||
        ""
      ).trim();


    if (
      fotoAnterior &&
      fotoAnterior.startsWith(
        "/uploads/imagenes/psicologos/"
      ) &&
      fotoAnterior !==
      fotoUrl
    ) {

      try {

        const fs =
          await import(
            "fs/promises"
          );


        const path =
          await import(
            "path"
          );


        const {
          fileURLToPath
        } =
          await import(
            "url"
          );


        const __filename =
          fileURLToPath(
            import.meta.url
          );


        const __dirname =
          path.dirname(
            __filename
          );


        const nombreAnterior =
          path.basename(
            fotoAnterior
          );


        const rutaAnterior =
          path.join(
            __dirname,
            "..",
            "uploads",
            "imagenes",
            "psicologos",
            nombreAnterior
          );


        await fs.unlink(
          rutaAnterior
        );


      } catch (
        errorEliminar
      ) {

        console.warn(
          "⚠️ No se pudo eliminar la foto anterior:",
          errorEliminar.message
        );

      }

    }


    return res.json({

      success:
        true,

      message:
        "Foto profesional actualizada correctamente",

      foto_url:
        fotoUrl

    });


  } catch (error) {

    if (
      req.file?.path
    ) {

      try {

        const fs =
          await import(
            "fs/promises"
          );


        await fs.unlink(
          req.file.path
        );

      } catch {}

    }


    console.error(
      "❌ Error subiendo foto profesional:",
      error
    );


    return res
      .status(500)
      .json({

        success:
          false,

        message:
          "Error interno al subir la foto profesional",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined

      });

  }

}
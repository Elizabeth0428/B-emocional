// backend/controllers/psicologoController.js

import pool from "../config/database.js";


/* ==================================================
   LISTAR PSICÓLOGOS

   MASTER:
   - Puede ver TODOS los psicólogos.
   - Sin importar quién los creó.
   - Sin importar el área.

   ADMIN NORMAL CLÍNICA:
   - Solo puede ver los psicólogos que ÉL creó.
   - No puede ver psicólogos creados por otro admin.

   ADMIN NORMAL RH:
   - No puede entrar a este módulo.

   ADMIN NORMAL EDUCATIVO:
   - No puede entrar a este módulo.

   ADMIN NORMAL INDEPENDIENTE:
   - No puede entrar a este módulo.
================================================== */

export async function listarPsicologos(req, res) {

  try {

    /* ================================================
       VALIDAR QUE SEA ADMINISTRADOR
    ================================================ */

    if (req.user?.role !== 1) {

      return res.status(403).json({
        message: "Solo administradores"
      });

    }


    /* ================================================
       DATOS DEL ADMINISTRADOR ACTUAL
    ================================================ */

    const tipoAdmin =
      req.user?.tipo_admin
        ? String(req.user.tipo_admin)
            .trim()
            .toLowerCase()
        : null;


    const idAdmin =
      req.user?.id_usuario || null;


    const areaAdmin =
      req.user?.area
        ? String(req.user.area)
            .trim()
            .toLowerCase()
        : null;


    /* ================================================
       CONSULTA BASE

       Solamente usuarios que realmente sean
       psicólogos y tengan registro en psicologos.
    ================================================ */

    let sql = `
      SELECT
        p.id_psicologo,
        p.id_usuario,
        u.nombre,
        u.correo,
        u.area,
        u.id_admin_padre,
        p.cedula_profesional,
        p.especialidad
      FROM psicologos p
      INNER JOIN usuarios u
        ON p.id_usuario = u.id_usuario
      WHERE u.rol = 'psicologo'
    `;


    const params = [];


    /* ==================================================
       ADMIN MASTER
       
       EL MASTER VE TODO.

       No importa:
       - quién creó al psicólogo
       - área
       - id_admin_padre
    ================================================== */

    if (tipoAdmin === "master") {

      // Sin filtros adicionales.
      // Acceso global.


    }


    /* ==================================================
       ADMIN NORMAL
    ================================================== */

    else if (tipoAdmin === "normal") {


      /* ================================================
         VALIDAR ID DEL ADMINISTRADOR
      ================================================ */

      if (!idAdmin) {

        return res.status(403).json({
          message:
            "El administrador no tiene un ID válido"
        });

      }


      /* ================================================
         SOLO ADMIN NORMAL DE CLÍNICA

         Los administradores normales de:
         - RH
         - Educativo
         - Independiente

         NO pueden entrar al módulo de psicólogos.
      ================================================ */

      if (areaAdmin !== "clinica") {

        return res.status(403).json({
          message:
            "No tienes acceso al módulo de psicólogos"
        });

      }


      /* ================================================
         SOLO PSICÓLOGOS CREADOS POR ESTE ADMIN

         ESTA ES LA REGLA PRINCIPAL.

         id_admin_padre = ID del administrador
         que registró al psicólogo.

         Por lo tanto:

         Admin A
           └── Psicólogo 1
           └── Psicólogo 2

         Admin B
           └── Psicólogo 3
           └── Psicólogo 4

         Admin A solamente verá:
           Psicólogo 1
           Psicólogo 2

         Nunca:
           Psicólogo 3
           Psicólogo 4
      ================================================ */

      sql += `
        AND u.id_admin_padre = ?
      `;


      params.push(idAdmin);

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
       ORDENAR RESULTADOS
    ================================================== */

    sql += `
      ORDER BY u.nombre ASC
    `;


    /* ==================================================
       EJECUTAR CONSULTA
    ================================================== */

    const [rows] =
      await pool.query(
        sql,
        params
      );


    /* ==================================================
       RESPUESTA
    ================================================== */

    return res.json(
      rows || []
    );


  } catch (err) {

    console.error(
      "❌ Error al obtener psicólogos:",
      err
    );


    return res.status(500).json({
      message:
        "Error al obtener psicólogos"
    });

  }

}
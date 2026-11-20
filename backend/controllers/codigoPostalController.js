// ==================================================
// backend/controllers/codigoPostalController.js
// ==================================================
//
// Consulta códigos postales de México usando Postali.
//
// GRATIS:
// - Sin API key
// - Sin registro
// - Sin token
//
// Endpoint utilizado:
//
// https://postali.app/api/v1/mx/cp/56400
//
// Postali devuelve:
//
// {
//   cp: "56400",
//   estado: "México",
//   municipio: "La Paz",
//   asentamientos: [
//     {
//       nombre: "Los Reyes Acaquilpan",
//       tipo: "Colonia",
//       ciudad: "...",
//       zona: "Urbano"
//     }
//   ]
// }
//
// Este controlador normaliza la respuesta para que
// EmpleadoDetalle.jsx reciba:
//
// {
//   success: true,
//   codigo_postal: "56400",
//   estado: "México",
//   municipio: "La Paz",
//   ciudad: "...",
//   colonias: [
//     "Los Reyes Acaquilpan"
//   ]
// }
//
// ==================================================


// ==================================================
// CONFIGURACIÓN
// ==================================================

const POSTALI_BASE_URL =
  "https://postali.app/api/v1/mx";


// ==================================================
// AUXILIAR: LIMPIAR TEXTO
// ==================================================

const limpiarTexto =
  valor => {

    if (
      valor === null ||
      valor === undefined
    ) {
      return "";
    }

    return String(
      valor
    ).trim();

  };


// ==================================================
// AUXILIAR: NORMALIZAR CÓDIGO POSTAL
// ==================================================

const normalizarCodigoPostal =
  valor => {

    return String(
      valor ||
      ""
    )
      .replace(
        /\D/g,
        ""
      )
      .slice(
        0,
        5
      );

  };


// ==================================================
// AUXILIAR: OBTENER COLONIAS ÚNICAS
// ==================================================

const obtenerColoniasUnicas =
  asentamientos => {

    if (
      !Array.isArray(
        asentamientos
      )
    ) {
      return [];
    }


    const colonias =
      asentamientos
        .map(
          item => {

            if (
              typeof item ===
              "string"
            ) {
              return limpiarTexto(
                item
              );
            }


            return limpiarTexto(
              item?.nombre
            );

          }
        )
        .filter(
          Boolean
        );


    return [
      ...new Set(
        colonias
      )
    ].sort(
      (
        a,
        b
      ) =>
        a.localeCompare(
          b,
          "es"
        )
    );

  };


// ==================================================
// AUXILIAR: OBTENER CIUDAD
// ==================================================

const obtenerCiudad =
  asentamientos => {

    if (
      !Array.isArray(
        asentamientos
      )
    ) {
      return "";
    }


    const asentamientoConCiudad =
      asentamientos.find(
        item =>
          limpiarTexto(
            item?.ciudad
          )
      );


    return limpiarTexto(
      asentamientoConCiudad
        ?.ciudad
    );

  };


// ==================================================
// CONSULTAR CÓDIGO POSTAL
//
// GET /api/codigos-postales/:cp
// ==================================================

export const consultarCodigoPostal =
  async (
    req,
    res
  ) => {

    try {

      // ==================================================
      // VALIDAR CP
      // ==================================================

      const codigoPostal =
        normalizarCodigoPostal(
          req.params.cp
        );


      if (
        !/^\d{5}$/.test(
          codigoPostal
        )
      ) {

        return res
          .status(400)
          .json({

            success:
              false,

            message:
              "El código postal debe contener exactamente 5 dígitos.",

            codigo_postal:
              codigoPostal,

            manual:
              true

          });

      }


      // ==================================================
      // URL POSTALI
      // ==================================================

      const url =
        `${POSTALI_BASE_URL}/cp/${codigoPostal}`;


      console.log(
        "📮 Consultando código postal:",
        codigoPostal
      );


      console.log(
        "🌎 Postali:",
        url
      );


      // ==================================================
      // CONSULTAR POSTALI
      // ==================================================

      const respuesta =
        await fetch(
          url,
          {

            method:
              "GET",

            headers: {

              Accept:
                "application/json"

            }

          }
        );


      // ==================================================
      // CP NO ENCONTRADO
      // ==================================================

      if (
        respuesta.status ===
        404
      ) {

        console.log(
          `⚠️ CP ${codigoPostal} no encontrado`
        );


        return res
          .status(404)
          .json({

            success:
              false,

            message:
              "No se encontró información para ese código postal.",

            codigo_postal:
              codigoPostal,

            manual:
              true

          });

      }


      // ==================================================
      // FORMATO INVÁLIDO
      // ==================================================

      if (
        respuesta.status ===
        400
      ) {

        const detalle =
          await respuesta
            .json()
            .catch(
              () => null
            );


        console.error(
          "❌ Postali indicó CP inválido:",
          detalle
        );


        return res
          .status(400)
          .json({

            success:
              false,

            message:
              detalle
                ?.error
                ?.message ||
              "El código postal enviado no es válido.",

            codigo_postal:
              codigoPostal,

            manual:
              true

          });

      }


      // ==================================================
      // LÍMITE TEMPORAL
      // ==================================================

      if (
        respuesta.status ===
        429
      ) {

        console.error(
          "⚠️ Postali respondió 429: demasiadas solicitudes"
        );


        return res
          .status(503)
          .json({

            success:
              false,

            message:
              "El servicio de códigos postales está temporalmente ocupado. Intenta nuevamente.",

            codigo_postal:
              codigoPostal,

            manual:
              true

          });

      }


      // ==================================================
      // OTRO ERROR DEL SERVICIO
      // ==================================================

      if (
        !respuesta.ok
      ) {

        const detalle =
          await respuesta
            .text()
            .catch(
              () => ""
            );


        console.error(
          "❌ Error consultando Postali:",
          respuesta.status,
          detalle
        );


        return res
          .status(502)
          .json({

            success:
              false,

            message:
              "El servicio externo de códigos postales no está disponible en este momento.",

            codigo_postal:
              codigoPostal,

            manual:
              true

          });

      }


      // ==================================================
      // LEER RESPUESTA
      // ==================================================

      const datos =
        await respuesta.json();


      console.log(
        "📦 Respuesta Postali:",
        datos
      );


      // ==================================================
      // VALIDAR RESPUESTA
      // ==================================================

      if (
        !datos ||
        !datos.cp
      ) {

        console.error(
          "❌ Postali respondió sin información válida:",
          datos
        );


        return res
          .status(502)
          .json({

            success:
              false,

            message:
              "El servicio devolvió una respuesta inválida.",

            codigo_postal:
              codigoPostal,

            manual:
              true

          });

      }


      // ==================================================
      // ESTADO
      // ==================================================

      const estado =
        limpiarTexto(
          datos.estado
        );


      // ==================================================
      // MUNICIPIO
      // ==================================================

      const municipio =
        limpiarTexto(
          datos.municipio
        );


      // ==================================================
      // ASENTAMIENTOS / COLONIAS
      // ==================================================

      const colonias =
        obtenerColoniasUnicas(
          datos.asentamientos
        );


      // ==================================================
      // CIUDAD
      //
      // Postali guarda ciudad dentro de cada asentamiento.
      // Puede venir null.
      // ==================================================

      const ciudad =
        obtenerCiudad(
          datos.asentamientos
        );


      // ==================================================
      // LOG
      // ==================================================

      console.log(
        "✅ Código postal encontrado:",
        {
          codigoPostal,
          estado,
          municipio,
          ciudad,
          totalColonias:
            colonias.length
        }
      );


      // ==================================================
      // RESPUESTA PARA REACT
      // ==================================================

      return res.json({

        success:
          true,

        codigo_postal:
          codigoPostal,

        estado,

        municipio,

        ciudad,

        colonias,

        total_colonias:
          colonias.length,

        manual:
          false

      });


    } catch (error) {

      // ==================================================
      // ERROR DE RED / FETCH / SERVIDOR
      // ==================================================

      console.error(
        "❌ Error interno consultando código postal:",
        error
      );


      return res
        .status(500)
        .json({

          success:
            false,

          message:
            "No fue posible consultar el código postal en este momento.",

          manual:
            true,

          error:
            process.env.NODE_ENV ===
            "development"
              ? error.message
              : undefined

        });

    }

  };
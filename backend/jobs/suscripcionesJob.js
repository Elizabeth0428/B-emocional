// ==================================================
// backend/jobs/suscripcionesJob.js
// ==================================================

import pool from "../config/database.js";


// ==================================================
// CONFIGURACIÓN
// ==================================================

const DIAS_GRACIA = 3;


// Revisar cada hora
const INTERVALO_REVISION =
  60 * 60 * 1000;


// ==================================================
// REVISAR SUSCRIPCIONES VENCIDAS
// ==================================================

export async function revisarSuscripcionesVencidas() {

  try {

    const [
      resultado
    ] =
      await pool.query(
        `
          UPDATE suscripciones

          SET
            estado = 'vencida',

            fecha_fin =
              CASE

                WHEN fecha_fin IS NULL
                THEN CURDATE()

                ELSE fecha_fin

              END

          WHERE

            estado IN (
              'activa',
              'prueba'
            )

            AND proxima_renovacion
                IS NOT NULL

            AND CURDATE() >
                DATE_ADD(
                  proxima_renovacion,
                  INTERVAL ? DAY
                )
        `,
        [
          DIAS_GRACIA
        ]
      );


    const total =
      Number(
        resultado?.affectedRows || 0
      );


    if (
      total > 0
    ) {

      console.log(
        `💳 Suscripciones vencidas automáticamente: ${total}`
      );

    }

    else {

      console.log(
        "💳 Revisión automática de suscripciones: sin vencimientos"
      );

    }


    return {

      success: true,

      dias_gracia:
        DIAS_GRACIA,

      suscripciones_vencidas:
        total

    };


  }

  catch (
    error
  ) {

    console.error(
      "❌ Error revisando suscripciones automáticamente:",
      error
    );


    return {

      success: false,

      error:
        error.message

    };

  }

}


// ==================================================
// INICIAR REVISIÓN AUTOMÁTICA
// ==================================================

export function iniciarRevisionSuscripciones() {

  console.log(
    "✅ Revisión automática de suscripciones iniciada"
  );


  // ==================================================
  // PRIMERA REVISIÓN AL INICIAR EL SERVIDOR
  // ==================================================

  revisarSuscripcionesVencidas()
    .catch(
      error => {

        console.error(
          "❌ Error en revisión inicial de suscripciones:",
          error
        );

      }
    );


  // ==================================================
  // REVISIÓN CADA HORA
  // ==================================================

  const intervalo =
    setInterval(
      () => {

        revisarSuscripcionesVencidas()
          .catch(
            error => {

              console.error(
                "❌ Error en revisión periódica de suscripciones:",
                error
              );

            }
          );

      },
      INTERVALO_REVISION
    );


  // ==================================================
  // NO MANTENER NODE ABIERTO SOLO POR EL INTERVALO
  // ==================================================

  if (
    typeof intervalo.unref ===
    "function"
  ) {

    intervalo.unref();

  }


  return intervalo;

}
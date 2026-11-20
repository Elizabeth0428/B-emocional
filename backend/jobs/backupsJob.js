// ==================================================
// backend/jobs/backupsJob.js
// ==================================================

import {
  ejecutarBackupAutomatico,
  existeBackupDeHoy
} from "../svc/backupService.js";


// ==================================================
// HORA DEL RESPALDO AUTOMÁTICO
// ==================================================

const HORA_BACKUP =
  Number(
    process.env.BACKUP_HOUR ||
    2
  );


// ==================================================
// CALCULAR PRÓXIMA EJECUCIÓN
// ==================================================

function milisegundosHastaProximoBackup() {

  const ahora =
    new Date();


  const proximo =
    new Date();


  proximo.setHours(
    HORA_BACKUP,
    0,
    0,
    0
  );


  /*
    Si ya pasó la hora de hoy,
    programamos mañana.
  */

  if (
    proximo <=
    ahora
  ) {

    proximo.setDate(
      proximo.getDate() +
      1
    );

  }


  return (
    proximo.getTime() -
    ahora.getTime()
  );

}


// ==================================================
// EJECUTAR RESPALDO
// ==================================================

async function ejecutar() {

  console.log(
    "🗄️ Ejecutando respaldo automático diario..."
  );


  const resultado =
    await ejecutarBackupAutomatico();


  if (
    resultado.success
  ) {

    console.log(
      "✅ Respaldo automático diario completado"
    );

  }

  else {

    console.error(
      "❌ El respaldo automático diario falló:",
      resultado.error
    );

  }

}


// ==================================================
// INICIAR SISTEMA AUTOMÁTICO
// ==================================================

export async function iniciarBackupsAutomaticos() {

  console.log(
    `✅ Sistema automático de respaldos iniciado (${HORA_BACKUP}:00)`
  );


  /*
    Si el servidor inicia después de las 2 AM
    y todavía no existe respaldo de hoy,
    hacemos uno inmediatamente.

    Así no perdemos el respaldo del día
    porque Node estaba apagado a las 2 AM.
  */

  const ahora =
    new Date();


  if (
    ahora.getHours() >=
      HORA_BACKUP &&
    !existeBackupDeHoy()
  ) {

    console.log(
      "🗄️ No existe respaldo de hoy. Generando respaldo inicial..."
    );


    ejecutar().catch(
      error => {

        console.error(
          "❌ Error en respaldo inicial:",
          error
        );

      }
    );

  }


  const espera =
    milisegundosHastaProximoBackup();


  const timerInicial =
    setTimeout(
      () => {

        ejecutar();


        /*
          Después del primer respaldo programado,
          ejecutar cada 24 horas.
        */

        const intervalo =
          setInterval(
            ejecutar,
            24 *
            60 *
            60 *
            1000
          );


        if (
          typeof intervalo.unref ===
          "function"
        ) {

          intervalo.unref();

        }

      },
      espera
    );


  if (
    typeof timerInicial.unref ===
    "function"
  ) {

    timerInicial.unref();

  }


  return timerInicial;

}
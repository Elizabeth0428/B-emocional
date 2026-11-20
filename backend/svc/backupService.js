// ==================================================
// backend/svc/backupService.js
// ==================================================

import fs from "fs";
import path from "path";
import {
  spawn
} from "child_process";
import {
  fileURLToPath
} from "url";


// ==================================================
// RUTAS
// ==================================================

const __filename =
  fileURLToPath(
    import.meta.url
  );

const __dirname =
  path.dirname(
    __filename
  );


// backend/backups
const BACKUP_DIR =
  path.resolve(
    __dirname,
    "../backups"
  );


// ==================================================
// CONFIGURACIÓN
// ==================================================

const DIAS_RETENCION =
  7;


// ==================================================
// ASEGURAR CARPETA
// ==================================================

export function asegurarDirectorioBackups() {

  if (
    !fs.existsSync(
      BACKUP_DIR
    )
  ) {

    fs.mkdirSync(
      BACKUP_DIR,
      {
        recursive: true
      }
    );

    console.log(
      "📁 Carpeta de respaldos creada:",
      BACKUP_DIR
    );

  }

}


// ==================================================
// FECHA PARA NOMBRE DE ARCHIVO
// ==================================================

function obtenerFechaArchivo() {

  const ahora =
    new Date();


  const año =
    ahora
      .getFullYear();


  const mes =
    String(
      ahora.getMonth() + 1
    )
      .padStart(
        2,
        "0"
      );


  const dia =
    String(
      ahora.getDate()
    )
      .padStart(
        2,
        "0"
      );


  const hora =
    String(
      ahora.getHours()
    )
      .padStart(
        2,
        "0"
      );


  const minuto =
    String(
      ahora.getMinutes()
    )
      .padStart(
        2,
        "0"
      );


  const segundo =
    String(
      ahora.getSeconds()
    )
      .padStart(
        2,
        "0"
      );


  return (
    `${año}-${mes}-${dia}_${hora}-${minuto}-${segundo}`
  );

}


// ==================================================
// CONFIGURACIÓN MYSQL
// ==================================================

function obtenerConfiguracionBD() {

  const host =
    process.env.MYSQL_HOST ||
    "localhost";

  const port =
    process.env.MYSQL_PORT ||
    "3306";

  const user =
    process.env.MYSQL_USER ||
    "root";

  const password =
    process.env.MYSQL_PASSWORD ||
    "";

  const database =
    process.env.MYSQL_DATABASE;


  if (
    !database
  ) {

    throw new Error(
      "No se encontró MYSQL_DATABASE en el archivo .env"
    );

  }


  return {
    host,
    port,
    user,
    password,
    database
  };

}

// ==================================================
// UBICACIÓN MYSQLDUMP
// ==================================================

function obtenerComandoMysqlDump() {

  /*
    Puedes definirlo en .env:

    MYSQLDUMP_PATH=C:\\xampp\\mysql\\bin\\mysqldump.exe

    Si no se define, intenta ejecutar:

    mysqldump

    siempre que esté agregado al PATH del sistema.
  */

  return (
    process.env.MYSQLDUMP_PATH ||
    "mysqldump"
  );

}


// ==================================================
// CREAR RESPALDO
// ==================================================

export async function crearBackupBD({
  origen = "manual"
} = {}) {

  asegurarDirectorioBackups();


  const {
    host,
    port,
    user,
    password,
    database
  } =
    obtenerConfiguracionBD();


  const fecha =
    obtenerFechaArchivo();


  const nombreArchivo =
    `backup_${database}_${fecha}.sql`;


  const rutaArchivo =
    path.join(
      BACKUP_DIR,
      nombreArchivo
    );


  const comando =
    obtenerComandoMysqlDump();


  console.log(
    `🗄️ Iniciando respaldo ${origen}:`,
    nombreArchivo
  );


  return new Promise(
    (
      resolve,
      reject
    ) => {

      const argumentos = [

        `--host=${host}`,

        `--port=${port}`,

        `--user=${user}`,

        "--single-transaction",

        "--skip-lock-tables",

        "--routines",

        "--triggers",

        "--events",

        "--default-character-set=utf8mb4",

        database

      ];


      /*
        No mandamos --password por la línea
        de comandos para evitar exponerlo.

        MYSQL_PWD solo se entrega al proceso
        hijo de mysqldump.
      */

      const proceso =
        spawn(
          comando,
          argumentos,
          {
            env: {
              ...process.env,

              MYSQL_PWD:
                password
            },

            windowsHide:
              true
          }
        );


      const archivo =
        fs.createWriteStream(
          rutaArchivo
        );


      let errorDump =
        "";


      proceso.stdout.pipe(
        archivo
      );


      proceso.stderr.on(
        "data",
        data => {

          errorDump +=
            data.toString();

        }
      );


      proceso.on(
        "error",
        error => {

          archivo.close();


          try {

            if (
              fs.existsSync(
                rutaArchivo
              )
            ) {

              fs.unlinkSync(
                rutaArchivo
              );

            }

          }

          catch {}


          console.error(
            "❌ Error ejecutando mysqldump:",
            error
          );


          reject(
            new Error(
              `No se pudo ejecutar mysqldump. Verifica MYSQLDUMP_PATH. ${error.message}`
            )
          );

        }
      );


      proceso.on(
        "close",
        codigo => {

          archivo.end();


          if (
            codigo !== 0
          ) {

            try {

              if (
                fs.existsSync(
                  rutaArchivo
                )
              ) {

                fs.unlinkSync(
                  rutaArchivo
                );

              }

            }

            catch {}


            console.error(
              "❌ mysqldump terminó con error:",
              errorDump
            );


            return reject(
              new Error(
                errorDump ||
                `mysqldump terminó con código ${codigo}`
              )
            );

          }


          try {

            const stats =
              fs.statSync(
                rutaArchivo
              );


            /*
              Evitamos aceptar un archivo vacío.
            */

            if (
              stats.size <
              100
            ) {

              fs.unlinkSync(
                rutaArchivo
              );


              return reject(
                new Error(
                  "El respaldo generado está vacío o incompleto."
                )
              );

            }


            console.log(
              "✅ Respaldo creado:",
              nombreArchivo
            );


            console.log(
              `📦 Tamaño: ${(stats.size / 1024 / 1024).toFixed(2)} MB`
            );


            resolve({
              success: true,

              nombre:
                nombreArchivo,

              ruta:
                rutaArchivo,

              tamaño:
                stats.size,

              fecha:
                stats.mtime,

              origen
            });

          }

          catch (
            error
          ) {

            reject(
              error
            );

          }

        }
      );

    }
  );

}


// ==================================================
// LISTAR RESPALDOS
// ==================================================

export function listarBackups() {

  asegurarDirectorioBackups();


  const archivos =
    fs
      .readdirSync(
        BACKUP_DIR
      )
      .filter(
        nombre =>
          nombre
            .toLowerCase()
            .endsWith(
              ".sql"
            )
      )
      .map(
        nombre => {

          const ruta =
            path.join(
              BACKUP_DIR,
              nombre
            );


          const stats =
            fs.statSync(
              ruta
            );


          return {

            nombre,

            tamaño:
              stats.size,

            tamaño_mb:
              Number(
                (
                  stats.size /
                  1024 /
                  1024
                ).toFixed(
                  2
                )
              ),

            fecha:
              stats.mtime

          };

        }
      )
      .sort(
        (
          a,
          b
        ) =>
          new Date(
            b.fecha
          ) -
          new Date(
            a.fecha
          )
      );


  return archivos;

}


// ==================================================
// ELIMINAR RESPALDOS ANTIGUOS
// ==================================================

export function limpiarBackupsAntiguos(
  diasRetencion =
    DIAS_RETENCION
) {

  asegurarDirectorioBackups();


  const ahora =
    Date.now();


  const limite =
    diasRetencion *
    24 *
    60 *
    60 *
    1000;


  const archivos =
    fs.readdirSync(
      BACKUP_DIR
    );


  let eliminados =
    0;


  for (
    const nombre
    of archivos
  ) {

    if (
      !nombre
        .toLowerCase()
        .endsWith(
          ".sql"
        )
    ) {

      continue;

    }


    const ruta =
      path.join(
        BACKUP_DIR,
        nombre
      );


    const stats =
      fs.statSync(
        ruta
      );


    const antiguedad =
      ahora -
      stats.mtimeMs;


    if (
      antiguedad >
      limite
    ) {

      try {

        fs.unlinkSync(
          ruta
        );


        eliminados++;


        console.log(
          "🗑️ Respaldo antiguo eliminado:",
          nombre
        );

      }

      catch (
        error
      ) {

        console.error(
          "❌ No se pudo eliminar respaldo:",
          nombre,
          error.message
        );

      }

    }

  }


  return {
    success: true,
    dias_retencion:
      diasRetencion,
    eliminados
  };

}


// ==================================================
// OBTENER RUTA SEGURA DE RESPALDO
// ==================================================

export function obtenerRutaBackup(
  nombre
) {

  if (
    !nombre ||
    typeof nombre !==
      "string"
  ) {

    return null;

  }


  /*
    Evita:

    ../../archivo
    carpetas externas
    path traversal
  */

  const nombreSeguro =
    path.basename(
      nombre
    );


  if (
    nombreSeguro !==
    nombre
  ) {

    return null;

  }


  if (
    !nombreSeguro
      .toLowerCase()
      .endsWith(
        ".sql"
      )
  ) {

    return null;

  }


  const ruta =
    path.join(
      BACKUP_DIR,
      nombreSeguro
    );


  if (
    !fs.existsSync(
      ruta
    )
  ) {

    return null;

  }


  return ruta;

}


// ==================================================
// SABER SI YA EXISTE RESPALDO HOY
// ==================================================

export function existeBackupDeHoy() {

  const backups =
    listarBackups();


  if (
    backups.length ===
    0
  ) {

    return false;

  }


  const hoy =
    new Date();


  return backups.some(
    backup => {

      const fecha =
        new Date(
          backup.fecha
        );


      return (
        fecha.getFullYear() ===
          hoy.getFullYear() &&

        fecha.getMonth() ===
          hoy.getMonth() &&

        fecha.getDate() ===
          hoy.getDate()
      );

    }
  );

}


// ==================================================
// EJECUTAR CICLO COMPLETO
// ==================================================

export async function ejecutarBackupAutomatico() {

  try {

    /*
      Primero creamos el respaldo.

      Solo si se creó correctamente,
      limpiamos los antiguos.
    */

    const backup =
      await crearBackupBD({
        origen:
          "automatico"
      });


    const limpieza =
      limpiarBackupsAntiguos(
        DIAS_RETENCION
      );


    return {
      success: true,
      backup,
      limpieza
    };

  }

  catch (
    error
  ) {

    console.error(
      "❌ Error en respaldo automático:",
      error
    );


    /*
      IMPORTANTE:
      Si el respaldo falla, NO se limpian
      los respaldos anteriores.
    */

    return {
      success: false,
      error:
        error.message
    };

  }

}


// ==================================================
// EXPORTAR CONFIGURACIÓN
// ==================================================

export const backupConfig = {

  directorio:
    BACKUP_DIR,

  diasRetencion:
    DIAS_RETENCION

};
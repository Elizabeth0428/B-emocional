// utils/backup.js
import { exec } from "child_process";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 📂 Carpeta de backups
export const backupDir = process.env.BACKUP_DIR
  ? path.isAbsolute(process.env.BACKUP_DIR)
    ? process.env.BACKUP_DIR
    : path.join(process.cwd(), process.env.BACKUP_DIR)
  : path.join(__dirname, "../backup");

// 🛠 Crear respaldo .sql
export async function dumpDatabase({ host, user, password, database }) {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backupFile = path.join(backupDir, `${database}_${timestamp}.sql`);

    const mysqldumpPath = process.env.MYSQLDUMP_PATH || "mysqldump";

    // Sugerencia: --add-drop-table para que el restore reemplace tablas
    const command = `${mysqldumpPath} -h ${host} -u ${user} ${
      password ? `-p${password}` : ""
    } --add-drop-table ${database} > "${backupFile}"`;

    console.log("⏳ Ejecutando:", command);
    exec(command, { shell: true }, (error, stdout, stderr) => {
      if (error) {
        console.error("❌ mysqldump error:", stderr || error.message);
        return reject(new Error(stderr || error.message));
      }
      console.log("✅ Backup generado:", backupFile);
      resolve(backupFile);
    });
  });
}

// 📥 Restaurar BD desde un .sql
export async function restoreDatabase({ host, user, password, database, sqlFilePath }) {
  return new Promise((resolve, reject) => {
    if (!sqlFilePath) return reject(new Error("No se indicó ruta del archivo .sql"));

    const exists = fs.existsSync(sqlFilePath);
    if (!exists) return reject(new Error(`No existe el archivo: ${sqlFilePath}`));

    const mysqlPath = process.env.MYSQL_CLI_PATH || "mysql";
    const command = `${mysqlPath} -h ${host} -u ${user} ${
      password ? `-p${password}` : ""
    } ${database} < "${sqlFilePath}"`;

    console.log("⏳ Restaurando con:", command);
    exec(command, { shell: true }, (error, stdout, stderr) => {
      if (error) {
        console.error("❌ mysql restore error:", stderr || error.message);
        return reject(new Error(stderr || error.message));
      }
      console.log("✅ Restauración completa desde:", sqlFilePath);
      resolve(true);
    });
  });
}

// 📚 Listar archivos .sql disponibles en la carpeta de backups
export function listBackups() {
  if (!fs.existsSync(backupDir)) return [];
  return fs
    .readdirSync(backupDir)
    .filter((f) => f.toLowerCase().endsWith(".sql"))
    .map((f) => ({
      file: f,
      fullPath: path.join(backupDir, f),
    }));
}

// routes/backup.routes.js
import { Router } from "express";
import {
  dumpDatabase,
  restoreDatabase,
  listBackups,
  backupDir,
} from "../utils/backup.js";
import path from "path";
import fs from "fs";

const router = Router();

/** ✅ 1. Ruta simple de prueba */
router.get("/backup", (req, res) => {
  res.json({
    ok: true,
    message: "✅ Ruta de backup activa (listo para generar/recuperar)",
  });
});

/** ✅ 2. Crear backup */
router.get("/backup/create", async (req, res) => {
  try {
    const file = await dumpDatabase({
      host: process.env.MYSQL_HOST,
      user: process.env.MYSQL_USER,
      password: process.env.MYSQL_PASSWORD,
      database: process.env.MYSQL_DATABASE,
    });
    res.json({ ok: true, message: "✅ Backup generado correctamente", file });
  } catch (err) {
    res
      .status(500)
      .json({
        ok: false,
        message: "❌ Error al generar backup",
        error: err.message,
      });
  }
});

/** ✅ 3. Listar archivos .sql disponibles */
router.get("/backup/list", (req, res) => {
  try {
    const backups = listBackups();
    res.json({ ok: true, backups, total: backups.length });
  } catch (err) {
    res
      .status(500)
      .json({
        ok: false,
        message: "❌ Error al listar backups",
        error: err.message,
      });
  }
});

/** ✅ 4. Restaurar base desde un archivo enviado en JSON */
router.post("/backup/restore", async (req, res) => {
  const { file } = req.body;

  if (!file) {
    return res
      .status(400)
      .json({
        ok: false,
        message: "⚠️ Debes enviar el nombre del archivo .sql",
      });
  }

  try {
    await restoreDatabase({
      host: process.env.MYSQL_HOST,
      user: process.env.MYSQL_USER,
      password: process.env.MYSQL_PASSWORD,
      database: process.env.MYSQL_DATABASE,
      sqlFilePath: path.join(backupDir, file),
    });
    res.json({ ok: true, message: `✅ Base restaurada desde ${file}` });
  } catch (err) {
    res
      .status(500)
      .json({
        ok: false,
        message: "❌ Error al restaurar base de datos",
        error: err.message,
      });
  }
});

/** ✅ 5. Descargar archivo .sql */
router.get("/backup/download/:file", (req, res) => {
  const fileName = req.params.file;
  const filePath = path.join(backupDir, fileName);

  if (!fs.existsSync(filePath)) {
    return res
      .status(404)
      .json({ ok: false, message: "❌ Archivo no encontrado" });
  }

  res.download(filePath, fileName, (err) => {
    if (err) {
      console.error("Error al descargar:", err);
      res.status(500).send("⚠ Error al descargar archivo");
    }
  });
});

export default router;

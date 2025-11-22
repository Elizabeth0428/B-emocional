import "dotenv/config";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";

const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  port: process.env.MYSQL_PORT,
});

async function migrate() {
  const [rows] = await pool.query("SELECT id_psicologo, contrasena FROM psicologos");

  for (const row of rows) {
    if (row.contrasena.startsWith("$2b$")) continue; // ya es hash

    const hashed = await bcrypt.hash(row.contrasena, 10);
    await pool.query("UPDATE psicologos SET contrasena = ? WHERE id_psicologo = ?", [
      hashed,
      row.id_psicologo,
    ]);
    console.log(`🔐 Migrado id=${row.id_psicologo}`);
  }
  process.exit(0);
}

migrate();

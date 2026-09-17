import mysql from 'mysql2/promise';
import 'dotenv/config'; // Asegura que las variables de entorno se carguen

export const db = mysql.createPool({
  host: process.env.MYSQL_HOST || 'localhost',
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || '',
  database: process.env.MYSQL_DATABASE || 'pred_diag_emocional',
  port: process.env.MYSQL_PORT || 3306
});
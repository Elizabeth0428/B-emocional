// backend/db.js (crea la conexión al servidor MySQL) MySQL (localhost o remoto)

//El archivo db.js crea la conexión con la base de datos usando las variables del archivo .env.


//import mysql from "mysql2/promise";

//export const db = mysql.createPool({
  //host: process.env.MYSQL_HOST || "localhost",
  //user: process.env.MYSQL_USER || "root",
  //password: process.env.MYSQL_PASSWORD || "",
  //database: process.env.MYSQL_DATABASE || "pred_diag_emocional",
//});

import mysql from "mysql2/promise";
import dotenv from "dotenv";
dotenv.config();

//export const db = await mysql.createPool({
  //host: process.env.DB_HOST,
  //user: process.env.DB_USER,
  //password: process.env.DB_PASSWORD,
  //database: process.env.DB_NAME,
  //port: process.env.DB_PORT,
  //waitForConnections: true,
  //connectionLimit: 10,
  //queueLimit: 0,
  //ssl: {
    //rejectUnauthorized: false
  //}
//});
export const db = await mysql.createPool({
  host: shortline.proxy.rlwy.net,
  user: root,
  password: pmyevOYtoEIhVmpsRzvpyRyLDbtHuhhI,
  database: railway,
  port: 43845,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: {
    rejectUnauthorized: false
  }
});



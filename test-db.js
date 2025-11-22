//prueba de conexión.
//verifica que la base de datos está conectanda

import { db } from './db.js';

async function testConnection() {
  try {
    const [rows] = await db.query('SELECT 1+1 AS result');
    console.log('✅ Conexión exitosa:', rows);
  } catch (err) {
    console.error('❌ Error en conexión:', err);
  }
}

testConnection();


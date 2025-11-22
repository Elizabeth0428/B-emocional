import { db } from './db.js';

// ✅ Crear paciente
export async function createPatient(id_psicologo, nombre, edad, antecedentes, contacto) {
  const [result] = await db.query(
    `INSERT INTO pacientes (id_psicologo, nombre, edad, antecedentes, contacto) VALUES (?, ?, ?, ?, ?)`,
    [id_psicologo, nombre, edad, antecedentes, contacto]
  );
  return result.insertId;
}

// ✅ Listar todos los pacientes de un psicólogo
export async function listPatients(id_psicologo) {
  const [rows] = await db.query(
    `SELECT * FROM pacientes WHERE id_psicologo = ?`,
    [id_psicologo]
  );
  return rows;
}

// ✅ Buscar paciente por ID
export async function getPatientById(id_paciente) {
  const [rows] = await db.query(
    `SELECT * FROM pacientes WHERE id_paciente = ?`,
    [id_paciente]
  );
  return rows[0];
}

// ✅ Actualizar paciente
export async function updatePatient(id_paciente, nombre, edad, antecedentes, contacto) {
  const [result] = await db.query(
    `UPDATE pacientes SET nombre = ?, edad = ?, antecedentes = ?, contacto = ? WHERE id_paciente = ?`,
    [nombre, edad, antecedentes, contacto, id_paciente]
  );
  return result.affectedRows;
}

// ✅ Eliminar paciente (opcional)
export async function deletePatient(id_paciente) {
  const [result] = await db.query(
    `DELETE FROM pacientes WHERE id_paciente = ?`,
    [id_paciente]
  );
  return result.affectedRows;
}

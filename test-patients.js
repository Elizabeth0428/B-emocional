import { createPatient, listPatients, getPatientById, updatePatient } from './patients.js';

async function test() {
  // 1️⃣ Crear paciente
  const newId = await createPatient(1, 'Paciente Demo', 28, 'Sin antecedentes', 'demo@ejemplo.com');
  console.log('Nuevo paciente ID:', newId);

  // 2️⃣ Listar pacientes del psicólogo ID=1
  const pacientes = await listPatients(1);
  console.log('Lista de pacientes:', pacientes);

  // 3️⃣ Buscar paciente por ID
  const paciente = await getPatientById(newId);
  console.log('Paciente encontrado:', paciente);

  // 4️⃣ Actualizar paciente
  const actualizado = await updatePatient(newId, 'Paciente Demo Mod', 29, 'Leve ansiedad', 'demo@ejemplo.com');
  console.log('Filas actualizadas:', actualizado);

  // 5️⃣ Listar nuevamente
  const pacientesActualizados = await listPatients(1);
  console.log('Lista actualizada:', pacientesActualizados);
}

test();

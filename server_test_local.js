import express from 'express';
import cors from 'cors';
import { listPatients, createPatient } from './patients.js';

const app = express();

// Middleware
app.use(cors());           // Permite que Vite pueda hacer requests
app.use(express.json());   // Para recibir JSON en POST

// Endpoints CRUD de pacientes
app.get('/pacientes', async (req, res) => {
  const pacientes = await listPatients(1); // psicólogo ID=1
  res.json(pacientes);
});

app.post('/pacientes', async (req, res) => {
  const { nombre, edad, antecedentes, contacto } = req.body;
  const id = await createPatient(1, nombre, edad, antecedentes, contacto);
  res.json({ id });
});

// Servidor escuchando
app.listen(3000, () => console.log('Servidor backend corriendo en http://localhost:3000'));

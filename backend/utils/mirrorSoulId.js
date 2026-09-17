// ==================================================
// backend/utils/mirrorSoulId.js
// ==================================================

import pool from "../config/database.js";


// ==================================================
// GENERAR ID MIRRORSOUL GLOBAL
//
// Formato:
// MS-2026-18-FE-001
//
// MS   = MirrorSoul
// 2026 = año de creación
// 18   = edad
// FE   = femenino
// 001  = consecutivo GLOBAL
//
// Este generador SOLO debe utilizarse para:
//
// - Prospectos
// - Pacientes
// - Empleados
// - Estudiantes
//
// NO utilizar para:
//
// - Psicólogos
// - Administradores
// ==================================================

export async function generarIdMirror(
  edad,
  sexo
) {

  // ==================================================
  // AÑO ACTUAL
  // ==================================================

  const añoActual =
    new Date().getFullYear();


  // ==================================================
  // NORMALIZAR EDAD
  // ==================================================

  const edadNumero =
    Number(edad);


  const edadNormalizada =
    Number.isFinite(edadNumero) &&
    edadNumero >= 0
      ? Math.floor(edadNumero)
      : 0;


  // ==================================================
  // NORMALIZAR SEXO
  // ==================================================

  const sexoNormalizado =
    String(sexo || "")
      .trim()
      .toUpperCase();


  // ==================================================
  // CONVERTIR SEXO A CÓDIGO
  // ==================================================

  let codigoSexo = "XX";


  if (sexoNormalizado === "F") {

    codigoSexo = "FE";

  } else if (
    sexoNormalizado === "M"
  ) {

    codigoSexo = "MA";

  }


  // ==================================================
  // OBTENER CONSECUTIVO GLOBAL
  // ==================================================

  const [resultado] =
    await pool.query(
      `
      INSERT INTO mirror_consecutivos
      VALUES ()
      `
    );


  const consecutivo =
    resultado.insertId;


  // ==================================================
  // FORMATEAR CONSECUTIVO
  // ==================================================

  const numero =
    String(consecutivo)
      .padStart(3, "0");


  // ==================================================
  // CONSTRUIR ID
  // ==================================================

  const idMirror =
    `MS-${añoActual}-${edadNormalizada}-${codigoSexo}-${numero}`;


  return idMirror;

}
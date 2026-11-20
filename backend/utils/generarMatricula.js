// ==================================================
// backend/utils/generarMatricula.js
// ==================================================

import pool
from "../config/database.js";


// ==================================================
// PREFIJO SEGÚN ÁREA
// ==================================================

function obtenerPrefijoArea(
  area
) {

  const areaNormalizada =
    String(
      area || ""
    )
      .trim()
      .toLowerCase();


  const prefijos = {

    clinica:
      "CLI",

    rh:
      "RH",

    educativo:
      "EDU"

  };


  return (
    prefijos[
      areaNormalizada
    ] ||
    null
  );

}


// ==================================================
// GENERAR MATRÍCULA
// ==================================================

export async function generarMatricula({
  idOrganizacion,
  area,
  connection = pool
}) {

  const idOrg =
    Number(
      idOrganizacion
    );


  if (
    !Number.isInteger(
      idOrg
    ) ||
    idOrg <= 0
  ) {

    throw new Error(
      "No se pudo generar matrícula: organización inválida."
    );

  }


  const prefijo =
    obtenerPrefijoArea(
      area
    );


  if (
    !prefijo
  ) {

    throw new Error(
      `No se pudo generar matrícula: área inválida (${area}).`
    );

  }


  const organizacion =
    String(
      idOrg
    )
      .padStart(
        3,
        "0"
      );


  const prefijoBase =
    `MS-${prefijo}-${organizacion}-`;


  /*
    Buscamos las matrículas existentes
    de esta organización y área.

    Ejemplo:
    MS-CLI-001-0001
    MS-CLI-001-0002
  */

  const [
    rows
  ] =
    await connection.query(
      `
        SELECT
          matricula

        FROM usuarios

        WHERE
          id_organizacion = ?
          AND matricula LIKE ?

        ORDER BY
          matricula DESC

        LIMIT 1
      `,
      [
        idOrg,
        `${prefijoBase}%`
      ]
    );


  let siguiente =
    1;


  if (
    rows.length >
    0 &&
    rows[0].matricula
  ) {

    const ultimaMatricula =
      String(
        rows[0].matricula
      );


    const partes =
      ultimaMatricula
        .split(
          "-"
        );


    const consecutivoActual =
      Number(
        partes[
          partes.length - 1
        ]
      );


    if (
      Number.isInteger(
        consecutivoActual
      )
    ) {

      siguiente =
        consecutivoActual +
        1;

    }

  }


  const consecutivo =
    String(
      siguiente
    )
      .padStart(
        4,
        "0"
      );


  const matricula =
    `${prefijoBase}${consecutivo}`;


  /*
    Validación extra por seguridad.
  */

  const [
    duplicados
  ] =
    await connection.query(
      `
        SELECT
          id_usuario

        FROM usuarios

        WHERE matricula = ?

        LIMIT 1
      `,
      [
        matricula
      ]
    );


  if (
    duplicados.length >
    0
  ) {

    throw new Error(
      "No se pudo generar una matrícula única."
    );

  }


  return matricula;

}


export default generarMatricula;
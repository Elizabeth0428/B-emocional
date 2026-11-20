// ==================================================
// REGISTRO CENTRAL DE MOTORES DE EVALUACIÓN
//
// IMPORTANTE:
// - pruebaEmpleadoController.js solo llama a este registro.
// - Las nuevas pruebas se agregan aquí.
// - Cada prueba conserva su cálculo en su propio archivo.
// - La IA NO se genera aquí.
// ==================================================

import {
  gad7
} from "./gad7.js";


import {
  who5
} from "./who5.js";


// ==================================================
// MOTORES REGISTRADOS
// ==================================================

const evaluaciones = [

  gad7,

  who5

];


// ==================================================
// BUSCAR MOTOR
// ==================================================

export const buscarEvaluacion =
  habilitacion => {

    if (
      !habilitacion
    ) {

      return null;

    }


    const evaluacion =
      evaluaciones.find(
        item => {

          try {

            return (
              typeof item?.coincide ===
                "function" &&

              item.coincide(
                habilitacion
              )
            );

          } catch (error) {

            console.error(
              `❌ Error identificando motor ${item?.codigo || "desconocido"}:`,
              error
            );


            return false;

          }

        }
      );


    return (
      evaluacion ||
      null
    );

  };


// ==================================================
// SABER SI TIENE MOTOR
// ==================================================

export const tieneMotorEvaluacion =
  habilitacion => {

    return Boolean(
      buscarEvaluacion(
        habilitacion
      )
    );

  };


// ==================================================
// LISTAR MOTORES
// ==================================================

export const listarMotoresEvaluacion =
  () => {

    return evaluaciones.map(
      item => ({

        codigo:
          item?.codigo ||
          "SIN-CODIGO"

      })
    );

  };
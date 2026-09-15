import express from "express";

import {
  generarAnalisisIA,
  generarAnalisisSesion
} from "../controllers/iaController.js";


const router = express.Router();


router.get("/test", (req, res) => {

  res.json({
    ok: true,
    mensaje: "Ruta IA funcionando"
  });

});


router.post(
  "/analizar",
  generarAnalisisIA
);


router.post(
  "/analisis-sesion",
  generarAnalisisSesion
);


export default router;
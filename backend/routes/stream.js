import express from "express";

import {
  transmitirVideo
} from "../controllers/streamController.js";


const router = express.Router();


/* ==================================================
   Streaming de videos
================================================== */

router.get(
  "/videos/:filename",
  transmitirVideo
);


export default router;
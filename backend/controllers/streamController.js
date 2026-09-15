import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";


/* ==================================================
   __dirname para ES Modules
================================================== */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


/* ==================================================
   Streaming de videos
================================================== */

export function transmitirVideo(req, res) {

  const filePath = path.join(
    __dirname,
    "../uploads/videos",
    req.params.filename
  );


  fs.stat(
    filePath,
    (err, stats) => {

      /* ==============================================
         Validar archivo
      ============================================== */

      if (
        err ||
        !stats.isFile()
      ) {

        return res
          .status(404)
          .send("Archivo no encontrado");

      }


      const range = req.headers.range;


      /* ==============================================
         Sin Range
      ============================================== */

      if (!range) {

        res.writeHead(
          200,
          {
            "Content-Length": stats.size,
            "Content-Type": "video/webm"
          }
        );


        return fs
          .createReadStream(filePath)
          .pipe(res);

      }


      /* ==============================================
         Streaming por partes
      ============================================== */

      const videoSize = stats.size;

      const CHUNK_SIZE = 1 * 1e6;


      const start = Number(
        range.replace(/\D/g, "")
      );


      const end = Math.min(
        start + CHUNK_SIZE,
        videoSize - 1
      );


      const contentLength =
        end - start + 1;


      res.writeHead(
        206,
        {

          "Content-Range":
            `bytes ${start}-${end}/${videoSize}`,

          "Accept-Ranges":
            "bytes",

          "Content-Length":
            contentLength,

          "Content-Type":
            "video/webm"

        }
      );


      fs
        .createReadStream(
          filePath,
          {
            start,
            end
          }
        )
        .pipe(res);

    }
  );

}
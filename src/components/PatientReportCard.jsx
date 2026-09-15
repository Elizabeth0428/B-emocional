// src/components/PatientReportCard.jsx
import React from "react";

export default function PatientReportCard({ reporte }) {
  if (!reporte) {
    return (
      <div className="border p-4 rounded-lg shadow-sm mb-4 bg-gray-100 text-gray-600">
        ⚠️ No hay datos disponibles del reporte.
      </div>
    );
  }

  // 🔹 Normalizar fecha
  let fechaStr = "No disponible";
  if (reporte.fecha_reporte) {
    try {
      fechaStr = new Date(reporte.fecha_reporte).toLocaleString("es-MX");
    } catch (e) {
      fechaStr = "Formato de fecha inválido";
    }
  } else if (reporte.fecha_aplicacion) {
    try {
      fechaStr = new Date(reporte.fecha_aplicacion).toLocaleString("es-MX");
    } catch (e) {
      fechaStr = "Formato de fecha inválido";
    }
  }

  return (
    <div className="border p-4 rounded-lg shadow-sm mb-4 bg-white">
      <h3 className="text-lg font-bold text-blue-700 mb-2">
        🧑‍⚕️ Reporte / Resultado
      </h3>

      {/* Si viene de resultados_prueba */}
      {reporte.nombre_prueba && (
        <p>
          <strong>Prueba:</strong> {reporte.nombre_prueba}
        </p>
      )}
      {reporte.puntaje_total !== undefined && (
        <p>
          <strong>Puntaje:</strong> {reporte.puntaje_total}
        </p>
      )}
      {reporte.interpretacion && (
        <p>
          <strong>Interpretación:</strong>{" "}
          <span className="font-semibold">{reporte.interpretacion}</span>
        </p>
      )}

      {/* Si viene de reportes */}
      {reporte.resultado_final && (
        <div className="mt-2">
          <strong>Resultado Final:</strong>
          <p className="whitespace-pre-wrap">{reporte.resultado_final}</p>
        </div>
      )}
      {reporte.recomendaciones && (
        <div className="mt-2">
          <strong>Recomendaciones:</strong>
          <p className="whitespace-pre-wrap">{reporte.recomendaciones}</p>
        </div>
      )}

      <p className="mt-2 text-sm text-gray-600">
        📅 {fechaStr}
      </p>
    </div>
  );
}

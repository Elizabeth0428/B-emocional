// src/components/ReportViewer.jsx
import { useEffect, useState } from "react";
import { getToken } from "../services/AuthService";

// ⭐ API dinámico para producción
const API = import.meta.env.VITE_API_URL;

export default function ReportViewer({ reporte, iaInsights, pacienteId }) {
  const [reportesPrevios, setReportesPrevios] = useState([]);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  // 🔹 Cargar reportes previos desde backend
  useEffect(() => {
    if (!pacienteId) return;

    const fetchReportes = async () => {
      setLoading(true);
      setErrorMsg(null);

      try {
        const token = getToken();
        const res = await fetch(`${API}/api/reportes/${pacienteId}`, {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (!res.ok) throw new Error(`Error ${res.status}`);

        const data = await res.json();

        if (Array.isArray(data)) {
          setReportesPrevios(data);
        } else {
          setReportesPrevios([]);
        }
      } catch (err) {
        console.error("❌ Error cargando reportes previos:", err);
        setErrorMsg("❌ No se pudieron cargar reportes anteriores.");
      } finally {
        setLoading(false);
      }
    };

    fetchReportes();
  }, [pacienteId]);

  return (
    <div className="bg-gray-100 p-6 rounded-lg shadow-md">
      <h2 className="text-xl font-bold text-blue-700 mb-4">
        📄 Reporte clínico del paciente
      </h2>

      {/* Reporte actual */}
      {reporte ? (
        <div className="p-4 bg-white rounded shadow mb-4">
          <h3 className="font-semibold text-gray-800 mb-2">Reporte actual</h3>
          <div className="whitespace-pre-wrap text-gray-700">{reporte}</div>
        </div>
      ) : (
        <p className="text-gray-500 italic mb-4">
          ⚠️ No se ha generado reporte actual.
        </p>
      )}

      {/* Insights de IA */}
      {iaInsights && (
        <div className="mt-4 p-4 border-l-4 border-blue-400 bg-white rounded shadow">
          <h3 className="font-bold text-blue-700">🤖 Análisis IA complementario</h3>
          <p className="whitespace-pre-wrap text-gray-800 mt-2">{iaInsights}</p>
        </div>
      )}

      {/* Reportes anteriores */}
      <div className="mt-6">
        {loading && <p className="text-gray-500">⏳ Cargando reportes previos...</p>}
        {errorMsg && <p className="text-red-500">{errorMsg}</p>}

        {!loading && !errorMsg && reportesPrevios.length > 0 && (
          <>
            <h3 className="font-semibold text-gray-800 mb-2">📂 Reportes anteriores</h3>
            <ul className="space-y-3">
              {reportesPrevios.map((r) => (
                <li
                  key={r.id_reporte || r.id || Math.random()}
                  className="p-4 bg-white rounded shadow text-sm"
                >
                  <p><strong>Sesión:</strong> {r.id_sesion}</p>
                  <p><strong>Resultado:</strong> {r.resultado_final}</p>
                  <p><strong>Recomendaciones:</strong> {r.recomendaciones}</p>
                  <small className="text-gray-500">
                    📅 {r.fecha_reporte ? new Date(r.fecha_reporte).toLocaleString("es-MX") : "Fecha no registrada"}
                  </small>
                </li>
              ))}
            </ul>
          </>
        )}

        {!loading && !errorMsg && reportesPrevios.length === 0 && (
          <p className="text-gray-500">No hay reportes previos registrados.</p>
        )}
      </div>

      <p className="text-sm text-gray-600 mt-6 italic">
        🌱 Recuerda: este reporte es preliminar, el psicólogo siempre tiene la decisión final.
      </p>
    </div>
  );
}

import { useEffect, useState } from "react";
import { getToken } from "../services/AuthService";
import { useNavigate } from "react-router-dom";

export default function PacienteDetalle({ idPaciente, onBack }) {
  console.log("PacienteDetalle montado con idPaciente:", idPaciente);
  const [paciente, setPaciente] = useState(null);
  const [historialInicial, setHistorialInicial] = useState(null);
  const [seguimiento, setSeguimiento] = useState([]);
  const [sesiones, setSesiones] = useState([]);
  const [resultados, setResultados] = useState([]); 
  const [loading, setLoading] = useState(true);
  const [links, setLinks] = useState(null);
  const [newSeguimiento, setNewSeguimiento] = useState({
    diagnostico: "",
    tratamiento: "",
    evolucion: "",
    observaciones: "",
  });

  const token = getToken(); // NUEVO
// === Estado para reportes guardados (historial IA) ===
const [reportesGuardados, setReportesGuardados] = useState([]);


  // Estados para pruebas
  const [catalogoPruebas, setCatalogoPruebas] = useState([]);
  const [pruebasHabilitadas, setPruebasHabilitadas] = useState([]);
  const [selectedPrueba, setSelectedPrueba] = useState("");
  const [notasPrueba, setNotasPrueba] = useState("");

  // === Estado para reporte IA ===
  const [reporteIA, setReporteIA] = useState(null);
  const [loadingIA, setLoadingIA] = useState(false);
  const [idSesion, setIdSesion] = useState(null);

  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const headers = { Authorization: `Bearer ${getToken()}` };

        const resPaciente = await fetch(`http://localhost:5000/api/pacientes/${idPaciente}`, { headers });
        if (resPaciente.ok) setPaciente(await resPaciente.json());

        const resHist = await fetch(`http://localhost:5000/api/historial-inicial/${idPaciente}`, { headers });
        if (resHist.ok) setHistorialInicial(await resHist.json());

        const resSeg = await fetch(`http://localhost:5000/api/seguimiento/${idPaciente}`, { headers });
        if (resSeg.ok) setSeguimiento(await resSeg.json());

        // ✅ Cargar sesiones + incluir videos reales desde backend
const res = await fetch("http://localhost:5000/api/sesiones", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  },
  body: JSON.stringify({
    id_paciente: Number(idPaciente),
    notas: "Sesión con videollamada",
  }),
});

const data = await res.json();
const idSesion = data.id_sesion; // ✅ ESTE ID DEBE USARSE EN LA VIDEOLLAMADA


        const resCat = await fetch("http://localhost:5000/api/pruebas", { headers });
        if (resCat.ok) setCatalogoPruebas(await resCat.json());

        const resHab = await fetch(`http://localhost:5000/api/pruebas/habilitadas/${idPaciente}`, { headers });
        if (resHab.ok) setPruebasHabilitadas(await resHab.json());

       const resResultados = await fetch(`http://localhost:5000/api/reportes/${idPaciente}`, { headers });
if (resResultados.ok) {
  const data = await resResultados.json();
  setResultados(data.resultados || []);
}

      } catch (err) {
        console.error("❌ Error al obtener datos del paciente:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [idPaciente]);

// 📑 Cargar reportes guardados del paciente
useEffect(() => {
  const fetchReportesGuardados = async () => {
    try {
      const res = await fetch(`http://localhost:5000/api/pacientes/${idPaciente}/reportes-ia`, {
        headers: { Authorization: `Bearer ${getToken()}` }
      });
      if (res.ok) {
        const data = await res.json();
        setReportesGuardados(data);
      }
    } catch (err) {
      console.error("❌ Error al obtener reportes guardados:", err);
    }
  };

  if (idPaciente) {
    fetchReportesGuardados();
  }
}, [idPaciente]);



// ✅ 1. Guardar seguimiento
const handleAddSeguimiento = async () => {
  try {
    const token = getToken();
    const res = await fetch("http://localhost:5000/api/seguimiento", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ ...newSeguimiento, id_paciente: Number(idPaciente) }),
    });

    if (!res.ok) throw new Error("Error al guardar seguimiento");

    const data = await res.json();
    setSeguimiento([{ ...newSeguimiento, id_seguimiento: data.id_seguimiento, fecha: new Date() }, ...seguimiento]);
    setNewSeguimiento({ diagnostico: "", tratamiento: "", evolucion: "", observaciones: "" });
    alert("✅ Seguimiento agregado");
  } catch (err) {
    console.error("❌ Error:", err);
    alert("❌ No se pudo guardar seguimiento");
  }
};

// ✅ 2. Generar texto IA (se guarda en BD, NO PDF)
const generarReporteIA = async () => {
  try {
    setLoadingIA(true);
    const res = await fetch(`http://localhost:5000/api/pacientes/${idPaciente}/generar-reporte-ia`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${getToken()}`,
      },
    });

    const data = await res.json();

    if (res.ok) {
      alert("✅ Reporte IA generado correctamente");

      // Refrescar historial de reportes IA
      const resReportes = await fetch(`http://localhost:5000/api/pacientes/${idPaciente}/reportes-ia`, {
        headers: { Authorization: `Bearer ${getToken()}` },
      });
      if (resReportes.ok) {
        setReportesGuardados(await resReportes.json());
      }
    } else {
      alert("❌ Error al generar reporte IA: " + data.message);
    }
  } catch (err) {
    console.error("❌ Error al generar reporte IA:", err);
    alert("No se pudo generar el reporte IA");
  } finally {
    setLoadingIA(false);
  }
};

// ✅ Generar PDF y actualizar historial
const generarPDF = async () => {
  try {
    const res = await fetch(
      `http://localhost:5000/api/pacientes/${idPaciente}/generar-reporte-pdf`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${getToken()}`,
        },
      }
    );

    const data = await res.json();

    if (res.ok) {
      alert("✅ PDF generado correctamente");

      // 🔄 Recargar historial de reportes para mostrar la ruta PDF actualizada
      const resReportes = await fetch(
        `http://localhost:5000/api/pacientes/${idPaciente}/reportes-ia`,
        { headers: { Authorization: `Bearer ${getToken()}` } }
      );

      if (resReportes.ok) {
        const nuevosReportes = await resReportes.json();
        setReportesGuardados(nuevosReportes); // ✅ Esto refresca la vista en pantalla
      }

      // 📂 Abrir el PDF automáticamente
      if (data.ruta) {
        window.open(`http://localhost:5000${data.ruta}`, "_blank");
      }
    } else {
      alert("⚠ No se pudo generar el PDF");
    }
  } catch (err) {
    console.error("❌ Error al generar PDF:", err);
  }
};


// ✅ Habilitar prueba para el paciente
const handleHabilitarPrueba = async () => {
  if (!historialInicial) {
    alert("⚠️ Debes completar el Historial Clínico Inicial antes de habilitar pruebas.");
    return;
  }
  if (!selectedPrueba) {
    return alert("⚠️ Selecciona una prueba");
  }

  try {
    const res = await fetch("http://localhost:5000/api/pruebas/habilitar", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${getToken()}`,
      },
      body: JSON.stringify({
        id_paciente: Number(idPaciente),
        id_prueba: Number(selectedPrueba),
        notas: notasPrueba || null,
      }),
    });

    if (!res.ok) throw new Error("Error al habilitar prueba");
    alert("✅ Prueba habilitada");

    // 🔄 Actualizar listado de pruebas habilitadas
    const resHab = await fetch(`http://localhost:5000/api/pruebas/habilitadas/${idPaciente}`, {
      headers: { Authorization: `Bearer ${getToken()}` },
    });

    if (resHab.ok) {
      const data = await resHab.json();
      setPruebasHabilitadas(data);
    }

    setSelectedPrueba("");
    setNotasPrueba("");
  } catch (err) {
    console.error("❌ Error:", err);
    alert("❌ No se pudo habilitar la prueba");
  }
};


  if (loading) return <p>Cargando...</p>;

  return (
    <div style={container}>
      <button onClick={onBack} style={backButton}>⬅ Volver</button>

      <h2>👤 {paciente?.nombre || "Paciente desconocido"}</h2>
      <div style={card}>
        <p><b>Sexo:</b> {paciente?.sexo}</p>
        <p><b>Edad:</b> {paciente?.edad}</p>
        <p><b>Correo:</b> {paciente?.correo}</p>
        <p><b>Teléfono:</b> {paciente?.telefono}</p>
      </div>

      {/* 🔹 Opciones del paciente */}
      <hr />
      <h3>📌 Opciones del paciente</h3>
      <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
        <button style={btnOption} onClick={() => navigate(`/historial/${idPaciente}`)}>📋 Ver historial clínico inicial</button>
        <button style={btnOption} onClick={() => navigate(`/seguimiento/${idPaciente}`)}>📑 Ver historial de seguimiento</button>
        <button style={btnOption} onClick={() => navigate(`/resultados/${idPaciente}`)}>🧪 Ver resultados de pruebas</button>
        <button style={btnOption} onClick={() => navigate(`/sesiones/${idPaciente}`)}>📅 Ver sesiones</button>
      </div>

      {/* 🚀 Pruebas habilitadas (se queda aquí) */}
      <hr />
      <h3>🧾 Pruebas habilitadas</h3>
      <div style={card}>
        <select value={selectedPrueba} onChange={(e) => setSelectedPrueba(e.target.value)} style={textarea}>
          <option value="">-- Selecciona una prueba --</option>
          {catalogoPruebas.map((p) => (
            <option key={p.id_prueba} value={p.id_prueba}>{p.nombre} ({p.tipo})</option>
          ))}
        </select>

        <textarea placeholder="Notas (opcional)" value={notasPrueba} onChange={(e) => setNotasPrueba(e.target.value)} style={textarea} />
        <button style={btnSave} onClick={handleHabilitarPrueba}>➕ Habilitar prueba</button>
      </div>

      {pruebasHabilitadas.length > 0 && (
        <div style={card}>
          <ul>
            {pruebasHabilitadas.map((p) => (
              <li key={p.id_habilitacion}>
                <b>{p.nombre}</b> – {new Date(p.fecha).toLocaleDateString("es-MX")}
                <br />
                <small>{p.descripcion}</small>
                <br />
                <a href={`${window.location.origin}/responder-prueba/${p.id_habilitacion}`} target="_blank" rel="noopener noreferrer">
                  📩 Link para paciente
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}


    {/* 🚀 Reporte IA */}
<hr />
<h3>🧠 Reporte automático con IA</h3>
<div style={card}>
  {/* Botón para generar reporte IA */}
  <button style={btnSave} disabled={loadingIA} onClick={generarReporteIA}>
    {loadingIA ? "⏳ Generando..." : "⚡ Generar reporte IA"}
  </button>

  {/* ✅ Nuevo botón para generar PDF */}
  <button style={{ ...btnSave, background: "#2196F3" }} onClick={generarPDF}>
    🖨 Generar PDF del último reporte
  </button>
</div>

{/* 🚀 Historial de reportes IA */}
<hr />
<h3>📑 Historial de reportes IA</h3>
<div style={card}>
  {reportesGuardados.length > 0 ? (
    <ul>
      {reportesGuardados.map((r) => (
        <li key={r.id_reporte} style={{ marginBottom: "12px" }}>
          <b>🗓️ {new Date(r.fecha).toLocaleString("es-MX")}</b> <br />

          {/* ✅ Mostrar botón de PDF si existe la ruta */}
          {r.ruta_pdf ? (
            <a
              href={`http://localhost:5000${r.ruta_pdf}`}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                display: "inline-block",
                marginTop: "5px",
                backgroundColor: "#3f51b5",
                color: "white",
                padding: "6px 12px",
                borderRadius: "6px",
                textDecoration: "none",
                fontWeight: "bold",
              }}
            >
              📄 Ver reporte PDF
            </a>
          ) : (
            <p style={{ color: "gray" }}>⚠️ Reporte generado, pero sin PDF</p>
          )}
        </li>
      ))}
    </ul>
  ) : (
    <p className="text-gray-500">No hay reportes generados todavía.</p>
  )}
</div>





      {/* 🚀 Videollamada */}
      <hr />
      <h3>📞 Videollamada</h3>
      <div style={card}>
        <p>Inicia una videollamada con este paciente.</p>
        
        <button
          style={btnSave}
          onClick={async () => {
            try {
              const token = getToken();

              // 1️⃣ Crear sesión en backend
              const res = await fetch("http://localhost:5000/api/sesiones", {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({
                  id_paciente: Number(idPaciente),
                  notas: "Sesión con videollamada",
                }),
              });

              if (!res.ok) throw new Error("No se pudo crear sesión");
              const data = await res.json();
              const idSesion = data.id_sesion;

              // 2️⃣ Generar link en backend
              const resLink = await fetch(
                `http://localhost:5000/api/sesiones/${idSesion}/videollamada`,
                {
                  method: "POST",
                  headers: { Authorization: `Bearer ${token}` },
                }
              );

              if (!resLink.ok) throw new Error("No se pudo generar link");
              const { link } = await resLink.json();

              // 3️⃣ Crear enlaces
              const origin = window.location.origin;
              const sala = link.split("/").pop();

              setLinks({
                psicologo: `${origin}/SalaVideollamada/${idSesion}-${sala}`,
                paciente: `${origin}/videollamada-paciente/${sala}`,
              });

              alert("✅ Link de videollamada generado y guardado en BD");
            } catch (err) {
              console.error("❌ Error al generar link:", err);
              alert("No se pudo generar link de videollamada");
            }
          }}
        >
          🔗 Generar link
        </button>

        {links && (
          <div style={{ marginTop: "10px" }}>
            <p>
              <a
                href={links.psicologo}
                target="_blank"
                rel="noreferrer"
                style={linkBtn}
              >
                🚀 Iniciar videollamada (Psicólogo)
              </a>
            </p>
            <p>
              <b>👤 Link para el Paciente:</b>{" "}
              <a href={links.paciente} target="_blank" rel="noreferrer">
                {links.paciente}
              </a>
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

// === Estilos ===
const container = { padding: "20px", maxWidth: "800px", margin: "20px auto", background: "#fff", borderRadius: "12px", boxShadow: "0 4px 12px rgba(0,0,0,0.1)" };
const backButton = { padding: "8px 12px", marginBottom: "15px", border: "none", borderRadius: "6px", background: "#90CAF9", cursor: "pointer" };
const card = { background: "#f9f9f9", padding: "15px", borderRadius: "8px", boxShadow: "0 2px 6px rgba(0,0,0,0.1)", marginBottom: "15px" };
const textarea = { width: "100%", marginBottom: "8px", padding: "8px", borderRadius: "6px", border: "1px solid #ccc" };
const btnSave = { background: "#4CAF50", color: "white", border: "none", borderRadius: "6px", padding: "8px 14px", cursor: "pointer", marginRight: "8px" };
const btnOption = { background: "#3f51b5", color: "white", border: "none", borderRadius: "8px", padding: "12px 18px", fontWeight: "600", cursor: "pointer", textAlign: "left" };
const btnCancel = { background: "#E53935", color: "white", border: "none", borderRadius: "6px", padding: "8px 14px", cursor: "pointer" };
const btnEdit = { background: "#FFC107", color: "black", border: "none", borderRadius: "6px", padding: "8px 14px", cursor: "pointer" };

const linkBtn = {  // 🔹 Para el botón azul de iniciar videollamada
  display: "inline-block",
  padding: "10px 15px",
  backgroundColor: "#03A9F4",
  color: "#fff",
  borderRadius: "8px",
  textDecoration: "none",
  fontWeight: "bold",
};

// src/views/BackupManager.jsx
import React, { useEffect, useState } from "react";
import axios from "axios";
import Swal from "sweetalert2";
import { getToken } from "../services/AuthService";

const API = import.meta.env.VITE_API_URL; // ⭐ SIEMPRE desde .env

const BackupManager = ({ onBack }) => {
  const [backups, setBackups] = useState([]);
  const [loading, setLoading] = useState(false);

  // ============================================================
  // 🔹 1. Cargar lista de respaldos
  // ============================================================
  const fetchBackups = async () => {
    try {
      const res = await axios.get(`${API}/api/backup/list`, {
        headers: {
          Authorization: `Bearer ${getToken()}`,
        },
      });

      setBackups(res.data.backups || []);
    } catch (error) {
      console.error("❌ Error", error);
      Swal.fire("❌ Error", "No se pudieron cargar los backups", "error");
    }
  };

  // ============================================================
  // 🔹 2. Crear un nuevo backup
  // ============================================================
  const handleCreateBackup = async () => {
    const confirm = await Swal.fire({
      title: "¿Crear respaldo?",
      text: "Se generará un archivo .sql del sistema",
      icon: "question",
      showCancelButton: true,
      confirmButtonText: "Sí, crear",
      cancelButtonText: "Cancelar",
    });

    if (!confirm.isConfirmed) return;
    setLoading(true);

    try {
      await axios.get(`${API}/api/backup/create`, {
        headers: { Authorization: `Bearer ${getToken()}` },
      });

      Swal.fire("✅ Listo", "Backup generado correctamente", "success");
      fetchBackups();
    } catch (err) {
      Swal.fire("❌ Error", "No se pudo generar el backup", "error");
    } finally {
      setLoading(false);
    }
  };

  // ============================================================
  // 🔹 3. Restaurar backup
  // ============================================================
  const handleRestore = async (file) => {
    const confirm = await Swal.fire({
      title: "⚠ Restaurar Base de Datos",
      text: `Se usará el archivo: ${file}`,
      icon: "warning",
      showCancelButton: true,
      confirmButtonText: "Sí, restaurar",
      cancelButtonText: "Cancelar",
    });

    if (!confirm.isConfirmed) return;
    setLoading(true);

    try {
      await axios.post(
        `${API}/api/backup/restore`,
        { file },
        {
          headers: { Authorization: `Bearer ${getToken()}` },
        }
      );

      Swal.fire("✅ Restaurado", "Base de datos restaurada correctamente", "success");
    } catch (err) {
      Swal.fire("❌ Error", "No se pudo restaurar la base", "error");
    } finally {
      setLoading(false);
    }
  };

  // ============================================================
  // 🔹 4. Descargar archivo .sql
  // ============================================================
  const handleDownload = (file) => {
    window.open(`${API}/api/backup/download/${file}`, "_blank");
  };

  // Cargar lista inicial
  useEffect(() => {
    fetchBackups();
  }, []);

  return (
    <div style={styles.container}>
      <h2 style={styles.title}>💾 Gestión de Backups</h2>

      <div style={styles.actions}>
        <button style={styles.createBtn} onClick={handleCreateBackup} disabled={loading}>
          {loading ? "Procesando..." : "📁 Crear Backup"}
        </button>

        <button style={styles.backBtn} onClick={onBack}>
          ⬅ Volver
        </button>
      </div>

      <table style={styles.table}>
        <thead>
          <tr>
            <th>📂 Archivo</th>
            <th>⚙ Acciones</th>
          </tr>
        </thead>

        <tbody>
          {backups.length > 0 ? (
            backups.map((b, i) => (
              <tr key={i}>
                <td>{b.file}</td>
                <td>
                  <button
                    style={styles.restoreBtn}
                    onClick={() => handleRestore(b.file)}
                  >
                    ♻ Restaurar
                  </button>

                  <button
                    style={styles.downloadBtn}
                    onClick={() => handleDownload(b.file)}
                  >
                    ⬇ Descargar
                  </button>
                </td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan="2">⚠ No hay respaldos almacenados</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
};
/* ✅ Estilos */
const styles = {
  container: {
    padding: "30px",
    maxWidth: "800px",
    margin: "40px auto",
    background: "white",
    borderRadius: "16px",
    boxShadow: "0 10px 24px rgba(0,0,0,0.1)",
    fontFamily: "'Poppins', sans-serif",
  },
  title: {
    textAlign: "center",
    fontSize: "26px",
    color: "#0D47A1",
    marginBottom: "20px",
  },
  actions: {
    display: "flex",
    justifyContent: "space-between",
    marginBottom: "20px",
  },
  createBtn: {
    backgroundColor: "#1E88E5",
    color: "white",
    border: "none",
    padding: "10px 20px",
    borderRadius: "8px",
    cursor: "pointer",
  },
  backBtn: {
    backgroundColor: "#9E9E9E",
    color: "white",
    border: "none",
    padding: "10px 20px",
    borderRadius: "8px",
    cursor: "pointer",
  },
  table: {
    width: "100%",
    borderCollapse: "collapse",
  },
  restoreBtn: {
    backgroundColor: "#FFB300",
    color: "white",
    padding: "6px 12px",
    border: "none",
    borderRadius: "8px",
    marginRight: "8px",
    cursor: "pointer",
  },
  downloadBtn: {
    backgroundColor: "#4CAF50",
    color: "white",
    padding: "6px 12px",
    border: "none",
    borderRadius: "8px",
    cursor: "pointer",
  },
};

export default BackupManager;

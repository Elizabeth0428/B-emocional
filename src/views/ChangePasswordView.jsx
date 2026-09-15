import React, { useState } from "react";
import { changePassword } from "../services/AuthService";

const ChangePasswordView = ({ onBack }) => {
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage("");
    setError("");

    if (newPassword !== confirmPassword) {
      setError("⚠️ Las contraseñas no coinciden");
      return;
    }

    try {
      const res = await changePassword(oldPassword, newPassword);
      setMessage(res.message || "✅ Contraseña cambiada con éxito");
      setOldPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err) {
      setError(err.message || "❌ Error al cambiar contraseña");
    }
  };

  return (
    <div style={containerStyle}>
      <h2 style={titleStyle}>🔑 Cambiar Contraseña</h2>
      <form onSubmit={handleSubmit}>
        <div style={fieldStyle}>
          <label>Contraseña actual</label>
          <input
            type="password"
            value={oldPassword}
            onChange={(e) => setOldPassword(e.target.value)}
            required
            style={inputStyle}
          />
        </div>
        <div style={fieldStyle}>
          <label>Nueva contraseña</label>
          <input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
            style={inputStyle}
          />
        </div>
        <div style={fieldStyle}>
          <label>Confirmar nueva contraseña</label>
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
            style={inputStyle}
          />
        </div>
        <button type="submit" style={buttonPrimary}>
          Cambiar Contraseña
        </button>
      </form>

      {message && <p style={successMsg}>{message}</p>}
      {error && <p style={errorMsg}>{error}</p>}

      <button onClick={onBack} style={buttonSecondary}>
        ⬅️ Volver
      </button>
    </div>
  );
};

// === Estilos ===
const containerStyle = {
  maxWidth: "420px",
  margin: "60px auto",
  padding: "30px",
  background: "linear-gradient(145deg, #ffffff, #f7f9fc)",
  borderRadius: "16px",
  boxShadow: "0 8px 16px rgba(0,0,0,0.1)",
  fontFamily: "'Segoe UI', sans-serif",
};

const titleStyle = {
  textAlign: "center",
  marginBottom: "20px",
  fontSize: "22px",
  fontWeight: "700",
  color: "#2c3e50",
};

const fieldStyle = { marginBottom: 15 };

const inputStyle = {
  width: "100%",
  padding: "10px",
  marginTop: "6px",
  borderRadius: "8px",
  border: "1px solid #ccc",
  fontSize: "15px",
};

const buttonPrimary = {
  width: "100%",
  padding: "12px",
  backgroundColor: "#1976d2",
  color: "#fff",
  border: "none",
  borderRadius: "10px",
  cursor: "pointer",
  fontSize: "16px",
  fontWeight: "600",
  boxShadow: "0 6px 12px rgba(25,118,210,0.3)",
};

const buttonSecondary = {
  marginTop: "15px",
  width: "100%",
  padding: "10px",
  background: "#f5f5f5",
  color: "#333",
  border: "1px solid #ccc",
  borderRadius: "10px",
  cursor: "pointer",
  fontSize: "14px",
};

const successMsg = { color: "green", marginTop: 10, fontWeight: "600" };
const errorMsg = { color: "red", marginTop: 10, fontWeight: "600" };

export default ChangePasswordView;

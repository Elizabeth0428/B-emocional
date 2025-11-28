// src/views/LoginView.jsx
import React, { useState } from "react";
import { login } from "../services/AuthService";
import { FaUserCircle } from "react-icons/fa";

const LoginView = ({ onLoginSuccess, onBack }) => {
  const [correo, setCorreo] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    setError("");
    if (!correo || !password) {
      setError("Por favor ingresa correo y contraseña");
      return;
    }

    setLoading(true);
    try {
      const data = await login(correo, password);

      if (data && data.user && data.token) {
        sessionStorage.setItem("token", data.token);
        sessionStorage.setItem("user", JSON.stringify(data.user));

        onLoginSuccess({ ...data.user, token: data.token });
      } else {
        setError("Error: respuesta inesperada del servidor");
      }
    } catch (err) {
      setError(err.message || "Error al iniciar sesión");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={formContainer}>
      <FaUserCircle size={60} color="#3f51b5" style={{ marginBottom: 10 }} />
      <h2 style={title}>Iniciar Sesión</h2>

      <input
        type="email"
        placeholder="Correo electrónico"
        value={correo}
        onChange={(e) => setCorreo(e.target.value)}
        style={inputStyle}
      />

      <input
        type="password"
        placeholder="Contraseña"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && handleLogin()}
        style={inputStyle}
      />

      <button onClick={handleLogin} style={buttonStyle} disabled={loading}>
        {loading ? "Ingresando..." : "Ingresar"}
      </button>
      <button onClick={onBack} style={backStyle}>
        ← Volver
      </button>

      {error && (
        <div style={errorBox}>
          <p>{error}</p>
        </div>
      )}
    </div>
  );
};

// 🎨 Estilos
const formContainer = {
  maxWidth: 400,
  margin: "50px auto",
  padding: 30,
  backgroundColor: "#fff",
  borderRadius: 16,
  boxShadow: "0 6px 16px rgba(0,0,0,0.15)",
  textAlign: "center",
  fontFamily: "Segoe UI, sans-serif",
};

const title = {
  marginBottom: 20,
  color: "#0D47A1",
};

const inputStyle = {
  width: "100%",
  padding: "12px",
  marginBottom: "12px",
  borderRadius: "8px",
  border: "1px solid #ccc",
  fontSize: "14px",
};

const buttonStyle = {
  width: "100%",
  padding: "12px",
  border: "none",
  borderRadius: "8px",
  backgroundColor: "#1976D2",
  color: "white",
  fontWeight: "600",
  fontSize: "15px",
  marginBottom: "10px",
  cursor: "pointer",
};

const backStyle = {
  ...buttonStyle,
  backgroundColor: "#90CAF9",
  color: "#0D47A1",
};

const errorBox = {
  marginTop: 15,
  padding: 10,
  backgroundColor: "#FFEBEE",
  color: "#C62828",
  borderRadius: 8,
  fontWeight: "600",
};

export default LoginView;

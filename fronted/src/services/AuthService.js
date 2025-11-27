// src/services/AuthService.js

// const API = import.meta.env.VITE_API_URL;
const API = "https://bemocional-backend.onrender.com";

// ===============================================================
// 🔐 LOGIN
// ===============================================================
export const login = async (correo, password) => {
  const res = await fetch(`${API}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ correo, password }),
  });

  const data = await res.json();
  if (!res.ok) throw new Error(data.message || "Error en login");

  // Guardar token + datos
  if (data.token) {
    const userData = {
      ...data.user,
      id_psicologo: data.user?.id_psicologo || null,
      role: data.user.rol === "psicologo" ? 2 : 1
    };

    // 🔥 FIX para Render
    sessionStorage.setItem("token", data.token);
    sessionStorage.setItem("user", JSON.stringify(userData));
  }

  return data;
};

// ===============================================================
// 🔓 LOGOUT
// ===============================================================
export const logout = () => {
  sessionStorage.removeItem("token");
  sessionStorage.removeItem("user");
  console.log("✅ Sesión cerrada correctamente");
};

// ===============================================================
// 👤 OBTENER USUARIO
// ===============================================================
export const getCurrentUser = () => {
  try {
    const user = sessionStorage.getItem("user");
    return user ? JSON.parse(user) : null;
  } catch {
    return null;
  }
};

// ===============================================================
// 🔑 TOKEN
// ===============================================================
export const getToken = () => {
  return sessionStorage.getItem("token") || null;
};

// ===============================================================
// REGISTRO
// ===============================================================
export const register = async (payload) => {
  const token = getToken();

  const res = await fetch(`${API}/api/psicologos/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
  });

  const data = await res.json();
  if (!res.ok) throw new Error(data.message || "Error en registro");

  return data;
};

// ===============================================================
// CAMBIAR CONTRASEÑA
// ===============================================================
export const changePassword = async (oldPassword, newPassword) => {
  const token = getToken();

  const res = await fetch(`${API}/api/change-password`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ oldPassword, newPassword }),
  });

  const data = await res.json();
  if (!res.ok) throw new Error(data.message || "Error al cambiar contraseña");

  return data;
};


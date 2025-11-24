// src/services/AuthService.js

// ⭐ API dinámico desde .env (Render / Vercel / Producción)
const API = import.meta.env.VITE_API_URL;

// ===============================================================
// 🔐 LOGIN (Admin / Psicólogos / Usuarios)
// ===============================================================
export const login = async (correo, password) => {
  const res = await fetch(`${API}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ correo, password }),
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(data.message || "Error en login");
  }

  // Guardar token + datos del usuario
  if (data.token) {
    const userData = {
      ...data.user,
      id_psicologo: data.user?.id_psicologo || null, // Siempre definido
    };

    localStorage.setItem("token", data.token);
    localStorage.setItem("user", JSON.stringify(userData));
  }

  return data;
};

// ===============================================================
// 👨‍⚕️ REGISTRO DE PSICÓLOGOS (Solo Admin)
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

  if (!res.ok) {
    throw new Error(data.message || "Error en registro");
  }

  return data;
};

// ===============================================================
// 🔓 LOGOUT
// ===============================================================
export const logout = () => {
  localStorage.removeItem("token");
  localStorage.removeItem("user");
  console.log("✅ Sesión cerrada correctamente");
};

// ===============================================================
// 👤 OBTENER USUARIO ACTUAL
// ===============================================================
export const getCurrentUser = () => {
  try {
    const user = localStorage.getItem("user");
    return user ? JSON.parse(user) : null;
  } catch (error) {
    console.error("❌ Error al leer usuario de localStorage:", error);
    return null;
  }
};

// ===============================================================
// 🔑 CAMBIAR CONTRASEÑA
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

  if (!res.ok) {
    throw new Error(data.message || "Error al cambiar contraseña");
  }

  return data;
};

// ===============================================================
// 🔑 OBTENER TOKEN ACTUAL
// ===============================================================
export const getToken = () => {
  return localStorage.getItem("token") || null;
};

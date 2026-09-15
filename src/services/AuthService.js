// src/services/AuthService.js

const API = import.meta.env.VITE_API_URL; // 👈 usamos la variable del .env

// 🔹 Login (para todos los usuarios: admin y psicólogos)
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

  // Guardar sesión en localStorage (token + user con permisos)
  if (data.token) {
    const userData = {
      ...data.user,
      id_psicologo: data.user?.id_psicologo || null, // 👈 aseguramos que exista
    };

    localStorage.setItem("token", data.token);
    localStorage.setItem("user", JSON.stringify(userData));
  }

  return data;
};

// 🔹 Registro de psicólogos (solo un admin puede hacerlo)
export const register = async ({
  cedula_profesional,
  nombre,
  correo,
  password,
  especialidad,
}) => {
  const token = getToken();

  const res = await fetch(`${API}/api/psicologos/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      cedula_profesional,
      nombre,
      correo,
      password,
      especialidad,
    }),
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(data.message || "Error en registro");
  }

  return data;
};

// 🔹 Logout (elimina token y datos de usuario)
export const logout = () => {
  localStorage.removeItem("token");
  localStorage.removeItem("user");
  console.log("✅ Sesión cerrada correctamente");
};

// 🔹 Obtener usuario actual de localStorage
export const getCurrentUser = () => {
  try {
    const user = localStorage.getItem("user");
    return user ? JSON.parse(user) : null;
  } catch (error) {
    console.error("❌ Error al leer usuario de localStorage:", error);
    return null;
  }
};

// 🔹 Cambiar contraseña (usuarios y psicólogos)
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

// 🔹 Obtener token guardado
export const getToken = () => {
  return localStorage.getItem("token") || null;
};

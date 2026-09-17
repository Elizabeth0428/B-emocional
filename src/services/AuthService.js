
// src/services/AuthService.js

const API = import.meta.env.VITE_API_URL;


// ==================================================
// LOGIN
// Todos los usuarios:
// - Administrador Master
// - Administrador Normal
// - Psicólogo
// - RH
// - Educativo
// - Independiente
// ==================================================

export const login = async (
  correo,
  password
) => {

  const res = await fetch(
    `${API}/api/login`,
    {
      method: "POST",

      headers: {
        "Content-Type": "application/json",
      },

      body: JSON.stringify({
        correo,
        password,
      }),
    }
  );


  const data = await res.json();


  if (!res.ok) {

    throw new Error(
      data.message ||
      "Error en login"
    );

  }


  // ==================================================
  // GUARDAR SESIÓN
  // ==================================================

  if (data.token) {

    const userData = {

      ...data.user,

      // Aseguramos que siempre exista
      // aunque no sea psicólogo.
      id_psicologo:
        data.user?.id_psicologo ||
        null,

    };


    localStorage.setItem(
      "token",
      data.token
    );


    localStorage.setItem(
      "user",
      JSON.stringify(userData)
    );

  }


  return data;

};


// ==================================================
// REGISTRO DE USUARIO
//
// Lo utiliza el administrador.
//
// Puede registrar:
//
// psicologo
// rh
// educativo
// independiente
//
// La validación definitiva de permisos
// se realiza en el backend.
// ==================================================

export const register = async ({

  rol,
  cedula_profesional,
  nombre,
  correo,
  password,
  especialidad,
  area,
  telefono,
  direccion,
  fecha_nacimiento,

}) => {

  const token =
    getToken();


  if (!token) {

    throw new Error(
      "No existe una sesión de administrador."
    );

  }


  const res = await fetch(

    `${API}/api/psicologos/register`,

    {

      method: "POST",

      headers: {

        "Content-Type":
          "application/json",

        Authorization:
          `Bearer ${token}`,

      },

      body: JSON.stringify({

        rol:
          rol || "psicologo",

        cedula_profesional:
          cedula_profesional ||
          null,

        nombre:
          nombre?.trim() ||
          "",

        correo:
          correo?.trim() ||
          "",

        password:
          password || "",

        especialidad:
          especialidad?.trim() ||
          null,

        area:
          area || null,

        telefono:
          telefono?.trim() ||
          null,

        direccion:
          direccion?.trim() ||
          null,

        fecha_nacimiento:
          fecha_nacimiento ||
          null,

      }),

    }

  );


  const data =
    await res.json();


  if (!res.ok) {

    throw new Error(

      data?.message ||
      "Error al registrar usuario"

    );

  }


  return data;

};


// ==================================================
// LOGOUT
// ==================================================

export const logout = () => {

  localStorage.removeItem(
    "token"
  );

  localStorage.removeItem(
    "user"
  );

  console.log(
    "✅ Sesión cerrada correctamente"
  );

};


// ==================================================
// OBTENER USUARIO ACTUAL
// ==================================================

export const getCurrentUser = () => {

  try {

    const user =
      localStorage.getItem(
        "user"
      );


    return user
      ? JSON.parse(user)
      : null;

  } catch (error) {

    console.error(
      "❌ Error al leer usuario de localStorage:",
      error
    );

    return null;

  }

};


// ==================================================
// CAMBIAR CONTRASEÑA
// ==================================================

export const changePassword = async (
  oldPassword,
  newPassword
) => {

  const token =
    getToken();


  if (!token) {

    throw new Error(
      "No existe una sesión activa."
    );

  }


  const res = await fetch(

    `${API}/api/change-password`,

    {

      method: "PUT",

      headers: {

        "Content-Type":
          "application/json",

        Authorization:
          `Bearer ${token}`,

      },

      body: JSON.stringify({

        oldPassword,
        newPassword,

      }),

    }

  );


  const data =
    await res.json();


  if (!res.ok) {

    throw new Error(

      data.message ||
      "Error al cambiar contraseña"

    );

  }


  return data;

};


// ==================================================
// OBTENER TOKEN
// ==================================================

export const getToken = () => {

  return (
    localStorage.getItem(
      "token"
    ) || null
  );

};
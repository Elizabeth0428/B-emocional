// src/services/AuthService.js

const API = import.meta.env.VITE_API_URL;

// ==================================================
// CLAVES DE SESIÓN
// ==================================================

const TOKEN_KEY = "token";
const USER_KEY = "user";

// ==================================================
// LOGIN
//
// IMPORTANTE:
// La sesión se guarda en sessionStorage.
//
// Esto evita que diferentes pestañas del navegador
// compartan el mismo usuario.
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
        "Content-Type":
          "application/json",
      },

      body: JSON.stringify({
        correo,
        password,
      }),
    }
  );

  const data =
    await res.json();

  if (!res.ok) {
    throw new Error(
      data.message ||
      "Error en login"
    );
  }

  // ==================================================
  // VALIDAR RESPUESTA
  // ==================================================

  if (
    !data.token ||
    !data.user
  ) {
    throw new Error(
      "El servidor no devolvió una sesión válida."
    );
  }

  // ==================================================
  // NORMALIZAR USUARIO
  // ==================================================

  const userData = {
    ...data.user,

    id_psicologo:
      data.user?.id_psicologo ||
      null,
  };

  // ==================================================
  // LIMPIAR SESIÓN ANTERIOR DE ESTA PESTAÑA
  // ==================================================

  sessionStorage.removeItem(
    TOKEN_KEY
  );

  sessionStorage.removeItem(
    USER_KEY
  );

  // ==================================================
  // GUARDAR SESIÓN
  //
  // NO usar localStorage para autenticación.
  // ==================================================

  sessionStorage.setItem(
    TOKEN_KEY,
    data.token
  );

  sessionStorage.setItem(
    USER_KEY,
    JSON.stringify(
      userData
    )
  );

  console.log(
    "✅ Sesión iniciada:",
    {
      id:
        userData.id_usuario ||
        userData.id,

      nombre:
        userData.nombre,

      rol:
        userData.rol,

      role:
        userData.role,

      tipo_admin:
        userData.tipo_admin,

      area:
        userData.area,
    }
  );

  return {
    ...data,
    user: userData,
  };
};

// ==================================================
// REGISTRO DE USUARIO
//
// Lo utiliza el administrador.
//
// Puede registrar:
//
// - psicologo
// - rh
// - educativo
// - independiente
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
          rol ||
          "psicologo",

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
          password ||
          "",

        especialidad:
          especialidad?.trim() ||
          null,

        area:
          area ||
          null,

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
  // Sesión actual de esta pestaña
  sessionStorage.removeItem(
    TOKEN_KEY
  );

  sessionStorage.removeItem(
    USER_KEY
  );

  // ==================================================
  // LIMPIAR SESIONES ANTIGUAS
  //
  // Esto elimina las claves que usábamos antes
  // con localStorage para evitar conflictos.
  // ==================================================

  localStorage.removeItem(
    TOKEN_KEY
  );

  localStorage.removeItem(
    USER_KEY
  );

  console.log(
    "✅ Sesión cerrada correctamente"
  );

  return true;
};

// ==================================================
// OBTENER USUARIO ACTUAL
// ==================================================

export const getCurrentUser =
  () => {
    try {
      const user =
        sessionStorage.getItem(
          USER_KEY
        );

      if (!user) {
        return null;
      }

      return JSON.parse(
        user
      );
    } catch (error) {
      console.error(
        "❌ Error al leer usuario de sessionStorage:",
        error
      );

      sessionStorage.removeItem(
        USER_KEY
      );

      return null;
    }
  };

// ==================================================
// OBTENER TOKEN
// ==================================================

export const getToken =
  () => {
    const token =
      sessionStorage.getItem(
        TOKEN_KEY
      );

    return token || null;
  };

// ==================================================
// VERIFICAR SI EXISTE SESIÓN
// ==================================================

export const isAuthenticated =
  () => {
    const token =
      getToken();

    const user =
      getCurrentUser();

    return Boolean(
      token && user
    );
  };

// ==================================================
// LIMPIAR SESIÓN INVÁLIDA
// ==================================================

export const clearSession =
  () => {
    sessionStorage.removeItem(
      TOKEN_KEY
    );

    sessionStorage.removeItem(
      USER_KEY
    );

    localStorage.removeItem(
      TOKEN_KEY
    );

    localStorage.removeItem(
      USER_KEY
    );
  };

// ==================================================
// CAMBIAR CONTRASEÑA
// ==================================================

export const changePassword =
  async (
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

    const res =
      await fetch(
        `${API}/api/change-password`,
        {
          method: "PUT",

          headers: {
            "Content-Type":
              "application/json",

            Authorization:
              `Bearer ${token}`,
          },

          body:
            JSON.stringify({
              oldPassword,
              newPassword,
            }),
        }
      );

    const data =
      await res.json();

    if (!res.ok) {
      // Token vencido o inválido
      if (
        res.status === 401 ||
        res.status === 403
      ) {
        clearSession();
      }

      throw new Error(
        data.message ||
        "Error al cambiar contraseña"
      );
    }

    return data;
  };

// ==================================================
// HELPER PARA PETICIONES AUTENTICADAS
//
// OPCIONAL:
// Podemos empezar a usarlo posteriormente para
// centralizar fetch y detectar tokens expirados.
// ==================================================

export const authFetch =
  async (
    url,
    options = {}
  ) => {
    const token =
      getToken();

    if (!token) {
      clearSession();

      throw new Error(
        "No existe una sesión activa."
      );
    }

    const headers = {
      ...(options.headers ||
        {}),

      Authorization:
        `Bearer ${token}`,
    };

    const response =
      await fetch(
        url,
        {
          ...options,
          headers,
        }
      );

    if (
      response.status ===
        401 ||
      response.status ===
        403
    ) {
      /*
       * IMPORTANTE:
       * Un 403 también puede significar
       * falta de permiso y no necesariamente
       * token inválido.
       *
       * Por eso solo borramos automáticamente
       * la sesión cuando el backend confirma
       * que el problema es el token.
       */

      if (
        response.status ===
        401
      ) {
        clearSession();
      }
    }

    return response;
  };
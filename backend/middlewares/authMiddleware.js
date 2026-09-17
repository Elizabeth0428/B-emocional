import jwt from "jsonwebtoken";


// ==================================================
// MIDDLEWARE DE AUTENTICACIÓN
// ==================================================

export function verifyToken(req, res, next) {

  const authHeader =
    req.headers["authorization"];

  const token =
    authHeader &&
    authHeader.split(" ")[1];


  // ==================================================
  // VERIFICAR QUE EXISTA EL TOKEN
  // ==================================================

  if (!token) {

    return res.status(403).json({
      message: "Token requerido"
    });

  }


  // ==================================================
  // VERIFICAR JWT
  // ==================================================

  jwt.verify(
    token,
    process.env.JWT_SECRET,
    (err, user) => {

      if (err) {

        return res.status(401).json({
          message:
            "Token inválido o expirado"
        });

      }


      // Guardamos toda la información
      // del usuario dentro de req.user

      req.user = user;


      next();

    }
  );

}



// ==================================================
// SOLO ADMINISTRADORES
// ==================================================

export function isAdmin(
  req,
  res,
  next
) {

  if (
    req.user?.role !== 1
  ) {

    return res.status(403).json({

      message:
        "Acceso denegado: solo administradores"

    });

  }


  next();

}



// ==================================================
// SOLO ADMIN MASTER
// ==================================================
//
// Permite únicamente:
//
// rol = admin
// tipo_admin = master
//
// ==================================================

export function isMasterAdmin(
  req,
  res,
  next
) {

  // Primero debe ser administrador

  if (
    req.user?.role !== 1
  ) {

    return res.status(403).json({

      message:
        "Acceso denegado: se requiere una cuenta de administrador"

    });

  }


  // Después verificamos que sea MASTER

  if (
    req.user?.tipo_admin !== "master"
  ) {

    return res.status(403).json({

      message:
        "Acceso denegado: solo el Administrador Master puede realizar esta acción"

    });

  }


  next();

}



// ==================================================
// SOLO ADMIN NORMAL
// ==================================================
//
// Permite únicamente:
//
// rol = admin
// tipo_admin = normal
//
// ==================================================

export function isNormalAdmin(
  req,
  res,
  next
) {

  // Primero debe ser administrador

  if (
    req.user?.role !== 1
  ) {

    return res.status(403).json({

      message:
        "Acceso denegado: solo administradores"

    });

  }


  // Después verificamos que sea NORMAL

  if (
    req.user?.tipo_admin !== "normal"
  ) {

    return res.status(403).json({

      message:
        "Acceso denegado: esta acción es exclusiva para administradores normales"

    });

  }


  next();

}



// ==================================================
// ADMIN MASTER O ADMIN NORMAL
// ==================================================
//
// Permite:
//
// rol = admin
// tipo_admin = master
//
// O:
//
// rol = admin
// tipo_admin = normal
//
// ==================================================

export function isAdminMasterOrNormal(
  req,
  res,
  next
) {

  // Debe ser administrador

  if (
    req.user?.role !== 1
  ) {

    return res.status(403).json({

      message:
        "Acceso denegado: solo administradores"

    });

  }


  // Debe tener un tipo de administrador válido

  if (
    req.user?.tipo_admin !== "master" &&
    req.user?.tipo_admin !== "normal"
  ) {

    return res.status(403).json({

      message:
        "Tipo de administrador inválido"

    });

  }


  next();

}



// ==================================================
// PERMISOS ESPECÍFICOS
// ==================================================

export function hasPermission(
  permisoId
) {

  return (
    req,
    res,
    next
  ) => {

    if (
      !req.user?.permisos?.includes(
        permisoId
      )
    ) {

      return res.status(403).json({

        message:
          "Acceso denegado: permiso insuficiente"

      });

    }


    next();

  };

}
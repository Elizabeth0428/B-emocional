import React, { useEffect, useState } from "react";
import axios from "axios";
import { useParams } from "react-router-dom";

import PruebaGenericaRH from "./PruebaGenericaRH";
import RavenRH from "./RavenRH";
import Beta3RH from "./Beta3RH";

const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);

const ResponderPruebaRH = () => {
  const { token } = useParams();

  const [prueba, setPrueba] = useState(null);
  const [cargando, setCargando] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const cargar = async () => {
      try {
        setCargando(true);
        setError("");

        const respuesta = await axios.get(
          `${API_URL}/api/prospectos/prueba-publica/${token}`
        );

        const datos = respuesta.data?.prueba || null;

        if (!datos) {
          throw new Error(
            "No se encontró información de la prueba."
          );
        }

        setPrueba(datos);

      } catch (err) {
        console.error(
          "❌ Error cargando prueba RH:",
          err.response?.data || err
        );

        setError(
          err.response?.data?.message ||
            err.message ||
            "No fue posible cargar la prueba."
        );

      } finally {
        setCargando(false);
      }
    };

    if (token) {
      cargar();
    }
  }, [token]);

  if (cargando) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#f5f7fa"
        }}
      >
        <div
          style={{
            background: "#fff",
            padding: "30px",
            borderRadius: "16px"
          }}
        >
          <h2>🧠 MirrorSoul</h2>
          <p>Cargando evaluación...</p>
        </div>
      </div>
    );
  }

  if (error || !prueba) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#f5f7fa"
        }}
      >
        <div
          style={{
            background: "#fff",
            padding: "30px",
            borderRadius: "16px"
          }}
        >
          <h2>⚠️ No fue posible abrir la prueba</h2>
          <p>{error}</p>
        </div>
      </div>
    );
  }

  const idPrueba = Number(
    prueba.id_prueba_rh
  );

  const version = String(
    prueba.version || ""
  ).toLowerCase();

  const nombre = String(
    prueba.nombre || ""
  ).toLowerCase();

  const esRaven =
    idPrueba === 3 ||
    version === "raven-spm" ||
    nombre.includes(
      "matrices progresivas de raven"
    );

  const esBeta3 =
    idPrueba === 4 ||
    version === "beta-iii" ||
    nombre.includes("beta iii");

  if (esRaven) {
    return (
      <RavenRH
        token={token}
        pruebaBase={prueba}
      />
    );
  }

  if (esBeta3) {
    return (
      <Beta3RH
        token={token}
        pruebaBase={prueba}
      />
    );
  }

  return (
    <PruebaGenericaRH
      token={token}
      pruebaBase={prueba}
    />
  );
};

export default ResponderPruebaRH;
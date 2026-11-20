-- MariaDB dump 10.19  Distrib 10.4.32-MariaDB, for Win64 (AMD64)
--
-- Host: localhost    Database: pred_diag_emocional
-- ------------------------------------------------------
-- Server version	10.4.32-MariaDB

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `acciones_preventivas_empleados`
--

DROP TABLE IF EXISTS `acciones_preventivas_empleados`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `acciones_preventivas_empleados` (
  `id_accion` int(11) NOT NULL AUTO_INCREMENT,
  `id_empleado` int(11) NOT NULL,
  `id_usuario_registro` int(11) DEFAULT NULL,
  `fecha` datetime NOT NULL DEFAULT current_timestamp(),
  `tipo` enum('seguimiento','carga_trabajo','adaptacion','clima_laboral','conflicto','bienestar','prevencion','orientacion','otro') NOT NULL DEFAULT 'prevencion',
  `origen` enum('seguimiento','evaluacion','observacion_rh','observacion','solicitud_empleado','solicitud_supervisor','iniciativa_rh','otro') NOT NULL DEFAULT 'iniciativa_rh',
  `descripcion` text NOT NULL,
  `accion_realizada` text NOT NULL,
  `responsable` varchar(150) DEFAULT NULL,
  `resultado` enum('pendiente','en_revision','en_seguimiento','sin_cambio','mejora','mejora_observada','requiere_atencion','canalizacion_sugerida','completado','completada','requiere_nueva_revision') NOT NULL DEFAULT 'pendiente',
  `estado` enum('activa','abierto','en_seguimiento','cerrado','anulada') NOT NULL DEFAULT 'abierto',
  `proxima_accion` text DEFAULT NULL,
  `fecha_proxima_revision` datetime DEFAULT NULL,
  `fecha_cierre` datetime DEFAULT NULL,
  `id_usuario_cierre` int(11) DEFAULT NULL,
  `observaciones` text DEFAULT NULL,
  `motivo_anulacion` text DEFAULT NULL,
  `fecha_anulacion` datetime DEFAULT NULL,
  `id_usuario_anulacion` int(11) DEFAULT NULL,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `actualizado_en` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_accion`),
  KEY `idx_accion_empleado` (`id_empleado`),
  KEY `idx_accion_usuario` (`id_usuario_registro`),
  KEY `idx_accion_fecha` (`fecha`),
  KEY `idx_accion_tipo` (`tipo`),
  KEY `idx_accion_resultado` (`resultado`),
  KEY `idx_accion_revision` (`fecha_proxima_revision`),
  KEY `idx_accion_estado` (`estado`),
  KEY `idx_accion_usuario_anulacion` (`id_usuario_anulacion`),
  CONSTRAINT `fk_accion_empleado` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id_empleado`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_accion_usuario` FOREIGN KEY (`id_usuario_registro`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_accion_usuario_anulacion` FOREIGN KEY (`id_usuario_anulacion`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `acciones_preventivas_empleados`
--

LOCK TABLES `acciones_preventivas_empleados` WRITE;
/*!40000 ALTER TABLE `acciones_preventivas_empleados` DISABLE KEYS */;
INSERT INTO `acciones_preventivas_empleados` VALUES (1,4,36,'2026-11-12 14:25:00','prevencion','iniciativa_rh','ni','no','rh','pendiente','abierto','no','2026-11-12 14:25:00',NULL,NULL,'no',NULL,NULL,NULL,'2026-11-12 20:25:40','2026-11-12 20:25:40');
/*!40000 ALTER TABLE `acciones_preventivas_empleados` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `agenda_rh`
--

DROP TABLE IF EXISTS `agenda_rh`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `agenda_rh` (
  `id_agenda` int(11) NOT NULL AUTO_INCREMENT,
  `id_usuario_rh` int(11) NOT NULL,
  `titulo` varchar(150) NOT NULL,
  `tipo_actividad` enum('entrevista','reunion','llamada','seguimiento','evaluacion','recordatorio','actividad','otro') NOT NULL DEFAULT 'actividad',
  `fecha` date NOT NULL,
  `hora_inicio` time DEFAULT NULL,
  `hora_fin` time DEFAULT NULL,
  `descripcion` text DEFAULT NULL,
  `ubicacion` varchar(255) DEFAULT NULL,
  `enlace` varchar(500) DEFAULT NULL,
  `persona_relacionada` varchar(150) DEFAULT NULL,
  `recordatorio_activo` tinyint(1) NOT NULL DEFAULT 0,
  `minutos_recordatorio` int(11) DEFAULT NULL,
  `estado` enum('pendiente','realizado','cancelado') NOT NULL DEFAULT 'pendiente',
  `fecha_creacion` datetime NOT NULL DEFAULT current_timestamp(),
  `fecha_actualizacion` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_agenda`),
  KEY `idx_agenda_usuario` (`id_usuario_rh`),
  KEY `idx_agenda_fecha` (`fecha`),
  KEY `idx_agenda_estado` (`estado`),
  CONSTRAINT `fk_agenda_rh_usuario` FOREIGN KEY (`id_usuario_rh`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `agenda_rh`
--

LOCK TABLES `agenda_rh` WRITE;
/*!40000 ALTER TABLE `agenda_rh` DISABLE KEYS */;
INSERT INTO `agenda_rh` VALUES (1,19,'entrega','reunion','2026-11-25','10:00:00','12:00:00','avances','CDMX',NULL,NULL,1,30,'pendiente','2026-11-04 12:44:04','2026-11-04 12:44:04');
/*!40000 ALTER TABLE `agenda_rh` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auditoria_seguimiento_empleados`
--

DROP TABLE IF EXISTS `auditoria_seguimiento_empleados`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auditoria_seguimiento_empleados` (
  `id_auditoria` int(11) NOT NULL AUTO_INCREMENT,
  `id_seguimiento` int(11) NOT NULL,
  `id_empleado` int(11) NOT NULL,
  `id_usuario` int(11) DEFAULT NULL,
  `accion` enum('crear','actualizar','cerrar','anular') NOT NULL,
  `datos_anteriores` longtext DEFAULT NULL,
  `datos_nuevos` longtext DEFAULT NULL,
  `motivo` text DEFAULT NULL,
  `fecha` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_auditoria`),
  KEY `idx_auditoria_seguimiento` (`id_seguimiento`),
  KEY `idx_auditoria_empleado` (`id_empleado`),
  KEY `idx_auditoria_usuario` (`id_usuario`),
  CONSTRAINT `fk_auditoria_seg_empleado` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id_empleado`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_auditoria_seg_usuario` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auditoria_seguimiento_empleados`
--

LOCK TABLES `auditoria_seguimiento_empleados` WRITE;
/*!40000 ALTER TABLE `auditoria_seguimiento_empleados` DISABLE KEYS */;
INSERT INTO `auditoria_seguimiento_empleados` VALUES (1,1,3,19,'cerrar','null','{\"id_seguimiento\":1,\"id_empleado\":3,\"id_usuario_registro\":19,\"fecha\":\"2026-10-27T20:01:00.000Z\",\"tipo\":\"incidencia\",\"prioridad\":\"media\",\"motivo\":\"diferencia de opiniones\",\"participantes\":\"2 empleados\",\"version_empleado\":\"petra lo agredió primero\",\"version_supervisor\":\"ambos se agredieron pero comenzo petra\",\"observacion\":\"se pelearon por que petra se comió su comida\",\"accion_realizada\":\"petra le pagará su comida, y si vuelve a pasar habrá una suspensión\",\"acuerdo\":\"no volverán agarrar pertenencias que no son suyas\",\"compromiso_empresa\":\"estar al pendiente y revisar primero\",\"compromiso_empleado\":\"no tomar lo que no es de el\",\"resultado\":\"resuelto\",\"estado\":\"cerrado\",\"proxima_accion\":\"aun no\",\"fecha_proxima_accion\":\"2026-10-27T20:04:00.000Z\",\"fecha_cierre\":\"2026-10-27T20:04:24.000Z\",\"id_usuario_cierre\":19,\"motivo_anulacion\":null,\"fecha_anulacion\":null,\"id_usuario_anulacion\":null,\"creado_en\":\"2026-10-27T20:04:24.000Z\",\"actualizado_en\":\"2026-10-27T20:04:24.000Z\",\"usuario_registro\":\"Alberto González\",\"usuario_cierre\":\"Alberto González\",\"usuario_anulacion\":null}',NULL,'2026-10-27 14:04:24'),(2,2,4,36,'crear','null','{\"id_seguimiento\":2,\"id_empleado\":4,\"id_usuario_registro\":36,\"fecha\":\"2026-11-12T19:50:00.000Z\",\"tipo\":\"incidencia\",\"prioridad\":\"media\",\"motivo\":\"conflicto\",\"participantes\":\"2 empleados\",\"version_empleado\":\"El empleado marco a gredio al empleado Marilu\",\"version_supervisor\":\"todos confirman que marco empezo\",\"observacion\":\"se hicieron de palabras por comentario machista\",\"accion_realizada\":\"una suspencion a marco\",\"acuerdo\":\"se fue suspendido sin goce de sueldo 7 dias\",\"compromiso_empresa\":\"la siguiente se va despedido\",\"compromiso_empleado\":\"comenta que no volvera a pasar\",\"resultado\":\"pendiente\",\"estado\":\"abierto\",\"proxima_accion\":\"seguimiento\",\"fecha_proxima_accion\":\"2026-11-18T19:54:00.000Z\",\"fecha_cierre\":null,\"id_usuario_cierre\":null,\"motivo_anulacion\":null,\"fecha_anulacion\":null,\"id_usuario_anulacion\":null,\"creado_en\":\"2026-11-12T19:54:48.000Z\",\"actualizado_en\":\"2026-11-12T19:54:48.000Z\",\"usuario_registro\":\"PONCE\",\"usuario_cierre\":null,\"usuario_anulacion\":null}',NULL,'2026-11-12 13:54:48');
/*!40000 ALTER TABLE `auditoria_seguimiento_empleados` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `baremos_beta3`
--

DROP TABLE IF EXISTS `baremos_beta3`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `baremos_beta3` (
  `id_baremo_beta3` int(11) NOT NULL AUTO_INCREMENT,
  `id_prueba_rh` int(11) NOT NULL DEFAULT 4,
  `edad_min` int(11) NOT NULL,
  `edad_max` int(11) NOT NULL,
  `puntuacion_escalar` int(11) NOT NULL,
  `claves_min` int(11) DEFAULT NULL,
  `claves_max` int(11) DEFAULT NULL,
  `figuras_min` int(11) DEFAULT NULL,
  `figuras_max` int(11) DEFAULT NULL,
  `pares_min` int(11) DEFAULT NULL,
  `pares_max` int(11) DEFAULT NULL,
  `objetos_min` int(11) DEFAULT NULL,
  `objetos_max` int(11) DEFAULT NULL,
  `matrices_min` int(11) DEFAULT NULL,
  `matrices_max` int(11) DEFAULT NULL,
  `fuente` varchar(150) NOT NULL DEFAULT 'Beta III - Manual Moderno - Tabla A-1',
  PRIMARY KEY (`id_baremo_beta3`),
  UNIQUE KEY `uk_beta3_baremo` (`id_prueba_rh`,`edad_min`,`edad_max`,`puntuacion_escalar`)
) ENGINE=InnoDB AUTO_INCREMENT=172 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `baremos_beta3`
--

LOCK TABLES `baremos_beta3` WRITE;
/*!40000 ALTER TABLE `baremos_beta3` DISABLE KEYS */;
INSERT INTO `baremos_beta3` VALUES (1,4,16,17,1,0,28,0,2,NULL,2,0,5,0,6,'Beta III - Manual Moderno - Tabla A-1'),(2,4,16,17,2,29,39,3,4,3,11,6,9,7,8,'Beta III - Manual Moderno - Tabla A-1'),(3,4,16,17,3,40,45,5,6,12,22,10,12,9,10,'Beta III - Manual Moderno - Tabla A-1'),(4,4,16,17,4,46,50,7,8,23,27,13,15,11,12,'Beta III - Manual Moderno - Tabla A-1'),(5,4,16,17,5,51,55,9,10,28,31,16,17,13,14,'Beta III - Manual Moderno - Tabla A-1'),(6,4,16,17,6,56,60,11,11,32,34,18,18,15,15,'Beta III - Manual Moderno - Tabla A-1'),(7,4,16,17,7,61,66,12,13,35,36,19,19,16,16,'Beta III - Manual Moderno - Tabla A-1'),(8,4,16,17,8,67,71,14,15,37,38,20,20,17,17,'Beta III - Manual Moderno - Tabla A-1'),(9,4,16,17,9,72,75,16,16,39,40,21,21,18,18,'Beta III - Manual Moderno - Tabla A-1'),(10,4,16,17,10,76,79,17,17,41,41,NULL,NULL,19,19,'Beta III - Manual Moderno - Tabla A-1'),(11,4,16,17,11,80,84,18,18,42,43,22,22,20,20,'Beta III - Manual Moderno - Tabla A-1'),(12,4,16,17,12,85,89,19,19,44,44,23,23,21,22,'Beta III - Manual Moderno - Tabla A-1'),(13,4,16,17,13,90,95,NULL,NULL,45,46,NULL,NULL,23,23,'Beta III - Manual Moderno - Tabla A-1'),(14,4,16,17,14,96,101,20,20,47,47,24,24,24,24,'Beta III - Manual Moderno - Tabla A-1'),(15,4,16,17,15,102,107,21,21,48,48,NULL,NULL,25,25,'Beta III - Manual Moderno - Tabla A-1'),(16,4,16,17,16,108,115,22,22,49,50,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(17,4,16,17,17,116,127,23,23,51,52,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(18,4,16,17,18,128,135,24,24,53,53,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(19,4,16,17,19,136,140,NULL,NULL,54,55,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(20,4,18,19,1,0,24,0,2,NULL,0,0,4,0,4,'Beta III - Manual Moderno - Tabla A-1'),(21,4,18,19,2,25,36,3,4,1,10,5,7,5,6,'Beta III - Manual Moderno - Tabla A-1'),(22,4,18,19,3,37,44,5,6,11,20,8,10,7,8,'Beta III - Manual Moderno - Tabla A-1'),(23,4,18,19,4,45,49,7,8,21,26,11,13,9,10,'Beta III - Manual Moderno - Tabla A-1'),(24,4,18,19,5,50,54,9,10,27,30,14,15,11,12,'Beta III - Manual Moderno - Tabla A-1'),(25,4,18,19,6,55,59,11,11,31,34,16,17,13,14,'Beta III - Manual Moderno - Tabla A-1'),(26,4,18,19,7,60,65,12,13,35,36,18,19,15,16,'Beta III - Manual Moderno - Tabla A-1'),(27,4,18,19,8,66,70,14,15,37,38,20,20,17,17,'Beta III - Manual Moderno - Tabla A-1'),(28,4,18,19,9,71,74,16,16,39,39,21,21,18,18,'Beta III - Manual Moderno - Tabla A-1'),(29,4,18,19,10,75,77,17,17,40,41,NULL,NULL,19,19,'Beta III - Manual Moderno - Tabla A-1'),(30,4,18,19,11,78,82,18,18,42,43,22,22,20,20,'Beta III - Manual Moderno - Tabla A-1'),(31,4,18,19,12,83,86,19,19,44,44,23,23,21,21,'Beta III - Manual Moderno - Tabla A-1'),(32,4,18,19,13,87,92,NULL,NULL,45,46,NULL,NULL,22,22,'Beta III - Manual Moderno - Tabla A-1'),(33,4,18,19,14,93,99,20,20,47,47,24,24,23,23,'Beta III - Manual Moderno - Tabla A-1'),(34,4,18,19,15,100,105,21,21,48,48,NULL,NULL,24,24,'Beta III - Manual Moderno - Tabla A-1'),(35,4,18,19,16,106,113,22,22,49,50,NULL,NULL,25,25,'Beta III - Manual Moderno - Tabla A-1'),(36,4,18,19,17,114,124,23,23,51,51,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(37,4,18,19,18,125,134,24,24,52,53,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(38,4,18,19,19,135,140,NULL,NULL,54,55,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(39,4,20,24,1,0,20,0,1,NULL,-2,0,3,0,2,'Beta III - Manual Moderno - Tabla A-1'),(40,4,20,24,2,21,32,2,3,-1,7,4,6,3,4,'Beta III - Manual Moderno - Tabla A-1'),(41,4,20,24,3,33,41,4,5,8,18,7,9,5,7,'Beta III - Manual Moderno - Tabla A-1'),(42,4,20,24,4,42,47,6,7,19,24,10,12,8,9,'Beta III - Manual Moderno - Tabla A-1'),(43,4,20,24,5,48,52,8,9,25,29,13,15,10,11,'Beta III - Manual Moderno - Tabla A-1'),(44,4,20,24,6,53,56,10,11,30,32,16,17,12,13,'Beta III - Manual Moderno - Tabla A-1'),(45,4,20,24,7,57,63,12,13,33,34,18,19,14,15,'Beta III - Manual Moderno - Tabla A-1'),(46,4,20,24,8,64,68,14,15,35,37,20,20,16,16,'Beta III - Manual Moderno - Tabla A-1'),(47,4,20,24,9,69,72,16,16,38,39,21,21,17,17,'Beta III - Manual Moderno - Tabla A-1'),(48,4,20,24,10,73,76,17,17,40,41,NULL,NULL,18,19,'Beta III - Manual Moderno - Tabla A-1'),(49,4,20,24,11,77,81,18,18,42,43,22,22,20,20,'Beta III - Manual Moderno - Tabla A-1'),(50,4,20,24,12,82,86,19,19,44,44,23,23,21,21,'Beta III - Manual Moderno - Tabla A-1'),(51,4,20,24,13,87,92,NULL,NULL,45,46,NULL,NULL,22,22,'Beta III - Manual Moderno - Tabla A-1'),(52,4,20,24,14,93,98,20,20,47,47,24,24,23,23,'Beta III - Manual Moderno - Tabla A-1'),(53,4,20,24,15,99,103,21,21,48,48,NULL,NULL,24,24,'Beta III - Manual Moderno - Tabla A-1'),(54,4,20,24,16,104,110,22,22,49,50,NULL,NULL,25,25,'Beta III - Manual Moderno - Tabla A-1'),(55,4,20,24,17,111,119,23,23,51,51,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(56,4,20,24,18,120,132,24,24,52,53,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(57,4,20,24,19,133,140,NULL,NULL,54,55,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(58,4,25,34,1,0,16,0,1,NULL,-4,0,2,0,1,'Beta III - Manual Moderno - Tabla A-1'),(59,4,25,34,2,17,29,2,2,-3,4,3,5,2,4,'Beta III - Manual Moderno - Tabla A-1'),(60,4,25,34,3,30,39,3,4,5,16,6,8,5,6,'Beta III - Manual Moderno - Tabla A-1'),(61,4,25,34,4,40,45,5,6,17,23,9,12,7,8,'Beta III - Manual Moderno - Tabla A-1'),(62,4,25,34,5,46,51,7,8,24,28,13,15,9,10,'Beta III - Manual Moderno - Tabla A-1'),(63,4,25,34,6,52,55,9,10,29,31,16,17,11,12,'Beta III - Manual Moderno - Tabla A-1'),(64,4,25,34,7,56,61,11,12,32,33,18,19,13,14,'Beta III - Manual Moderno - Tabla A-1'),(65,4,25,34,8,62,67,13,14,34,36,20,20,15,15,'Beta III - Manual Moderno - Tabla A-1'),(66,4,25,34,9,68,70,15,16,37,38,21,21,16,17,'Beta III - Manual Moderno - Tabla A-1'),(67,4,25,34,10,71,73,17,17,39,40,NULL,NULL,18,18,'Beta III - Manual Moderno - Tabla A-1'),(68,4,25,34,11,74,79,18,18,41,42,22,22,19,19,'Beta III - Manual Moderno - Tabla A-1'),(69,4,25,34,12,80,84,19,19,43,44,23,23,20,20,'Beta III - Manual Moderno - Tabla A-1'),(70,4,25,34,13,85,88,NULL,NULL,45,46,NULL,NULL,21,21,'Beta III - Manual Moderno - Tabla A-1'),(71,4,25,34,14,89,93,20,20,47,47,24,24,22,22,'Beta III - Manual Moderno - Tabla A-1'),(72,4,25,34,15,94,101,21,21,48,48,NULL,NULL,23,23,'Beta III - Manual Moderno - Tabla A-1'),(73,4,25,34,16,102,107,22,22,49,50,NULL,NULL,24,24,'Beta III - Manual Moderno - Tabla A-1'),(74,4,25,34,17,108,116,23,23,51,51,NULL,NULL,25,25,'Beta III - Manual Moderno - Tabla A-1'),(75,4,25,34,18,117,128,24,24,52,52,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(76,4,25,34,19,129,140,NULL,NULL,53,55,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(77,4,35,44,1,0,14,0,1,NULL,-6,0,1,0,1,'Beta III - Manual Moderno - Tabla A-1'),(78,4,35,44,2,15,25,2,2,-5,2,2,4,2,3,'Beta III - Manual Moderno - Tabla A-1'),(79,4,35,44,3,26,35,3,4,3,13,5,6,4,5,'Beta III - Manual Moderno - Tabla A-1'),(80,4,35,44,4,36,42,5,6,14,22,7,10,6,7,'Beta III - Manual Moderno - Tabla A-1'),(81,4,35,44,5,43,49,7,8,23,26,11,14,8,9,'Beta III - Manual Moderno - Tabla A-1'),(82,4,35,44,6,50,53,9,10,27,30,15,17,10,10,'Beta III - Manual Moderno - Tabla A-1'),(83,4,35,44,7,54,57,11,11,31,32,18,19,11,12,'Beta III - Manual Moderno - Tabla A-1'),(84,4,35,44,8,58,62,12,13,33,34,20,20,13,14,'Beta III - Manual Moderno - Tabla A-1'),(85,4,35,44,9,63,67,14,15,35,36,21,21,15,15,'Beta III - Manual Moderno - Tabla A-1'),(86,4,35,44,10,68,72,16,16,37,38,NULL,NULL,16,17,'Beta III - Manual Moderno - Tabla A-1'),(87,4,35,44,11,73,78,17,17,39,41,22,22,18,19,'Beta III - Manual Moderno - Tabla A-1'),(88,4,35,44,12,79,83,18,18,42,43,23,23,20,20,'Beta III - Manual Moderno - Tabla A-1'),(89,4,35,44,13,84,86,19,19,44,44,NULL,NULL,21,21,'Beta III - Manual Moderno - Tabla A-1'),(90,4,35,44,14,87,91,20,20,45,46,24,24,22,22,'Beta III - Manual Moderno - Tabla A-1'),(91,4,35,44,15,92,99,21,21,47,47,NULL,NULL,23,23,'Beta III - Manual Moderno - Tabla A-1'),(92,4,35,44,16,100,104,22,22,48,49,NULL,NULL,24,24,'Beta III - Manual Moderno - Tabla A-1'),(93,4,35,44,17,105,111,23,23,50,50,NULL,NULL,25,25,'Beta III - Manual Moderno - Tabla A-1'),(94,4,35,44,18,112,123,24,24,51,51,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(95,4,35,44,19,124,140,NULL,NULL,52,55,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(96,4,45,54,1,0,12,0,0,NULL,-8,0,1,0,0,'Beta III - Manual Moderno - Tabla A-1'),(97,4,45,54,2,13,20,1,1,-7,0,2,4,1,2,'Beta III - Manual Moderno - Tabla A-1'),(98,4,45,54,3,21,30,2,2,1,11,5,6,3,4,'Beta III - Manual Moderno - Tabla A-1'),(99,4,45,54,4,31,38,3,4,12,20,7,9,5,5,'Beta III - Manual Moderno - Tabla A-1'),(100,4,45,54,5,39,42,5,6,21,24,10,12,6,7,'Beta III - Manual Moderno - Tabla A-1'),(101,4,45,54,6,43,48,7,8,25,28,13,15,8,9,'Beta III - Manual Moderno - Tabla A-1'),(102,4,45,54,7,49,53,9,10,29,30,16,17,10,10,'Beta III - Manual Moderno - Tabla A-1'),(103,4,45,54,8,54,57,11,12,31,32,18,19,11,12,'Beta III - Manual Moderno - Tabla A-1'),(104,4,45,54,9,58,61,13,14,33,34,20,20,13,14,'Beta III - Manual Moderno - Tabla A-1'),(105,4,45,54,10,62,66,15,15,35,37,21,21,15,16,'Beta III - Manual Moderno - Tabla A-1'),(106,4,45,54,11,67,71,16,16,38,39,22,22,17,18,'Beta III - Manual Moderno - Tabla A-1'),(107,4,45,54,12,72,75,17,17,40,41,23,23,19,19,'Beta III - Manual Moderno - Tabla A-1'),(108,4,45,54,13,76,80,18,18,42,43,NULL,NULL,20,20,'Beta III - Manual Moderno - Tabla A-1'),(109,4,45,54,14,81,85,19,19,44,44,24,24,21,21,'Beta III - Manual Moderno - Tabla A-1'),(110,4,45,54,15,86,89,20,20,45,46,NULL,NULL,22,22,'Beta III - Manual Moderno - Tabla A-1'),(111,4,45,54,16,90,93,21,21,47,48,NULL,NULL,23,23,'Beta III - Manual Moderno - Tabla A-1'),(112,4,45,54,17,94,102,22,22,49,49,NULL,NULL,24,24,'Beta III - Manual Moderno - Tabla A-1'),(113,4,45,54,18,103,112,23,23,50,50,NULL,NULL,25,25,'Beta III - Manual Moderno - Tabla A-1'),(114,4,45,54,19,113,140,24,24,51,55,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(115,4,55,64,1,0,10,0,0,NULL,-9,0,0,0,0,'Beta III - Manual Moderno - Tabla A-1'),(116,4,55,64,2,11,18,1,1,-8,-1,1,2,1,1,'Beta III - Manual Moderno - Tabla A-1'),(117,4,55,64,3,19,25,2,2,0,9,3,4,2,2,'Beta III - Manual Moderno - Tabla A-1'),(118,4,55,64,4,26,31,3,4,10,18,5,6,3,4,'Beta III - Manual Moderno - Tabla A-1'),(119,4,55,64,5,32,37,5,5,19,22,7,9,5,5,'Beta III - Manual Moderno - Tabla A-1'),(120,4,55,64,6,38,41,6,7,23,26,10,12,6,7,'Beta III - Manual Moderno - Tabla A-1'),(121,4,55,64,7,42,46,8,8,27,28,13,15,8,9,'Beta III - Manual Moderno - Tabla A-1'),(122,4,55,64,8,47,50,9,10,29,30,16,17,10,10,'Beta III - Manual Moderno - Tabla A-1'),(123,4,55,64,9,51,55,11,12,31,32,18,19,11,12,'Beta III - Manual Moderno - Tabla A-1'),(124,4,55,64,10,56,59,13,13,33,34,20,20,13,14,'Beta III - Manual Moderno - Tabla A-1'),(125,4,55,64,11,60,63,14,14,35,36,21,21,15,15,'Beta III - Manual Moderno - Tabla A-1'),(126,4,55,64,12,64,67,15,15,37,38,22,22,16,17,'Beta III - Manual Moderno - Tabla A-1'),(127,4,55,64,13,68,72,16,17,39,40,23,23,18,18,'Beta III - Manual Moderno - Tabla A-1'),(128,4,55,64,14,73,77,18,18,41,42,NULL,NULL,19,19,'Beta III - Manual Moderno - Tabla A-1'),(129,4,55,64,15,78,82,19,19,43,44,24,24,20,20,'Beta III - Manual Moderno - Tabla A-1'),(130,4,55,64,16,83,88,20,20,45,46,NULL,NULL,21,21,'Beta III - Manual Moderno - Tabla A-1'),(131,4,55,64,17,89,93,21,21,47,48,NULL,NULL,22,22,'Beta III - Manual Moderno - Tabla A-1'),(132,4,55,64,18,94,105,22,22,49,50,NULL,NULL,23,23,'Beta III - Manual Moderno - Tabla A-1'),(133,4,55,64,19,106,140,23,24,51,55,NULL,NULL,24,25,'Beta III - Manual Moderno - Tabla A-1'),(134,4,65,74,1,0,9,NULL,NULL,NULL,-11,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(135,4,65,74,2,10,15,0,0,-10,-2,0,1,0,1,'Beta III - Manual Moderno - Tabla A-1'),(136,4,65,74,3,16,22,1,1,-1,7,2,2,2,2,'Beta III - Manual Moderno - Tabla A-1'),(137,4,65,74,4,23,26,2,2,8,15,3,4,3,3,'Beta III - Manual Moderno - Tabla A-1'),(138,4,65,74,5,27,30,3,4,16,20,5,6,4,4,'Beta III - Manual Moderno - Tabla A-1'),(139,4,65,74,6,31,35,5,5,21,23,7,9,5,5,'Beta III - Manual Moderno - Tabla A-1'),(140,4,65,74,7,36,40,6,7,24,26,10,11,6,7,'Beta III - Manual Moderno - Tabla A-1'),(141,4,65,74,8,41,44,8,8,27,28,12,13,8,9,'Beta III - Manual Moderno - Tabla A-1'),(142,4,65,74,9,45,49,9,10,29,30,14,15,10,10,'Beta III - Manual Moderno - Tabla A-1'),(143,4,65,74,10,50,53,11,11,31,32,16,17,11,12,'Beta III - Manual Moderno - Tabla A-1'),(144,4,65,74,11,54,58,12,12,33,34,18,19,13,14,'Beta III - Manual Moderno - Tabla A-1'),(145,4,65,74,12,59,63,13,13,35,36,20,20,15,15,'Beta III - Manual Moderno - Tabla A-1'),(146,4,65,74,13,64,67,14,14,37,38,21,21,16,16,'Beta III - Manual Moderno - Tabla A-1'),(147,4,65,74,14,68,72,15,15,39,40,22,22,17,17,'Beta III - Manual Moderno - Tabla A-1'),(148,4,65,74,15,73,77,16,17,41,42,23,23,18,18,'Beta III - Manual Moderno - Tabla A-1'),(149,4,65,74,16,78,83,18,18,43,44,24,24,19,19,'Beta III - Manual Moderno - Tabla A-1'),(150,4,65,74,17,84,88,19,19,45,46,NULL,NULL,20,20,'Beta III - Manual Moderno - Tabla A-1'),(151,4,65,74,18,89,97,20,20,47,48,NULL,NULL,21,21,'Beta III - Manual Moderno - Tabla A-1'),(152,4,65,74,19,98,140,21,24,49,55,NULL,NULL,22,25,'Beta III - Manual Moderno - Tabla A-1'),(153,4,75,89,1,0,3,NULL,NULL,NULL,-11,NULL,NULL,NULL,NULL,'Beta III - Manual Moderno - Tabla A-1'),(154,4,75,89,2,4,7,NULL,NULL,-10,-4,NULL,NULL,0,0,'Beta III - Manual Moderno - Tabla A-1'),(155,4,75,89,3,8,11,0,0,-3,4,0,0,1,1,'Beta III - Manual Moderno - Tabla A-1'),(156,4,75,89,4,12,14,1,1,5,10,1,1,2,2,'Beta III - Manual Moderno - Tabla A-1'),(157,4,75,89,5,15,19,2,2,11,15,2,2,3,3,'Beta III - Manual Moderno - Tabla A-1'),(158,4,75,89,6,20,24,3,3,16,18,3,4,4,4,'Beta III - Manual Moderno - Tabla A-1'),(159,4,75,89,7,25,28,4,4,19,20,5,6,5,5,'Beta III - Manual Moderno - Tabla A-1'),(160,4,75,89,8,29,33,5,6,21,23,7,8,6,6,'Beta III - Manual Moderno - Tabla A-1'),(161,4,75,89,9,34,39,7,7,24,25,9,10,7,8,'Beta III - Manual Moderno - Tabla A-1'),(162,4,75,89,10,40,45,8,8,26,28,11,12,9,9,'Beta III - Manual Moderno - Tabla A-1'),(163,4,75,89,11,46,51,9,9,29,30,13,14,10,11,'Beta III - Manual Moderno - Tabla A-1'),(164,4,75,89,12,52,56,10,11,31,32,15,16,12,12,'Beta III - Manual Moderno - Tabla A-1'),(165,4,75,89,13,57,61,12,12,33,34,17,18,13,14,'Beta III - Manual Moderno - Tabla A-1'),(166,4,75,89,14,62,66,13,13,35,36,19,20,15,15,'Beta III - Manual Moderno - Tabla A-1'),(167,4,75,89,15,67,71,14,14,37,38,21,21,16,16,'Beta III - Manual Moderno - Tabla A-1'),(168,4,75,89,16,72,75,15,15,39,40,22,22,17,17,'Beta III - Manual Moderno - Tabla A-1'),(169,4,75,89,17,76,81,16,16,41,42,23,23,18,18,'Beta III - Manual Moderno - Tabla A-1'),(170,4,75,89,18,82,89,17,17,43,44,24,24,19,19,'Beta III - Manual Moderno - Tabla A-1'),(171,4,75,89,19,90,140,18,24,45,55,NULL,NULL,20,25,'Beta III - Manual Moderno - Tabla A-1');
/*!40000 ALTER TABLE `baremos_beta3` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `baremos_raven`
--

DROP TABLE IF EXISTS `baremos_raven`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `baremos_raven` (
  `id_baremo` int(11) NOT NULL AUTO_INCREMENT,
  `id_prueba_rh` int(11) NOT NULL,
  `poblacion` varchar(100) NOT NULL,
  `edad_min` int(11) NOT NULL,
  `edad_max` int(11) NOT NULL,
  `percentil` int(11) NOT NULL,
  `puntaje_min` int(11) NOT NULL,
  `fuente` varchar(255) DEFAULT NULL,
  `activo` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id_baremo`),
  UNIQUE KEY `uk_baremo_raven` (`id_prueba_rh`,`poblacion`,`edad_min`,`edad_max`,`percentil`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `baremos_raven`
--

LOCK TABLES `baremos_raven` WRITE;
/*!40000 ALTER TABLE `baremos_raven` DISABLE KEYS */;
INSERT INTO `baremos_raven` VALUES (1,3,'Aguascalientes México - muestra total',22,44,95,56,'Aguascalientes 1999-2000',1),(2,3,'Aguascalientes México - muestra total',22,44,90,53,'Aguascalientes 1999-2000',1),(3,3,'Aguascalientes México - muestra total',22,44,75,49,'Aguascalientes 1999-2000',1),(4,3,'Aguascalientes México - muestra total',22,44,50,44,'Aguascalientes 1999-2000',1),(5,3,'Aguascalientes México - muestra total',22,44,25,39,'Aguascalientes 1999-2000',1),(6,3,'Aguascalientes México - muestra total',22,44,10,30,'Aguascalientes 1999-2000',1),(7,3,'Aguascalientes México - muestra total',22,44,5,25,'Aguascalientes 1999-2000',1);
/*!40000 ALTER TABLE `baremos_raven` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `canalizacion_historial`
--

DROP TABLE IF EXISTS `canalizacion_historial`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `canalizacion_historial` (
  `id_historial` int(11) NOT NULL AUTO_INCREMENT,
  `id_canalizacion` int(11) NOT NULL,
  `id_usuario` int(11) DEFAULT NULL,
  `evento` varchar(120) NOT NULL,
  `detalle` text DEFAULT NULL,
  `fecha_evento` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_historial`),
  KEY `idx_hist_canalizacion` (`id_canalizacion`),
  KEY `idx_hist_usuario` (`id_usuario`),
  KEY `idx_hist_fecha` (`fecha_evento`),
  CONSTRAINT `fk_hist_canalizacion` FOREIGN KEY (`id_canalizacion`) REFERENCES `canalizaciones` (`id_canalizacion`) ON DELETE CASCADE,
  CONSTRAINT `fk_hist_usuario` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=62 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `canalizacion_historial`
--

LOCK TABLES `canalizacion_historial` WRITE;
/*!40000 ALTER TABLE `canalizacion_historial` DISABLE KEYS */;
INSERT INTO `canalizacion_historial` VALUES (1,1,19,'Canalización creada desde recomendación del sistema','Recomendación #7. Origen: otra_prueba. Referencia: 2.','2026-11-03 12:58:45'),(2,2,19,'Canalización creada desde recomendación del sistema','Recomendación #3. Origen: nom035. Referencia: 6.','2026-11-03 13:10:34'),(3,2,19,'Opciones enviadas al empleado','Se enviaron 4 opciones: Abraham Rivera Salinas, Abraham Rivera Salinas, ARELY HERNANDEZ LUCAS, Liliana','2026-11-03 13:36:54'),(4,2,19,'Opciones enviadas al empleado','Se enviaron 4 opciones: Abraham Rivera Salinas, Abraham Rivera Salinas, ARELY HERNANDEZ LUCAS, Liliana','2026-11-03 14:00:09'),(5,2,19,'Opciones enviadas al empleado','Se enviaron 4 opciones: Abraham Rivera Salinas, Abraham Rivera Salinas, ARELY HERNANDEZ LUCAS, Liliana','2026-11-03 14:00:31'),(6,2,19,'Opciones enviadas al empleado','Se enviaron 4 opciones: Abraham Rivera Salinas, Abraham Rivera Salinas, ARELY HERNANDEZ LUCAS, Liliana','2026-11-03 14:28:02'),(7,2,19,'Opciones enviadas al empleado','Se enviaron 4 opciones: Abraham Rivera Salinas, Abraham Rivera Salinas, ARELY HERNANDEZ LUCAS, Liliana','2026-11-03 14:41:22'),(8,2,NULL,'Empleado seleccionó profesional','Profesional seleccionado: Liliana','2026-11-03 14:41:59'),(9,1,19,'Opciones enviadas al empleado','Se enviaron 4 opciones: Abraham Rivera Salinas, Abraham Rivera Salinas, ARELY HERNANDEZ LUCAS, Liliana','2026-11-03 14:42:46'),(10,1,NULL,'Empleado seleccionó profesional','Profesional seleccionado: ARELY HERNANDEZ LUCAS','2026-11-03 14:42:58'),(11,1,19,'Canalización cerrada','ninguno','2026-11-03 14:43:30'),(12,2,19,'Canalización cerrada','no','2026-11-03 14:44:48'),(13,3,19,'Canalización creada desde recomendación del sistema','Recomendación #9. Origen: otra_prueba. Referencia: 6.','2026-11-03 15:45:10'),(14,3,19,'Opciones enviadas al empleado','Se enviaron 4 opciones: Abraham Rivera Salinas, Abraham Rivera Salinas, ARELY HERNANDEZ LUCAS, Liliana','2026-11-03 17:31:28'),(15,3,19,'Opciones enviadas al empleado','Se enviaron 4 opciones: Abraham Rivera Salinas, Abraham Rivera Salinas, ARELY HERNANDEZ LUCAS, Liliana','2026-11-03 17:47:26'),(16,3,19,'Opciones enviadas al empleado','Se enviaron 4 opciones: Abraham Rivera Salinas, Abraham Rivera Salinas, ARELY HERNANDEZ LUCAS, Liliana','2026-11-03 17:53:25'),(17,3,19,'Opciones enviadas al empleado','Se enviaron 4 opciones: Abraham Rivera Salinas, Abraham Rivera Salinas, ARELY HERNANDEZ LUCAS, Liliana','2026-11-03 17:54:25'),(18,3,19,'Opciones enviadas al empleado','Se enviaron 1 opciones: Liliana','2026-11-03 17:57:14'),(19,3,19,'Opciones enviadas al empleado','Se enviaron 1 opciones: Liliana','2026-11-03 17:58:08'),(20,3,19,'Opciones enviadas al empleado','Se enviaron 1 opciones: Liliana','2026-11-03 17:58:20'),(21,3,19,'Opciones enviadas al empleado','Se enviaron 1 opciones: Liliana','2026-11-03 18:00:18'),(22,3,19,'Opciones enviadas al empleado','Se enviaron 1 opciones: Liliana','2026-11-04 10:21:23'),(23,3,19,'Criterios de ranking actualizados','Modalidad: indistinta. Áreas: 1, 3, 4','2026-11-05 10:41:25'),(24,3,19,'Criterios de ranking actualizados','Modalidad: indistinta. Áreas: 1, 3, 5','2026-11-05 10:42:11'),(25,3,19,'Criterios de ranking actualizados','Modalidad: indistinta. Áreas: 1, 3, 9, 7','2026-11-05 10:42:37'),(26,3,19,'Criterios de ranking actualizados','Modalidad: indistinta. Áreas: 1, 3, 9, 7, 2','2026-11-05 10:42:54'),(27,3,19,'Criterios de ranking actualizados','Modalidad: indistinta. Áreas: 1, 3, 9, 7, 2','2026-11-05 10:45:11'),(28,3,19,'Criterios de ranking actualizados','Modalidad: indistinta. Áreas: 1, 3, 9, 7, 2, 5','2026-11-05 10:45:20'),(29,3,19,'Opciones enviadas al empleado','Se enviaron 3 opciones: ARELY HERNANDEZ LUCAS, Abraham Rivera Salinas, Liliana','2026-11-05 10:45:44'),(30,3,NULL,'Empleado seleccionó profesional','Profesional seleccionado: ARELY HERNANDEZ LUCAS','2026-11-05 10:46:30'),(31,4,19,'Canalización creada por RH','Origen: observacion_rh. Motivo: problemas laborales','2026-11-05 10:55:31'),(32,4,19,'Criterios de ranking actualizados','Modalidad: indistinta. Áreas: 3, 4, 13, 2, 1','2026-11-05 11:05:39'),(33,4,19,'Opciones enviadas al empleado','Se enviaron 3 opciones: Abraham Rivera Salinas, Liliana, ARELY HERNANDEZ LUCAS','2026-11-05 11:05:53'),(34,4,NULL,'Empleado seleccionó profesional','Profesional seleccionado: Abraham Rivera Salinas','2026-11-05 11:06:16'),(35,5,19,'Canalización creada por RH','Origen: observacion_rh. Motivo: no se adapta','2026-11-05 11:46:49'),(36,5,19,'Criterios de ranking actualizados','Modalidad: indistinta. Áreas: 1, 2, 5, 6, 7','2026-11-05 11:47:04'),(37,5,19,'Opciones enviadas al empleado','Se enviaron 2 opciones: ARELY HERNANDEZ LUCAS, Liliana','2026-11-05 11:47:13'),(38,5,NULL,'Empleado seleccionó profesional','Profesional seleccionado: Liliana','2026-11-05 11:51:01'),(39,5,19,'Canalización cerrada','ninguna','2026-11-05 12:00:24'),(40,4,19,'Canalización cerrada','no','2026-11-05 12:00:42'),(41,6,19,'Canalización creada por RH','Origen: observacion_rh. Motivo: no','2026-11-05 13:20:53'),(42,6,19,'Criterios de ranking actualizados','Modalidad: indistinta. Áreas: 2, 3','2026-11-05 13:21:20'),(43,6,19,'Opciones enviadas al empleado','Se enviaron 3 opciones: julieta lopez, ARELY HERNANDEZ LUCAS, Liliana','2026-11-05 13:21:47'),(44,6,NULL,'Empleado seleccionó profesional','Profesional seleccionado: julieta lopez','2026-11-05 13:22:07'),(45,7,36,'Canalización creada desde recomendación del sistema','Recomendación #11. Origen: otra_prueba. Referencia: 7.','2026-11-12 14:31:46'),(46,7,36,'Criterios de ranking actualizados','Modalidad: indistinta. Áreas: 1','2026-11-12 15:37:22'),(47,7,36,'Opciones enviadas al empleado','Se enviaron 3 opciones: Liliana, ARELY HERNANDEZ LUCAS, Abraham Rivera Salinas','2026-11-12 15:37:39'),(48,7,NULL,'Empleado seleccionó profesional','Profesional seleccionado: Liliana','2026-11-12 15:39:29'),(49,7,2,'Profesional rechazó la canalización','Psicólogo: Liliana. Motivo: periodo_ausencia. Observación: me voy de vacaciones','2026-11-12 16:39:11'),(50,7,36,'Opciones enviadas al empleado','Se enviaron 3 opciones: Liliana, ARELY HERNANDEZ LUCAS, Abraham Rivera Salinas','2026-11-12 16:41:30'),(51,7,NULL,'Empleado seleccionó profesional','Profesional seleccionado: Liliana','2026-11-12 16:41:47'),(52,7,2,'Profesional rechazó la canalización','Psicólogo: Liliana. Motivo: periodo_ausencia. Observación: vacaciones','2026-11-12 16:44:05'),(53,7,36,'Opciones enviadas al empleado','Se enviaron 2 opciones: ARELY HERNANDEZ LUCAS, Abraham Rivera Salinas','2026-11-12 17:08:39'),(54,7,NULL,'Empleado seleccionó profesional','Profesional seleccionado: ARELY HERNANDEZ LUCAS','2026-11-12 17:08:54'),(55,5,2,'Profesional aceptó la canalización','Psicólogo: Liliana','2026-11-12 17:11:35'),(56,2,2,'Profesional aceptó la canalización','Psicólogo: Liliana','2026-11-12 17:11:39'),(57,5,2,'Atención iniciada','Se creó el expediente clínico 4 a partir de una canalización aceptada','2026-11-12 17:40:10'),(58,5,2,'Atención iniciada','Paciente existente vinculado al expediente clínico 4','2026-11-12 17:46:14'),(59,5,2,'Atención iniciada','Paciente existente vinculado al expediente clínico 4','2026-11-12 17:46:36'),(60,2,2,'Atención iniciada','Paciente existente vinculado al expediente clínico 4','2026-11-12 17:46:57'),(61,5,2,'Atención iniciada','Paciente existente vinculado al expediente clínico 4','2026-11-12 17:52:06');
/*!40000 ALTER TABLE `canalizacion_historial` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `canalizacion_profesionales`
--

DROP TABLE IF EXISTS `canalizacion_profesionales`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `canalizacion_profesionales` (
  `id_opcion` int(11) NOT NULL AUTO_INCREMENT,
  `id_canalizacion` int(11) NOT NULL,
  `tipo_profesional` enum('mirrorsoul','externo') NOT NULL,
  `id_psicologo` int(11) DEFAULT NULL,
  `id_profesional_externo` int(11) DEFAULT NULL,
  `orden` int(11) NOT NULL DEFAULT 1,
  `enviado` tinyint(1) NOT NULL DEFAULT 0,
  `seleccionado` tinyint(1) NOT NULL DEFAULT 0,
  `fecha_envio` datetime DEFAULT NULL,
  `fecha_seleccion` datetime DEFAULT NULL,
  `estado_respuesta_profesional` enum('pendiente','aceptada','rechazada') NOT NULL DEFAULT 'pendiente',
  `motivo_rechazo_profesional` enum('agenda_llena','sin_disponibilidad_horario','no_atiende_caso','periodo_ausencia','capacidad_maxima','otro') DEFAULT NULL,
  `observacion_respuesta_profesional` text DEFAULT NULL,
  `fecha_respuesta_profesional` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_opcion`),
  KEY `idx_can_prof_canalizacion` (`id_canalizacion`),
  KEY `idx_can_prof_psicologo` (`id_psicologo`),
  KEY `idx_can_prof_externo` (`id_profesional_externo`),
  KEY `idx_can_prof_seleccionado` (`seleccionado`),
  CONSTRAINT `fk_can_prof_canalizacion` FOREIGN KEY (`id_canalizacion`) REFERENCES `canalizaciones` (`id_canalizacion`) ON DELETE CASCADE,
  CONSTRAINT `fk_can_prof_externo` FOREIGN KEY (`id_profesional_externo`) REFERENCES `profesionales_externos` (`id_profesional_externo`),
  CONSTRAINT `fk_can_prof_psicologo` FOREIGN KEY (`id_psicologo`) REFERENCES `psicologos` (`id_psicologo`),
  CONSTRAINT `chk_tipo_profesional` CHECK (`tipo_profesional` = 'mirrorsoul' and `id_psicologo` is not null and `id_profesional_externo` is null or `tipo_profesional` = 'externo' and `id_psicologo` is null and `id_profesional_externo` is not null)
) ENGINE=InnoDB AUTO_INCREMENT=65 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `canalizacion_profesionales`
--

LOCK TABLES `canalizacion_profesionales` WRITE;
/*!40000 ALTER TABLE `canalizacion_profesionales` DISABLE KEYS */;
INSERT INTO `canalizacion_profesionales` VALUES (17,2,'mirrorsoul',8,NULL,1,1,0,'2026-11-03 14:41:22',NULL,'pendiente',NULL,NULL,NULL,'2026-11-03 20:41:22'),(18,2,'mirrorsoul',10,NULL,2,1,0,'2026-11-03 14:41:22',NULL,'pendiente',NULL,NULL,NULL,'2026-11-03 20:41:22'),(19,2,'mirrorsoul',9,NULL,3,1,0,'2026-11-03 14:41:22',NULL,'pendiente',NULL,NULL,NULL,'2026-11-03 20:41:22'),(20,2,'mirrorsoul',1,NULL,4,1,1,'2026-11-03 14:41:22','2026-11-03 14:41:58','aceptada',NULL,NULL,'2026-11-12 17:11:39','2026-11-03 20:41:22'),(21,1,'mirrorsoul',8,NULL,1,1,0,'2026-11-03 14:42:46',NULL,'pendiente',NULL,NULL,NULL,'2026-11-03 20:42:46'),(22,1,'mirrorsoul',10,NULL,2,1,0,'2026-11-03 14:42:46',NULL,'pendiente',NULL,NULL,NULL,'2026-11-03 20:42:46'),(23,1,'mirrorsoul',9,NULL,3,1,1,'2026-11-03 14:42:46','2026-11-03 14:42:58','pendiente',NULL,NULL,NULL,'2026-11-03 20:42:46'),(24,1,'mirrorsoul',1,NULL,4,1,0,'2026-11-03 14:42:46',NULL,'pendiente',NULL,NULL,NULL,'2026-11-03 20:42:46'),(46,3,'mirrorsoul',9,NULL,1,1,1,'2026-11-05 10:45:44','2026-11-05 10:46:30','pendiente',NULL,NULL,NULL,'2026-11-05 16:45:44'),(47,3,'mirrorsoul',8,NULL,2,1,0,'2026-11-05 10:45:44',NULL,'pendiente',NULL,NULL,NULL,'2026-11-05 16:45:44'),(48,3,'mirrorsoul',1,NULL,3,1,0,'2026-11-05 10:45:44',NULL,'pendiente',NULL,NULL,NULL,'2026-11-05 16:45:44'),(49,4,'mirrorsoul',8,NULL,1,1,1,'2026-11-05 11:05:53','2026-11-05 11:06:16','pendiente',NULL,NULL,NULL,'2026-11-05 17:05:53'),(50,4,'mirrorsoul',1,NULL,2,1,0,'2026-11-05 11:05:53',NULL,'pendiente',NULL,NULL,NULL,'2026-11-05 17:05:53'),(51,4,'mirrorsoul',9,NULL,3,1,0,'2026-11-05 11:05:53',NULL,'pendiente',NULL,NULL,NULL,'2026-11-05 17:05:53'),(52,5,'mirrorsoul',9,NULL,1,1,0,'2026-11-05 11:47:13',NULL,'pendiente',NULL,NULL,NULL,'2026-11-05 17:47:13'),(53,5,'mirrorsoul',1,NULL,2,1,1,'2026-11-05 11:47:13','2026-11-05 11:51:01','aceptada',NULL,NULL,'2026-11-12 17:11:35','2026-11-05 17:47:13'),(54,6,'mirrorsoul',12,NULL,1,1,1,'2026-11-05 13:21:47','2026-11-05 13:22:07','pendiente',NULL,NULL,NULL,'2026-11-05 19:21:47'),(55,6,'mirrorsoul',9,NULL,2,1,0,'2026-11-05 13:21:47',NULL,'pendiente',NULL,NULL,NULL,'2026-11-05 19:21:47'),(56,6,'mirrorsoul',1,NULL,3,1,0,'2026-11-05 13:21:47',NULL,'pendiente',NULL,NULL,NULL,'2026-11-05 19:21:47'),(60,7,'mirrorsoul',1,NULL,1,0,0,'2026-11-12 16:41:30',NULL,'rechazada','periodo_ausencia','vacaciones','2026-11-12 16:44:05','2026-11-12 22:41:30'),(61,7,'mirrorsoul',9,NULL,2,0,0,'2026-11-12 16:41:30',NULL,'pendiente',NULL,NULL,NULL,'2026-11-12 22:41:30'),(62,7,'mirrorsoul',8,NULL,3,0,0,'2026-11-12 16:41:30',NULL,'pendiente',NULL,NULL,NULL,'2026-11-12 22:41:30'),(63,7,'mirrorsoul',9,NULL,1,1,1,'2026-11-12 17:08:39','2026-11-12 17:08:54','pendiente',NULL,NULL,NULL,'2026-11-12 23:08:39'),(64,7,'mirrorsoul',8,NULL,2,1,0,'2026-11-12 17:08:39',NULL,'pendiente',NULL,NULL,NULL,'2026-11-12 23:08:39');
/*!40000 ALTER TABLE `canalizacion_profesionales` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `canalizacion_seguimientos`
--

DROP TABLE IF EXISTS `canalizacion_seguimientos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `canalizacion_seguimientos` (
  `id_seguimiento` int(11) NOT NULL AUTO_INCREMENT,
  `id_canalizacion` int(11) NOT NULL,
  `id_usuario_rh` int(11) NOT NULL,
  `tipo_seguimiento` enum('contacto','recordatorio','sin_respuesta','nuevas_opciones','rechazo','seguimiento_general') NOT NULL,
  `motivo_no_seleccion` enum('costo','ubicacion','horario','no_interesaron_opciones','prefiere_otro_profesional','no_desea_atencion','no_respondio','aun_valorando','otro') DEFAULT NULL,
  `observacion` text DEFAULT NULL,
  `fecha_seguimiento` datetime NOT NULL DEFAULT current_timestamp(),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_seguimiento`),
  KEY `idx_seg_canalizacion` (`id_canalizacion`),
  KEY `idx_seg_usuario` (`id_usuario_rh`),
  KEY `idx_seg_fecha` (`fecha_seguimiento`),
  CONSTRAINT `fk_seg_canalizacion` FOREIGN KEY (`id_canalizacion`) REFERENCES `canalizaciones` (`id_canalizacion`) ON DELETE CASCADE,
  CONSTRAINT `fk_seg_usuario_rh` FOREIGN KEY (`id_usuario_rh`) REFERENCES `usuarios` (`id_usuario`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `canalizacion_seguimientos`
--

LOCK TABLES `canalizacion_seguimientos` WRITE;
/*!40000 ALTER TABLE `canalizacion_seguimientos` DISABLE KEYS */;
/*!40000 ALTER TABLE `canalizacion_seguimientos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `canalizaciones`
--

DROP TABLE IF EXISTS `canalizaciones`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `canalizaciones` (
  `id_canalizacion` int(11) NOT NULL AUTO_INCREMENT,
  `id_empleado` int(11) NOT NULL,
  `id_usuario_rh` int(11) NOT NULL,
  `tipo_deteccion` enum('sistema','rh') NOT NULL DEFAULT 'rh',
  `token_publico` varchar(128) DEFAULT NULL,
  `origen` enum('nom035','estres_laboral','otra_prueba','entrevista_rh','observacion_rh') NOT NULL,
  `id_referencia_origen` int(11) DEFAULT NULL,
  `recomendacion_sistema` enum('no_requiere','seguimiento','canalizacion') DEFAULT NULL,
  `preevaluacion_ia` text DEFAULT NULL,
  `decision_rh` enum('pendiente','canalizar','seguimiento','no_canalizar') NOT NULL DEFAULT 'pendiente',
  `motivo_decision_rh` text DEFAULT NULL,
  `motivo` text NOT NULL,
  `modalidad_atencion_preferida` enum('presencial','videollamada','indistinta') DEFAULT NULL,
  `areas_atencion_requeridas` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`areas_atencion_requeridas`)),
  `estatus` enum('pendiente_revision','opciones_enviadas','pendiente_eleccion','seleccion_realizada','pendiente_aceptacion_profesional','profesional_acepto','profesional_rechazo','requiere_nuevas_opciones','sin_seleccion','en_seguimiento','cerrada','cancelada') NOT NULL DEFAULT 'pendiente_revision',
  `fecha_creacion` datetime NOT NULL DEFAULT current_timestamp(),
  `fecha_envio_opciones` datetime DEFAULT NULL,
  `fecha_limite_seguimiento` datetime DEFAULT NULL,
  `fecha_eleccion` datetime DEFAULT NULL,
  `id_opcion_elegida` int(11) DEFAULT NULL,
  `fecha_cierre` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_canalizacion`),
  UNIQUE KEY `token_publico` (`token_publico`),
  KEY `idx_canalizacion_empleado` (`id_empleado`),
  KEY `idx_canalizacion_rh` (`id_usuario_rh`),
  KEY `idx_canalizacion_estatus` (`estatus`),
  KEY `idx_canalizacion_origen` (`origen`),
  KEY `idx_canalizacion_fecha_limite` (`fecha_limite_seguimiento`),
  CONSTRAINT `fk_canalizacion_empleado` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id_empleado`) ON DELETE CASCADE,
  CONSTRAINT `fk_canalizacion_usuario_rh` FOREIGN KEY (`id_usuario_rh`) REFERENCES `usuarios` (`id_usuario`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `canalizaciones`
--

LOCK TABLES `canalizaciones` WRITE;
/*!40000 ALTER TABLE `canalizaciones` DISABLE KEYS */;
INSERT INTO `canalizaciones` VALUES (1,3,19,'sistema','9e4f1a58f438a56495a4fc8046027cadf6cf50f69ca46a4ea4e96df25bbcf6b5','otra_prueba',2,'seguimiento','PRE-EVALUACIÓN IA\n\n**Interpretación:**\nSe aplicó el WHO-5 Índice de Bienestar, obteniendo un puntaje bruto de 9. Para este instrumento, las interpretaciones técnicas y laborales no están configuradas, por lo que no es posible extraer conclusiones definitivas a partir de este resultado.\n\n**Atención sugerida:**\nDado que la interpretación configurada no está disponible, se sugiere a Recursos Humanos considerar este puntaje bruto en su contexto, junto con cualquier otra información relevante. Puede ser útil revisar evaluaciones periódicas previas o futuras para identificar patrones.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión final corresponde a Recursos Humanos.','canalizar',NULL,'Puntaje bruto obtenido: 9',NULL,NULL,'cerrada','2026-11-03 12:58:45','2026-11-03 14:42:46','2026-11-08 14:42:46','2026-11-03 14:42:58',23,'2026-11-03 14:43:30','2026-11-03 18:58:45','2026-11-03 20:43:30'),(2,3,19,'sistema','0746f2c8da2e1cdc5ed0918d022956a3de60acc1bfacec2111b76752789c3d04','nom035',6,'canalizacion',NULL,'canalizar',NULL,'La aplicación cumple al menos uno de los criterios de la Guía de Referencia I para requerir atención clínica.',NULL,NULL,'','2026-11-03 13:10:34','2026-11-03 14:41:22','2026-11-08 14:41:22','2026-11-03 14:41:58',20,'2026-11-03 14:44:48','2026-11-03 19:10:34','2026-11-12 23:46:57'),(3,3,19,'sistema','82f96c897184e30ec43cbb41dba6229b183242d87be2436dbba2963a01a813b6','otra_prueba',6,'canalizacion','PRE-EVALUACIÓN IA\n\n**Interpretación:**\nEl tamizaje GAD-7, realizado de forma periódica, indica indicadores moderados de ansiedad. Este resultado es preventivo y no constituye un diagnóstico médico o psicológico.\n\n**Atención sugerida:**\nRecursos Humanos podría considerar una revisión preventiva y valorar la canalización voluntaria con un profesional para un seguimiento adecuado.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión administrativa final corresponde a Recursos Humanos.','canalizar','ok','ok','indistinta','[1,3,9,7,2,5]','seleccion_realizada','2026-11-03 15:45:10','2026-11-05 10:45:44','2026-11-10 10:45:44','2026-11-05 10:46:30',46,NULL,'2026-11-03 21:45:10','2026-11-05 16:46:30'),(4,3,19,'rh','3e831ebf3e56b0bada555a7167d57da236b1b7997e27e48335995e8abbe0aa48','observacion_rh',4,NULL,NULL,'canalizar','problemas laborales','problemas laborales','indistinta','[3,4,13,2,1]','cerrada','2026-11-05 10:55:31','2026-11-05 11:05:53','2026-11-10 11:05:53','2026-11-05 11:06:16',49,'2026-11-05 12:00:42','2026-11-05 16:55:31','2026-11-05 18:00:42'),(5,3,19,'rh','c3961b46288a45367d85f5c49f7ea95373ddf42df166a2eb50eb8a72833c8472','observacion_rh',5,NULL,NULL,'canalizar','no se adapta','no se adapta','indistinta','[1,2,5,6,7]','','2026-11-05 11:46:49','2026-11-05 11:47:13','2026-11-10 11:47:13','2026-11-05 11:51:01',53,'2026-11-05 12:00:24','2026-11-05 17:46:49','2026-11-12 23:40:10'),(6,3,19,'rh','bfd1a59a5579d7bc95f934f13c4a16f7ecac9d35637b4c3f5cd8072406d0757b','observacion_rh',7,NULL,NULL,'canalizar','no','no','indistinta','[2,3]','seleccion_realizada','2026-11-05 13:20:53','2026-11-05 13:21:47','2026-11-10 13:21:47','2026-11-05 13:22:07',54,NULL,'2026-11-05 19:20:53','2026-11-05 19:22:07'),(7,4,36,'sistema','497ae23842455a2de5e4c0a4e7d2f8026bfcb136761737c14378dd22a41797d6','otra_prueba',7,'canalizacion','PRE-EVALUACIÓN IA\n\n**Interpretación:**\nEl tamizaje preventivo de bienestar GAD-7 para ansiedad indica la presencia de indicadores elevados según la escala de puntuación del instrumento. Este resultado se utiliza exclusivamente como tamizaje.\n\n**Atención sugerida:**\nRecursos Humanos debe considerar que los indicadores elevados ameritan atención preventiva. Se recomienda valorar la canalización con un profesional para una revisión adecuada.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión final corresponde a Recursos Humanos.','canalizar',NULL,'El tamizaje muestra indicadores elevados que ameritan atención preventiva. Se recomienda que Recursos Humanos valore oportunamente la canalización con un profesional.','indistinta','[1]','seleccion_realizada','2026-11-12 14:31:46','2026-11-12 17:08:39','2026-11-17 17:08:39','2026-11-12 17:08:54',63,NULL,'2026-11-12 20:31:46','2026-11-12 23:08:54');
/*!40000 ALTER TABLE `canalizaciones` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `catalogo_areas_atencion`
--

DROP TABLE IF EXISTS `catalogo_areas_atencion`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `catalogo_areas_atencion` (
  `id_area` int(11) NOT NULL AUTO_INCREMENT,
  `clave` varchar(80) NOT NULL,
  `nombre` varchar(150) NOT NULL,
  `activo` tinyint(1) NOT NULL DEFAULT 1,
  `orden` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id_area`),
  UNIQUE KEY `uk_area_clave` (`clave`)
) ENGINE=InnoDB AUTO_INCREMENT=25 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `catalogo_areas_atencion`
--

LOCK TABLES `catalogo_areas_atencion` WRITE;
/*!40000 ALTER TABLE `catalogo_areas_atencion` DISABLE KEYS */;
INSERT INTO `catalogo_areas_atencion` VALUES (1,'ansiedad','Ansiedad',1,1),(2,'depresion','Depresión',1,2),(3,'estres','Estrés',1,3),(4,'estres_laboral','Estrés laboral',1,4),(5,'burnout','Burnout',1,5),(6,'duelo','Duelo',1,6),(7,'violencia','Violencia',1,7),(8,'violencia_laboral','Violencia laboral',1,8),(9,'autoestima','Autoestima',1,9),(10,'manejo_emocional','Manejo emocional',1,10),(11,'problemas_familiares','Problemas familiares',1,11),(12,'pareja','Terapia de pareja',1,12),(13,'insomnio','Insomnio',1,13),(14,'crisis','Intervención en crisis',1,14),(15,'habilidades_sociales','Habilidades sociales',1,15),(16,'adicciones','Adicciones',1,16),(17,'trauma','Trauma',1,17),(18,'estres_postraumatico','Estrés postraumático',1,18),(19,'acoso_laboral','Acoso laboral',1,19),(20,'conflictos_laborales','Conflictos laborales',1,20),(21,'orientacion_psicologica','Orientación psicológica',1,21),(22,'adultos','Adultos',1,22),(23,'adolescentes','Adolescentes',1,23),(24,'ninos','Niños',1,24);
/*!40000 ALTER TABLE `catalogo_areas_atencion` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `citas`
--

DROP TABLE IF EXISTS `citas`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `citas` (
  `id_cita` int(11) NOT NULL AUTO_INCREMENT,
  `id_psicologo` int(11) NOT NULL,
  `id_paciente` int(11) DEFAULT NULL,
  `tipo_evento` enum('consulta','reunion','supervision','capacitacion','administrativo','personal','otro') NOT NULL DEFAULT 'consulta',
  `titulo` varchar(200) DEFAULT NULL,
  `fecha` date NOT NULL,
  `hora` time NOT NULL,
  `modalidad` enum('presencial','videollamada','otro') DEFAULT NULL,
  `motivo` varchar(200) DEFAULT NULL,
  `notas` text DEFAULT NULL,
  `estado` enum('apartada','pendiente','completada','cancelada') NOT NULL DEFAULT 'apartada',
  PRIMARY KEY (`id_cita`)
) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `citas`
--

LOCK TABLES `citas` WRITE;
/*!40000 ALTER TABLE `citas` DISABLE KEYS */;
INSERT INTO `citas` VALUES (14,2,NULL,'reunion','trabajo','2026-09-07','16:04:00','videollamada','trabajo',NULL,'cancelada'),(15,1,1,'consulta',NULL,'2026-09-23','14:07:00','presencial','seguimiento','seguimiento sesion 6','apartada'),(16,1,1,'consulta',NULL,'2026-10-10','15:07:00','presencial','seguimiento',NULL,'apartada'),(17,1,1,'consulta',NULL,'2026-09-24','18:53:00','videollamada','seguimiento',NULL,'apartada'),(18,1,1,'consulta',NULL,'2026-10-16','17:21:00','presencial','seguimiento',NULL,'apartada'),(19,1,1,'consulta',NULL,'2026-10-01','16:51:00','presencial','seguimiento',NULL,'cancelada'),(20,1,1,'consulta',NULL,'2026-11-05','14:07:00','presencial','sseguimiento','no','apartada'),(21,9,2,'consulta',NULL,'2026-11-27','10:47:00','presencial','sseguimiento','ninguna','apartada'),(22,19,3,'consulta',NULL,'2026-11-27','17:11:00',NULL,'sseguimiento','no','apartada');
/*!40000 ALTER TABLE `citas` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `claves_cleaver`
--

DROP TABLE IF EXISTS `claves_cleaver`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `claves_cleaver` (
  `id_clave` int(11) NOT NULL AUTO_INCREMENT,
  `id_prueba` int(11) NOT NULL,
  `id_pregunta` int(11) NOT NULL,
  `id_opcion` int(11) NOT NULL,
  `seleccion` enum('M','L') NOT NULL,
  `factor` enum('D','I','S','C') NOT NULL,
  PRIMARY KEY (`id_clave`),
  UNIQUE KEY `uq_clave_cleaver` (`id_prueba`,`id_pregunta`,`id_opcion`,`seleccion`,`factor`),
  KEY `idx_cc_pregunta` (`id_pregunta`),
  KEY `idx_cc_opcion` (`id_opcion`),
  CONSTRAINT `fk_cc_opcion` FOREIGN KEY (`id_opcion`) REFERENCES `opciones_respuesta` (`id_opcion`) ON DELETE CASCADE,
  CONSTRAINT `fk_cc_pregunta` FOREIGN KEY (`id_pregunta`) REFERENCES `preguntas_prueba` (`id_pregunta`) ON DELETE CASCADE,
  CONSTRAINT `fk_cc_prueba` FOREIGN KEY (`id_prueba`) REFERENCES `pruebas` (`id_prueba`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=155 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `claves_cleaver`
--

LOCK TABLES `claves_cleaver` WRITE;
/*!40000 ALTER TABLE `claves_cleaver` DISABLE KEYS */;
INSERT INTO `claves_cleaver` VALUES (41,4,78,275,'M','I'),(77,4,78,276,'M','S'),(78,4,78,276,'L','S'),(115,4,78,277,'M','C'),(116,4,78,277,'L','C'),(1,4,78,278,'L','D'),(2,4,79,279,'M','D'),(42,4,79,280,'M','I'),(43,4,79,280,'L','I'),(79,4,79,281,'M','S'),(80,4,79,281,'L','S'),(117,4,79,281,'L','C'),(81,4,80,283,'L','S'),(118,4,80,284,'M','C'),(119,4,80,284,'L','C'),(3,4,80,285,'M','D'),(4,4,80,285,'L','D'),(44,4,80,286,'M','I'),(45,4,80,286,'L','I'),(120,4,81,287,'M','C'),(121,4,81,287,'L','C'),(5,4,81,288,'M','D'),(46,4,81,289,'M','I'),(47,4,81,289,'L','I'),(82,4,81,290,'M','S'),(151,4,82,291,'M','D'),(152,4,82,291,'L','D'),(122,4,82,291,'L','C'),(83,4,82,293,'M','S'),(48,4,82,294,'M','I'),(49,4,82,294,'L','I'),(84,4,83,295,'M','S'),(123,4,83,297,'M','C'),(124,4,83,297,'L','C'),(8,4,84,299,'L','D'),(125,4,84,300,'M','C'),(85,4,84,301,'M','S'),(86,4,84,301,'L','S'),(50,4,84,302,'M','I'),(51,4,84,302,'L','I'),(52,4,85,303,'M','I'),(87,4,85,304,'L','S'),(126,4,85,305,'L','C'),(9,4,85,306,'M','D'),(10,4,85,306,'L','D'),(88,4,86,307,'M','S'),(89,4,86,307,'L','S'),(127,4,86,308,'M','C'),(128,4,86,308,'L','C'),(11,4,86,309,'L','D'),(53,4,86,310,'L','I'),(129,4,87,311,'M','C'),(90,4,87,312,'M','S'),(91,4,87,312,'L','S'),(12,4,87,313,'M','D'),(13,4,87,313,'L','D'),(54,4,87,313,'L','I'),(14,4,88,315,'M','D'),(15,4,88,315,'L','D'),(55,4,88,316,'L','I'),(92,4,88,317,'M','S'),(93,4,88,317,'L','S'),(130,4,88,318,'L','C'),(56,4,89,319,'M','I'),(94,4,89,320,'M','S'),(131,4,89,321,'L','C'),(16,4,89,322,'M','D'),(17,4,89,322,'L','D'),(95,4,90,323,'M','S'),(132,4,90,324,'L','C'),(18,4,90,325,'M','D'),(19,4,90,325,'L','D'),(57,4,90,326,'M','I'),(58,4,90,326,'L','I'),(133,4,91,327,'M','C'),(20,4,91,328,'M','D'),(21,4,91,328,'L','D'),(59,4,91,329,'M','I'),(60,4,91,329,'L','I'),(96,4,91,330,'M','S'),(97,4,91,330,'L','S'),(22,4,92,331,'M','D'),(61,4,92,332,'M','I'),(98,4,92,333,'L','S'),(134,4,92,334,'L','C'),(135,4,93,335,'M','C'),(23,4,93,336,'M','D'),(24,4,93,336,'L','D'),(99,4,93,337,'L','S'),(62,4,93,338,'M','I'),(63,4,93,338,'L','I'),(64,4,94,339,'M','I'),(100,4,94,339,'M','S'),(65,4,94,339,'L','I'),(101,4,94,339,'L','S'),(25,4,94,341,'M','D'),(26,4,94,341,'L','D'),(136,4,94,342,'M','C'),(102,4,95,343,'L','S'),(103,4,95,344,'M','S'),(66,4,95,344,'L','I'),(137,4,95,345,'M','C'),(138,4,95,345,'L','C'),(27,4,95,346,'M','D'),(28,4,95,346,'L','D'),(29,4,96,347,'M','D'),(30,4,96,347,'L','D'),(139,4,96,348,'M','C'),(67,4,96,349,'L','I'),(104,4,96,350,'M','S'),(105,4,96,350,'L','S'),(106,4,97,351,'M','S'),(107,4,97,351,'L','S'),(140,4,97,352,'L','C'),(31,4,97,353,'M','D'),(32,4,97,353,'L','D'),(68,4,97,354,'M','I'),(69,4,97,354,'L','I'),(70,4,98,355,'M','I'),(71,4,98,355,'L','I'),(147,4,98,356,'M','S'),(148,4,98,356,'L','S'),(141,4,98,357,'L','C'),(33,4,98,358,'M','D'),(34,4,98,358,'L','D'),(110,4,99,359,'L','S'),(153,4,99,360,'M','D'),(142,4,99,360,'M','C'),(154,4,99,360,'L','D'),(72,4,99,362,'M','I'),(73,4,99,362,'L','I'),(143,4,100,363,'M','C'),(37,4,100,364,'M','D'),(38,4,100,364,'L','D'),(146,4,100,365,'L','I'),(111,4,100,366,'M','S'),(112,4,100,366,'L','S'),(39,4,101,367,'M','D'),(40,4,101,367,'L','D'),(75,4,101,368,'M','I'),(76,4,101,368,'L','I'),(149,4,101,369,'M','S'),(150,4,101,369,'L','S'),(144,4,101,370,'M','C'),(145,4,101,370,'L','C');
/*!40000 ALTER TABLE `claves_cleaver` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `conversion_ci_beta3`
--

DROP TABLE IF EXISTS `conversion_ci_beta3`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `conversion_ci_beta3` (
  `id_conversion_ci` int(11) NOT NULL AUTO_INCREMENT,
  `id_prueba_rh` int(11) NOT NULL DEFAULT 4,
  `suma_escalares` int(11) NOT NULL,
  `ci` int(11) NOT NULL,
  `percentil` decimal(6,2) NOT NULL,
  `rango_percentil` varchar(30) DEFAULT NULL,
  `intervalo_90` varchar(30) DEFAULT NULL,
  `intervalo_95` varchar(30) DEFAULT NULL,
  `clasificacion` varchar(100) DEFAULT NULL,
  `fuente` varchar(150) NOT NULL DEFAULT 'Beta III - Manual Moderno - Tabla A-2',
  PRIMARY KEY (`id_conversion_ci`),
  UNIQUE KEY `uk_beta3_suma` (`id_prueba_rh`,`suma_escalares`)
) ENGINE=InnoDB AUTO_INCREMENT=92 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `conversion_ci_beta3`
--

LOCK TABLES `conversion_ci_beta3` WRITE;
/*!40000 ALTER TABLE `conversion_ci_beta3` DISABLE KEYS */;
INSERT INTO `conversion_ci_beta3` VALUES (1,4,5,48,0.00,'P0.0','41-55','39-57','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(2,4,6,49,0.00,'P0.0','42-56','40-58','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(3,4,7,50,0.00,'P0.0','43-57','41-59','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(4,4,8,52,0.10,'P0.1','45-59','43-61','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(5,4,9,53,0.10,'P0.1','46-60','44-62','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(6,4,10,54,0.10,'P0.1','47-61','45-63','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(7,4,11,55,0.10,'P0.1','48-62','46-64','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(8,4,12,56,0.20,'P0.2','49-63','47-65','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(9,4,13,57,0.20,'P0.2','50-64','48-66','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(10,4,14,58,0.30,'P0.3','51-65','49-67','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(11,4,15,60,0.40,'P0.4','53-67','51-69','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(12,4,16,61,0.50,'P0.5','54-68','52-70','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(13,4,17,62,1.00,'P1.0','55-69','53-71','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(14,4,18,63,1.00,'P1.0','56-70','54-72','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(15,4,19,64,1.00,'P1.0','57-71','55-73','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(16,4,20,65,1.00,'P1.0','58-72','56-74','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(17,4,21,66,1.00,'P1.0','59-73','57-75','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(18,4,22,67,1.00,'P1.0','60-74','58-76','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(19,4,23,68,2.00,'P2.0','61-75','59-77','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(20,4,24,69,2.00,'P2.0','62-76','60-78','Extremadamente bajo','Beta III - Manual Moderno - Tabla A-2'),(21,4,25,70,2.00,'P2.0','63-77','61-79','Limítrofe','Beta III - Manual Moderno - Tabla A-2'),(22,4,26,71,3.00,'P3.0','64-78','62-80','Limítrofe','Beta III - Manual Moderno - Tabla A-2'),(23,4,27,72,3.00,'P3.0','65-79','63-81','Limítrofe','Beta III - Manual Moderno - Tabla A-2'),(24,4,28,73,4.00,'P4.0','66-80','64-82','Limítrofe','Beta III - Manual Moderno - Tabla A-2'),(25,4,29,74,4.00,'P4.0','67-81','65-83','Limítrofe','Beta III - Manual Moderno - Tabla A-2'),(26,4,30,75,5.00,'P5.0','68-82','66-84','Limítrofe','Beta III - Manual Moderno - Tabla A-2'),(27,4,31,76,5.00,'P5.0','69-83','67-85','Limítrofe','Beta III - Manual Moderno - Tabla A-2'),(28,4,32,77,6.00,'P6.0','70-84','68-86','Limítrofe','Beta III - Manual Moderno - Tabla A-2'),(29,4,33,78,7.00,'P7.0','71-85','69-87','Limítrofe','Beta III - Manual Moderno - Tabla A-2'),(30,4,34,79,8.00,'P8.0','72-86','70-88','Limítrofe','Beta III - Manual Moderno - Tabla A-2'),(31,4,35,81,10.00,'P10.0','74-88','72-90','Promedio bajo','Beta III - Manual Moderno - Tabla A-2'),(32,4,36,82,12.00,'P12.0','75-89','73-91','Promedio bajo','Beta III - Manual Moderno - Tabla A-2'),(33,4,37,83,13.00,'P13.0','76-90','74-92','Promedio bajo','Beta III - Manual Moderno - Tabla A-2'),(34,4,38,84,14.00,'P14.0','77-91','75-93','Promedio bajo','Beta III - Manual Moderno - Tabla A-2'),(35,4,39,85,16.00,'P16.0','78-92','76-94','Promedio bajo','Beta III - Manual Moderno - Tabla A-2'),(36,4,40,86,18.00,'P18.0','79-93','77-95','Promedio bajo','Beta III - Manual Moderno - Tabla A-2'),(37,4,41,87,19.00,'P19.0','80-94','78-96','Promedio bajo','Beta III - Manual Moderno - Tabla A-2'),(38,4,42,88,21.00,'P21.0','81-95','79-97','Promedio bajo','Beta III - Manual Moderno - Tabla A-2'),(39,4,43,89,23.00,'P23.0','82-96','80-98','Promedio bajo','Beta III - Manual Moderno - Tabla A-2'),(40,4,44,91,27.00,'P27.0','84-98','82-100','Promedio','Beta III - Manual Moderno - Tabla A-2'),(41,4,45,92,30.00,'P30.0','85-99','83-101','Promedio','Beta III - Manual Moderno - Tabla A-2'),(42,4,46,94,34.00,'P34.0','87-101','85-103','Promedio','Beta III - Manual Moderno - Tabla A-2'),(43,4,47,95,37.00,'P37.0','88-102','86-104','Promedio','Beta III - Manual Moderno - Tabla A-2'),(44,4,48,96,39.00,'P39.0','89-103','87-105','Promedio','Beta III - Manual Moderno - Tabla A-2'),(45,4,49,98,45.00,'P45.0','91-105','89-107','Promedio','Beta III - Manual Moderno - Tabla A-2'),(46,4,50,99,47.00,'P47.0','92-106','90-108','Promedio','Beta III - Manual Moderno - Tabla A-2'),(47,4,51,100,50.00,'P50.0','93-107','91-109','Promedio','Beta III - Manual Moderno - Tabla A-2'),(48,4,52,102,55.00,'P55.0','95-109','93-111','Promedio','Beta III - Manual Moderno - Tabla A-2'),(49,4,53,103,58.00,'P58.0','96-110','94-112','Promedio','Beta III - Manual Moderno - Tabla A-2'),(50,4,54,105,63.00,'P63.0','98-112','96-114','Promedio','Beta III - Manual Moderno - Tabla A-2'),(51,4,55,106,66.00,'P66.0','99-113','97-115','Promedio','Beta III - Manual Moderno - Tabla A-2'),(52,4,56,107,68.00,'P68.0','100-114','98-116','Promedio','Beta III - Manual Moderno - Tabla A-2'),(53,4,57,108,70.00,'P70.0','101-115','99-117','Promedio','Beta III - Manual Moderno - Tabla A-2'),(54,4,58,109,73.00,'P73.0','102-116','100-118','Promedio','Beta III - Manual Moderno - Tabla A-2'),(55,4,59,111,77.00,'P77.0','104-118','102-120','Promedio alto','Beta III - Manual Moderno - Tabla A-2'),(56,4,60,112,79.00,'P79.0','105-119','103-121','Promedio alto','Beta III - Manual Moderno - Tabla A-2'),(57,4,61,114,82.00,'P82.0','107-121','105-123','Promedio alto','Beta III - Manual Moderno - Tabla A-2'),(58,4,62,115,84.00,'P84.0','108-122','106-124','Promedio alto','Beta III - Manual Moderno - Tabla A-2'),(59,4,63,117,87.00,'P87.0','110-124','108-126','Promedio alto','Beta III - Manual Moderno - Tabla A-2'),(60,4,64,118,88.00,'P88.0','111-125','109-127','Promedio alto','Beta III - Manual Moderno - Tabla A-2'),(61,4,65,120,91.00,'P91.0','113-127','111-129','Superior','Beta III - Manual Moderno - Tabla A-2'),(62,4,66,122,93.00,'P93.0','115-129','113-131','Superior','Beta III - Manual Moderno - Tabla A-2'),(63,4,67,124,95.00,'P95.0','117-131','115-133','Superior','Beta III - Manual Moderno - Tabla A-2'),(64,4,68,126,96.00,'P96.0','119-133','117-135','Superior','Beta III - Manual Moderno - Tabla A-2'),(65,4,69,128,97.00,'P97.0','121-135','119-137','Superior','Beta III - Manual Moderno - Tabla A-2'),(66,4,70,129,97.00,'P97.0','122-136','120-138','Superior','Beta III - Manual Moderno - Tabla A-2'),(67,4,71,131,98.00,'P98.0','124-138','122-140','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(68,4,72,133,99.00,'P99.0','126-140','124-142','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(69,4,73,135,99.00,'P99.0','128-142','126-144','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(70,4,74,137,99.00,'P99.0','130-144','128-146','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(71,4,75,139,99.50,'P99.5','132-146','130-148','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(72,4,76,141,99.70,'P99.7','134-148','132-150','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(73,4,77,142,99.70,'P99.7','135-149','133-151','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(74,4,78,144,99.80,'P99.8','137-151','135-153','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(75,4,79,146,99.90,'P99.9','139-153','137-155','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(76,4,80,148,99.90,'P99.9','141-155','139-157','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(77,4,81,149,99.90,'P99.9','142-156','140-158','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(78,4,82,151,100.00,'P100.0','144-158','142-160','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(79,4,83,153,100.00,'P100.0','146-160','144-162','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(80,4,84,155,100.00,'P100.0','148-162','146-164','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(81,4,85,155,100.00,'P100.0','148-162','146-164','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(82,4,86,155,100.00,'P100.0','148-162','146-164','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(83,4,87,155,100.00,'P100.0','148-162','146-164','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(84,4,88,155,100.00,'P100.0','148-162','146-164','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(85,4,89,155,100.00,'P100.0','148-162','146-164','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(86,4,90,155,100.00,'P100.0','148-162','146-164','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(87,4,91,155,100.00,'P100.0','148-162','146-164','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(88,4,92,155,100.00,'P100.0','148-162','146-164','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(89,4,93,155,100.00,'P100.0','148-162','146-164','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(90,4,94,155,100.00,'P100.0','148-162','146-164','Muy superior','Beta III - Manual Moderno - Tabla A-2'),(91,4,95,155,100.00,'P100.0','148-162','146-164','Muy superior','Beta III - Manual Moderno - Tabla A-2');
/*!40000 ALTER TABLE `conversion_ci_beta3` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `conversion_cleaver`
--

DROP TABLE IF EXISTS `conversion_cleaver`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `conversion_cleaver` (
  `id_conversion` int(11) NOT NULL AUTO_INCREMENT,
  `id_prueba` int(11) NOT NULL,
  `patron` enum('M','L','T') NOT NULL,
  `factor` enum('D','I','S','C') NOT NULL,
  `puntaje_bruto` int(11) NOT NULL,
  `percentil` int(11) DEFAULT NULL,
  `posicion_grafica` decimal(6,2) DEFAULT NULL,
  PRIMARY KEY (`id_conversion`),
  UNIQUE KEY `uq_conversion_cleaver` (`id_prueba`,`patron`,`factor`,`puntaje_bruto`),
  CONSTRAINT `fk_conversion_prueba` FOREIGN KEY (`id_prueba`) REFERENCES `pruebas` (`id_prueba`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=594 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `conversion_cleaver`
--

LOCK TABLES `conversion_cleaver` WRITE;
/*!40000 ALTER TABLE `conversion_cleaver` DISABLE KEYS */;
INSERT INTO `conversion_cleaver` VALUES (198,4,'M','D',0,NULL,1.00),(199,4,'M','D',1,NULL,5.00),(200,4,'M','D',2,NULL,10.00),(201,4,'M','D',3,NULL,20.00),(202,4,'M','D',4,NULL,30.00),(203,4,'M','D',5,NULL,40.00),(204,4,'M','D',6,NULL,45.00),(205,4,'M','D',7,NULL,58.00),(206,4,'M','D',8,NULL,67.00),(207,4,'M','D',9,NULL,75.00),(208,4,'M','D',10,NULL,84.00),(209,4,'M','D',11,NULL,90.00),(210,4,'M','D',12,NULL,95.00),(211,4,'M','D',13,NULL,99.00),(212,4,'M','D',14,NULL,99.00),(213,4,'M','D',15,NULL,99.00),(214,4,'M','D',16,NULL,99.00),(215,4,'M','D',17,NULL,99.00),(216,4,'M','D',18,NULL,99.00),(217,4,'M','D',19,NULL,99.00),(218,4,'M','D',20,NULL,99.00),(219,4,'M','D',21,NULL,99.00),(220,4,'M','D',22,NULL,99.00),(221,4,'M','D',23,NULL,99.00),(222,4,'M','D',24,NULL,99.00),(223,4,'M','I',0,NULL,1.00),(224,4,'M','I',1,NULL,10.00),(225,4,'M','I',2,NULL,22.00),(226,4,'M','I',3,NULL,37.00),(227,4,'M','I',4,NULL,55.00),(228,4,'M','I',5,NULL,72.00),(229,4,'M','I',6,NULL,82.00),(230,4,'M','I',7,NULL,90.00),(231,4,'M','I',8,NULL,95.00),(232,4,'M','I',9,NULL,97.00),(233,4,'M','I',10,NULL,99.00),(234,4,'M','I',11,NULL,99.00),(235,4,'M','I',12,NULL,99.00),(236,4,'M','I',13,NULL,99.00),(237,4,'M','I',14,NULL,99.00),(238,4,'M','I',15,NULL,99.00),(239,4,'M','I',16,NULL,99.00),(240,4,'M','I',17,NULL,99.00),(241,4,'M','I',18,NULL,99.00),(242,4,'M','I',19,NULL,99.00),(243,4,'M','I',20,NULL,99.00),(244,4,'M','I',21,NULL,99.00),(245,4,'M','I',22,NULL,99.00),(246,4,'M','I',23,NULL,99.00),(247,4,'M','I',24,NULL,99.00),(248,4,'M','S',0,NULL,4.00),(249,4,'M','S',1,NULL,10.00),(250,4,'M','S',2,NULL,16.00),(251,4,'M','S',3,NULL,29.00),(252,4,'M','S',4,NULL,40.00),(253,4,'M','S',5,NULL,56.00),(254,4,'M','S',6,NULL,64.00),(255,4,'M','S',7,NULL,75.00),(256,4,'M','S',8,NULL,83.00),(257,4,'M','S',9,NULL,89.00),(258,4,'M','S',10,NULL,96.00),(259,4,'M','S',11,NULL,99.00),(260,4,'M','S',12,NULL,99.00),(261,4,'M','S',13,NULL,99.00),(262,4,'M','S',14,NULL,99.00),(263,4,'M','S',15,NULL,99.00),(264,4,'M','S',16,NULL,99.00),(265,4,'M','S',17,NULL,99.00),(266,4,'M','S',18,NULL,99.00),(267,4,'M','S',19,NULL,99.00),(268,4,'M','S',20,NULL,99.00),(269,4,'M','S',21,NULL,99.00),(270,4,'M','S',22,NULL,99.00),(271,4,'M','S',23,NULL,99.00),(272,4,'M','S',24,NULL,99.00),(273,4,'M','C',0,NULL,1.00),(274,4,'M','C',1,NULL,6.00),(275,4,'M','C',2,NULL,16.00),(276,4,'M','C',3,NULL,31.00),(277,4,'M','C',4,NULL,54.00),(278,4,'M','C',5,NULL,72.00),(279,4,'M','C',6,NULL,84.00),(280,4,'M','C',7,NULL,93.00),(281,4,'M','C',8,NULL,96.00),(282,4,'M','C',9,NULL,99.00),(283,4,'M','C',10,NULL,99.00),(284,4,'M','C',11,NULL,99.00),(285,4,'M','C',12,NULL,99.00),(286,4,'M','C',13,NULL,99.00),(287,4,'M','C',14,NULL,99.00),(288,4,'M','C',15,NULL,99.00),(289,4,'M','C',16,NULL,99.00),(290,4,'M','C',17,NULL,99.00),(291,4,'M','C',18,NULL,99.00),(292,4,'M','C',19,NULL,99.00),(293,4,'M','C',20,NULL,99.00),(294,4,'M','C',21,NULL,99.00),(295,4,'M','C',22,NULL,99.00),(296,4,'M','C',23,NULL,99.00),(297,4,'M','C',24,NULL,99.00),(298,4,'L','D',0,NULL,99.00),(299,4,'L','D',1,NULL,95.00),(300,4,'L','D',2,NULL,88.00),(301,4,'L','D',3,NULL,78.00),(302,4,'L','D',4,NULL,68.00),(303,4,'L','D',5,NULL,57.00),(304,4,'L','D',6,NULL,45.00),(305,4,'L','D',7,NULL,39.00),(306,4,'L','D',8,NULL,30.00),(307,4,'L','D',9,NULL,22.00),(308,4,'L','D',10,NULL,17.00),(309,4,'L','D',11,NULL,13.00),(310,4,'L','D',12,NULL,9.00),(311,4,'L','D',13,NULL,6.00),(312,4,'L','D',14,NULL,4.00),(313,4,'L','D',15,NULL,3.00),(314,4,'L','D',16,NULL,2.00),(315,4,'L','D',17,NULL,1.00),(316,4,'L','D',18,NULL,1.00),(317,4,'L','D',19,NULL,1.00),(318,4,'L','D',20,NULL,1.00),(319,4,'L','D',21,NULL,1.00),(320,4,'L','D',22,NULL,1.00),(321,4,'L','D',23,NULL,1.00),(322,4,'L','D',24,NULL,1.00),(323,4,'L','I',0,NULL,99.00),(324,4,'L','I',1,NULL,95.00),(325,4,'L','I',2,NULL,86.00),(326,4,'L','I',3,NULL,74.00),(327,4,'L','I',4,NULL,59.00),(328,4,'L','I',5,NULL,43.00),(329,4,'L','I',6,NULL,27.00),(330,4,'L','I',7,NULL,16.00),(331,4,'L','I',8,NULL,10.00),(332,4,'L','I',9,NULL,6.00),(333,4,'L','I',10,NULL,4.00),(334,4,'L','I',11,NULL,3.00),(335,4,'L','I',12,NULL,1.00),(336,4,'L','I',13,NULL,1.00),(337,4,'L','I',14,NULL,1.00),(338,4,'L','I',15,NULL,1.00),(339,4,'L','I',16,NULL,1.00),(340,4,'L','I',17,NULL,1.00),(341,4,'L','I',18,NULL,1.00),(342,4,'L','I',19,NULL,1.00),(343,4,'L','I',20,NULL,1.00),(344,4,'L','I',21,NULL,1.00),(345,4,'L','I',22,NULL,1.00),(346,4,'L','I',23,NULL,1.00),(347,4,'L','I',24,NULL,1.00),(348,4,'L','S',0,NULL,99.00),(349,4,'L','S',1,NULL,97.00),(350,4,'L','S',2,NULL,94.00),(351,4,'L','S',3,NULL,88.00),(352,4,'L','S',4,NULL,78.00),(353,4,'L','S',5,NULL,67.00),(354,4,'L','S',6,NULL,57.00),(355,4,'L','S',7,NULL,39.00),(356,4,'L','S',8,NULL,27.00),(357,4,'L','S',9,NULL,17.00),(358,4,'L','S',10,NULL,10.00),(359,4,'L','S',11,NULL,6.00),(360,4,'L','S',12,NULL,4.00),(361,4,'L','S',13,NULL,3.00),(362,4,'L','S',14,NULL,1.00),(363,4,'L','S',15,NULL,1.00),(364,4,'L','S',16,NULL,1.00),(365,4,'L','S',17,NULL,1.00),(366,4,'L','S',18,NULL,1.00),(367,4,'L','S',19,NULL,1.00),(368,4,'L','S',20,NULL,1.00),(369,4,'L','S',21,NULL,1.00),(370,4,'L','S',22,NULL,1.00),(371,4,'L','S',23,NULL,1.00),(372,4,'L','S',24,NULL,1.00),(373,4,'L','C',0,NULL,99.00),(374,4,'L','C',1,NULL,97.00),(375,4,'L','C',2,NULL,95.00),(376,4,'L','C',3,NULL,91.00),(377,4,'L','C',4,NULL,82.00),(378,4,'L','C',5,NULL,72.00),(379,4,'L','C',6,NULL,58.00),(380,4,'L','C',7,NULL,45.00),(381,4,'L','C',8,NULL,30.00),(382,4,'L','C',9,NULL,22.00),(383,4,'L','C',10,NULL,12.00),(384,4,'L','C',11,NULL,6.00),(385,4,'L','C',12,NULL,4.00),(386,4,'L','C',13,NULL,3.00),(387,4,'L','C',14,NULL,1.00),(388,4,'L','C',15,NULL,1.00),(389,4,'L','C',16,NULL,1.00),(390,4,'L','C',17,NULL,1.00),(391,4,'L','C',18,NULL,1.00),(392,4,'L','C',19,NULL,1.00),(393,4,'L','C',20,NULL,1.00),(394,4,'L','C',21,NULL,1.00),(395,4,'L','C',22,NULL,1.00),(396,4,'L','C',23,NULL,1.00),(397,4,'L','C',24,NULL,1.00),(398,4,'T','D',-24,NULL,1.00),(399,4,'T','D',-23,NULL,1.00),(400,4,'T','D',-22,NULL,1.00),(401,4,'T','D',-21,NULL,1.00),(402,4,'T','D',-20,NULL,1.00),(403,4,'T','D',-19,NULL,1.00),(404,4,'T','D',-18,NULL,1.00),(405,4,'T','D',-17,NULL,1.00),(406,4,'T','D',-16,NULL,1.00),(407,4,'T','D',-15,NULL,1.00),(408,4,'T','D',-14,NULL,2.00),(409,4,'T','D',-13,NULL,3.00),(410,4,'T','D',-12,NULL,4.00),(411,4,'T','D',-11,NULL,6.00),(412,4,'T','D',-10,NULL,8.00),(413,4,'T','D',-9,NULL,10.00),(414,4,'T','D',-8,NULL,13.00),(415,4,'T','D',-7,NULL,16.00),(416,4,'T','D',-6,NULL,20.00),(417,4,'T','D',-5,NULL,24.00),(418,4,'T','D',-4,NULL,27.00),(419,4,'T','D',-3,NULL,32.00),(420,4,'T','D',-2,NULL,40.00),(421,4,'T','D',-1,NULL,44.00),(422,4,'T','D',0,NULL,47.00),(423,4,'T','D',1,NULL,52.00),(424,4,'T','D',2,NULL,56.00),(425,4,'T','D',3,NULL,62.00),(426,4,'T','D',4,NULL,66.00),(427,4,'T','D',5,NULL,70.00),(428,4,'T','D',6,NULL,74.00),(429,4,'T','D',7,NULL,80.00),(430,4,'T','D',8,NULL,84.00),(431,4,'T','D',9,NULL,87.00),(432,4,'T','D',10,NULL,90.00),(433,4,'T','D',11,NULL,93.00),(434,4,'T','D',12,NULL,95.00),(435,4,'T','D',13,NULL,96.00),(436,4,'T','D',14,NULL,97.00),(437,4,'T','D',15,NULL,98.00),(438,4,'T','D',16,NULL,99.00),(439,4,'T','D',17,NULL,99.00),(440,4,'T','D',18,NULL,99.00),(441,4,'T','D',19,NULL,99.00),(442,4,'T','D',20,NULL,99.00),(443,4,'T','D',21,NULL,99.00),(444,4,'T','D',22,NULL,99.00),(445,4,'T','D',23,NULL,99.00),(446,4,'T','D',24,NULL,99.00),(447,4,'T','I',-24,NULL,1.00),(448,4,'T','I',-23,NULL,1.00),(449,4,'T','I',-22,NULL,1.00),(450,4,'T','I',-21,NULL,1.00),(451,4,'T','I',-20,NULL,1.00),(452,4,'T','I',-19,NULL,1.00),(453,4,'T','I',-18,NULL,1.00),(454,4,'T','I',-17,NULL,1.00),(455,4,'T','I',-16,NULL,1.00),(456,4,'T','I',-15,NULL,1.00),(457,4,'T','I',-14,NULL,1.00),(458,4,'T','I',-13,NULL,2.00),(459,4,'T','I',-12,NULL,3.00),(460,4,'T','I',-11,NULL,4.00),(461,4,'T','I',-10,NULL,5.00),(462,4,'T','I',-9,NULL,7.00),(463,4,'T','I',-8,NULL,9.00),(464,4,'T','I',-7,NULL,12.00),(465,4,'T','I',-6,NULL,16.00),(466,4,'T','I',-5,NULL,19.00),(467,4,'T','I',-4,NULL,23.00),(468,4,'T','I',-3,NULL,28.00),(469,4,'T','I',-2,NULL,34.00),(470,4,'T','I',-1,NULL,41.00),(471,4,'T','I',0,NULL,48.00),(472,4,'T','I',1,NULL,61.00),(473,4,'T','I',2,NULL,70.00),(474,4,'T','I',3,NULL,78.00),(475,4,'T','I',4,NULL,83.00),(476,4,'T','I',5,NULL,87.00),(477,4,'T','I',6,NULL,91.00),(478,4,'T','I',7,NULL,93.00),(479,4,'T','I',8,NULL,95.00),(480,4,'T','I',9,NULL,97.00),(481,4,'T','I',10,NULL,98.00),(482,4,'T','I',11,NULL,99.00),(483,4,'T','I',12,NULL,99.00),(484,4,'T','I',13,NULL,99.00),(485,4,'T','I',14,NULL,99.00),(486,4,'T','I',15,NULL,99.00),(487,4,'T','I',16,NULL,99.00),(488,4,'T','I',17,NULL,99.00),(489,4,'T','I',18,NULL,99.00),(490,4,'T','I',19,NULL,99.00),(491,4,'T','I',20,NULL,99.00),(492,4,'T','I',21,NULL,99.00),(493,4,'T','I',22,NULL,99.00),(494,4,'T','I',23,NULL,99.00),(495,4,'T','I',24,NULL,99.00),(496,4,'T','S',-24,NULL,1.00),(497,4,'T','S',-23,NULL,1.00),(498,4,'T','S',-22,NULL,1.00),(499,4,'T','S',-21,NULL,1.00),(500,4,'T','S',-20,NULL,1.00),(501,4,'T','S',-19,NULL,1.00),(502,4,'T','S',-18,NULL,1.00),(503,4,'T','S',-17,NULL,1.00),(504,4,'T','S',-16,NULL,1.00),(505,4,'T','S',-15,NULL,1.00),(506,4,'T','S',-14,NULL,1.00),(507,4,'T','S',-13,NULL,2.00),(508,4,'T','S',-12,NULL,3.00),(509,4,'T','S',-11,NULL,4.00),(510,4,'T','S',-10,NULL,6.00),(511,4,'T','S',-9,NULL,8.00),(512,4,'T','S',-8,NULL,10.00),(513,4,'T','S',-7,NULL,14.00),(514,4,'T','S',-6,NULL,18.00),(515,4,'T','S',-5,NULL,23.00),(516,4,'T','S',-4,NULL,27.00),(517,4,'T','S',-3,NULL,33.00),(518,4,'T','S',-2,NULL,40.00),(519,4,'T','S',-1,NULL,45.00),(520,4,'T','S',0,NULL,53.00),(521,4,'T','S',1,NULL,61.00),(522,4,'T','S',2,NULL,70.00),(523,4,'T','S',3,NULL,75.00),(524,4,'T','S',4,NULL,81.00),(525,4,'T','S',5,NULL,86.00),(526,4,'T','S',6,NULL,90.00),(527,4,'T','S',7,NULL,93.00),(528,4,'T','S',8,NULL,95.00),(529,4,'T','S',9,NULL,97.00),(530,4,'T','S',10,NULL,98.00),(531,4,'T','S',11,NULL,99.00),(532,4,'T','S',12,NULL,99.00),(533,4,'T','S',13,NULL,99.00),(534,4,'T','S',14,NULL,99.00),(535,4,'T','S',15,NULL,99.00),(536,4,'T','S',16,NULL,99.00),(537,4,'T','S',17,NULL,99.00),(538,4,'T','S',18,NULL,99.00),(539,4,'T','S',19,NULL,99.00),(540,4,'T','S',20,NULL,99.00),(541,4,'T','S',21,NULL,99.00),(542,4,'T','S',22,NULL,99.00),(543,4,'T','S',23,NULL,99.00),(544,4,'T','S',24,NULL,99.00),(545,4,'T','C',-24,NULL,1.00),(546,4,'T','C',-23,NULL,1.00),(547,4,'T','C',-22,NULL,1.00),(548,4,'T','C',-21,NULL,1.00),(549,4,'T','C',-20,NULL,1.00),(550,4,'T','C',-19,NULL,1.00),(551,4,'T','C',-18,NULL,1.00),(552,4,'T','C',-17,NULL,1.00),(553,4,'T','C',-16,NULL,1.00),(554,4,'T','C',-15,NULL,1.00),(555,4,'T','C',-14,NULL,2.00),(556,4,'T','C',-13,NULL,3.00),(557,4,'T','C',-12,NULL,4.00),(558,4,'T','C',-11,NULL,5.00),(559,4,'T','C',-10,NULL,7.00),(560,4,'T','C',-9,NULL,10.00),(561,4,'T','C',-8,NULL,13.00),(562,4,'T','C',-7,NULL,17.00),(563,4,'T','C',-6,NULL,21.00),(564,4,'T','C',-5,NULL,25.00),(565,4,'T','C',-4,NULL,32.00),(566,4,'T','C',-3,NULL,40.00),(567,4,'T','C',-2,NULL,49.00),(568,4,'T','C',-1,NULL,56.00),(569,4,'T','C',0,NULL,67.00),(570,4,'T','C',1,NULL,77.00),(571,4,'T','C',2,NULL,84.00),(572,4,'T','C',3,NULL,90.00),(573,4,'T','C',4,NULL,93.00),(574,4,'T','C',5,NULL,96.00),(575,4,'T','C',6,NULL,98.00),(576,4,'T','C',7,NULL,99.00),(577,4,'T','C',8,NULL,99.00),(578,4,'T','C',9,NULL,99.00),(579,4,'T','C',10,NULL,99.00),(580,4,'T','C',11,NULL,99.00),(581,4,'T','C',12,NULL,99.00),(582,4,'T','C',13,NULL,99.00),(583,4,'T','C',14,NULL,99.00),(584,4,'T','C',15,NULL,99.00),(585,4,'T','C',16,NULL,99.00),(586,4,'T','C',17,NULL,99.00),(587,4,'T','C',18,NULL,99.00),(588,4,'T','C',19,NULL,99.00),(589,4,'T','C',20,NULL,99.00),(590,4,'T','C',21,NULL,99.00),(591,4,'T','C',22,NULL,99.00),(592,4,'T','C',23,NULL,99.00),(593,4,'T','C',24,NULL,99.00);
/*!40000 ALTER TABLE `conversion_cleaver` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `decisiones_prospectos`
--

DROP TABLE IF EXISTS `decisiones_prospectos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `decisiones_prospectos` (
  `id_decision` int(11) NOT NULL AUTO_INCREMENT,
  `id_prospecto` int(11) NOT NULL,
  `id_usuario_registro` int(11) DEFAULT NULL,
  `id_empleado` int(11) DEFAULT NULL,
  `decision` enum('contratar','no_contratar') NOT NULL,
  `motivo` text DEFAULT NULL,
  `observaciones` text DEFAULT NULL,
  `fecha_decision` datetime NOT NULL DEFAULT current_timestamp(),
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_decision`),
  KEY `idx_decision_prospecto` (`id_prospecto`),
  KEY `idx_decision_usuario` (`id_usuario_registro`),
  KEY `idx_decision_empleado` (`id_empleado`),
  KEY `idx_decision_tipo` (`decision`),
  CONSTRAINT `fk_decision_empleado` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id_empleado`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_decision_prospecto` FOREIGN KEY (`id_prospecto`) REFERENCES `prospectos` (`id_prospecto`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_decision_usuario` FOREIGN KEY (`id_usuario_registro`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `decisiones_prospectos`
--

LOCK TABLES `decisiones_prospectos` WRITE;
/*!40000 ALTER TABLE `decisiones_prospectos` DISABLE KEYS */;
INSERT INTO `decisiones_prospectos` VALUES (1,1,15,1,'contratar','es un buen elemento','no ninguna','2026-09-17 20:53:59','2026-09-18 02:53:59'),(2,2,15,NULL,'no_contratar','falta experiencia','ninguna','2026-10-20 11:52:26','2026-10-20 17:52:26'),(3,3,15,NULL,'no_contratar','falta experiencia','paso todo solo le falta experiencia','2026-10-20 15:31:01','2026-10-20 21:31:01'),(4,4,15,2,'contratar','buen elemento tiene experiencia y cartas de referencia','ninguna','2026-10-26 11:38:08','2026-10-26 17:38:08'),(5,5,15,3,'contratar','tiene experiencia limitada pero aprende rápido','prueba','2026-10-26 14:11:20','2026-10-26 20:11:20'),(6,8,36,NULL,'no_contratar','pruebas reprobadas','ninguna','2026-11-12 12:41:51','2026-11-12 18:41:51'),(7,9,36,4,'contratar','buena en vetantas','tiene experiencia se le haran mas pruebas de inteligencia posteriormente','2026-11-12 12:57:50','2026-11-12 18:57:50'),(8,10,36,NULL,'no_contratar','mo','no','2026-11-12 13:02:51','2026-11-12 19:02:51');
/*!40000 ALTER TABLE `decisiones_prospectos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `documentos_empleados`
--

DROP TABLE IF EXISTS `documentos_empleados`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `documentos_empleados` (
  `id_documento` int(11) NOT NULL AUTO_INCREMENT,
  `id_empleado` int(11) NOT NULL,
  `tipo_documento` enum('cv','identificacion','constancia','certificado','comprobante','otro') NOT NULL DEFAULT 'otro',
  `nombre_original` varchar(255) NOT NULL,
  `nombre_archivo` varchar(255) NOT NULL,
  `ruta_archivo` varchar(500) NOT NULL,
  `mime_type` varchar(150) DEFAULT NULL,
  `descripcion` varchar(500) DEFAULT NULL,
  `fecha_subida` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_documento`),
  KEY `idx_documento_empleado` (`id_empleado`),
  CONSTRAINT `fk_documento_empleado` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id_empleado`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `documentos_empleados`
--

LOCK TABLES `documentos_empleados` WRITE;
/*!40000 ALTER TABLE `documentos_empleados` DISABLE KEYS */;
INSERT INTO `documentos_empleados` VALUES (1,2,'otro','CURP_SALV070508MMCNPNA4.pdf','1793040965702-ef68y2l6.pdf','/uploads/documentos-empleados/1793040965702-ef68y2l6.pdf','application/pdf','curp','2026-10-26 18:56:05'),(2,3,'identificacion','CURP_SALV070508MMCNPNA4.pdf','1793041826550-f48c96ccd96c84b37500a014.pdf','storage/documentos-prospectos/1793041826550-f48c96ccd96c84b37500a014.pdf','application/pdf',NULL,'2026-10-26 19:10:26'),(3,4,'cv','CURP_SALV070508MMCNPNA4.pdf','1794509685811-d81dcd783f9e0d8cbd22d621.pdf','storage/documentos-prospectos/1794509685811-d81dcd783f9e0d8cbd22d621.pdf','application/pdf','curp','2026-11-12 18:54:45'),(4,4,'cv','CURP_SALV070508MMCNPNA4.pdf','1794512426522-t6wzevh9.pdf','/uploads/documentos-empleados/1794512426522-t6wzevh9.pdf','application/pdf',NULL,'2026-11-12 19:40:26');
/*!40000 ALTER TABLE `documentos_empleados` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `documentos_prospectos`
--

DROP TABLE IF EXISTS `documentos_prospectos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `documentos_prospectos` (
  `id_documento` int(11) NOT NULL AUTO_INCREMENT,
  `id_prospecto` int(11) NOT NULL,
  `id_usuario_registro` int(11) DEFAULT NULL,
  `tipo_documento` enum('cv','identificacion','constancia','certificado','comprobante','otro') NOT NULL DEFAULT 'otro',
  `nombre_original` varchar(255) NOT NULL,
  `nombre_archivo` varchar(255) NOT NULL,
  `ruta_archivo` varchar(500) NOT NULL,
  `mime_type` varchar(150) DEFAULT NULL,
  `descripcion` varchar(500) DEFAULT NULL,
  `fecha_subida` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_documento`),
  KEY `idx_documentos_prospecto` (`id_prospecto`),
  KEY `idx_documentos_usuario` (`id_usuario_registro`),
  CONSTRAINT `fk_documentos_prospecto` FOREIGN KEY (`id_prospecto`) REFERENCES `prospectos` (`id_prospecto`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `documentos_prospectos`
--

LOCK TABLES `documentos_prospectos` WRITE;
/*!40000 ALTER TABLE `documentos_prospectos` DISABLE KEYS */;
INSERT INTO `documentos_prospectos` VALUES (2,1,15,'cv','cveli (1).pdf','1790890093645-483a581905e7d4b26f892775.pdf','storage/documentos-prospectos/1790890093645-483a581905e7d4b26f892775.pdf','application/pdf',NULL,'2026-10-01 21:28:13'),(5,4,15,'cv','invitacion_cafe_jardin_brujas_qr.png','1793036600446-12a001b3529acef852be94b2.png','storage/documentos-prospectos/1793036600446-12a001b3529acef852be94b2.png','image/png',NULL,'2026-10-26 17:43:20');
/*!40000 ALTER TABLE `documentos_prospectos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `empleados`
--

DROP TABLE IF EXISTS `empleados`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `empleados` (
  `id_empleado` int(11) NOT NULL AUTO_INCREMENT,
  `id_prospecto` int(11) NOT NULL,
  `id_admin_padre` int(11) DEFAULT NULL,
  `id_usuario_responsable` int(11) DEFAULT NULL,
  `id_mirror` varchar(30) NOT NULL,
  `nombre` varchar(150) NOT NULL,
  `edad` int(11) DEFAULT NULL,
  `sexo` enum('F','M') DEFAULT NULL,
  `correo` varchar(150) DEFAULT NULL,
  `telefono` varchar(30) DEFAULT NULL,
  `direccion` varchar(255) DEFAULT NULL,
  `estado_residencia` varchar(100) DEFAULT NULL,
  `municipio_residencia` varchar(150) DEFAULT NULL,
  `colonia_residencia` varchar(150) DEFAULT NULL,
  `codigo_postal_residencia` varchar(10) DEFAULT NULL,
  `puesto` varchar(150) DEFAULT NULL,
  `departamento` varchar(150) DEFAULT NULL,
  `sueldo` decimal(10,2) DEFAULT NULL,
  `periodicidad_sueldo` enum('semanal','quincenal','mensual') DEFAULT NULL,
  `modalidad_trabajo` enum('presencial','hibrido','remoto') DEFAULT NULL,
  `modalidad_atencion_preferida` enum('presencial','videollamada','indistinta') DEFAULT NULL,
  `horario_laboral` varchar(120) DEFAULT NULL,
  `fecha_contratacion` date DEFAULT NULL,
  `estatus` enum('activo','inactivo','baja') NOT NULL DEFAULT 'activo',
  `perfil_laboral_completo` tinyint(1) NOT NULL DEFAULT 0,
  `fecha_registro` timestamp NOT NULL DEFAULT current_timestamp(),
  `fecha_actualizacion` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_empleado`),
  UNIQUE KEY `uq_empleado_prospecto` (`id_prospecto`),
  UNIQUE KEY `uq_empleado_mirror` (`id_mirror`),
  KEY `idx_empleado_admin` (`id_admin_padre`),
  KEY `idx_empleado_estatus` (`estatus`),
  KEY `idx_empleados_responsable` (`id_usuario_responsable`),
  CONSTRAINT `fk_empleado_admin` FOREIGN KEY (`id_admin_padre`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_empleado_prospecto` FOREIGN KEY (`id_prospecto`) REFERENCES `prospectos` (`id_prospecto`) ON UPDATE CASCADE,
  CONSTRAINT `fk_empleados_usuario_responsable` FOREIGN KEY (`id_usuario_responsable`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `empleados`
--

LOCK TABLES `empleados` WRITE;
/*!40000 ALTER TABLE `empleados` DISABLE KEYS */;
INSERT INTO `empleados` VALUES (1,1,15,NULL,'MS-2026-25-MA-002','JUAN',25,'M','cortina88@gmail.com','5546513125','carretera sor juana',NULL,NULL,NULL,NULL,'secretario','administracion',NULL,NULL,NULL,NULL,NULL,'2026-09-17','activo',0,'2026-09-18 02:53:59','2026-09-18 02:53:59'),(2,4,14,20,'MS-2026-29-MA-005','Abraham salinas rivera',29,'M','salinasabram@gmail.com','5546455555','CDMX',NULL,NULL,NULL,NULL,'sistemas','sistemas',NULL,NULL,NULL,NULL,NULL,'2026-10-26','activo',0,'2026-10-26 17:38:08','2026-10-27 18:37:56'),(3,5,14,19,'MS-2026-30-FE-006','ARELY HERNANDEZ LUCAS',30,'F','ary789456@gmail.com','5546478963','CDMX','México','La Paz','Ampliación Los Reyes','56400','sistemas','sistemas',6000.00,'quincenal','presencial','indistinta','lunes a viernes de 08:00 a 8:00','2026-10-26','activo',1,'2026-10-26 20:11:20','2026-11-05 16:43:55'),(4,9,36,36,'MS-2026-25-FE-012','MARILU PEREZ',25,'F','mar588@gmail.com','5546525256','la paz','México','Nezahualcóyotl','Evolución','57700','ventas','ventas',7000.00,'quincenal','presencial','indistinta','lunes a viernes de 08:00 a 8:00','2026-11-12','activo',1,'2026-11-12 18:57:50','2026-11-12 21:37:22');
/*!40000 ALTER TABLE `empleados` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `entrevistas_prospectos`
--

DROP TABLE IF EXISTS `entrevistas_prospectos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `entrevistas_prospectos` (
  `id_entrevista` int(11) NOT NULL AUTO_INCREMENT,
  `id_prospecto` int(11) NOT NULL,
  `id_usuario_registro` int(11) DEFAULT NULL,
  `tipo_entrevista` varchar(100) DEFAULT NULL,
  `modalidad` enum('presencial','videollamada') NOT NULL DEFAULT 'presencial',
  `fecha_entrevista` datetime NOT NULL,
  `motivo` varchar(255) DEFAULT NULL,
  `observaciones` text DEFAULT NULL,
  `resultado` enum('pendiente','continua','segunda_entrevista','pruebas','aprobado','no_continua') NOT NULL DEFAULT 'pendiente',
  `enlace_videollamada` varchar(500) DEFAULT NULL,
  `grabacion_url` varchar(500) DEFAULT NULL,
  `transcripcion` longtext DEFAULT NULL,
  `estatus` enum('programada','realizada','cancelada') NOT NULL DEFAULT 'programada',
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `actualizado_en` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_entrevista`),
  KEY `idx_entrevista_prospecto` (`id_prospecto`),
  KEY `idx_entrevista_usuario` (`id_usuario_registro`),
  KEY `idx_entrevista_fecha` (`fecha_entrevista`),
  KEY `idx_entrevista_modalidad` (`modalidad`),
  KEY `idx_entrevista_estatus` (`estatus`),
  CONSTRAINT `fk_entrevista_prospecto` FOREIGN KEY (`id_prospecto`) REFERENCES `prospectos` (`id_prospecto`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_entrevista_usuario` FOREIGN KEY (`id_usuario_registro`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=18 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `entrevistas_prospectos`
--

LOCK TABLES `entrevistas_prospectos` WRITE;
/*!40000 ALTER TABLE `entrevistas_prospectos` DISABLE KEYS */;
INSERT INTO `entrevistas_prospectos` VALUES (1,1,15,'Entrevista inicial','presencial','2026-09-16 21:24:00','trabaja bajo presion es puntual','es muy tranquilo, tiene un buen perfil','continua',NULL,NULL,NULL,'realizada','2026-09-17 03:25:31','2026-09-19 02:04:44'),(3,1,15,'Entrevista de seguimiento','presencial','2026-09-22 00:24:00','seguimiento',NULL,'pendiente',NULL,NULL,NULL,'realizada','2026-09-22 17:24:02','2026-09-22 17:25:40'),(4,1,15,'Entrevista de seguimiento','presencial','2026-10-02 21:18:00','seguimiento','ninguna','pendiente',NULL,NULL,NULL,'programada','2026-10-03 01:16:40','2026-10-03 01:16:40');
/*!40000 ALTER TABLE `entrevistas_prospectos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `evidencias_seguimiento_empleados`
--

DROP TABLE IF EXISTS `evidencias_seguimiento_empleados`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `evidencias_seguimiento_empleados` (
  `id_evidencia` int(11) NOT NULL AUTO_INCREMENT,
  `id_seguimiento` int(11) NOT NULL,
  `id_empleado` int(11) NOT NULL,
  `id_usuario_registro` int(11) DEFAULT NULL,
  `tipo_evidencia` enum('documento','acta','correo','imagen','constancia','carta','otro') NOT NULL DEFAULT 'documento',
  `titulo` varchar(255) DEFAULT NULL,
  `descripcion` text DEFAULT NULL,
  `nombre_original` varchar(255) NOT NULL,
  `nombre_archivo` varchar(255) NOT NULL,
  `ruta_archivo` varchar(500) NOT NULL,
  `mime_type` varchar(150) DEFAULT NULL,
  `fecha_evidencia` datetime DEFAULT NULL,
  `fecha_subida` datetime NOT NULL DEFAULT current_timestamp(),
  `estado` enum('activo','anulado') NOT NULL DEFAULT 'activo',
  `motivo_anulacion` text DEFAULT NULL,
  `fecha_anulacion` datetime DEFAULT NULL,
  `id_usuario_anulacion` int(11) DEFAULT NULL,
  PRIMARY KEY (`id_evidencia`),
  KEY `idx_evidencia_seguimiento` (`id_seguimiento`),
  KEY `idx_evidencia_empleado` (`id_empleado`),
  KEY `idx_evidencia_usuario` (`id_usuario_registro`),
  KEY `idx_evidencia_estado` (`estado`),
  KEY `fk_evidencia_usuario_anulacion` (`id_usuario_anulacion`),
  CONSTRAINT `fk_evidencia_empleado` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id_empleado`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_evidencia_seguimiento` FOREIGN KEY (`id_seguimiento`) REFERENCES `seguimiento_empleados` (`id_seguimiento`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_evidencia_usuario` FOREIGN KEY (`id_usuario_registro`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_evidencia_usuario_anulacion` FOREIGN KEY (`id_usuario_anulacion`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `evidencias_seguimiento_empleados`
--

LOCK TABLES `evidencias_seguimiento_empleados` WRITE;
/*!40000 ALTER TABLE `evidencias_seguimiento_empleados` DISABLE KEYS */;
INSERT INTO `evidencias_seguimiento_empleados` VALUES (1,1,3,19,'acta','acuerdos','acuerdos','JardÃ­n de las Brujas.png','1793137771661-1edyfq2k.png','/uploads/evidencias-seguimiento-empleados/1793137771661-1edyfq2k.png','image/png','2026-10-28 15:48:00','2026-10-27 15:49:31','activo',NULL,NULL,NULL),(2,2,4,36,'documento','acuerdos','no','JardÃ­n de las Brujas.png','1794513793526-0j2bkys1.png','/uploads/evidencias-seguimiento-empleados/1794513793526-0j2bkys1.png','image/png','2026-11-12 14:02:00','2026-11-12 14:03:13','activo',NULL,NULL,NULL);
/*!40000 ALTER TABLE `evidencias_seguimiento_empleados` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `historial_inicial`
--

DROP TABLE IF EXISTS `historial_inicial`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `historial_inicial` (
  `id_historial_inicial` int(11) NOT NULL AUTO_INCREMENT,
  `id_paciente` int(11) NOT NULL,
  `fecha_registro` date NOT NULL,
  `estado_civil` varchar(50) DEFAULT NULL,
  `ocupacion` varchar(100) DEFAULT NULL,
  `escolaridad` varchar(100) DEFAULT NULL,
  `antecedentes_personales` text DEFAULT NULL,
  `antecedentes_familiares` text DEFAULT NULL,
  `antecedentes_patologicos` text DEFAULT NULL,
  `antecedentes_emocionales` text DEFAULT NULL,
  `habitos` text DEFAULT NULL,
  `alergias` text DEFAULT NULL,
  `enfermedades_previas` text DEFAULT NULL,
  `medicamentos_actuales` text DEFAULT NULL,
  `cirugias` text DEFAULT NULL,
  `historia_desarrollo` text DEFAULT NULL,
  `evaluacion_inicial` text DEFAULT NULL,
  `diagnostico_inicial` text DEFAULT NULL,
  `tratamiento_inicial` text DEFAULT NULL,
  `notas` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_historial_inicial`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `historial_inicial`
--

LOCK TABLES `historial_inicial` WRITE;
/*!40000 ALTER TABLE `historial_inicial` DISABLE KEYS */;
INSERT INTO `historial_inicial` VALUES (5,1,'2026-09-02','soltera','trabajadora','preparatoria','le cuesta expresar sus emociones','hipertension','problemas para dormir ','tristesa , enojo','comer mucho ','sol','no','no','no','Paciente femenina de 25 años. Durante su desarrollo infantil presentó un crecimiento aparentemente acorde con su edad, sin antecedentes relevantes reportados. En la etapa escolar mantuvo un desempeño general adecuado y desarrolló relaciones sociales funcionales con familiares y compañeros.\n\nDurante la adolescencia comenzó a experimentar mayores responsabilidades académicas y personales, acompañadas de periodos de preocupación y dificultad para relajarse. No se reportan acontecimientos relevantes que hayan afectado significativamente su desarrollo.\n\nEn la etapa adulta ha asumido responsabilidades laborales y personales que han incrementado sus niveles de preocupación. Actualmente refiere dificultades para conciliar el sueño y despertares ocasionales durante la noche, principalmente durante periodos de mayor carga de actividades o preocupaciones.\n\nLa paciente identifica que sus dificultades actuales para dormir han aumentado durante los últimos meses y que esto ha generado cansancio durante el día y dificultad ocasional para concentrarse.\n','Paciente femenina de 25 años que acude a evaluación debido a dificultades para conciliar y mantener el sueño. Refiere que los problemas se presentan desde hace aproximadamente dos meses y han aumentado durante periodos de preocupación y carga de responsabilidades.\n\nDurante la entrevista se muestra colaboradora y con disposición para proporcionar información sobre su situación actual. Refiere pensamientos recurrentes al momento de acostarse, dificultad para relajarse y sensación de cansancio durante el día. También señala episodios ocasionales de dificultad para mantener la concentración.\n\nA partir de la información inicial se identifican como principales áreas de atención los hábitos de sueño, el nivel de preocupación y los factores asociados a la rutina diaria. Se recomienda continuar con la valoración y seguimiento para conocer la evolución de los indicadores identificados.\n\nImpresión inicial: Se observan indicadores relacionados con dificultades del sueño y posibles factores emocionales asociados. La información obtenida en esta evaluación no constituye un diagnóstico.','Se identifican dificultades para conciliar el sueño, acompañadas de cansancio diurno y pensamientos recurrentes al momento de dormir. Se recomienda continuar con valoración y seguimiento profesional.','Se recomienda establecer hábitos de sueño saludables, mantener horarios regulares de descanso y trabajar en estrategias de relajación para disminuir pensamientos recurrentes antes de dormir. Se dará seguimiento a la evolución de los síntomas y hábitos de sueño.','La paciente presenta dificultades de sueño asociadas principalmente a preocupaciones y pensamientos recurrentes. Se recomienda mantener seguimiento para valorar su evolución y respuesta a las estrategias establecidas.','2026-09-03 03:17:12'),(6,2,'2026-10-26','soltera','estudiante ','universidad','agresividad','diabetes','ansiedad','depresion','duerme poco','al sol','pre diabetes','metformina','ninguna','no hay','no hay','ansiedad','aun no hay','ninguna','2026-10-26 23:40:48'),(7,3,'2026-11-10','soltera','estudiante ','universidad','aun no','no','no','no','no','no','no','no','si','no','no','no','si','no','2026-11-09 23:03:26'),(8,4,'2026-11-12','soltera','trabajadora','universidad','no','no','no','no','no','no','no\n','no','no','no','no','no','no','no','2026-11-12 23:53:09');
/*!40000 ALTER TABLE `historial_inicial` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `historial_seguimiento`
--

DROP TABLE IF EXISTS `historial_seguimiento`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `historial_seguimiento` (
  `id_seguimiento` int(11) NOT NULL AUTO_INCREMENT,
  `id_paciente` int(11) NOT NULL,
  `id_sesion` int(11) DEFAULT NULL,
  `fecha` date NOT NULL,
  `diagnostico` text DEFAULT NULL,
  `tratamiento` text DEFAULT NULL,
  `evolucion` text DEFAULT NULL,
  `observaciones` text DEFAULT NULL,
  `tareas_acuerdos` text DEFAULT NULL,
  PRIMARY KEY (`id_seguimiento`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `historial_seguimiento`
--

LOCK TABLES `historial_seguimiento` WRITE;
/*!40000 ALTER TABLE `historial_seguimiento` DISABLE KEYS */;
INSERT INTO `historial_seguimiento` VALUES (2,1,2,'2026-09-05','Se dispone de información sobre las dificultades de sueño de la paciente, sus niveles de ansiedad moderada y antecedentes de preocupación. Es fundamental revisar la eficacia de las estrategias implementadas y la evolución de los síntomas reportados. Se sugiere profundizar en la relación entre las preocupaciones, la regulación emocional y los patrones de sueño durante el cierre clínico.','ejercicios antes de dormir','primera vez','por el momento no','ejercicios'),(3,1,6,'2026-09-07','aun nmo','aun no','aun no','aun no','aun no'),(4,1,8,'2026-09-07','no','no','no','no','no'),(5,1,9,'2026-09-07','no','no','no','no','np'),(6,1,10,'2026-09-09','no','no','no','no','no'),(7,1,11,'2026-09-14','no','no','no','no','no'),(8,1,12,'2026-09-15','no ','no','no','no','no'),(9,1,13,'2026-09-15','no','no','no','no','no'),(10,1,14,'2026-09-15','Malestar emocional asociado a conflictos familiares, con nerviosismo e irritabilidad durante la sesión. Se requiere continuar valoración antes de establecer un diagnóstico definitivo.','Se realizó contención emocional, escucha activa y exploración de los principales factores de conflicto en el entorno familiar.','Continúan las dificultades relacionadas con el entorno familiar. En esta sesión se observa mayor malestar y aparece la decisión de salir del hogar buscando mayor tranquilidad.','La paciente refiere sentirse constantemente regañada y emocionalmente saturada por la situación en casa. Conviene continuar explorando su red de apoyo y las implicaciones de su decisión.','Identificar personas de apoyo, registrar situaciones que incrementen el malestar y revisar en la próxima sesión cómo ha evolucionado la situación familiar.'),(11,1,15,'2026-09-15','no','no','no','no','no'),(12,1,16,'2026-09-15','no ','no','no','no','no'),(13,1,17,'2026-09-15','presenta estres y ansiedad','ejercicios para relajar ','un poco de mejoria ','un poco ansisosa al cambio','debe realizar ejercicios y tareas a decir no '),(14,1,18,'2026-10-05','gf','gf','ccv','ffd','cvb'),(15,2,20,'2026-10-27','seguir con pruebas','aun faltan pruebas','es la primera sesion','debemos hacer mas pruebas y darle la confianza para que se exprese','debe identificar cuando se siente enojada feliz y triste en diferentes escenarios '),(16,3,21,'2026-11-09','no','no','no','no','no'),(17,3,22,'2026-11-10','ni','ni','ni','ni','ni'),(18,3,23,'2026-11-10','ni','ni','n','ni','ni');
/*!40000 ALTER TABLE `historial_seguimiento` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `interpretaciones_cleaver`
--

DROP TABLE IF EXISTS `interpretaciones_cleaver`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `interpretaciones_cleaver` (
  `id_interpretacion` int(11) NOT NULL AUTO_INCREMENT,
  `id_prueba` int(11) NOT NULL,
  `codigo` varchar(50) NOT NULL,
  `nombre` varchar(150) NOT NULL,
  `tipo` enum('factor','combinacion','especial','aplanamiento') NOT NULL,
  `descripcion` text NOT NULL,
  PRIMARY KEY (`id_interpretacion`),
  UNIQUE KEY `uq_interpretacion_cleaver` (`id_prueba`,`codigo`),
  CONSTRAINT `fk_interpretacion_prueba` FOREIGN KEY (`id_prueba`) REFERENCES `pruebas` (`id_prueba`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `interpretaciones_cleaver`
--

LOCK TABLES `interpretaciones_cleaver` WRITE;
/*!40000 ALTER TABLE `interpretaciones_cleaver` DISABLE KEYS */;
/*!40000 ALTER TABLE `interpretaciones_cleaver` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `laminas_beta3`
--

DROP TABLE IF EXISTS `laminas_beta3`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `laminas_beta3` (
  `id_lamina_beta3` int(11) NOT NULL AUTO_INCREMENT,
  `id_prueba_rh` int(11) NOT NULL,
  `id_subprueba` int(11) DEFAULT NULL,
  `numero_archivo` int(11) NOT NULL,
  `nombre_archivo` varchar(100) NOT NULL,
  `tipo` enum('plantilla','ejemplo','ejercicios') NOT NULL DEFAULT 'ejercicios',
  `ruta_imagen` varchar(255) NOT NULL,
  `orden` int(11) NOT NULL,
  `activo` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id_lamina_beta3`),
  UNIQUE KEY `uk_beta3_lamina` (`id_prueba_rh`,`numero_archivo`)
) ENGINE=InnoDB AUTO_INCREMENT=22 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `laminas_beta3`
--

LOCK TABLES `laminas_beta3` WRITE;
/*!40000 ALTER TABLE `laminas_beta3` DISABLE KEYS */;
INSERT INTO `laminas_beta3` VALUES (1,4,NULL,0,'0.jpg','plantilla','beta3/0.jpg',0,1),(2,4,1,1,'1.jpg','ejemplo','beta3/1.jpg',1,1),(3,4,1,2,'2.jpg','ejercicios','beta3/2.jpg',2,1),(4,4,2,3,'3.jpg','ejemplo','beta3/3.jpg',3,1),(5,4,2,4,'4.jpg','ejercicios','beta3/4.jpg',4,1),(6,4,2,5,'5.jpg','ejercicios','beta3/5.jpg',5,1),(7,4,2,6,'6.jpg','ejercicios','beta3/6.jpg',6,1),(8,4,3,7,'7.jpg','ejemplo','beta3/7.jpg',7,1),(9,4,3,8,'8.jpg','ejercicios','beta3/8.jpg',8,1),(10,4,3,9,'9.jpg','ejercicios','beta3/9.jpg',9,1),(11,4,4,10,'10.jpg','ejemplo','beta3/10.jpg',10,1),(12,4,4,11,'11.jpg','ejercicios','beta3/11.jpg',11,1),(13,4,4,12,'12.jpg','ejercicios','beta3/12.jpg',12,1),(14,4,4,13,'13.jpg','ejercicios','beta3/13.jpg',13,1),(15,4,4,14,'14.jpg','ejercicios','beta3/14.jpg',14,1),(16,4,5,15,'15.jpg','ejemplo','beta3/15.jpg',15,1),(17,4,5,16,'16.jpg','ejercicios','beta3/16.jpg',16,1),(18,4,5,17,'17.jpg','ejercicios','beta3/17.jpg',17,1),(19,4,5,18,'18.jpg','ejercicios','beta3/18.jpg',18,1),(20,4,5,19,'19.jpg','ejercicios','beta3/19.jpg',19,1),(21,4,5,20,'20.jpg','ejercicios','beta3/20.jpg',20,1);
/*!40000 ALTER TABLE `laminas_beta3` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `licencias`
--

DROP TABLE IF EXISTS `licencias`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `licencias` (
  `id_licencia` int(11) NOT NULL AUTO_INCREMENT,
  `id_suscripcion` int(11) NOT NULL,
  `id_usuario` int(11) DEFAULT NULL,
  `tipo` enum('psicologo','rh','educativo','independiente') NOT NULL,
  `estado` enum('disponible','asignada','suspendida','cancelada') NOT NULL DEFAULT 'disponible',
  `fecha_asignacion` datetime DEFAULT NULL,
  `fecha_liberacion` datetime DEFAULT NULL,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_licencia`),
  KEY `idx_licencias_suscripcion` (`id_suscripcion`),
  KEY `idx_licencias_usuario` (`id_usuario`),
  KEY `idx_licencias_estado` (`estado`),
  CONSTRAINT `fk_licencia_suscripcion` FOREIGN KEY (`id_suscripcion`) REFERENCES `suscripciones` (`id_suscripcion`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_licencia_usuario` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `licencias`
--

LOCK TABLES `licencias` WRITE;
/*!40000 ALTER TABLE `licencias` DISABLE KEYS */;
INSERT INTO `licencias` VALUES (1,1,24,'psicologo','asignada','2026-11-06 12:14:31',NULL,'2026-11-05 23:23:17'),(2,1,25,'psicologo','asignada','2026-11-06 12:17:20',NULL,'2026-11-05 23:23:17'),(3,1,26,'psicologo','asignada','2026-11-06 12:17:35',NULL,'2026-11-05 23:23:17'),(4,1,27,'psicologo','asignada','2026-11-06 12:17:50',NULL,'2026-11-05 23:23:17'),(5,1,33,'psicologo','asignada','2026-11-07 02:07:29',NULL,'2026-11-05 23:23:17'),(6,2,31,'rh','asignada','2026-11-06 21:20:00',NULL,'2026-11-06 19:25:20'),(7,2,32,'rh','asignada','2026-11-07 01:13:55',NULL,'2026-11-06 19:25:20'),(8,2,NULL,'rh','disponible',NULL,NULL,'2026-11-06 19:25:20'),(9,3,34,'independiente','asignada','2026-11-09 12:06:31',NULL,'2026-11-09 18:06:31'),(10,2,NULL,'rh','disponible',NULL,NULL,'2026-11-09 18:46:43'),(11,4,NULL,'independiente','disponible',NULL,NULL,'2026-11-09 22:59:45'),(12,5,NULL,'independiente','disponible',NULL,NULL,'2026-11-12 15:43:59');
/*!40000 ALTER TABLE `licencias` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `mirror_consecutivo`
--

DROP TABLE IF EXISTS `mirror_consecutivo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `mirror_consecutivo` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `mirror_consecutivo`
--

LOCK TABLES `mirror_consecutivo` WRITE;
/*!40000 ALTER TABLE `mirror_consecutivo` DISABLE KEYS */;
/*!40000 ALTER TABLE `mirror_consecutivo` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `mirror_ids`
--

DROP TABLE IF EXISTS `mirror_ids`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `mirror_ids` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `id_mirror` varchar(30) NOT NULL,
  `consecutivo` int(11) NOT NULL,
  `año` int(11) NOT NULL,
  `tipo_persona` enum('paciente','prospecto','empleado','estudiante') NOT NULL,
  `id_referencia` int(11) DEFAULT NULL,
  `fecha_registro` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_id_mirror` (`id_mirror`),
  UNIQUE KEY `uk_año_consecutivo` (`año`,`consecutivo`)
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `mirror_ids`
--

LOCK TABLES `mirror_ids` WRITE;
/*!40000 ALTER TABLE `mirror_ids` DISABLE KEYS */;
INSERT INTO `mirror_ids` VALUES (1,'MS-2026-25-FE-001',1,2026,'paciente',1,'2026-09-03 02:48:50'),(2,'MS-2026-25-MA-002',2,2026,'empleado',1,'2026-09-16 19:11:10'),(3,'MS-2026-24-FE-003',3,2026,'prospecto',2,'2026-10-08 16:49:12'),(4,'MS-2026-30-MA-004',4,2026,'prospecto',3,'2026-10-20 18:16:41'),(5,'MS-2026-29-MA-005',5,2026,'empleado',2,'2026-10-20 22:44:46'),(6,'MS-2026-30-FE-006',6,2026,'empleado',3,'2026-10-26 18:57:03'),(7,'MS-2026-25-FE-007',7,2026,'paciente',2,'2026-10-26 23:37:56'),(8,'MS-2026-36-FE-008',8,2026,'prospecto',6,'2026-10-27 18:46:24'),(9,'MS-2026-38-FE-009',9,2026,'prospecto',7,'2026-10-27 20:57:04'),(10,'MS-2026-28-FE-010',10,2026,'paciente',3,'2026-11-09 23:02:48'),(11,'MS-2026-35-FE-011',11,2026,'prospecto',8,'2026-11-12 16:11:33'),(12,'MS-2026-25-FE-012',12,2026,'empleado',4,'2026-11-12 18:46:47'),(13,'MS-2026-35-MA-013',13,2026,'prospecto',10,'2026-11-12 19:02:02'),(14,'MS-2026-0-XX-014',14,2026,'paciente',4,'2026-11-12 23:40:10');
/*!40000 ALTER TABLE `mirror_ids` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `nom035_aplicaciones`
--

DROP TABLE IF EXISTS `nom035_aplicaciones`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `nom035_aplicaciones` (
  `id_aplicacion` int(11) NOT NULL AUTO_INCREMENT,
  `id_empleado` int(11) NOT NULL,
  `id_cuestionario` int(11) NOT NULL,
  `id_usuario_registro` int(11) DEFAULT NULL,
  `token_publico` varchar(120) NOT NULL,
  `tipo_aplicacion` enum('inicial','periodica','seguimiento','extraordinaria') NOT NULL DEFAULT 'periodica',
  `motivo` varchar(255) DEFAULT NULL,
  `atiende_clientes` tinyint(1) DEFAULT NULL,
  `tiene_personal_cargo` tinyint(1) DEFAULT NULL,
  `estatus` enum('habilitada','iniciada','completada','cancelada') NOT NULL DEFAULT 'habilitada',
  `fecha_habilitacion` datetime NOT NULL DEFAULT current_timestamp(),
  `fecha_inicio` datetime DEFAULT NULL,
  `fecha_completada` datetime DEFAULT NULL,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `actualizado_en` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_aplicacion`),
  UNIQUE KEY `uq_nom035_token` (`token_publico`),
  KEY `idx_nom035_aplicacion_empleado` (`id_empleado`),
  KEY `idx_nom035_aplicacion_cuestionario` (`id_cuestionario`),
  KEY `idx_nom035_aplicacion_estatus` (`estatus`),
  KEY `fk_nom035_aplicacion_usuario` (`id_usuario_registro`),
  CONSTRAINT `fk_nom035_aplicacion_cuestionario` FOREIGN KEY (`id_cuestionario`) REFERENCES `nom035_cuestionarios` (`id_cuestionario`) ON UPDATE CASCADE,
  CONSTRAINT `fk_nom035_aplicacion_empleado` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id_empleado`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_nom035_aplicacion_usuario` FOREIGN KEY (`id_usuario_registro`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `nom035_aplicaciones`
--

LOCK TABLES `nom035_aplicaciones` WRITE;
/*!40000 ALTER TABLE `nom035_aplicaciones` DISABLE KEYS */;
INSERT INTO `nom035_aplicaciones` VALUES (6,3,1,19,'878429475120045a57d4ec945d8976db60b0a5469fc4e7673ea8832c59357304','periodica','protocolo',NULL,NULL,'completada','2026-10-30 09:51:28','2026-10-30 09:51:36','2026-10-30 09:52:52','2026-10-30 15:51:28','2026-10-30 15:52:52'),(7,4,1,36,'e62a3eea5d24abad76c4108987206ffc69f27e8f1b2fd0a9f41b6469b6b64edf','periodica','seguimiento',NULL,NULL,'completada','2026-11-12 14:27:26','2026-11-12 14:27:42','2026-11-12 14:27:57','2026-11-12 20:27:26','2026-11-12 20:27:57'),(8,4,1,36,'43335379238617a35fd58b989b8b6eba876313aef12ebb2055c11777752dba2f','periodica','periodica',NULL,NULL,'completada','2026-11-12 14:28:45','2026-11-12 14:29:12','2026-11-12 14:30:05','2026-11-12 20:28:45','2026-11-12 20:30:05');
/*!40000 ALTER TABLE `nom035_aplicaciones` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `nom035_cuestionarios`
--

DROP TABLE IF EXISTS `nom035_cuestionarios`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `nom035_cuestionarios` (
  `id_cuestionario` int(11) NOT NULL AUTO_INCREMENT,
  `clave` varchar(30) NOT NULL,
  `nombre` varchar(180) NOT NULL,
  `descripcion` text DEFAULT NULL,
  `guia` enum('I','II','III') NOT NULL,
  `tipo` enum('acontecimiento_traumatico','factores_riesgo','factores_riesgo_entorno') NOT NULL,
  `version` varchar(30) DEFAULT 'NOM-035-STPS-2018',
  `activo` tinyint(1) NOT NULL DEFAULT 1,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `actualizado_en` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_cuestionario`),
  UNIQUE KEY `uq_nom035_clave` (`clave`),
  KEY `idx_nom035_guia` (`guia`),
  KEY `idx_nom035_activo` (`activo`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `nom035_cuestionarios`
--

LOCK TABLES `nom035_cuestionarios` WRITE;
/*!40000 ALTER TABLE `nom035_cuestionarios` DISABLE KEYS */;
INSERT INTO `nom035_cuestionarios` VALUES (1,'NOM035-GUIA-I','Cuestionario para identificar acontecimientos traumáticos severos','Identificación de trabajadores que fueron sujetos a acontecimientos traumáticos severos durante o con motivo del trabajo.','I','acontecimiento_traumatico','NOM-035-STPS-2018',1,'2026-09-17 02:50:48','2026-09-17 02:50:48'),(2,'NOM035-GUIA-II','Identificación y análisis de los factores de riesgo psicosocial','Cuestionario para identificar y analizar factores de riesgo psicosocial en el centro de trabajo.','II','factores_riesgo','NOM-035-STPS-2018',1,'2026-09-17 02:50:48','2026-09-17 02:50:48'),(3,'NOM035-GUIA-III','Identificación de factores de riesgo psicosocial y evaluación del entorno organizacional','Cuestionario para identificar factores de riesgo psicosocial y evaluar el entorno organizacional.','III','factores_riesgo_entorno','NOM-035-STPS-2018',1,'2026-09-17 02:50:48','2026-09-17 02:50:48');
/*!40000 ALTER TABLE `nom035_cuestionarios` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `nom035_opciones`
--

DROP TABLE IF EXISTS `nom035_opciones`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `nom035_opciones` (
  `id_opcion` int(11) NOT NULL AUTO_INCREMENT,
  `id_pregunta` int(11) NOT NULL,
  `texto_opcion` varchar(120) NOT NULL,
  `valor` decimal(10,2) DEFAULT NULL,
  `orden` int(11) NOT NULL DEFAULT 0,
  `activo` tinyint(1) NOT NULL DEFAULT 1,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_opcion`),
  KEY `idx_nom035_opcion_pregunta` (`id_pregunta`),
  CONSTRAINT `fk_nom035_opcion_pregunta` FOREIGN KEY (`id_pregunta`) REFERENCES `nom035_preguntas` (`id_pregunta`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=947 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `nom035_opciones`
--

LOCK TABLES `nom035_opciones` WRITE;
/*!40000 ALTER TABLE `nom035_opciones` DISABLE KEYS */;
INSERT INTO `nom035_opciones` VALUES (1,1,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(2,2,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(3,3,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(4,4,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(5,5,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(6,6,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(7,7,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(8,8,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(9,9,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(10,10,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(11,11,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(12,12,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(13,13,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(14,14,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(15,15,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(16,16,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(17,17,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(18,18,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(19,19,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(20,20,'Sí',1.00,1,1,'2026-09-17 02:57:42'),(32,1,'No',0.00,2,1,'2026-09-17 02:57:42'),(33,2,'No',0.00,2,1,'2026-09-17 02:57:42'),(34,3,'No',0.00,2,1,'2026-09-17 02:57:42'),(35,4,'No',0.00,2,1,'2026-09-17 02:57:42'),(36,5,'No',0.00,2,1,'2026-09-17 02:57:42'),(37,6,'No',0.00,2,1,'2026-09-17 02:57:42'),(38,7,'No',0.00,2,1,'2026-09-17 02:57:42'),(39,8,'No',0.00,2,1,'2026-09-17 02:57:42'),(40,9,'No',0.00,2,1,'2026-09-17 02:57:42'),(41,10,'No',0.00,2,1,'2026-09-17 02:57:42'),(42,11,'No',0.00,2,1,'2026-09-17 02:57:42'),(43,12,'No',0.00,2,1,'2026-09-17 02:57:42'),(44,13,'No',0.00,2,1,'2026-09-17 02:57:42'),(45,14,'No',0.00,2,1,'2026-09-17 02:57:42'),(46,15,'No',0.00,2,1,'2026-09-17 02:57:42'),(47,16,'No',0.00,2,1,'2026-09-17 02:57:42'),(48,17,'No',0.00,2,1,'2026-09-17 02:57:42'),(49,18,'No',0.00,2,1,'2026-09-17 02:57:42'),(50,19,'No',0.00,2,1,'2026-09-17 02:57:42'),(51,20,'No',0.00,2,1,'2026-09-17 02:57:42'),(52,21,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(53,22,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(54,23,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(55,24,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(56,25,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(57,26,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(58,27,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(59,28,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(60,29,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(61,30,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(62,31,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(63,32,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(64,33,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(65,34,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(66,35,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(67,36,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(68,37,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(69,38,'Siempre',0.00,1,1,'2026-10-29 06:15:11'),(70,39,'Siempre',0.00,1,1,'2026-10-29 06:15:11'),(71,40,'Siempre',0.00,1,1,'2026-10-29 06:15:11'),(72,41,'Siempre',0.00,1,1,'2026-10-29 06:15:11'),(73,42,'Siempre',0.00,1,1,'2026-10-29 06:15:11'),(74,43,'Siempre',0.00,1,1,'2026-10-29 06:15:11'),(75,44,'Siempre',0.00,1,1,'2026-10-29 06:15:11'),(76,45,'Siempre',0.00,1,1,'2026-10-29 06:15:11'),(77,46,'Siempre',0.00,1,1,'2026-10-29 06:15:11'),(78,47,'Siempre',0.00,1,1,'2026-10-29 06:15:11'),(79,48,'Siempre',0.00,1,1,'2026-10-29 06:15:11'),(80,49,'Siempre',0.00,1,1,'2026-10-29 06:15:11'),(81,50,'Siempre',0.00,1,1,'2026-10-29 06:15:11'),(82,51,'Siempre',0.00,1,1,'2026-10-29 06:15:11'),(83,52,'Siempre',0.00,1,1,'2026-10-29 06:15:11'),(84,53,'Siempre',0.00,1,1,'2026-10-29 06:15:11'),(85,54,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(86,55,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(87,56,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(88,57,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(89,58,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(90,59,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(91,60,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(92,61,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(93,62,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(94,63,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(95,64,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(96,65,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(97,66,'Siempre',4.00,1,1,'2026-10-29 06:15:11'),(115,21,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(116,22,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(117,23,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(118,24,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(119,25,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(120,26,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(121,27,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(122,28,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(123,29,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(124,30,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(125,31,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(126,32,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(127,33,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(128,34,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(129,35,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(130,36,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(131,37,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(132,38,'Casi siempre',1.00,2,1,'2026-10-29 06:15:11'),(133,39,'Casi siempre',1.00,2,1,'2026-10-29 06:15:11'),(134,40,'Casi siempre',1.00,2,1,'2026-10-29 06:15:11'),(135,41,'Casi siempre',1.00,2,1,'2026-10-29 06:15:11'),(136,42,'Casi siempre',1.00,2,1,'2026-10-29 06:15:11'),(137,43,'Casi siempre',1.00,2,1,'2026-10-29 06:15:11'),(138,44,'Casi siempre',1.00,2,1,'2026-10-29 06:15:11'),(139,45,'Casi siempre',1.00,2,1,'2026-10-29 06:15:11'),(140,46,'Casi siempre',1.00,2,1,'2026-10-29 06:15:11'),(141,47,'Casi siempre',1.00,2,1,'2026-10-29 06:15:11'),(142,48,'Casi siempre',1.00,2,1,'2026-10-29 06:15:11'),(143,49,'Casi siempre',1.00,2,1,'2026-10-29 06:15:11'),(144,50,'Casi siempre',1.00,2,1,'2026-10-29 06:15:11'),(145,51,'Casi siempre',1.00,2,1,'2026-10-29 06:15:11'),(146,52,'Casi siempre',1.00,2,1,'2026-10-29 06:15:11'),(147,53,'Casi siempre',1.00,2,1,'2026-10-29 06:15:11'),(148,54,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(149,55,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(150,56,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(151,57,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(152,58,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(153,59,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(154,60,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(155,61,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(156,62,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(157,63,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(158,64,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(159,65,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(160,66,'Casi siempre',3.00,2,1,'2026-10-29 06:15:11'),(178,21,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(179,22,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(180,23,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(181,24,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(182,25,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(183,26,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(184,27,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(185,28,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(186,29,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(187,30,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(188,31,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(189,32,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(190,33,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(191,34,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(192,35,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(193,36,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(194,37,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(195,38,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(196,39,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(197,40,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(198,41,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(199,42,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(200,43,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(201,44,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(202,45,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(203,46,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(204,47,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(205,48,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(206,49,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(207,50,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(208,51,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(209,52,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(210,53,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(211,54,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(212,55,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(213,56,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(214,57,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(215,58,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(216,59,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(217,60,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(218,61,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(219,62,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(220,63,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(221,64,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(222,65,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(223,66,'Algunas veces',2.00,3,1,'2026-10-29 06:15:11'),(241,21,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(242,22,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(243,23,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(244,24,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(245,25,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(246,26,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(247,27,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(248,28,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(249,29,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(250,30,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(251,31,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(252,32,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(253,33,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(254,34,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(255,35,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(256,36,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(257,37,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(258,38,'Casi nunca',3.00,4,1,'2026-10-29 06:15:11'),(259,39,'Casi nunca',3.00,4,1,'2026-10-29 06:15:11'),(260,40,'Casi nunca',3.00,4,1,'2026-10-29 06:15:11'),(261,41,'Casi nunca',3.00,4,1,'2026-10-29 06:15:11'),(262,42,'Casi nunca',3.00,4,1,'2026-10-29 06:15:11'),(263,43,'Casi nunca',3.00,4,1,'2026-10-29 06:15:11'),(264,44,'Casi nunca',3.00,4,1,'2026-10-29 06:15:11'),(265,45,'Casi nunca',3.00,4,1,'2026-10-29 06:15:11'),(266,46,'Casi nunca',3.00,4,1,'2026-10-29 06:15:11'),(267,47,'Casi nunca',3.00,4,1,'2026-10-29 06:15:11'),(268,48,'Casi nunca',3.00,4,1,'2026-10-29 06:15:11'),(269,49,'Casi nunca',3.00,4,1,'2026-10-29 06:15:11'),(270,50,'Casi nunca',3.00,4,1,'2026-10-29 06:15:11'),(271,51,'Casi nunca',3.00,4,1,'2026-10-29 06:15:11'),(272,52,'Casi nunca',3.00,4,1,'2026-10-29 06:15:11'),(273,53,'Casi nunca',3.00,4,1,'2026-10-29 06:15:11'),(274,54,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(275,55,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(276,56,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(277,57,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(278,58,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(279,59,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(280,60,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(281,61,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(282,62,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(283,63,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(284,64,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(285,65,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(286,66,'Casi nunca',1.00,4,1,'2026-10-29 06:15:11'),(304,21,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(305,22,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(306,23,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(307,24,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(308,25,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(309,26,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(310,27,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(311,28,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(312,29,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(313,30,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(314,31,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(315,32,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(316,33,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(317,34,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(318,35,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(319,36,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(320,37,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(321,38,'Nunca',4.00,5,1,'2026-10-29 06:15:11'),(322,39,'Nunca',4.00,5,1,'2026-10-29 06:15:11'),(323,40,'Nunca',4.00,5,1,'2026-10-29 06:15:11'),(324,41,'Nunca',4.00,5,1,'2026-10-29 06:15:11'),(325,42,'Nunca',4.00,5,1,'2026-10-29 06:15:11'),(326,43,'Nunca',4.00,5,1,'2026-10-29 06:15:11'),(327,44,'Nunca',4.00,5,1,'2026-10-29 06:15:11'),(328,45,'Nunca',4.00,5,1,'2026-10-29 06:15:11'),(329,46,'Nunca',4.00,5,1,'2026-10-29 06:15:11'),(330,47,'Nunca',4.00,5,1,'2026-10-29 06:15:11'),(331,48,'Nunca',4.00,5,1,'2026-10-29 06:15:11'),(332,49,'Nunca',4.00,5,1,'2026-10-29 06:15:11'),(333,50,'Nunca',4.00,5,1,'2026-10-29 06:15:11'),(334,51,'Nunca',4.00,5,1,'2026-10-29 06:15:11'),(335,52,'Nunca',4.00,5,1,'2026-10-29 06:15:11'),(336,53,'Nunca',4.00,5,1,'2026-10-29 06:15:11'),(337,54,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(338,55,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(339,56,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(340,57,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(341,58,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(342,59,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(343,60,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(344,61,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(345,62,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(346,63,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(347,64,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(348,65,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(349,66,'Nunca',0.00,5,1,'2026-10-29 06:15:11'),(367,67,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(368,68,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(369,69,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(370,70,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(371,71,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(372,72,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(373,73,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(374,74,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(375,75,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(376,76,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(377,77,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(378,78,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(379,79,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(380,80,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(381,81,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(382,82,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(383,83,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(384,84,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(385,85,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(386,86,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(387,87,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(388,88,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(389,89,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(390,90,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(391,91,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(392,92,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(393,93,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(394,94,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(395,95,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(396,96,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(397,97,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(398,98,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(399,99,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(400,100,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(401,101,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(402,102,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(403,103,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(404,104,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(405,105,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(406,106,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(407,107,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(408,108,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(409,109,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(410,110,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(411,111,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(412,112,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(413,113,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(414,114,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(415,115,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(416,116,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(417,117,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(418,118,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(419,119,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(420,120,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(421,121,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(422,122,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(423,123,'Siempre',0.00,1,1,'2026-10-29 06:30:49'),(424,124,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(425,125,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(426,126,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(427,127,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(428,128,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(429,129,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(430,130,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(431,131,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(432,132,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(433,133,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(434,134,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(435,135,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(436,136,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(437,137,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(438,138,'Siempre',4.00,1,1,'2026-10-29 06:30:49'),(494,67,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(495,68,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(496,69,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(497,70,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(498,71,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(499,72,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(500,73,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(501,74,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(502,75,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(503,76,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(504,77,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(505,78,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(506,79,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(507,80,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(508,81,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(509,82,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(510,83,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(511,84,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(512,85,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(513,86,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(514,87,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(515,88,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(516,89,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(517,90,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(518,91,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(519,92,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(520,93,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(521,94,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(522,95,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(523,96,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(524,97,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(525,98,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(526,99,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(527,100,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(528,101,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(529,102,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(530,103,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(531,104,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(532,105,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(533,106,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(534,107,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(535,108,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(536,109,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(537,110,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(538,111,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(539,112,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(540,113,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(541,114,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(542,115,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(543,116,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(544,117,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(545,118,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(546,119,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(547,120,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(548,121,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(549,122,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(550,123,'Casi siempre',1.00,2,1,'2026-10-29 06:30:49'),(551,124,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(552,125,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(553,126,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(554,127,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(555,128,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(556,129,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(557,130,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(558,131,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(559,132,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(560,133,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(561,134,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(562,135,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(563,136,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(564,137,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(565,138,'Casi siempre',3.00,2,1,'2026-10-29 06:30:49'),(621,67,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(622,68,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(623,69,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(624,70,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(625,71,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(626,72,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(627,73,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(628,74,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(629,75,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(630,76,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(631,77,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(632,78,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(633,79,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(634,80,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(635,81,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(636,82,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(637,83,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(638,84,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(639,85,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(640,86,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(641,87,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(642,88,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(643,89,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(644,90,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(645,91,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(646,92,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(647,93,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(648,94,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(649,95,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(650,96,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(651,97,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(652,98,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(653,99,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(654,100,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(655,101,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(656,102,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(657,103,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(658,104,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(659,105,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(660,106,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(661,107,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(662,108,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(663,109,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(664,110,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(665,111,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(666,112,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(667,113,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(668,114,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(669,115,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(670,116,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(671,117,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(672,118,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(673,119,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(674,120,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(675,121,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(676,122,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(677,123,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(678,124,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(679,125,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(680,126,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(681,127,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(682,128,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(683,129,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(684,130,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(685,131,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(686,132,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(687,133,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(688,134,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(689,135,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(690,136,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(691,137,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(692,138,'Algunas veces',2.00,3,1,'2026-10-29 06:30:49'),(748,67,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(749,68,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(750,69,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(751,70,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(752,71,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(753,72,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(754,73,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(755,74,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(756,75,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(757,76,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(758,77,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(759,78,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(760,79,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(761,80,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(762,81,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(763,82,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(764,83,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(765,84,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(766,85,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(767,86,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(768,87,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(769,88,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(770,89,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(771,90,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(772,91,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(773,92,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(774,93,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(775,94,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(776,95,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(777,96,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(778,97,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(779,98,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(780,99,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(781,100,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(782,101,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(783,102,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(784,103,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(785,104,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(786,105,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(787,106,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(788,107,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(789,108,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(790,109,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(791,110,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(792,111,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(793,112,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(794,113,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(795,114,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(796,115,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(797,116,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(798,117,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(799,118,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(800,119,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(801,120,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(802,121,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(803,122,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(804,123,'Casi nunca',3.00,4,1,'2026-10-29 06:30:49'),(805,124,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(806,125,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(807,126,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(808,127,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(809,128,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(810,129,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(811,130,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(812,131,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(813,132,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(814,133,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(815,134,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(816,135,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(817,136,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(818,137,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(819,138,'Casi nunca',1.00,4,1,'2026-10-29 06:30:49'),(875,67,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(876,68,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(877,69,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(878,70,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(879,71,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(880,72,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(881,73,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(882,74,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(883,75,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(884,76,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(885,77,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(886,78,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(887,79,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(888,80,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(889,81,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(890,82,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(891,83,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(892,84,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(893,85,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(894,86,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(895,87,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(896,88,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(897,89,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(898,90,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(899,91,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(900,92,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(901,93,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(902,94,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(903,95,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(904,96,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(905,97,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(906,98,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(907,99,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(908,100,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(909,101,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(910,102,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(911,103,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(912,104,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(913,105,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(914,106,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(915,107,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(916,108,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(917,109,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(918,110,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(919,111,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(920,112,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(921,113,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(922,114,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(923,115,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(924,116,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(925,117,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(926,118,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(927,119,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(928,120,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(929,121,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(930,122,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(931,123,'Nunca',4.00,5,1,'2026-10-29 06:30:49'),(932,124,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(933,125,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(934,126,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(935,127,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(936,128,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(937,129,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(938,130,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(939,131,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(940,132,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(941,133,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(942,134,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(943,135,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(944,136,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(945,137,'Nunca',0.00,5,1,'2026-10-29 06:30:49'),(946,138,'Nunca',0.00,5,1,'2026-10-29 06:30:49');
/*!40000 ALTER TABLE `nom035_opciones` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `nom035_preguntas`
--

DROP TABLE IF EXISTS `nom035_preguntas`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `nom035_preguntas` (
  `id_pregunta` int(11) NOT NULL AUTO_INCREMENT,
  `id_cuestionario` int(11) NOT NULL,
  `numero` varchar(20) DEFAULT NULL,
  `seccion` varchar(150) DEFAULT NULL,
  `categoria` varchar(150) DEFAULT NULL,
  `dominio` varchar(150) DEFAULT NULL,
  `dimension` varchar(180) DEFAULT NULL,
  `texto_pregunta` text NOT NULL,
  `tipo_respuesta` enum('si_no','frecuencia') NOT NULL,
  `orden` int(11) NOT NULL DEFAULT 0,
  `activo` tinyint(1) NOT NULL DEFAULT 1,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_pregunta`),
  KEY `idx_nom035_pregunta_cuestionario` (`id_cuestionario`),
  KEY `idx_nom035_pregunta_orden` (`orden`),
  CONSTRAINT `fk_nom035_pregunta_cuestionario` FOREIGN KEY (`id_cuestionario`) REFERENCES `nom035_cuestionarios` (`id_cuestionario`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=139 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `nom035_preguntas`
--

LOCK TABLES `nom035_preguntas` WRITE;
/*!40000 ALTER TABLE `nom035_preguntas` DISABLE KEYS */;
INSERT INTO `nom035_preguntas` VALUES (1,1,'1','I. Acontecimiento traumático severo','Acontecimiento traumático severo',NULL,NULL,'¿Ha presenciado o sufrido alguna vez, durante o con motivo del trabajo, un accidente que tenga como consecuencia la muerte, la pérdida de un miembro o una lesión grave?','si_no',1,1,'2026-09-17 02:57:23'),(2,1,'2','I. Acontecimiento traumático severo','Acontecimiento traumático severo',NULL,NULL,'¿Ha presenciado o sufrido alguna vez, durante o con motivo del trabajo, asaltos?','si_no',2,1,'2026-09-17 02:57:23'),(3,1,'3','I. Acontecimiento traumático severo','Acontecimiento traumático severo',NULL,NULL,'¿Ha presenciado o sufrido alguna vez, durante o con motivo del trabajo, actos violentos que derivaron en lesiones graves?','si_no',3,1,'2026-09-17 02:57:23'),(4,1,'4','I. Acontecimiento traumático severo','Acontecimiento traumático severo',NULL,NULL,'¿Ha presenciado o sufrido alguna vez, durante o con motivo del trabajo, un secuestro?','si_no',4,1,'2026-09-17 02:57:23'),(5,1,'5','I. Acontecimiento traumático severo','Acontecimiento traumático severo',NULL,NULL,'¿Ha presenciado o sufrido alguna vez, durante o con motivo del trabajo, amenazas?','si_no',5,1,'2026-09-17 02:57:23'),(6,1,'6','I. Acontecimiento traumático severo','Acontecimiento traumático severo',NULL,NULL,'¿Ha presenciado o sufrido alguna vez, durante o con motivo del trabajo, cualquier otro acontecimiento que ponga en riesgo su vida o salud, y/o la de otras personas?','si_no',6,1,'2026-09-17 02:57:23'),(7,1,'7','II. Recuerdos persistentes sobre el acontecimiento','Recuerdos persistentes',NULL,NULL,'¿Ha tenido recuerdos recurrentes sobre el acontecimiento que le provocan malestares?','si_no',7,1,'2026-09-17 02:57:23'),(8,1,'8','II. Recuerdos persistentes sobre el acontecimiento','Recuerdos persistentes',NULL,NULL,'¿Ha tenido sueños de carácter recurrente sobre el acontecimiento, que le producen malestar?','si_no',8,1,'2026-09-17 02:57:23'),(9,1,'9','III. Esfuerzo por evitar circunstancias asociadas','Evitación',NULL,NULL,'¿Se ha esforzado por evitar todo tipo de sentimientos, conversaciones o situaciones que le puedan recordar el acontecimiento?','si_no',9,1,'2026-09-17 02:57:23'),(10,1,'10','III. Esfuerzo por evitar circunstancias asociadas','Evitación',NULL,NULL,'¿Se ha esforzado por evitar todo tipo de actividades, lugares o personas que motivan recuerdos del acontecimiento?','si_no',10,1,'2026-09-17 02:57:23'),(11,1,'11','III. Esfuerzo por evitar circunstancias asociadas','Evitación',NULL,NULL,'¿Ha tenido dificultad para recordar alguna parte importante del evento?','si_no',11,1,'2026-09-17 02:57:23'),(12,1,'12','III. Esfuerzo por evitar circunstancias asociadas','Evitación',NULL,NULL,'¿Ha disminuido su interés en sus actividades cotidianas?','si_no',12,1,'2026-09-17 02:57:23'),(13,1,'13','III. Esfuerzo por evitar circunstancias asociadas','Evitación',NULL,NULL,'¿Se ha sentido usted alejado o distante de los demás?','si_no',13,1,'2026-09-17 02:57:23'),(14,1,'14','III. Esfuerzo por evitar circunstancias asociadas','Evitación',NULL,NULL,'¿Ha notado que tiene dificultad para expresar sus sentimientos?','si_no',14,1,'2026-09-17 02:57:23'),(15,1,'15','III. Esfuerzo por evitar circunstancias asociadas','Evitación',NULL,NULL,'¿Ha tenido la impresión de que su vida se va a acortar, que va a morir antes que otras personas o que tiene un futuro limitado?','si_no',15,1,'2026-09-17 02:57:23'),(16,1,'16','IV. Afectación','Afectación',NULL,NULL,'¿Ha tenido usted dificultades para dormir?','si_no',16,1,'2026-09-17 02:57:23'),(17,1,'17','IV. Afectación','Afectación',NULL,NULL,'¿Ha estado particularmente irritable o le han dado arranques de coraje?','si_no',17,1,'2026-09-17 02:57:23'),(18,1,'18','IV. Afectación','Afectación',NULL,NULL,'¿Ha tenido dificultad para concentrarse?','si_no',18,1,'2026-09-17 02:57:23'),(19,1,'19','IV. Afectación','Afectación',NULL,NULL,'¿Ha estado nervioso o constantemente en alerta?','si_no',19,1,'2026-09-17 02:57:23'),(20,1,'20','IV. Afectación','Afectación',NULL,NULL,'¿Se ha sobresaltado fácilmente por cualquier cosa?','si_no',20,1,'2026-09-17 02:57:23'),(21,2,'1','Condiciones del centro de trabajo','Ambiente de trabajo','Condiciones en el ambiente de trabajo','Condiciones deficientes e insalubres','Mi trabajo me exige hacer mucho esfuerzo físico','frecuencia',1,1,'2026-10-29 06:15:11'),(22,2,'2','Condiciones del centro de trabajo','Ambiente de trabajo','Condiciones en el ambiente de trabajo','Condiciones peligrosas e inseguras','Me preocupa sufrir un accidente en mi trabajo','frecuencia',2,1,'2026-10-29 06:15:11'),(23,2,'3','Condiciones del centro de trabajo','Ambiente de trabajo','Condiciones en el ambiente de trabajo','Trabajos peligrosos','Considero que las actividades que realizo son peligrosas','frecuencia',3,1,'2026-10-29 06:15:11'),(24,2,'4','Cantidad y ritmo de trabajo','Factores propios de la actividad','Carga de trabajo','Cargas cuantitativas','Por la cantidad de trabajo que tengo debo quedarme tiempo adicional a mi turno','frecuencia',4,1,'2026-10-29 06:15:11'),(25,2,'5','Cantidad y ritmo de trabajo','Factores propios de la actividad','Carga de trabajo','Ritmos de trabajo acelerado','Por la cantidad de trabajo que tengo debo trabajar sin parar','frecuencia',5,1,'2026-10-29 06:15:11'),(26,2,'6','Cantidad y ritmo de trabajo','Factores propios de la actividad','Carga de trabajo','Ritmos de trabajo acelerado','Considero que es necesario mantener un ritmo de trabajo acelerado','frecuencia',6,1,'2026-10-29 06:15:11'),(27,2,'7','Cantidad y ritmo de trabajo','Factores propios de la actividad','Carga de trabajo','Carga mental','Mi trabajo exige que esté muy concentrado','frecuencia',7,1,'2026-10-29 06:15:11'),(28,2,'8','Cantidad y ritmo de trabajo','Factores propios de la actividad','Carga de trabajo','Carga mental','Mi trabajo requiere que memorice mucha información','frecuencia',8,1,'2026-10-29 06:15:11'),(29,2,'9','Cantidad y ritmo de trabajo','Factores propios de la actividad','Carga de trabajo','Cargas cuantitativas','Mi trabajo exige que atienda varios asuntos al mismo tiempo','frecuencia',9,1,'2026-10-29 06:15:11'),(30,2,'10','Actividades y responsabilidades','Factores propios de la actividad','Carga de trabajo','Cargas de alta responsabilidad','En mi trabajo soy responsable de cosas de mucho valor','frecuencia',10,1,'2026-10-29 06:15:11'),(31,2,'11','Actividades y responsabilidades','Factores propios de la actividad','Carga de trabajo','Cargas de alta responsabilidad','Respondo ante mi jefe por los resultados de toda mi área de trabajo','frecuencia',11,1,'2026-10-29 06:15:11'),(32,2,'12','Actividades y responsabilidades','Factores propios de la actividad','Carga de trabajo','Cargas contradictorias o inconsistentes','En mi trabajo me dan órdenes contradictorias','frecuencia',12,1,'2026-10-29 06:15:11'),(33,2,'13','Actividades y responsabilidades','Factores propios de la actividad','Carga de trabajo','Cargas contradictorias o inconsistentes','Considero que en mi trabajo me piden hacer cosas innecesarias','frecuencia',13,1,'2026-10-29 06:15:11'),(34,2,'14','Tiempo de trabajo y responsabilidades familiares','Organización del tiempo de trabajo','Jornada de trabajo','Jornadas de trabajo extensas','Trabajo horas extras más de tres veces a la semana','frecuencia',14,1,'2026-10-29 06:15:11'),(35,2,'15','Tiempo de trabajo y responsabilidades familiares','Organización del tiempo de trabajo','Jornada de trabajo','Jornadas de trabajo extensas','Mi trabajo me exige laborar en días de descanso, festivos o fines de semana','frecuencia',15,1,'2026-10-29 06:15:11'),(36,2,'16','Tiempo de trabajo y responsabilidades familiares','Organización del tiempo de trabajo','Interferencia en la relación trabajo-familia','Influencia del trabajo fuera del centro laboral','Considero que el tiempo en el trabajo es mucho y perjudica mis actividades familiares o personales','frecuencia',16,1,'2026-10-29 06:15:11'),(37,2,'17','Tiempo de trabajo y responsabilidades familiares','Organización del tiempo de trabajo','Interferencia en la relación trabajo-familia','Influencia de las responsabilidades familiares','Pienso en las actividades familiares o personales cuando estoy en mi trabajo','frecuencia',17,1,'2026-10-29 06:15:11'),(38,2,'18','Decisiones que puede tomar en su trabajo','Factores propios de la actividad','Falta de control sobre el trabajo','Limitada o nula posibilidad de desarrollo','Mi trabajo permite que desarrolle nuevas habilidades','frecuencia',18,1,'2026-10-29 06:15:11'),(39,2,'19','Decisiones que puede tomar en su trabajo','Factores propios de la actividad','Falta de control sobre el trabajo','Limitada o nula posibilidad de desarrollo','En mi trabajo puedo aspirar a un mejor puesto','frecuencia',19,1,'2026-10-29 06:15:11'),(40,2,'20','Decisiones que puede tomar en su trabajo','Factores propios de la actividad','Falta de control sobre el trabajo','Falta de control y autonomía sobre el trabajo','Durante mi jornada de trabajo puedo tomar pausas cuando las necesito','frecuencia',20,1,'2026-10-29 06:15:11'),(41,2,'21','Decisiones que puede tomar en su trabajo','Factores propios de la actividad','Falta de control sobre el trabajo','Falta de control y autonomía sobre el trabajo','Puedo decidir la velocidad a la que realizo mis actividades en mi trabajo','frecuencia',21,1,'2026-10-29 06:15:11'),(42,2,'22','Decisiones que puede tomar en su trabajo','Factores propios de la actividad','Falta de control sobre el trabajo','Falta de control y autonomía sobre el trabajo','Puedo cambiar el orden de las actividades que realizo en mi trabajo','frecuencia',22,1,'2026-10-29 06:15:11'),(43,2,'23','Capacitación e información sobre el trabajo','Liderazgo y relaciones en el trabajo','Liderazgo','Escasa claridad de funciones','Me informan con claridad cuáles son mis funciones','frecuencia',23,1,'2026-10-29 06:15:11'),(44,2,'24','Capacitación e información sobre el trabajo','Liderazgo y relaciones en el trabajo','Liderazgo','Escasa claridad de funciones','Me explican claramente los resultados que debo obtener en mi trabajo','frecuencia',24,1,'2026-10-29 06:15:11'),(45,2,'25','Capacitación e información sobre el trabajo','Liderazgo y relaciones en el trabajo','Liderazgo','Escasa claridad de funciones','Me informan con quién puedo resolver problemas o asuntos de trabajo','frecuencia',25,1,'2026-10-29 06:15:11'),(46,2,'26','Capacitación e información sobre el trabajo','Factores propios de la actividad','Falta de control sobre el trabajo','Limitada o inexistente capacitación','Me permiten asistir a capacitaciones relacionadas con mi trabajo','frecuencia',26,1,'2026-10-29 06:15:11'),(47,2,'27','Capacitación e información sobre el trabajo','Factores propios de la actividad','Falta de control sobre el trabajo','Limitada o inexistente capacitación','Recibo capacitación útil para hacer mi trabajo','frecuencia',27,1,'2026-10-29 06:15:11'),(48,2,'28','Relaciones con compañeros y jefe','Liderazgo y relaciones en el trabajo','Liderazgo','Características del liderazgo','Mi jefe tiene en cuenta mis puntos de vista y opiniones','frecuencia',28,1,'2026-10-29 06:15:11'),(49,2,'29','Relaciones con compañeros y jefe','Liderazgo y relaciones en el trabajo','Liderazgo','Características del liderazgo','Mi jefe ayuda a solucionar los problemas que se presentan en el trabajo','frecuencia',29,1,'2026-10-29 06:15:11'),(50,2,'30','Relaciones con compañeros y jefe','Liderazgo y relaciones en el trabajo','Relaciones en el trabajo','Relaciones sociales en el trabajo','Puedo confiar en mis compañeros de trabajo','frecuencia',30,1,'2026-10-29 06:15:11'),(51,2,'31','Relaciones con compañeros y jefe','Liderazgo y relaciones en el trabajo','Relaciones en el trabajo','Relaciones sociales en el trabajo','Cuando tenemos que realizar trabajo de equipo los compañeros colaboran','frecuencia',31,1,'2026-10-29 06:15:11'),(52,2,'32','Relaciones con compañeros y jefe','Liderazgo y relaciones en el trabajo','Relaciones en el trabajo','Relaciones sociales en el trabajo','Mis compañeros de trabajo me ayudan cuando tengo dificultades','frecuencia',32,1,'2026-10-29 06:15:11'),(53,2,'33','Relaciones con compañeros y jefe','Liderazgo y relaciones en el trabajo','Violencia','Violencia laboral','En mi trabajo puedo expresarme libremente sin interrupciones','frecuencia',33,1,'2026-10-29 06:15:11'),(54,2,'34','Relaciones con compañeros y jefe','Liderazgo y relaciones en el trabajo','Violencia','Violencia laboral','Recibo críticas constantes a mi persona y/o trabajo','frecuencia',34,1,'2026-10-29 06:15:11'),(55,2,'35','Relaciones con compañeros y jefe','Liderazgo y relaciones en el trabajo','Violencia','Violencia laboral','Recibo burlas, calumnias, difamaciones, humillaciones o ridiculizaciones','frecuencia',35,1,'2026-10-29 06:15:11'),(56,2,'36','Relaciones con compañeros y jefe','Liderazgo y relaciones en el trabajo','Violencia','Violencia laboral','Se ignora mi presencia o se me excluye de las reuniones de trabajo y en la toma de decisiones','frecuencia',36,1,'2026-10-29 06:15:11'),(57,2,'37','Relaciones con compañeros y jefe','Liderazgo y relaciones en el trabajo','Violencia','Violencia laboral','Se manipulan las situaciones de trabajo para hacerme parecer un mal trabajador','frecuencia',37,1,'2026-10-29 06:15:11'),(58,2,'38','Relaciones con compañeros y jefe','Liderazgo y relaciones en el trabajo','Violencia','Violencia laboral','Se ignoran mis éxitos laborales y se atribuyen a otros trabajadores','frecuencia',38,1,'2026-10-29 06:15:11'),(59,2,'39','Relaciones con compañeros y jefe','Liderazgo y relaciones en el trabajo','Violencia','Violencia laboral','Me bloquean o impiden las oportunidades que tengo para obtener ascenso o mejora en mi trabajo','frecuencia',39,1,'2026-10-29 06:15:11'),(60,2,'40','Relaciones con compañeros y jefe','Liderazgo y relaciones en el trabajo','Violencia','Violencia laboral','He presenciado actos de violencia en mi centro de trabajo','frecuencia',40,1,'2026-10-29 06:15:11'),(61,2,'41','Atención a clientes y usuarios','Factores propios de la actividad','Carga de trabajo','Cargas psicológicas emocionales','Atiendo clientes o usuarios muy enojados','frecuencia',41,1,'2026-10-29 06:15:11'),(62,2,'42','Atención a clientes y usuarios','Factores propios de la actividad','Carga de trabajo','Cargas psicológicas emocionales','Mi trabajo me exige atender personas muy necesitadas de ayuda o enfermas','frecuencia',42,1,'2026-10-29 06:15:11'),(63,2,'43','Atención a clientes y usuarios','Factores propios de la actividad','Carga de trabajo','Cargas psicológicas emocionales','Para hacer mi trabajo debo demostrar sentimientos distintos a los míos','frecuencia',43,1,'2026-10-29 06:15:11'),(64,2,'44','Personal a cargo','Liderazgo y relaciones en el trabajo','Relaciones en el trabajo','Deficiente relación con los colaboradores que supervisa','Comunican tarde los asuntos de trabajo','frecuencia',44,1,'2026-10-29 06:15:11'),(65,2,'45','Personal a cargo','Liderazgo y relaciones en el trabajo','Relaciones en el trabajo','Deficiente relación con los colaboradores que supervisa','Dificultan el logro de los resultados del trabajo','frecuencia',45,1,'2026-10-29 06:15:11'),(66,2,'46','Personal a cargo','Liderazgo y relaciones en el trabajo','Relaciones en el trabajo','Deficiente relación con los colaboradores que supervisa','Ignoran las sugerencias para mejorar su trabajo','frecuencia',46,1,'2026-10-29 06:15:11'),(67,3,'1','Condiciones ambientales','Ambiente de trabajo','Condiciones en el ambiente de trabajo','Condiciones peligrosas e inseguras','El espacio donde trabajo me permite realizar mis actividades de manera segura e higiénica','frecuencia',1,1,'2026-10-29 06:30:49'),(68,3,'2','Condiciones ambientales','Ambiente de trabajo','Condiciones en el ambiente de trabajo','Condiciones deficientes e insalubres','Mi trabajo me exige hacer mucho esfuerzo físico','frecuencia',2,1,'2026-10-29 06:30:49'),(69,3,'3','Condiciones ambientales','Ambiente de trabajo','Condiciones en el ambiente de trabajo','Condiciones peligrosas e inseguras','Me preocupa sufrir un accidente en mi trabajo','frecuencia',3,1,'2026-10-29 06:30:49'),(70,3,'4','Condiciones ambientales','Ambiente de trabajo','Condiciones en el ambiente de trabajo','Condiciones deficientes e insalubres','Considero que en mi trabajo se aplican las normas de seguridad y salud en el trabajo','frecuencia',4,1,'2026-10-29 06:30:49'),(71,3,'5','Condiciones ambientales','Ambiente de trabajo','Condiciones en el ambiente de trabajo','Trabajos peligrosos','Considero que las actividades que realizo son peligrosas','frecuencia',5,1,'2026-10-29 06:30:49'),(72,3,'6','Cantidad y ritmo de trabajo','Factores propios de la actividad','Carga de trabajo','Cargas cuantitativas','Por la cantidad de trabajo que tengo debo quedarme tiempo adicional a mi turno','frecuencia',6,1,'2026-10-29 06:30:49'),(73,3,'7','Cantidad y ritmo de trabajo','Factores propios de la actividad','Carga de trabajo','Ritmos de trabajo acelerado','Por la cantidad de trabajo que tengo debo trabajar sin parar','frecuencia',7,1,'2026-10-29 06:30:49'),(74,3,'8','Cantidad y ritmo de trabajo','Factores propios de la actividad','Carga de trabajo','Ritmos de trabajo acelerado','Considero que es necesario mantener un ritmo de trabajo acelerado','frecuencia',8,1,'2026-10-29 06:30:49'),(75,3,'9','Exigencias del trabajo','Factores propios de la actividad','Carga de trabajo','Carga mental','Mi trabajo exige que esté muy concentrado','frecuencia',9,1,'2026-10-29 06:30:49'),(76,3,'10','Exigencias del trabajo','Factores propios de la actividad','Carga de trabajo','Carga mental','Mi trabajo requiere que memorice mucha información','frecuencia',10,1,'2026-10-29 06:30:49'),(77,3,'11','Exigencias del trabajo','Factores propios de la actividad','Carga de trabajo','Carga mental','En mi trabajo tengo que tomar decisiones difíciles muy rápido','frecuencia',11,1,'2026-10-29 06:30:49'),(78,3,'12','Exigencias del trabajo','Factores propios de la actividad','Carga de trabajo','Cargas cuantitativas','Mi trabajo exige que atienda varios asuntos al mismo tiempo','frecuencia',12,1,'2026-10-29 06:30:49'),(79,3,'13','Responsabilidades','Factores propios de la actividad','Carga de trabajo','Cargas de alta responsabilidad','En mi trabajo soy responsable de cosas de mucho valor','frecuencia',13,1,'2026-10-29 06:30:49'),(80,3,'14','Responsabilidades','Factores propios de la actividad','Carga de trabajo','Cargas de alta responsabilidad','Respondo ante mi jefe por los resultados de toda mi área de trabajo','frecuencia',14,1,'2026-10-29 06:30:49'),(81,3,'15','Responsabilidades','Factores propios de la actividad','Carga de trabajo','Cargas contradictorias o inconsistentes','En el trabajo me dan órdenes contradictorias','frecuencia',15,1,'2026-10-29 06:30:49'),(82,3,'16','Responsabilidades','Factores propios de la actividad','Carga de trabajo','Cargas contradictorias o inconsistentes','Considero que en mi trabajo me piden hacer cosas innecesarias','frecuencia',16,1,'2026-10-29 06:30:49'),(83,3,'17','Tiempo de trabajo','Organización del tiempo de trabajo','Jornada de trabajo','Jornadas de trabajo extensas','Trabajo horas extras más de tres veces a la semana','frecuencia',17,1,'2026-10-29 06:30:49'),(84,3,'18','Tiempo de trabajo','Organización del tiempo de trabajo','Jornada de trabajo','Jornadas de trabajo extensas','Mi trabajo me exige laborar en días de descanso, festivos o fines de semana','frecuencia',18,1,'2026-10-29 06:30:49'),(85,3,'19','Trabajo y vida personal','Organización del tiempo de trabajo','Interferencia en la relación trabajo-familia','Influencia del trabajo fuera del centro laboral','Considero que el tiempo en el trabajo es mucho y perjudica mis actividades familiares o personales','frecuencia',19,1,'2026-10-29 06:30:49'),(86,3,'20','Trabajo y vida personal','Organización del tiempo de trabajo','Interferencia en la relación trabajo-familia','Influencia del trabajo fuera del centro laboral','Debo atender asuntos de trabajo cuando estoy en casa','frecuencia',20,1,'2026-10-29 06:30:49'),(87,3,'21','Trabajo y vida personal','Organización del tiempo de trabajo','Interferencia en la relación trabajo-familia','Influencia de las responsabilidades familiares','Pienso en las actividades familiares o personales cuando estoy en mi trabajo','frecuencia',21,1,'2026-10-29 06:30:49'),(88,3,'22','Trabajo y vida personal','Organización del tiempo de trabajo','Interferencia en la relación trabajo-familia','Influencia de las responsabilidades familiares','Pienso que mis responsabilidades familiares afectan mi trabajo','frecuencia',22,1,'2026-10-29 06:30:49'),(89,3,'23','Desarrollo en el trabajo','Factores propios de la actividad','Falta de control sobre el trabajo','Limitada o nula posibilidad de desarrollo','Mi trabajo permite que desarrolle nuevas habilidades','frecuencia',23,1,'2026-10-29 06:30:49'),(90,3,'24','Desarrollo en el trabajo','Factores propios de la actividad','Falta de control sobre el trabajo','Limitada o nula posibilidad de desarrollo','En mi trabajo puedo aspirar a un mejor puesto','frecuencia',24,1,'2026-10-29 06:30:49'),(91,3,'25','Decisiones sobre el trabajo','Factores propios de la actividad','Falta de control sobre el trabajo','Falta de control y autonomía sobre el trabajo','Durante mi jornada de trabajo puedo tomar pausas cuando las necesito','frecuencia',25,1,'2026-10-29 06:30:49'),(92,3,'26','Decisiones sobre el trabajo','Factores propios de la actividad','Falta de control sobre el trabajo','Falta de control y autonomía sobre el trabajo','Puedo decidir cuánto trabajo realizo durante la jornada laboral','frecuencia',26,1,'2026-10-29 06:30:49'),(93,3,'27','Decisiones sobre el trabajo','Factores propios de la actividad','Falta de control sobre el trabajo','Falta de control y autonomía sobre el trabajo','Puedo decidir la velocidad a la que realizo mis actividades en mi trabajo','frecuencia',27,1,'2026-10-29 06:30:49'),(94,3,'28','Decisiones sobre el trabajo','Factores propios de la actividad','Falta de control sobre el trabajo','Falta de control y autonomía sobre el trabajo','Puedo cambiar el orden de las actividades que realizo en mi trabajo','frecuencia',28,1,'2026-10-29 06:30:49'),(95,3,'29','Cambios organizacionales','Factores propios de la actividad','Falta de control sobre el trabajo','Insuficiente participación y manejo del cambio','Los cambios que se presentan en mi trabajo dificultan mi labor','frecuencia',29,1,'2026-10-29 06:30:49'),(96,3,'30','Cambios organizacionales','Factores propios de la actividad','Falta de control sobre el trabajo','Insuficiente participación y manejo del cambio','Cuando se presentan cambios en mi trabajo se tienen en cuenta mis ideas o aportaciones','frecuencia',30,1,'2026-10-29 06:30:49'),(97,3,'31','Información sobre el trabajo','Liderazgo y relaciones en el trabajo','Liderazgo','Escasa claridad de funciones','Me informan con claridad cuáles son mis funciones','frecuencia',31,1,'2026-10-29 06:30:49'),(98,3,'32','Información sobre el trabajo','Liderazgo y relaciones en el trabajo','Liderazgo','Escasa claridad de funciones','Me explican claramente los resultados que debo obtener en mi trabajo','frecuencia',32,1,'2026-10-29 06:30:49'),(99,3,'33','Información sobre el trabajo','Liderazgo y relaciones en el trabajo','Liderazgo','Escasa claridad de funciones','Me explican claramente los objetivos de mi trabajo','frecuencia',33,1,'2026-10-29 06:30:49'),(100,3,'34','Información sobre el trabajo','Liderazgo y relaciones en el trabajo','Liderazgo','Escasa claridad de funciones','Me informan con quién puedo resolver problemas o asuntos de trabajo','frecuencia',34,1,'2026-10-29 06:30:49'),(101,3,'35','Capacitación','Factores propios de la actividad','Falta de control sobre el trabajo','Limitada o inexistente capacitación','Me permiten asistir a capacitaciones relacionadas con mi trabajo','frecuencia',35,1,'2026-10-29 06:30:49'),(102,3,'36','Capacitación','Factores propios de la actividad','Falta de control sobre el trabajo','Limitada o inexistente capacitación','Recibo capacitación útil para hacer mi trabajo','frecuencia',36,1,'2026-10-29 06:30:49'),(103,3,'37','Relación con el jefe','Liderazgo y relaciones en el trabajo','Liderazgo','Características del liderazgo','Mi jefe ayuda a organizar mejor el trabajo','frecuencia',37,1,'2026-10-29 06:30:49'),(104,3,'38','Relación con el jefe','Liderazgo y relaciones en el trabajo','Liderazgo','Características del liderazgo','Mi jefe tiene en cuenta mis puntos de vista y opiniones','frecuencia',38,1,'2026-10-29 06:30:49'),(105,3,'39','Relación con el jefe','Liderazgo y relaciones en el trabajo','Liderazgo','Características del liderazgo','Mi jefe me comunica a tiempo la información relacionada con el trabajo','frecuencia',39,1,'2026-10-29 06:30:49'),(106,3,'40','Relación con el jefe','Liderazgo y relaciones en el trabajo','Liderazgo','Características del liderazgo','La orientación que me da mi jefe me ayuda a realizar mejor mi trabajo','frecuencia',40,1,'2026-10-29 06:30:49'),(107,3,'41','Relación con el jefe','Liderazgo y relaciones en el trabajo','Liderazgo','Características del liderazgo','Mi jefe ayuda a solucionar los problemas que se presentan en el trabajo','frecuencia',41,1,'2026-10-29 06:30:49'),(108,3,'42','Relaciones laborales','Liderazgo y relaciones en el trabajo','Relaciones en el trabajo','Relaciones sociales en el trabajo','Puedo confiar en mis compañeros de trabajo','frecuencia',42,1,'2026-10-29 06:30:49'),(109,3,'43','Relaciones laborales','Liderazgo y relaciones en el trabajo','Relaciones en el trabajo','Relaciones sociales en el trabajo','Entre compañeros solucionamos los problemas de trabajo de forma respetuosa','frecuencia',43,1,'2026-10-29 06:30:49'),(110,3,'44','Relaciones laborales','Liderazgo y relaciones en el trabajo','Relaciones en el trabajo','Relaciones sociales en el trabajo','En mi trabajo me hacen sentir parte del grupo','frecuencia',44,1,'2026-10-29 06:30:49'),(111,3,'45','Relaciones laborales','Liderazgo y relaciones en el trabajo','Relaciones en el trabajo','Relaciones sociales en el trabajo','Cuando tenemos que realizar trabajo de equipo los compañeros colaboran','frecuencia',45,1,'2026-10-29 06:30:49'),(112,3,'46','Relaciones laborales','Liderazgo y relaciones en el trabajo','Relaciones en el trabajo','Relaciones sociales en el trabajo','Mis compañeros de trabajo me ayudan cuando tengo dificultades','frecuencia',46,1,'2026-10-29 06:30:49'),(113,3,'47','Desempeño','Entorno organizacional','Reconocimiento del desempeño','Escasa o nula retroalimentación del desempeño','Me informan sobre lo que hago bien en mi trabajo','frecuencia',47,1,'2026-10-29 06:30:49'),(114,3,'48','Desempeño','Entorno organizacional','Reconocimiento del desempeño','Escasa o nula retroalimentación del desempeño','La forma como evalúan mi trabajo en mi centro de trabajo me ayuda a mejorar mi desempeño','frecuencia',48,1,'2026-10-29 06:30:49'),(115,3,'49','Reconocimiento','Entorno organizacional','Reconocimiento del desempeño','Escaso o nulo reconocimiento y compensación','En mi centro de trabajo me pagan a tiempo mi salario','frecuencia',49,1,'2026-10-29 06:30:49'),(116,3,'50','Reconocimiento','Entorno organizacional','Reconocimiento del desempeño','Escaso o nulo reconocimiento y compensación','El pago que recibo es el que merezco por el trabajo que realizo','frecuencia',50,1,'2026-10-29 06:30:49'),(117,3,'51','Reconocimiento','Entorno organizacional','Reconocimiento del desempeño','Escaso o nulo reconocimiento y compensación','Si obtengo los resultados esperados en mi trabajo me recompensan o reconocen','frecuencia',51,1,'2026-10-29 06:30:49'),(118,3,'52','Reconocimiento','Entorno organizacional','Reconocimiento del desempeño','Escaso o nulo reconocimiento y compensación','Las personas que hacen bien el trabajo pueden crecer laboralmente','frecuencia',52,1,'2026-10-29 06:30:49'),(119,3,'53','Estabilidad laboral','Entorno organizacional','Insuficiente sentido de pertenencia e, inestabilidad','Inestabilidad laboral','Considero que mi trabajo es estable','frecuencia',53,1,'2026-10-29 06:30:49'),(120,3,'54','Estabilidad laboral','Entorno organizacional','Insuficiente sentido de pertenencia e, inestabilidad','Inestabilidad laboral','En mi trabajo existe continua rotación de personal','frecuencia',54,1,'2026-10-29 06:30:49'),(121,3,'55','Pertenencia','Entorno organizacional','Insuficiente sentido de pertenencia e, inestabilidad','Limitado sentido de pertenencia','Siento orgullo de laborar en este centro de trabajo','frecuencia',55,1,'2026-10-29 06:30:49'),(122,3,'56','Pertenencia','Entorno organizacional','Insuficiente sentido de pertenencia e, inestabilidad','Limitado sentido de pertenencia','Me siento comprometido con mi trabajo','frecuencia',56,1,'2026-10-29 06:30:49'),(123,3,'57','Violencia laboral','Liderazgo y relaciones en el trabajo','Violencia','Violencia laboral','En mi trabajo puedo expresarme libremente sin interrupciones','frecuencia',57,1,'2026-10-29 06:30:49'),(124,3,'58','Violencia laboral','Liderazgo y relaciones en el trabajo','Violencia','Violencia laboral','Recibo críticas constantes a mi persona y/o trabajo','frecuencia',58,1,'2026-10-29 06:30:49'),(125,3,'59','Violencia laboral','Liderazgo y relaciones en el trabajo','Violencia','Violencia laboral','Recibo burlas, calumnias, difamaciones, humillaciones o ridiculizaciones','frecuencia',59,1,'2026-10-29 06:30:49'),(126,3,'60','Violencia laboral','Liderazgo y relaciones en el trabajo','Violencia','Violencia laboral','Se ignora mi presencia o se me excluye de las reuniones de trabajo y en la toma de decisiones','frecuencia',60,1,'2026-10-29 06:30:49'),(127,3,'61','Violencia laboral','Liderazgo y relaciones en el trabajo','Violencia','Violencia laboral','Se manipulan las situaciones de trabajo para hacerme parecer un mal trabajador','frecuencia',61,1,'2026-10-29 06:30:49'),(128,3,'62','Violencia laboral','Liderazgo y relaciones en el trabajo','Violencia','Violencia laboral','Se ignoran mis éxitos laborales y se atribuyen a otros trabajadores','frecuencia',62,1,'2026-10-29 06:30:49'),(129,3,'63','Violencia laboral','Liderazgo y relaciones en el trabajo','Violencia','Violencia laboral','Me bloquean o impiden las oportunidades que tengo para obtener ascenso o mejora en mi trabajo','frecuencia',63,1,'2026-10-29 06:30:49'),(130,3,'64','Violencia laboral','Liderazgo y relaciones en el trabajo','Violencia','Violencia laboral','He presenciado actos de violencia en mi centro de trabajo','frecuencia',64,1,'2026-10-29 06:30:49'),(131,3,'65','Atención a clientes y usuarios','Factores propios de la actividad','Carga de trabajo','Cargas psicológicas emocionales','Atiendo clientes o usuarios muy enojados','frecuencia',65,1,'2026-10-29 06:30:49'),(132,3,'66','Atención a clientes y usuarios','Factores propios de la actividad','Carga de trabajo','Cargas psicológicas emocionales','Mi trabajo me exige atender personas muy necesitadas de ayuda o enfermas','frecuencia',66,1,'2026-10-29 06:30:49'),(133,3,'67','Atención a clientes y usuarios','Factores propios de la actividad','Carga de trabajo','Cargas psicológicas emocionales','Para hacer mi trabajo debo demostrar sentimientos distintos a los míos','frecuencia',67,1,'2026-10-29 06:30:49'),(134,3,'68','Atención a clientes y usuarios','Factores propios de la actividad','Carga de trabajo','Cargas psicológicas emocionales','Mi trabajo me exige atender situaciones de violencia','frecuencia',68,1,'2026-10-29 06:30:49'),(135,3,'69','Personal a cargo','Liderazgo y relaciones en el trabajo','Relaciones en el trabajo','Deficiente relación con los colaboradores que supervisa','Comunican tarde los asuntos de trabajo','frecuencia',69,1,'2026-10-29 06:30:49'),(136,3,'70','Personal a cargo','Liderazgo y relaciones en el trabajo','Relaciones en el trabajo','Deficiente relación con los colaboradores que supervisa','Dificultan el logro de los resultados del trabajo','frecuencia',70,1,'2026-10-29 06:30:49'),(137,3,'71','Personal a cargo','Liderazgo y relaciones en el trabajo','Relaciones en el trabajo','Deficiente relación con los colaboradores que supervisa','Cooperan poco cuando se necesita','frecuencia',71,1,'2026-10-29 06:30:49'),(138,3,'72','Personal a cargo','Liderazgo y relaciones en el trabajo','Relaciones en el trabajo','Deficiente relación con los colaboradores que supervisa','Ignoran las sugerencias para mejorar su trabajo','frecuencia',72,1,'2026-10-29 06:30:49');
/*!40000 ALTER TABLE `nom035_preguntas` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `nom035_respuestas`
--

DROP TABLE IF EXISTS `nom035_respuestas`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `nom035_respuestas` (
  `id_respuesta` int(11) NOT NULL AUTO_INCREMENT,
  `id_aplicacion` int(11) NOT NULL,
  `id_empleado` int(11) NOT NULL,
  `id_pregunta` int(11) NOT NULL,
  `id_opcion` int(11) DEFAULT NULL,
  `respuesta` varchar(255) DEFAULT NULL,
  `valor` decimal(10,2) DEFAULT NULL,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_respuesta`),
  UNIQUE KEY `uq_nom035_respuesta` (`id_aplicacion`,`id_pregunta`),
  KEY `idx_nom035_respuesta_empleado` (`id_empleado`),
  KEY `idx_nom035_respuesta_pregunta` (`id_pregunta`),
  KEY `fk_nom035_respuesta_opcion` (`id_opcion`),
  CONSTRAINT `fk_nom035_respuesta_aplicacion` FOREIGN KEY (`id_aplicacion`) REFERENCES `nom035_aplicaciones` (`id_aplicacion`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_nom035_respuesta_empleado` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id_empleado`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_nom035_respuesta_opcion` FOREIGN KEY (`id_opcion`) REFERENCES `nom035_opciones` (`id_opcion`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_nom035_respuesta_pregunta` FOREIGN KEY (`id_pregunta`) REFERENCES `nom035_preguntas` (`id_pregunta`) ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=113 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `nom035_respuestas`
--

LOCK TABLES `nom035_respuestas` WRITE;
/*!40000 ALTER TABLE `nom035_respuestas` DISABLE KEYS */;
INSERT INTO `nom035_respuestas` VALUES (67,6,3,1,32,'No',0.00,'2026-10-30 15:52:52'),(68,6,3,2,33,'No',0.00,'2026-10-30 15:52:52'),(69,6,3,3,34,'No',0.00,'2026-10-30 15:52:52'),(70,6,3,4,35,'No',0.00,'2026-10-30 15:52:52'),(71,6,3,5,5,'Sí',1.00,'2026-10-30 15:52:52'),(72,6,3,6,6,'Sí',1.00,'2026-10-30 15:52:52'),(73,6,3,7,7,'Sí',1.00,'2026-10-30 15:52:52'),(74,6,3,8,8,'Sí',1.00,'2026-10-30 15:52:52'),(75,6,3,9,9,'Sí',1.00,'2026-10-30 15:52:52'),(76,6,3,10,41,'No',0.00,'2026-10-30 15:52:52'),(77,6,3,11,11,'Sí',1.00,'2026-10-30 15:52:52'),(78,6,3,12,43,'No',0.00,'2026-10-30 15:52:52'),(79,6,3,13,13,'Sí',1.00,'2026-10-30 15:52:52'),(80,6,3,14,14,'Sí',1.00,'2026-10-30 15:52:52'),(81,6,3,15,15,'Sí',1.00,'2026-10-30 15:52:52'),(82,6,3,16,16,'Sí',1.00,'2026-10-30 15:52:52'),(83,6,3,17,17,'Sí',1.00,'2026-10-30 15:52:52'),(84,6,3,18,18,'Sí',1.00,'2026-10-30 15:52:52'),(85,6,3,19,19,'Sí',1.00,'2026-10-30 15:52:52'),(86,6,3,20,20,'Sí',1.00,'2026-10-30 15:52:52'),(87,7,4,1,32,'No',0.00,'2026-11-12 20:27:57'),(88,7,4,2,33,'No',0.00,'2026-11-12 20:27:57'),(89,7,4,3,34,'No',0.00,'2026-11-12 20:27:57'),(90,7,4,4,35,'No',0.00,'2026-11-12 20:27:57'),(91,7,4,5,36,'No',0.00,'2026-11-12 20:27:57'),(92,7,4,6,37,'No',0.00,'2026-11-12 20:27:57'),(93,8,4,1,32,'No',0.00,'2026-11-12 20:30:05'),(94,8,4,2,33,'No',0.00,'2026-11-12 20:30:05'),(95,8,4,3,34,'No',0.00,'2026-11-12 20:30:05'),(96,8,4,4,35,'No',0.00,'2026-11-12 20:30:05'),(97,8,4,5,5,'Sí',1.00,'2026-11-12 20:30:05'),(98,8,4,6,6,'Sí',1.00,'2026-11-12 20:30:05'),(99,8,4,7,38,'No',0.00,'2026-11-12 20:30:05'),(100,8,4,8,8,'Sí',1.00,'2026-11-12 20:30:05'),(101,8,4,9,40,'No',0.00,'2026-11-12 20:30:05'),(102,8,4,10,10,'Sí',1.00,'2026-11-12 20:30:05'),(103,8,4,11,42,'No',0.00,'2026-11-12 20:30:05'),(104,8,4,12,12,'Sí',1.00,'2026-11-12 20:30:05'),(105,8,4,13,13,'Sí',1.00,'2026-11-12 20:30:05'),(106,8,4,14,45,'No',0.00,'2026-11-12 20:30:05'),(107,8,4,15,15,'Sí',1.00,'2026-11-12 20:30:05'),(108,8,4,16,47,'No',0.00,'2026-11-12 20:30:05'),(109,8,4,17,17,'Sí',1.00,'2026-11-12 20:30:05'),(110,8,4,18,49,'No',0.00,'2026-11-12 20:30:05'),(111,8,4,19,50,'No',0.00,'2026-11-12 20:30:05'),(112,8,4,20,51,'No',0.00,'2026-11-12 20:30:05');
/*!40000 ALTER TABLE `nom035_respuestas` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `nom035_resultados`
--

DROP TABLE IF EXISTS `nom035_resultados`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `nom035_resultados` (
  `id_resultado` int(11) NOT NULL AUTO_INCREMENT,
  `id_aplicacion` int(11) NOT NULL,
  `id_empleado` int(11) NOT NULL,
  `id_cuestionario` int(11) NOT NULL,
  `puntaje_total` decimal(10,2) DEFAULT NULL,
  `nivel_riesgo` enum('nulo','bajo','medio','alto','muy_alto','no_aplica') DEFAULT NULL,
  `resultado_general` text DEFAULT NULL,
  `categorias` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`categorias`)),
  `dominios` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`dominios`)),
  `dimensiones` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`dimensiones`)),
  `requiere_accion` tinyint(1) NOT NULL DEFAULT 0,
  `recomendaciones` text DEFAULT NULL,
  `preevaluacion_ia` text DEFAULT NULL,
  `ia_proveedor` varchar(50) DEFAULT NULL,
  `ia_modelo` varchar(100) DEFAULT NULL,
  `fecha_preevaluacion_ia` datetime DEFAULT NULL,
  `fecha_resultado` datetime NOT NULL DEFAULT current_timestamp(),
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `actualizado_en` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_resultado`),
  UNIQUE KEY `uq_nom035_resultado_aplicacion` (`id_aplicacion`),
  KEY `idx_nom035_resultado_empleado` (`id_empleado`),
  KEY `idx_nom035_resultado_nivel` (`nivel_riesgo`),
  KEY `fk_nom035_resultado_cuestionario` (`id_cuestionario`),
  CONSTRAINT `fk_nom035_resultado_aplicacion` FOREIGN KEY (`id_aplicacion`) REFERENCES `nom035_aplicaciones` (`id_aplicacion`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_nom035_resultado_cuestionario` FOREIGN KEY (`id_cuestionario`) REFERENCES `nom035_cuestionarios` (`id_cuestionario`) ON UPDATE CASCADE,
  CONSTRAINT `fk_nom035_resultado_empleado` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id_empleado`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `nom035_resultados`
--

LOCK TABLES `nom035_resultados` WRITE;
/*!40000 ALTER TABLE `nom035_resultados` DISABLE KEYS */;
INSERT INTO `nom035_resultados` VALUES (3,6,3,1,14.00,'no_aplica','La aplicación cumple al menos uno de los criterios de la Guía de Referencia I para requerir atención clínica.','[{\"nombre\":\"Acontecimiento traumático severo\",\"respuestas_si\":2},{\"nombre\":\"Recuerdos persistentes\",\"respuestas_si\":2},{\"nombre\":\"Evitación\",\"respuestas_si\":5},{\"nombre\":\"Afectación\",\"respuestas_si\":5}]','[]','[]',1,'Corresponde realizar la canalización para valoración clínica conforme a la Guía de Referencia I.','PRE-EVALUACIÓN IA\n\nInterpretación:\nLa aplicación de la Guía de Referencia I indica que se cumplen criterios para requerir atención clínica. Los resultados señalan respuestas relevantes en áreas como \'Evitación\', \'Afectación\' y \'Recuerdos persistentes\'.\n\nAtención sugerida:\nRecursos Humanos debe considerar la canalización del colaborador para una valoración clínica, según lo establecido por la Guía de Referencia I de la NOM-035. Esta acción permitiría una evaluación profesional de los hallazgos.\n\nNota:\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico y la decisión final corresponde a Recursos Humanos.','gemini','gemini','2026-10-30 09:52:59','2026-10-30 09:52:52','2026-10-30 15:52:52','2026-10-30 15:52:59'),(4,7,4,1,0.00,'no_aplica','No se identificó exposición al acontecimiento traumático severo en la Sección I, por lo que no se requiere continuar con las demás secciones de la Guía de Referencia I.','[{\"nombre\":\"Acontecimiento traumático severo\",\"respuestas_si\":0}]','[]','[]',0,'No se requiere continuar con las secciones II, III y IV conforme a la lógica de la Guía de Referencia I.','PRE-EVALUACIÓN IA\n\nInterpretación:\nLa aplicación del Cuestionario para identificar acontecimientos traumáticos severos (Guía I) no identificó exposición a este tipo de eventos. Como resultado, el puntaje total es 0 y no se requiere continuar con las secciones subsiguientes de la guía.\n\nAtención sugerida:\nRecursos Humanos puede registrar este resultado conforme a la NOM-035-STPS-2018. No se identifican acciones inmediatas específicas derivadas de este cuestionario para la persona evaluada en relación con Acontecimientos Traumáticos Severos.\n\nNota:\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión administrativa final corresponde a Recursos Humanos.','gemini','gemini','2026-11-12 14:28:03','2026-11-12 14:27:57','2026-11-12 20:27:57','2026-11-12 20:28:03'),(5,8,4,1,8.00,'no_aplica','La aplicación cumple al menos uno de los criterios de la Guía de Referencia I para requerir atención clínica.','[{\"nombre\":\"Acontecimiento traumático severo\",\"respuestas_si\":2},{\"nombre\":\"Recuerdos persistentes\",\"respuestas_si\":1},{\"nombre\":\"Evitación\",\"respuestas_si\":4},{\"nombre\":\"Afectación\",\"respuestas_si\":1}]','[]','[]',1,'Corresponde realizar la canalización para valoración clínica conforme a la Guía de Referencia I.','PRE-EVALUACIÓN IA\n\n**Interpretación:**\nLa aplicación de la Guía I indica que el individuo cumple al menos uno de los criterios para requerir atención clínica. Se identifican respuestas relevantes en las categorías de Evitación y Acontecimiento Traumático Severo.\n\n**Atención sugerida:**\nCon base en estos resultados, Recursos Humanos debe considerar la canalización del empleado para una valoración clínica profesional, conforme a la Guía de Referencia I. Es importante seguir los protocolos internos establecidos para esta gestión.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión administrativa final corresponde a Recursos Humanos.','gemini','gemini','2026-11-12 14:30:12','2026-11-12 14:30:05','2026-11-12 20:30:05','2026-11-12 20:30:12');
/*!40000 ALTER TABLE `nom035_resultados` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `notas_sesion`
--

DROP TABLE IF EXISTS `notas_sesion`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `notas_sesion` (
  `id_chat` int(11) NOT NULL AUTO_INCREMENT,
  `id_sesion` int(11) NOT NULL,
  `autor` varchar(50) NOT NULL DEFAULT 'psicologo',
  `pregunta` text NOT NULL,
  `respuesta` text DEFAULT NULL,
  `tipo` varchar(50) NOT NULL DEFAULT 'observacion',
  `fecha` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_chat`),
  KEY `idx_notas_sesion_id_sesion` (`id_sesion`),
  KEY `idx_notas_sesion_tipo` (`tipo`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `notas_sesion`
--

LOCK TABLES `notas_sesion` WRITE;
/*!40000 ALTER TABLE `notas_sesion` DISABLE KEYS */;
INSERT INTO `notas_sesion` VALUES (1,12,'psicologo','refiere que ya puede dormir mejor solo las alteraciones en la noche le da taquicardia y le falta la respiración son ataques que le dan de repente',NULL,'nota_ia','2026-09-15 15:06:53'),(2,13,'psicologo','hubo problemas familiares y eso altero sus emociones y estado',NULL,'nota_ia','2026-09-15 16:05:35'),(3,14,'psicologo','hoy viene muy nerviosa por problemas en casa  refiere que ha decidido salirse de casa para mejorar su paz mental',NULL,'nota_ia','2026-09-15 17:31:24'),(4,15,'psicologo','Continúan las dificultades relacionadas con el entorno familiar. En esta sesión se observa mayor malestar ya salió de su casa y refiere sentirse más tranquila',NULL,'nota_ia','2026-09-15 22:12:17'),(5,17,'psicologo','a pesar de que se ve mejoría aun afecta la situación familiar',NULL,'nota_ia','2026-09-15 23:15:11'),(6,18,'psicologo','la paciente ha tenido mejoria ha logrado dormir mas pero hizo contacto 0',NULL,'nota_ia','2026-09-16 19:16:50'),(7,20,'psicologo','Presenta dificultad para expresar sus emociones',NULL,'nota_ia','2026-10-27 10:41:33'),(8,21,'psicologo','no',NULL,'nota_ia','2026-11-09 17:27:05'),(9,23,'psicologo','yo tengo una computadora',NULL,'nota_ia','2026-11-10 14:38:29');
/*!40000 ALTER TABLE `notas_sesion` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `observaciones_prospectos`
--

DROP TABLE IF EXISTS `observaciones_prospectos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `observaciones_prospectos` (
  `id_observacion` int(11) NOT NULL AUTO_INCREMENT,
  `id_prospecto` int(11) NOT NULL,
  `id_usuario_registro` int(11) DEFAULT NULL,
  `tipo` enum('entrevista','conducta','experiencia','competencias','documentacion','referencias','proceso','general') NOT NULL DEFAULT 'general',
  `titulo` varchar(180) DEFAULT NULL,
  `observacion` text NOT NULL,
  `relevancia` enum('informativa','atencion','fortaleza') NOT NULL DEFAULT 'informativa',
  `fecha` datetime NOT NULL DEFAULT current_timestamp(),
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `actualizado_en` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_observacion`),
  KEY `idx_obs_prospecto` (`id_prospecto`),
  KEY `idx_obs_usuario` (`id_usuario_registro`),
  KEY `idx_obs_tipo` (`tipo`),
  KEY `idx_obs_relevancia` (`relevancia`),
  KEY `idx_obs_fecha` (`fecha`),
  CONSTRAINT `fk_obs_prospecto` FOREIGN KEY (`id_prospecto`) REFERENCES `prospectos` (`id_prospecto`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_obs_usuario` FOREIGN KEY (`id_usuario_registro`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `observaciones_prospectos`
--

LOCK TABLES `observaciones_prospectos` WRITE;
/*!40000 ALTER TABLE `observaciones_prospectos` DISABLE KEYS */;
INSERT INTO `observaciones_prospectos` VALUES (1,1,15,'entrevista','trabajo bajo presion y es responsablo y puntual','gffhfsrf','informativa','2026-10-01 16:42:00','2026-10-01 22:42:31','2026-10-01 22:42:31');
/*!40000 ALTER TABLE `observaciones_prospectos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `opciones_respuesta`
--

DROP TABLE IF EXISTS `opciones_respuesta`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `opciones_respuesta` (
  `id_opcion` int(11) NOT NULL AUTO_INCREMENT,
  `id_pregunta` int(11) NOT NULL,
  `texto` varchar(200) NOT NULL,
  `valor` int(11) DEFAULT NULL,
  PRIMARY KEY (`id_opcion`)
) ENGINE=InnoDB AUTO_INCREMENT=371 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `opciones_respuesta`
--

LOCK TABLES `opciones_respuesta` WRITE;
/*!40000 ALTER TABLE `opciones_respuesta` DISABLE KEYS */;
INSERT INTO `opciones_respuesta` VALUES (93,36,'Nunca',0),(94,36,'Casi nunca',1),(95,36,'De vez en cuando',2),(96,36,'A menudo',3),(97,36,'Muy a menudo',4),(98,37,'Nunca',0),(99,37,'Casi nunca',1),(100,37,'De vez en cuando',2),(101,37,'A menudo',3),(102,37,'Muy a menudo',4),(103,38,'Nunca',0),(104,38,'Casi nunca',1),(105,38,'De vez en cuando',2),(106,38,'A menudo',3),(107,38,'Muy a menudo',4),(108,39,'Nunca',0),(109,39,'Casi nunca',1),(110,39,'De vez en cuando',2),(111,39,'A menudo',3),(112,39,'Muy a menudo',4),(113,40,'Nunca',0),(114,40,'Casi nunca',1),(115,40,'De vez en cuando',2),(116,40,'A menudo',3),(117,40,'Muy a menudo',4),(118,41,'Nunca',0),(119,41,'Casi nunca',1),(120,41,'De vez en cuando',2),(121,41,'A menudo',3),(122,41,'Muy a menudo',4),(123,42,'Nunca',0),(124,42,'Casi nunca',1),(125,42,'De vez en cuando',2),(126,42,'A menudo',3),(127,42,'Muy a menudo',4),(128,43,'Nunca',0),(129,43,'Casi nunca',1),(130,43,'De vez en cuando',2),(131,43,'A menudo',3),(132,43,'Muy a menudo',4),(133,44,'Nunca',0),(134,44,'Casi nunca',1),(135,44,'De vez en cuando',2),(136,44,'A menudo',3),(137,44,'Muy a menudo',4),(138,45,'Nunca',0),(139,45,'Casi nunca',1),(140,45,'De vez en cuando',2),(141,45,'A menudo',3),(142,45,'Muy a menudo',4),(143,46,'Nunca',0),(144,46,'Casi nunca',1),(145,46,'De vez en cuando',2),(146,46,'A menudo',3),(147,46,'Muy a menudo',4),(148,47,'Nunca',0),(149,47,'Casi nunca',1),(150,47,'De vez en cuando',2),(151,47,'A menudo',3),(152,47,'Muy a menudo',4),(153,48,'Nunca',0),(154,48,'Casi nunca',1),(155,48,'De vez en cuando',2),(156,48,'A menudo',3),(157,48,'Muy a menudo',4),(158,49,'Nunca',0),(159,49,'Casi nunca',1),(160,49,'De vez en cuando',2),(161,49,'A menudo',3),(162,49,'Muy a menudo',4),(163,50,'0 - No me siento triste',0),(164,50,'1 - Me siento triste gran parte del tiempo',1),(165,50,'2 - Estoy triste todo el tiempo',2),(166,50,'3 - Estoy tan triste o infeliz que no puedo soportarlo',3),(167,51,'0 - No estoy desalentado respecto al futuro',0),(168,51,'1 - Me siento más desalentado que antes',1),(169,51,'2 - No espero que las cosas mejoren para mí',2),(170,51,'3 - Siento que no hay esperanza para mi futuro',3),(171,52,'0 - No me siento como un fracasado',0),(172,52,'1 - He fracasado más de lo que debería',1),(173,52,'2 - Cuando miro atrás, veo muchos fracasos',2),(174,52,'3 - Me siento como una persona totalmente fracasada',3),(175,53,'0 - Disfruto tanto como antes',0),(176,53,'1 - No disfruto tanto como antes',1),(177,53,'2 - Disfruto poco de las cosas',2),(178,53,'3 - No puedo disfrutar de nada',3),(179,54,'0 - No me siento particularmente culpable',0),(180,54,'1 - Me siento culpable a menudo',1),(181,54,'2 - Me siento culpable la mayor parte del tiempo',2),(182,54,'3 - Me siento culpable todo el tiempo',3),(183,55,'0 - No siento que esté siendo castigado',0),(184,55,'1 - Siento que puedo ser castigado',1),(185,55,'2 - Espero ser castigado',2),(186,55,'3 - Siento que estoy siendo castigado',3),(187,56,'0 - Me siento satisfecho conmigo mismo',0),(188,56,'1 - Pierdo confianza en mí mismo',1),(189,56,'2 - Estoy decepcionado conmigo mismo',2),(190,56,'3 - Me odio a mí mismo',3),(191,57,'0 - No me critico ni me culpo más que lo habitual',0),(192,57,'1 - Estoy más crítico conmigo mismo',1),(193,57,'2 - Me critico por todos mis errores',2),(194,57,'3 - Me culpo de todo lo malo que sucede',3),(195,58,'0 - No tengo pensamientos suicidas',0),(196,58,'1 - Tengo pensamientos suicidas pero no los llevaría a cabo',1),(197,58,'2 - Quisiera suicidarme',2),(198,58,'3 - Me suicidaría si tuviera la oportunidad',3),(199,59,'0 - No lloro más de lo habitual',0),(200,59,'1 - Lloro más de lo habitual',1),(201,59,'2 - Lloro todo el tiempo',2),(202,59,'3 - Antes podía llorar, pero ahora no puedo aunque quiera',3),(203,60,'0 - No estoy más inquieto o agitado de lo habitual',0),(204,60,'1 - Estoy más inquieto de lo habitual',1),(205,60,'2 - Estoy tan inquieto o agitado que me cuesta estar quieto',2),(206,60,'3 - Estoy tan agitado que debo moverme o hacer algo constantemente',3),(207,61,'0 - No he perdido interés en otras personas o actividades',0),(208,61,'1 - Estoy menos interesado que antes',1),(209,61,'2 - He perdido la mayor parte de mi interés',2),(210,61,'3 - He perdido todo el interés en otras personas o cosas',3),(211,62,'0 - Tomo decisiones igual que siempre',0),(212,62,'1 - Me resulta más difícil tomar decisiones',1),(213,62,'2 - Me resulta muy difícil tomar decisiones',2),(214,62,'3 - No puedo tomar ninguna decisión',3),(215,63,'0 - No siento que valga menos que los demás',0),(216,63,'1 - Me critico por mis debilidades',1),(217,63,'2 - Me siento inferior a los demás',2),(218,63,'3 - Siento que no valgo nada',3),(219,64,'0 - Tengo tanta energía como siempre',0),(220,64,'1 - Tengo menos energía que antes',1),(221,64,'2 - No tengo suficiente energía para muchas cosas',2),(222,64,'3 - No tengo energía para nada',3),(223,65,'0 - Duermo igual que siempre',0),(224,65,'1 - Duermo más o menos de lo habitual',1),(225,65,'2 - Duermo mucho menos/más que antes',2),(226,65,'3 - Casi no duermo o duermo demasiado',3),(227,66,'0 - No estoy más irritable que de costumbre',0),(228,66,'1 - Estoy más irritable de lo habitual',1),(229,66,'2 - Estoy muy irritable la mayor parte del tiempo',2),(230,66,'3 - Estoy irritable todo el tiempo',3),(231,67,'0 - Mi apetito no ha cambiado',0),(232,67,'1 - Mi apetito es algo menor o mayor',1),(233,67,'2 - Mi apetito es mucho menor o mayor',2),(234,67,'3 - No tengo apetito o quiero comer todo el tiempo',3),(235,68,'0 - Me concentro tan bien como siempre',0),(236,68,'1 - Me cuesta un poco concentrarme',1),(237,68,'2 - Me resulta difícil concentrarme mucho tiempo',2),(238,68,'3 - No puedo concentrarme en nada',3),(239,69,'0 - No estoy más cansado de lo habitual',0),(240,69,'1 - Me canso más fácilmente que antes',1),(241,69,'2 - Estoy muy cansado para hacer muchas cosas',2),(242,69,'3 - Estoy demasiado cansado para hacer nada',3),(243,70,'0 - No he notado ningún cambio en mi interés sexual',0),(244,70,'1 - Estoy menos interesado en el sexo que antes',1),(245,70,'2 - Estoy mucho menos interesado en el sexo',2),(246,70,'3 - He perdido todo el interés en el sexo',3),(247,71,'0 - Nunca',0),(248,71,'1 - Varios días',1),(249,71,'2 - Más de la mitad de los días',2),(250,71,'3 - Casi todos los días',3),(251,72,'0 - Nunca',0),(252,72,'1 - Varios días',1),(253,72,'2 - Más de la mitad de los días',2),(254,72,'3 - Casi todos los días',3),(255,73,'0 - Nunca',0),(256,73,'1 - Varios días',1),(257,73,'2 - Más de la mitad de los días',2),(258,73,'3 - Casi todos los días',3),(259,74,'0 - Nunca',0),(260,74,'1 - Varios días',1),(261,74,'2 - Más de la mitad de los días',2),(262,74,'3 - Casi todos los días',3),(263,75,'0 - Nunca',0),(264,75,'1 - Varios días',1),(265,75,'2 - Más de la mitad de los días',2),(266,75,'3 - Casi todos los días',3),(267,76,'0 - Nunca',0),(268,76,'1 - Varios días',1),(269,76,'2 - Más de la mitad de los días',2),(270,76,'3 - Casi todos los días',3),(271,77,'0 - Nunca',0),(272,77,'1 - Varios días',1),(273,77,'2 - Más de la mitad de los días',2),(274,77,'3 - Casi todos los días',3),(275,78,'Persuasivo',NULL),(276,78,'Gentil',NULL),(277,78,'Humilde',NULL),(278,78,'Original',NULL),(279,79,'Agresivo',NULL),(280,79,'Alma de la fiesta',NULL),(281,79,'Comodino',NULL),(282,79,'Temeroso',NULL),(283,80,'Agradable',NULL),(284,80,'Temeroso de Dios',NULL),(285,80,'Tenaz',NULL),(286,80,'Atractivo',NULL),(287,81,'Cauteloso',NULL),(288,81,'Determinado',NULL),(289,81,'Convincente',NULL),(290,81,'Bonachón',NULL),(291,82,'Dócil',NULL),(292,82,'Atrevido',NULL),(293,82,'Leal',NULL),(294,82,'Encantador',NULL),(295,83,'Dispuesto',NULL),(296,83,'Deseoso',NULL),(297,83,'Consecuente',NULL),(298,83,'Entusiasta',NULL),(299,84,'Fuerza de voluntad',NULL),(300,84,'Mente abierta',NULL),(301,84,'Complaciente',NULL),(302,84,'Animoso',NULL),(303,85,'Confiado',NULL),(304,85,'Simpatizador',NULL),(305,85,'Tolerante',NULL),(306,85,'Afirmativo',NULL),(307,86,'Ecuánime',NULL),(308,86,'Preciso',NULL),(309,86,'Nervioso',NULL),(310,86,'Jovial',NULL),(311,87,'Disciplinado',NULL),(312,87,'Generoso',NULL),(313,87,'Animoso',NULL),(314,87,'Persistente',NULL),(315,88,'Competitivo',NULL),(316,88,'Alegre',NULL),(317,88,'Considerado',NULL),(318,88,'Armonioso',NULL),(319,89,'Admirable',NULL),(320,89,'Bondadoso',NULL),(321,89,'Resignado',NULL),(322,89,'Carácter firme',NULL),(323,90,'Obediente',NULL),(324,90,'Quisquilloso',NULL),(325,90,'Inconquistable',NULL),(326,90,'Juguetón',NULL),(327,91,'Respetuoso',NULL),(328,91,'Emprendedor',NULL),(329,91,'Optimista',NULL),(330,91,'Servicial',NULL),(331,92,'Valiente',NULL),(332,92,'Inspirador',NULL),(333,92,'Sumiso',NULL),(334,92,'Tímido',NULL),(335,93,'Adaptable',NULL),(336,93,'Disputador',NULL),(337,93,'Indiferente',NULL),(338,93,'Sangre liviana',NULL),(339,94,'Amiguero',NULL),(340,94,'Paciente',NULL),(341,94,'Confianza en sí mismo',NULL),(342,94,'Mesurado para hablar',NULL),(343,95,'Conforme',NULL),(344,95,'Confiable',NULL),(345,95,'Pacífico',NULL),(346,95,'Positivo',NULL),(347,96,'Aventurero',NULL),(348,96,'Receptivo',NULL),(349,96,'Cordial',NULL),(350,96,'Moderado',NULL),(351,97,'Indulgente',NULL),(352,97,'Esteta',NULL),(353,97,'Vigoroso',NULL),(354,97,'Sociable',NULL),(355,98,'Parlanchín',NULL),(356,98,'Controlado',NULL),(357,98,'Convencional',NULL),(358,98,'Decisivo',NULL),(359,99,'Cohibido',NULL),(360,99,'Exacto',NULL),(361,99,'Franco',NULL),(362,99,'Buen compañero',NULL),(363,100,'Diplomático',NULL),(364,100,'Audaz',NULL),(365,100,'Refinado',NULL),(366,100,'Satisfecho',NULL),(367,101,'Inquieto',NULL),(368,101,'Popular',NULL),(369,101,'Buen vecino',NULL),(370,101,'Devoto',NULL);
/*!40000 ALTER TABLE `opciones_respuesta` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `opciones_respuesta_rh`
--

DROP TABLE IF EXISTS `opciones_respuesta_rh`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `opciones_respuesta_rh` (
  `id_opcion_rh` int(11) NOT NULL AUTO_INCREMENT,
  `id_pregunta_rh` int(11) NOT NULL,
  `texto_opcion` varchar(255) NOT NULL,
  `valor` decimal(10,2) DEFAULT NULL,
  `orden` int(11) NOT NULL DEFAULT 0,
  `activo` tinyint(1) NOT NULL DEFAULT 1,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_opcion_rh`),
  KEY `idx_orrh_pregunta` (`id_pregunta_rh`),
  CONSTRAINT `fk_orrh_pregunta` FOREIGN KEY (`id_pregunta_rh`) REFERENCES `preguntas_prueba_rh` (`id_pregunta_rh`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=805 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `opciones_respuesta_rh`
--

LOCK TABLES `opciones_respuesta_rh` WRITE;
/*!40000 ALTER TABLE `opciones_respuesta_rh` DISABLE KEYS */;
INSERT INTO `opciones_respuesta_rh` VALUES (1,101,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(2,102,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(3,103,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(4,104,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(5,105,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(6,106,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(7,107,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(8,108,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(9,109,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(10,110,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(11,111,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(12,112,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(13,113,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(14,114,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(15,115,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(16,116,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(17,117,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(18,118,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(19,119,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(20,120,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(21,121,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(22,122,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(23,123,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(24,124,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(25,125,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(26,126,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(27,127,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(28,128,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(29,129,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(30,130,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(31,131,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(32,132,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(33,133,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(34,134,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(35,135,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(36,136,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(37,137,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(38,138,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(39,139,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(40,140,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(41,141,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(42,142,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(43,143,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(44,144,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(45,145,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(46,146,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(47,147,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(48,148,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(49,149,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(50,150,'Muy en desacuerdo',1.00,1,1,'2026-10-01 23:45:45'),(51,101,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(52,102,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(53,103,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(54,104,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(55,105,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(56,106,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(57,107,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(58,108,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(59,109,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(60,110,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(61,111,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(62,112,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(63,113,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(64,114,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(65,115,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(66,116,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(67,117,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(68,118,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(69,119,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(70,120,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(71,121,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(72,122,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(73,123,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(74,124,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(75,125,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(76,126,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(77,127,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(78,128,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(79,129,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(80,130,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(81,131,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(82,132,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(83,133,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(84,134,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(85,135,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(86,136,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(87,137,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(88,138,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(89,139,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(90,140,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(91,141,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(92,142,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(93,143,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(94,144,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(95,145,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(96,146,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(97,147,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(98,148,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(99,149,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(100,150,'En desacuerdo',2.00,2,1,'2026-10-01 23:45:45'),(101,101,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(102,102,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(103,103,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(104,104,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(105,105,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(106,106,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(107,107,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(108,108,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(109,109,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(110,110,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(111,111,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(112,112,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(113,113,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(114,114,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(115,115,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(116,116,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(117,117,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(118,118,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(119,119,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(120,120,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(121,121,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(122,122,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(123,123,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(124,124,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(125,125,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(126,126,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(127,127,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(128,128,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(129,129,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(130,130,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(131,131,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(132,132,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(133,133,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(134,134,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(135,135,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(136,136,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(137,137,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(138,138,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(139,139,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(140,140,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(141,141,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(142,142,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(143,143,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(144,144,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(145,145,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(146,146,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(147,147,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(148,148,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(149,149,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(150,150,'Ni de acuerdo ni en desacuerdo',3.00,3,1,'2026-10-01 23:45:45'),(151,101,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(152,102,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(153,103,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(154,104,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(155,105,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(156,106,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(157,107,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(158,108,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(159,109,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(160,110,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(161,111,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(162,112,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(163,113,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(164,114,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(165,115,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(166,116,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(167,117,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(168,118,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(169,119,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(170,120,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(171,121,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(172,122,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(173,123,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(174,124,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(175,125,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(176,126,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(177,127,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(178,128,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(179,129,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(180,130,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(181,131,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(182,132,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(183,133,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(184,134,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(185,135,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(186,136,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(187,137,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(188,138,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(189,139,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(190,140,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(191,141,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(192,142,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(193,143,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(194,144,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(195,145,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(196,146,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(197,147,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(198,148,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(199,149,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(200,150,'De acuerdo',4.00,4,1,'2026-10-01 23:45:45'),(201,101,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(202,102,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(203,103,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(204,104,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(205,105,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(206,106,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(207,107,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(208,108,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(209,109,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(210,110,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(211,111,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(212,112,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(213,113,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(214,114,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(215,115,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(216,116,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(217,117,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(218,118,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(219,119,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(220,120,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(221,121,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(222,122,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(223,123,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(224,124,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(225,125,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(226,126,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(227,127,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(228,128,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(229,129,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(230,130,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(231,131,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(232,132,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(233,133,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(234,134,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(235,135,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(236,136,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(237,137,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(238,138,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(239,139,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(240,140,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(241,141,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(242,142,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(243,143,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(244,144,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(245,145,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(246,146,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(247,147,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(248,148,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(249,149,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(250,150,'Muy de acuerdo',5.00,5,1,'2026-10-01 23:45:45'),(251,151,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(252,152,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(253,153,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(254,154,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(255,155,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(256,156,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(257,157,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(258,158,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(259,159,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(260,160,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(261,161,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(262,162,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(263,163,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(264,164,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(265,165,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(266,166,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(267,167,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(268,168,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(269,169,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(270,170,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(271,171,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(272,172,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(273,173,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(274,174,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(275,175,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(276,176,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(277,177,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(278,178,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(279,179,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(280,180,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(281,181,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(282,182,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(283,183,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(284,184,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(285,185,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(286,186,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(287,187,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(288,188,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(289,189,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(290,190,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(291,191,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(292,192,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(293,193,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(294,194,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(295,195,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(296,196,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(297,197,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(298,198,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(299,199,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(300,200,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(301,201,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(302,202,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(303,203,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(304,204,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(305,205,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(306,206,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(307,207,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(308,208,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(309,209,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(310,210,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(311,211,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(312,212,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(313,213,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(314,214,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(315,215,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(316,216,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(317,217,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(318,218,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(319,219,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(320,220,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(321,221,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(322,222,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(323,223,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(324,224,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(325,225,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(326,226,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(327,227,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(328,228,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(329,229,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(330,230,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(331,231,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(332,232,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(333,233,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(334,234,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(335,235,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(336,236,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(337,237,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(338,238,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(339,239,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(340,240,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(341,241,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(342,242,'Me desagrada mucho',1.00,1,1,'2026-10-02 20:53:28'),(343,151,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(344,152,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(345,153,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(346,154,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(347,155,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(348,156,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(349,157,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(350,158,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(351,159,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(352,160,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(353,161,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(354,162,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(355,163,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(356,164,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(357,165,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(358,166,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(359,167,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(360,168,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(361,169,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(362,170,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(363,171,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(364,172,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(365,173,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(366,174,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(367,175,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(368,176,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(369,177,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(370,178,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(371,179,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(372,180,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(373,181,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(374,182,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(375,183,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(376,184,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(377,185,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(378,186,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(379,187,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(380,188,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(381,189,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(382,190,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(383,191,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(384,192,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(385,193,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(386,194,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(387,195,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(388,196,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(389,197,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(390,198,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(391,199,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(392,200,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(393,201,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(394,202,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(395,203,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(396,204,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(397,205,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(398,206,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(399,207,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(400,208,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(401,209,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(402,210,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(403,211,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(404,212,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(405,213,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(406,214,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(407,215,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(408,216,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(409,217,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(410,218,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(411,219,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(412,220,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(413,221,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(414,222,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(415,223,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(416,224,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(417,225,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(418,226,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(419,227,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(420,228,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(421,229,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(422,230,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(423,231,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(424,232,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(425,233,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(426,234,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(427,235,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(428,236,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(429,237,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(430,238,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(431,239,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(432,240,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(433,241,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(434,242,'Me desagrada',2.00,2,1,'2026-10-02 20:53:28'),(435,151,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(436,152,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(437,153,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(438,154,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(439,155,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(440,156,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(441,157,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(442,158,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(443,159,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(444,160,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(445,161,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(446,162,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(447,163,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(448,164,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(449,165,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(450,166,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(451,167,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(452,168,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(453,169,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(454,170,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(455,171,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(456,172,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(457,173,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(458,174,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(459,175,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(460,176,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(461,177,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(462,178,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(463,179,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(464,180,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(465,181,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(466,182,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(467,183,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(468,184,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(469,185,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(470,186,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(471,187,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(472,188,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(473,189,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(474,190,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(475,191,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(476,192,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(477,193,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(478,194,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(479,195,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(480,196,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(481,197,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(482,198,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(483,199,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(484,200,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(485,201,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(486,202,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(487,203,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(488,204,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(489,205,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(490,206,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(491,207,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(492,208,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(493,209,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(494,210,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(495,211,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(496,212,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(497,213,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(498,214,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(499,215,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(500,216,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(501,217,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(502,218,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(503,219,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(504,220,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(505,221,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(506,222,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(507,223,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(508,224,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(509,225,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(510,226,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(511,227,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(512,228,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(513,229,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(514,230,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(515,231,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(516,232,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(517,233,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(518,234,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(519,235,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(520,236,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(521,237,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(522,238,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(523,239,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(524,240,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(525,241,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(526,242,'Me es indiferente',3.00,3,1,'2026-10-02 20:53:28'),(527,151,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(528,152,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(529,153,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(530,154,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(531,155,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(532,156,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(533,157,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(534,158,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(535,159,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(536,160,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(537,161,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(538,162,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(539,163,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(540,164,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(541,165,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(542,166,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(543,167,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(544,168,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(545,169,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(546,170,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(547,171,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(548,172,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(549,173,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(550,174,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(551,175,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(552,176,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(553,177,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(554,178,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(555,179,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(556,180,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(557,181,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(558,182,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(559,183,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(560,184,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(561,185,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(562,186,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(563,187,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(564,188,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(565,189,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(566,190,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(567,191,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(568,192,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(569,193,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(570,194,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(571,195,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(572,196,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(573,197,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(574,198,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(575,199,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(576,200,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(577,201,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(578,202,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(579,203,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(580,204,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(581,205,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(582,206,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(583,207,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(584,208,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(585,209,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(586,210,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(587,211,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(588,212,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(589,213,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(590,214,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(591,215,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(592,216,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(593,217,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(594,218,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(595,219,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(596,220,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(597,221,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(598,222,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(599,223,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(600,224,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(601,225,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(602,226,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(603,227,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(604,228,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(605,229,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(606,230,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(607,231,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(608,232,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(609,233,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(610,234,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(611,235,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(612,236,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(613,237,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(614,238,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(615,239,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(616,240,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(617,241,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(618,242,'Me gusta',4.00,4,1,'2026-10-02 20:53:28'),(619,151,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(620,152,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(621,153,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(622,154,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(623,155,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(624,156,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(625,157,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(626,158,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(627,159,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(628,160,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(629,161,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(630,162,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(631,163,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(632,164,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(633,165,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(634,166,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(635,167,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(636,168,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(637,169,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(638,170,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(639,171,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(640,172,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(641,173,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(642,174,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(643,175,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(644,176,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(645,177,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(646,178,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(647,179,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(648,180,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(649,181,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(650,182,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(651,183,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(652,184,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(653,185,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(654,186,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(655,187,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(656,188,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(657,189,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(658,190,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(659,191,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(660,192,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(661,193,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(662,194,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(663,195,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(664,196,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(665,197,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(666,198,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(667,199,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(668,200,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(669,201,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(670,202,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(671,203,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(672,204,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(673,205,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(674,206,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(675,207,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(676,208,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(677,209,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(678,210,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(679,211,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(680,212,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(681,213,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(682,214,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(683,215,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(684,216,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(685,217,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(686,218,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(687,219,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(688,220,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(689,221,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(690,222,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(691,223,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(692,224,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(693,225,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(694,226,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(695,227,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(696,228,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(697,229,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(698,230,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(699,231,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(700,232,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(701,233,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(702,234,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(703,235,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(704,236,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(705,237,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(706,238,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(707,239,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(708,240,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(709,241,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(710,242,'Me gusta mucho',5.00,5,1,'2026-10-02 20:53:28'),(747,248,'En ningún momento',0.00,1,1,'2026-10-30 17:15:28'),(748,248,'Alguna vez',1.00,2,1,'2026-10-30 17:15:28'),(749,248,'Menos de la mitad del tiempo',2.00,3,1,'2026-10-30 17:15:28'),(750,248,'Más de la mitad del tiempo',3.00,4,1,'2026-10-30 17:15:28'),(751,248,'La mayor parte del tiempo',4.00,5,1,'2026-10-30 17:15:28'),(752,248,'Todo el tiempo',5.00,6,1,'2026-10-30 17:15:28'),(753,249,'En ningún momento',0.00,1,1,'2026-10-30 17:15:28'),(754,249,'Alguna vez',1.00,2,1,'2026-10-30 17:15:28'),(755,249,'Menos de la mitad del tiempo',2.00,3,1,'2026-10-30 17:15:28'),(756,249,'Más de la mitad del tiempo',3.00,4,1,'2026-10-30 17:15:28'),(757,249,'La mayor parte del tiempo',4.00,5,1,'2026-10-30 17:15:28'),(758,249,'Todo el tiempo',5.00,6,1,'2026-10-30 17:15:28'),(759,250,'En ningún momento',0.00,1,1,'2026-10-30 17:15:29'),(760,250,'Alguna vez',1.00,2,1,'2026-10-30 17:15:29'),(761,250,'Menos de la mitad del tiempo',2.00,3,1,'2026-10-30 17:15:29'),(762,250,'Más de la mitad del tiempo',3.00,4,1,'2026-10-30 17:15:29'),(763,250,'La mayor parte del tiempo',4.00,5,1,'2026-10-30 17:15:29'),(764,250,'Todo el tiempo',5.00,6,1,'2026-10-30 17:15:29'),(765,251,'En ningún momento',0.00,1,1,'2026-10-30 17:15:29'),(766,251,'Alguna vez',1.00,2,1,'2026-10-30 17:15:29'),(767,251,'Menos de la mitad del tiempo',2.00,3,1,'2026-10-30 17:15:29'),(768,251,'Más de la mitad del tiempo',3.00,4,1,'2026-10-30 17:15:29'),(769,251,'La mayor parte del tiempo',4.00,5,1,'2026-10-30 17:15:29'),(770,251,'Todo el tiempo',5.00,6,1,'2026-10-30 17:15:29'),(771,252,'En ningún momento',0.00,1,1,'2026-10-30 17:15:29'),(772,252,'Alguna vez',1.00,2,1,'2026-10-30 17:15:29'),(773,252,'Menos de la mitad del tiempo',2.00,3,1,'2026-10-30 17:15:29'),(774,252,'Más de la mitad del tiempo',3.00,4,1,'2026-10-30 17:15:29'),(775,252,'La mayor parte del tiempo',4.00,5,1,'2026-10-30 17:15:29'),(776,252,'Todo el tiempo',5.00,6,1,'2026-10-30 17:15:29'),(777,253,'Nunca',0.00,1,1,'2026-10-30 17:20:40'),(778,253,'Varios días',1.00,2,1,'2026-10-30 17:20:40'),(779,253,'Más de la mitad de los días',2.00,3,1,'2026-10-30 17:20:40'),(780,253,'Casi todos los días',3.00,4,1,'2026-10-30 17:20:40'),(781,254,'Nunca',0.00,1,1,'2026-10-30 17:20:40'),(782,254,'Varios días',1.00,2,1,'2026-10-30 17:20:40'),(783,254,'Más de la mitad de los días',2.00,3,1,'2026-10-30 17:20:40'),(784,254,'Casi todos los días',3.00,4,1,'2026-10-30 17:20:40'),(785,255,'Nunca',0.00,1,1,'2026-10-30 17:20:40'),(786,255,'Varios días',1.00,2,1,'2026-10-30 17:20:40'),(787,255,'Más de la mitad de los días',2.00,3,1,'2026-10-30 17:20:40'),(788,255,'Casi todos los días',3.00,4,1,'2026-10-30 17:20:40'),(789,256,'Nunca',0.00,1,1,'2026-10-30 17:20:41'),(790,256,'Varios días',1.00,2,1,'2026-10-30 17:20:41'),(791,256,'Más de la mitad de los días',2.00,3,1,'2026-10-30 17:20:41'),(792,256,'Casi todos los días',3.00,4,1,'2026-10-30 17:20:41'),(793,257,'Nunca',0.00,1,1,'2026-10-30 17:20:41'),(794,257,'Varios días',1.00,2,1,'2026-10-30 17:20:41'),(795,257,'Más de la mitad de los días',2.00,3,1,'2026-10-30 17:20:41'),(796,257,'Casi todos los días',3.00,4,1,'2026-10-30 17:20:41'),(797,258,'Nunca',0.00,1,1,'2026-10-30 17:20:41'),(798,258,'Varios días',1.00,2,1,'2026-10-30 17:20:41'),(799,258,'Más de la mitad de los días',2.00,3,1,'2026-10-30 17:20:41'),(800,258,'Casi todos los días',3.00,4,1,'2026-10-30 17:20:41'),(801,259,'Nunca',0.00,1,1,'2026-10-30 17:20:41'),(802,259,'Varios días',1.00,2,1,'2026-10-30 17:20:41'),(803,259,'Más de la mitad de los días',2.00,3,1,'2026-10-30 17:20:41'),(804,259,'Casi todos los días',3.00,4,1,'2026-10-30 17:20:41');
/*!40000 ALTER TABLE `opciones_respuesta_rh` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `organizaciones`
--

DROP TABLE IF EXISTS `organizaciones`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `organizaciones` (
  `id_organizacion` int(11) NOT NULL AUTO_INCREMENT,
  `nombre` varchar(150) NOT NULL,
  `nombre_comercial` varchar(150) DEFAULT NULL,
  `responsable` varchar(150) DEFAULT NULL,
  `correo` varchar(150) DEFAULT NULL,
  `telefono` varchar(30) DEFAULT NULL,
  `rfc` varchar(20) DEFAULT NULL,
  `direccion` varchar(255) DEFAULT NULL,
  `logo_url` varchar(255) DEFAULT NULL,
  `tipo` enum('clinica','rh','educativo','independiente') NOT NULL,
  `perfil_independiente` enum('clinica','rh') DEFAULT NULL,
  `estado` enum('activa','suspendida','cancelada') NOT NULL DEFAULT 'activa',
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `actualizado_en` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_organizacion`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `organizaciones`
--

LOCK TABLES `organizaciones` WRITE;
/*!40000 ALTER TABLE `organizaciones` DISABLE KEYS */;
INSERT INTO `organizaciones` VALUES (1,'Clínica Prueba MirrorSoul','Clínica Prueba','Laura Pérez','contacto@clinicaprueba.com','5512345678','CPM261105ABC','CDMX',NULL,'clinica',NULL,'activa','2026-11-05 23:23:17','2026-11-05 23:23:17'),(2,'Empresa RH Prueba MirrorSoul','Empresa RH Prueba','Andrea Martínez','contacto.rh@mirrorsoul.com','5512349900','ERH261106ABC','CDMX',NULL,'rh',NULL,'activa','2026-11-06 19:25:20','2026-11-06 19:25:20'),(3,'Consultorio Independiente Prueba','Consultorio Independiente Prueba','Profesional Independiente Prueba','independiente.prueba@correo.com','5578451296',NULL,'La Paz',NULL,'independiente',NULL,'activa','2026-11-07 19:43:59','2026-11-09 18:06:31'),(4,'salud mental','salud mental','Patricia Perez','paty89@gmail.com','5546513132','POTS890425','Nezahualcoyotl',NULL,'independiente','clinica','activa','2026-11-09 21:08:17','2026-11-09 22:59:45'),(5,'NANCY','NANCY','PONCE','nany69@gmail.com','5517878963','LOPN642807','Los Reyes',NULL,'independiente','rh','activa','2026-11-12 15:43:05','2026-11-12 15:43:59');
/*!40000 ALTER TABLE `organizaciones` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `pacientes`
--

DROP TABLE IF EXISTS `pacientes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pacientes` (
  `id_paciente` int(11) NOT NULL AUTO_INCREMENT,
  `id_mirror` varchar(30) DEFAULT NULL,
  `id_psicologo` int(11) NOT NULL,
  `nombre` varchar(120) NOT NULL,
  `sexo` enum('M','F','X') DEFAULT NULL,
  `fecha_nacimiento` date DEFAULT NULL,
  `edad` int(11) DEFAULT NULL,
  `correo` varchar(120) DEFAULT NULL,
  `telefono` varchar(30) DEFAULT NULL,
  `direccion` varchar(200) DEFAULT NULL,
  `antecedentes` text DEFAULT NULL,
  PRIMARY KEY (`id_paciente`),
  UNIQUE KEY `unique_id_mirror` (`id_mirror`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pacientes`
--

LOCK TABLES `pacientes` WRITE;
/*!40000 ALTER TABLE `pacientes` DISABLE KEYS */;
INSERT INTO `pacientes` VALUES (1,'MS-2026-25-FE-001',1,'SUSANA','F','2026-09-02',25,'susy89@gmail.com','5546513169','carretera sor juana','problemas para dormir '),(2,'MS-2026-25-FE-007',9,'ARELY HERNANDEZ LUCAS ','F','2003-02-26',25,'jupiter56@gmail.com','5546478888','CDMX','agresividad'),(3,'MS-2026-28-FE-010',19,'vanessa celic sandoval','F','2026-11-09',28,'lkij@gmail.com','5647828888','Los Reyes','mp'),(4,'MS-2026-0-XX-014',1,'ARELY HERNANDEZ LUCAS',NULL,NULL,NULL,'ary789456@gmail.com','5546478963',NULL,NULL);
/*!40000 ALTER TABLE `pacientes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `pagos`
--

DROP TABLE IF EXISTS `pagos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pagos` (
  `id_pago` int(11) NOT NULL AUTO_INCREMENT,
  `id_usuario` int(11) NOT NULL,
  `id_organizacion` int(11) NOT NULL,
  `id_plan` int(11) NOT NULL,
  `proveedor` varchar(40) NOT NULL DEFAULT 'manual',
  `referencia_externa` varchar(150) DEFAULT NULL,
  `monto` decimal(10,2) NOT NULL DEFAULT 0.00,
  `moneda` varchar(10) NOT NULL DEFAULT 'MXN',
  `periodo` enum('mensual','anual') NOT NULL DEFAULT 'mensual',
  `estado` enum('pendiente','aprobado','rechazado','cancelado','reembolsado') NOT NULL DEFAULT 'pendiente',
  `fecha_pago` datetime DEFAULT NULL,
  `creado_en` datetime NOT NULL DEFAULT current_timestamp(),
  `actualizado_en` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_pago`),
  KEY `idx_pago_usuario` (`id_usuario`),
  KEY `idx_pago_organizacion` (`id_organizacion`),
  KEY `idx_pago_plan` (`id_plan`),
  KEY `idx_pago_estado` (`estado`),
  CONSTRAINT `fk_pago_organizacion` FOREIGN KEY (`id_organizacion`) REFERENCES `organizaciones` (`id_organizacion`),
  CONSTRAINT `fk_pago_plan` FOREIGN KEY (`id_plan`) REFERENCES `planes` (`id_plan`),
  CONSTRAINT `fk_pago_usuario` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pagos`
--

LOCK TABLES `pagos` WRITE;
/*!40000 ALTER TABLE `pagos` DISABLE KEYS */;
INSERT INTO `pagos` VALUES (1,34,3,4,'manual',NULL,0.00,'MXN','mensual','aprobado','2026-11-09 12:06:31','2026-11-09 12:02:12','2026-11-09 12:06:31'),(2,35,4,4,'manual',NULL,0.00,'MXN','mensual','pendiente',NULL,'2026-11-09 15:08:52','2026-11-09 15:08:52'),(3,36,5,4,'manual',NULL,0.00,'MXN','mensual','pendiente',NULL,'2026-11-12 09:43:16','2026-11-12 09:43:16');
/*!40000 ALTER TABLE `pagos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `planes`
--

DROP TABLE IF EXISTS `planes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `planes` (
  `id_plan` int(11) NOT NULL AUTO_INCREMENT,
  `nombre` varchar(100) NOT NULL,
  `codigo` varchar(50) DEFAULT NULL,
  `descripcion` text DEFAULT NULL,
  `tipo` enum('psicologo','clinica','rh','educativo','independiente') NOT NULL,
  `precio_mensual` decimal(10,2) DEFAULT NULL,
  `precio_anual` decimal(10,2) DEFAULT NULL,
  `licencias_incluidas` int(11) NOT NULL DEFAULT 1,
  `permite_admin` tinyint(1) NOT NULL DEFAULT 0,
  `periodo_prueba_dias` int(11) NOT NULL DEFAULT 0,
  `max_pacientes` int(11) DEFAULT NULL,
  `destacado` tinyint(1) NOT NULL DEFAULT 0,
  `activo` tinyint(1) NOT NULL DEFAULT 1,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_plan`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `planes`
--

LOCK TABLES `planes` WRITE;
/*!40000 ALTER TABLE `planes` DISABLE KEYS */;
INSERT INTO `planes` VALUES (1,'Clínica Prueba','CLINICA_PRUEBA','Plan temporal para probar organizaciones y licencias','clinica',NULL,NULL,5,1,0,NULL,0,1,'2026-11-05 23:14:04'),(2,'RH Prueba','RH_PRUEBA','Plan temporal para probar organización y licencias RH','rh',NULL,NULL,3,1,0,NULL,0,1,'2026-11-06 19:23:19'),(3,'Educativo Prueba','EDUCATIVO_PRUEBA','Plan educativo temporal actualizado','educativo',0.00,0.00,4,1,0,NULL,1,1,'2026-11-07 04:44:03'),(4,'Independiente Prueba','INDEPENDIENTE_PRUEBA','Plan temporal para probar el flujo de profesionales independientes','independiente',0.00,0.00,1,0,0,NULL,1,1,'2026-11-09 17:51:00');
/*!40000 ALTER TABLE `planes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `preguntas_prueba`
--

DROP TABLE IF EXISTS `preguntas_prueba`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `preguntas_prueba` (
  `id_pregunta` int(11) NOT NULL AUTO_INCREMENT,
  `id_prueba` int(11) NOT NULL,
  `texto` text NOT NULL,
  `tipo` enum('opcion','abierta') DEFAULT 'opcion',
  PRIMARY KEY (`id_pregunta`)
) ENGINE=InnoDB AUTO_INCREMENT=102 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `preguntas_prueba`
--

LOCK TABLES `preguntas_prueba` WRITE;
/*!40000 ALTER TABLE `preguntas_prueba` DISABLE KEYS */;
INSERT INTO `preguntas_prueba` VALUES (36,2,'En el último mes, ¿con qué frecuencia se ha sentido incapaz de controlar las cosas importantes en su vida?','opcion'),(37,2,'En el último mes, ¿con qué frecuencia se ha sentido nervioso o estresado?','opcion'),(38,2,'En el último mes, ¿con qué frecuencia ha manejado con éxito los pequeños problemas irritantes de la vida?','opcion'),(39,2,'En el último mes, ¿con qué frecuencia ha sentido que estaba afrontando efectivamente los cambios importantes que estaban ocurriendo en su vida?','opcion'),(40,2,'En el último mes, ¿con qué frecuencia ha sentido confianza en su capacidad para manejar sus problemas personales?','opcion'),(41,2,'En el último mes, ¿con qué frecuencia ha sentido que las cosas le iban bien?','opcion'),(42,2,'En el último mes, ¿con qué frecuencia ha sentido que no podía afrontar todas las cosas que tenía que hacer?','opcion'),(43,2,'En el último mes, ¿con qué frecuencia ha podido controlar las dificultades de su vida?','opcion'),(44,2,'En el último mes, ¿con qué frecuencia ha sentido que tenía todo bajo control?','opcion'),(45,2,'En el último mes, ¿con qué frecuencia ha sentido que estaba enfadado porque las cosas que le han ocurrido estaban fuera de su control?','opcion'),(46,2,'En el último mes, ¿con qué frecuencia ha sentido que las dificultades se acumulaban tanto que no podía superarlas?','opcion'),(47,2,'En el último mes, ¿con qué frecuencia ha sentido que podía controlar la forma en que gastaba su tiempo?','opcion'),(48,2,'En el último mes, ¿con qué frecuencia ha sentido que las cosas estaban fuera de su control?','opcion'),(49,2,'En el último mes, ¿con qué frecuencia ha sentido que todo estaba bajo control?','opcion'),(50,1,'Tristeza','opcion'),(51,1,'Pesimismo','opcion'),(52,1,'Fracaso pasado','opcion'),(53,1,'Pérdida de placer','opcion'),(54,1,'Sentimientos de culpa','opcion'),(55,1,'Sentimientos de castigo','opcion'),(56,1,'Disconformidad con uno mismo','opcion'),(57,1,'Autocrítica','opcion'),(58,1,'Pensamientos o deseos suicidas','opcion'),(59,1,'Llanto','opcion'),(60,1,'Agitación','opcion'),(61,1,'Pérdida de interés','opcion'),(62,1,'Indecisión','opcion'),(63,1,'Desvalorización','opcion'),(64,1,'Pérdida de energía','opcion'),(65,1,'Cambios en los patrones de sueño','opcion'),(66,1,'Irritabilidad','opcion'),(67,1,'Cambios en el apetito','opcion'),(68,1,'Dificultad de concentración','opcion'),(69,1,'Cansancio o fatiga','opcion'),(70,1,'Pérdida de interés en el sexo','opcion'),(71,3,'En las últimas dos semanas, ¿con qué frecuencia se ha sentido nervioso o ansioso?','opcion'),(72,3,'En las últimas dos semanas, ¿con qué frecuencia no ha podido parar de preocuparse o controlar sus preocupaciones?','opcion'),(73,3,'En las últimas dos semanas, ¿con qué frecuencia se ha preocupado demasiado por diferentes cosas?','opcion'),(74,3,'En las últimas dos semanas, ¿con qué frecuencia ha tenido dificultades para relajarse?','opcion'),(75,3,'En las últimas dos semanas, ¿con qué frecuencia ha estado tan inquieto que no ha podido permanecer sentado?','opcion'),(76,3,'En las últimas dos semanas, ¿con qué frecuencia se ha irritado o enfadado fácilmente?','opcion'),(77,3,'En las últimas dos semanas, ¿con qué frecuencia ha sentido miedo como si algo terrible fuera a pasar?','opcion'),(78,4,'Grupo 1','opcion'),(79,4,'Grupo 2','opcion'),(80,4,'Grupo 3','opcion'),(81,4,'Grupo 4','opcion'),(82,4,'Grupo 5','opcion'),(83,4,'Grupo 6','opcion'),(84,4,'Grupo 7','opcion'),(85,4,'Grupo 8','opcion'),(86,4,'Grupo 9','opcion'),(87,4,'Grupo 10','opcion'),(88,4,'Grupo 11','opcion'),(89,4,'Grupo 12','opcion'),(90,4,'Grupo 13','opcion'),(91,4,'Grupo 14','opcion'),(92,4,'Grupo 15','opcion'),(93,4,'Grupo 16','opcion'),(94,4,'Grupo 17','opcion'),(95,4,'Grupo 18','opcion'),(96,4,'Grupo 19','opcion'),(97,4,'Grupo 20','opcion'),(98,4,'Grupo 21','opcion'),(99,4,'Grupo 22','opcion'),(100,4,'Grupo 23','opcion'),(101,4,'Grupo 24','opcion');
/*!40000 ALTER TABLE `preguntas_prueba` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `preguntas_prueba_rh`
--

DROP TABLE IF EXISTS `preguntas_prueba_rh`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `preguntas_prueba_rh` (
  `id_pregunta_rh` int(11) NOT NULL AUTO_INCREMENT,
  `id_prueba_rh` int(11) NOT NULL,
  `codigo` varchar(20) DEFAULT NULL,
  `texto_pregunta` text NOT NULL,
  `dimension` varchar(80) DEFAULT NULL,
  `invertida` tinyint(1) NOT NULL DEFAULT 0,
  `tipo_respuesta` enum('opcion','escala','abierta') NOT NULL DEFAULT 'opcion',
  `orden` int(11) NOT NULL DEFAULT 0,
  `activo` tinyint(1) NOT NULL DEFAULT 1,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_pregunta_rh`),
  KEY `idx_pprh_prueba` (`id_prueba_rh`),
  CONSTRAINT `fk_pprh_prueba` FOREIGN KEY (`id_prueba_rh`) REFERENCES `pruebas_rh` (`id_prueba_rh`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=260 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `preguntas_prueba_rh`
--

LOCK TABLES `preguntas_prueba_rh` WRITE;
/*!40000 ALTER TABLE `preguntas_prueba_rh` DISABLE KEYS */;
INSERT INTO `preguntas_prueba_rh` VALUES (101,1,'q01','Soy el alma de la fiesta','extraversión',0,'escala',1,1,'2026-10-01 23:40:49'),(102,1,'q02','Me preocupo poco por los demás','amabilidad',1,'escala',2,1,'2026-10-01 23:40:49'),(103,1,'q03','Siempre estoy preparado','responsabilidad',0,'escala',3,1,'2026-10-01 23:40:49'),(104,1,'q04','Me estreso con facilidad','estabilidad_emocional',1,'escala',4,1,'2026-10-01 23:40:49'),(105,1,'q05','Tengo un vocabulario amplio','intelecto',0,'escala',5,1,'2026-10-01 23:40:49'),(106,1,'q06','No hablo mucho','extraversión',1,'escala',6,1,'2026-10-01 23:40:49'),(107,1,'q07','Me intereso por la gente','amabilidad',0,'escala',7,1,'2026-10-01 23:40:49'),(108,1,'q08','Dejo mis pertenencias en cualquier lado','responsabilidad',1,'escala',8,1,'2026-10-01 23:40:49'),(109,1,'q09','Estoy relajado la mayor parte del tiempo','estabilidad_emocional',0,'escala',9,1,'2026-10-01 23:40:49'),(110,1,'q10','Me cuesta entender ideas abstractas','intelecto',1,'escala',10,1,'2026-10-01 23:40:49'),(111,1,'q11','Me siento cómodo con la gente','extraversión',0,'escala',11,1,'2026-10-01 23:40:49'),(112,1,'q12','Ofendo a la gente','amabilidad',1,'escala',12,1,'2026-10-01 23:40:49'),(113,1,'q13','Pongo atención en los detalles','responsabilidad',0,'escala',13,1,'2026-10-01 23:40:49'),(114,1,'q14','Me preocupo por todo','estabilidad_emocional',1,'escala',14,1,'2026-10-01 23:40:49'),(115,1,'q15','Tengo mucha imaginación','intelecto',0,'escala',15,1,'2026-10-01 23:40:49'),(116,1,'q16','Prefiero mantenerme al margen','extraversión',1,'escala',16,1,'2026-10-01 23:40:49'),(117,1,'q17','Soy sensible hacia las emociones de otros','amabilidad',0,'escala',17,1,'2026-10-01 23:40:49'),(118,1,'q18','Soy desordenado','responsabilidad',1,'escala',18,1,'2026-10-01 23:40:49'),(119,1,'q19','Rara vez me siento triste','estabilidad_emocional',0,'escala',19,1,'2026-10-01 23:40:49'),(120,1,'q20','No me interesan las ideas abstractas','intelecto',1,'escala',20,1,'2026-10-01 23:40:49'),(121,1,'q21','Comienzo las conversaciones','extraversión',0,'escala',21,1,'2026-10-01 23:40:49'),(122,1,'q22','No me interesan los problemas de otras personas','amabilidad',1,'escala',22,1,'2026-10-01 23:40:49'),(123,1,'q23','Realizo mis tareas inmediatamente','responsabilidad',0,'escala',23,1,'2026-10-01 23:40:49'),(124,1,'q24','Me molesto fácilmente','estabilidad_emocional',1,'escala',24,1,'2026-10-01 23:40:49'),(125,1,'q25','Tengo excelentes ideas','intelecto',0,'escala',25,1,'2026-10-01 23:40:49'),(126,1,'q26','No tengo mucho que decir','extraversión',1,'escala',26,1,'2026-10-01 23:40:49'),(127,1,'q27','Tengo un corazón sensible','amabilidad',0,'escala',27,1,'2026-10-01 23:40:49'),(128,1,'q28','A menudo olvido poner las cosas en su lugar','responsabilidad',1,'escala',28,1,'2026-10-01 23:40:49'),(129,1,'q29','Me disgusto con facilidad','estabilidad_emocional',1,'escala',29,1,'2026-10-01 23:40:49'),(130,1,'q30','No tengo una buena imaginación','intelecto',1,'escala',30,1,'2026-10-01 23:40:49'),(131,1,'q31','En las fiestas hablo con muchas personas diferentes','extraversión',0,'escala',31,1,'2026-10-01 23:40:49'),(132,1,'q32','En realidad no me intereso por los demás','amabilidad',1,'escala',32,1,'2026-10-01 23:40:49'),(133,1,'q33','Me gusta el orden','responsabilidad',0,'escala',33,1,'2026-10-01 23:40:49'),(134,1,'q34','Cambio mucho de humor','estabilidad_emocional',1,'escala',34,1,'2026-10-01 23:40:49'),(135,1,'q35','Soy rápido para entender las cosas','intelecto',0,'escala',35,1,'2026-10-01 23:40:49'),(136,1,'q36','No me gusta llamar la atención','extraversión',1,'escala',36,1,'2026-10-01 23:40:49'),(137,1,'q37','Dedico tiempo a los demás','amabilidad',0,'escala',37,1,'2026-10-01 23:40:49'),(138,1,'q38','Evado mis obligaciones','responsabilidad',1,'escala',38,1,'2026-10-01 23:40:49'),(139,1,'q39','Tengo cambios frecuentes de estado de ánimo','estabilidad_emocional',1,'escala',39,1,'2026-10-01 23:40:49'),(140,1,'q40','Utilizo palabras difíciles','intelecto',0,'escala',40,1,'2026-10-01 23:40:49'),(141,1,'q41','No me importa ser el centro de atención','extraversión',0,'escala',41,1,'2026-10-01 23:40:49'),(142,1,'q42','Siento las emociones de los otros','amabilidad',0,'escala',42,1,'2026-10-01 23:40:49'),(143,1,'q43','Hago un programa y lo sigo','responsabilidad',0,'escala',43,1,'2026-10-01 23:40:49'),(144,1,'q44','Me irrito fácilmente','estabilidad_emocional',1,'escala',44,1,'2026-10-01 23:40:49'),(145,1,'q45','Dedico tiempo a reflexionar','intelecto',0,'escala',45,1,'2026-10-01 23:40:49'),(146,1,'q46','Cuando estoy entre desconocidos me mantengo callado','extraversión',1,'escala',46,1,'2026-10-01 23:40:49'),(147,1,'q47','Hago sentir cómoda a la gente','amabilidad',0,'escala',47,1,'2026-10-01 23:40:49'),(148,1,'q48','Soy perfeccionista en mi trabajo','responsabilidad',0,'escala',48,1,'2026-10-01 23:40:49'),(149,1,'q49','Me siento triste frecuentemente','estabilidad_emocional',1,'escala',49,1,'2026-10-01 23:40:49'),(150,1,'q50','Estoy lleno de ideas','intelecto',0,'escala',50,1,'2026-10-01 23:40:49'),(151,2,'orv01','Hacer que sucedan cosas importantes','leadership',0,'escala',1,1,'2026-10-02 20:50:27'),(152,2,'orv02','Ser responsable financiero de una empresa','organization',0,'escala',2,1,'2026-10-02 20:50:27'),(153,2,'orv03','Ayudar a otras personas a aprender ideas nuevas','altruism',0,'escala',3,1,'2026-10-02 20:50:27'),(154,2,'orv04','Crear obras de arte','creativity',0,'escala',4,1,'2026-10-02 20:50:27'),(155,2,'orv05','Ser químico o química','analysis',0,'escala',5,1,'2026-10-02 20:50:27'),(156,2,'orv06','Cuidar ganado o caballos','production',0,'escala',6,1,'2026-10-02 20:50:27'),(157,2,'orv07','Ser atleta profesional','adventure',0,'escala',7,1,'2026-10-02 20:50:27'),(158,2,'orv08','Ser traductor o intérprete','erudition',0,'escala',8,1,'2026-10-02 20:50:27'),(159,2,'orv09','Dirigir a otras personas','leadership',0,'escala',9,1,'2026-10-02 20:50:27'),(160,2,'orv10','Ser gerente de oficina','organization',0,'escala',10,1,'2026-10-02 20:50:27'),(161,2,'orv11','Cuidar a personas enfermas','altruism',0,'escala',11,1,'2026-10-02 20:50:27'),(162,2,'orv12','Crear nuevos diseños de moda','creativity',0,'escala',12,1,'2026-10-02 20:50:27'),(163,2,'orv13','Diseñar un experimento de laboratorio','analysis',0,'escala',13,1,'2026-10-02 20:50:27'),(164,2,'orv14','Ser agricultor o agricultora','production',0,'escala',14,1,'2026-10-02 20:50:27'),(165,2,'orv15','Participar en aventuras emocionantes','adventure',0,'escala',15,1,'2026-10-02 20:50:27'),(166,2,'orv16','Ser bibliotecario o bibliotecaria','erudition',0,'escala',16,1,'2026-10-02 20:50:27'),(167,2,'orv17','Ser director de ventas o mercadotecnia','leadership',0,'escala',17,1,'2026-10-02 20:50:27'),(168,2,'orv18','Planear presupuestos','organization',0,'escala',18,1,'2026-10-02 20:50:27'),(169,2,'orv19','Ser maestro o maestra de primaria','altruism',0,'escala',19,1,'2026-10-02 20:50:27'),(170,2,'orv20','Ser bailarín o bailarina profesional','creativity',0,'escala',20,1,'2026-10-02 20:50:27'),(171,2,'orv21','Ser matemático o matemática','analysis',0,'escala',21,1,'2026-10-02 20:50:27'),(172,2,'orv22','Construir edificios nuevos','production',0,'escala',22,1,'2026-10-02 20:50:27'),(173,2,'orv23','Sobrevivir en la naturaleza','adventure',0,'escala',23,1,'2026-10-02 20:50:27'),(174,2,'orv24','Ser profesor o profesora de inglés','erudition',0,'escala',24,1,'2026-10-02 20:50:27'),(175,2,'orv25','Ser director general de una empresa grande','leadership',0,'escala',25,1,'2026-10-02 20:50:27'),(176,2,'orv26','Preparar contratos financieros','organization',0,'escala',26,1,'2026-10-02 20:50:27'),(177,2,'orv27','Ser trabajador o trabajadora social','altruism',0,'escala',27,1,'2026-10-02 20:50:27'),(178,2,'orv28','Escribir cuentos o novelas','creativity',0,'escala',28,1,'2026-10-02 20:50:27'),(179,2,'orv29','Explicar conceptos científicos a otras personas','analysis',0,'escala',29,1,'2026-10-02 20:50:27'),(180,2,'orv30','Ser guardabosques','production',0,'escala',30,1,'2026-10-02 20:50:27'),(181,2,'orv31','Ser piloto de automovilismo de carreras','adventure',0,'escala',31,1,'2026-10-02 20:50:27'),(182,2,'orv32','Crear acertijos de palabras','erudition',0,'escala',32,1,'2026-10-02 20:50:27'),(183,2,'orv33','Organizar una campaña política','leadership',0,'escala',33,1,'2026-10-02 20:50:27'),(184,2,'orv34','Desarrollar un sistema de archivo para una oficina','organization',0,'escala',34,1,'2026-10-02 20:50:27'),(185,2,'orv35','Ser ministro, sacerdote, rabino u otro maestro religioso','altruism',0,'escala',35,1,'2026-10-02 20:50:27'),(186,2,'orv36','Tocar un instrumento en una orquesta sinfónica','creativity',0,'escala',36,1,'2026-10-02 20:50:27'),(187,2,'orv37','Ser físico o física','analysis',0,'escala',37,1,'2026-10-02 20:50:27'),(188,2,'orv38','Cultivar plantas','production',0,'escala',38,1,'2026-10-02 20:50:27'),(189,2,'orv39','Enfrentar peligro físico','adventure',0,'escala',39,1,'2026-10-02 20:50:27'),(190,2,'orv40','Editar un periódico','erudition',0,'escala',40,1,'2026-10-02 20:50:27'),(191,2,'orv41','Ser maestro de ceremonias en una reunión','leadership',0,'escala',41,1,'2026-10-02 20:50:27'),(192,2,'orv42','Supervisar el trabajo de otras personas','organization',0,'escala',42,1,'2026-10-02 20:50:27'),(193,2,'orv43','Orientar a personas que necesitan ayuda','altruism',0,'escala',43,1,'2026-10-02 20:50:27'),(194,2,'orv44','Redecorar una casa','creativity',0,'escala',44,1,'2026-10-02 20:50:27'),(195,2,'orv45','Realizar investigación médica','analysis',0,'escala',45,1,'2026-10-02 20:50:27'),(196,2,'orv46','Salir a caminar por la naturaleza','production',0,'escala',46,1,'2026-10-02 20:50:27'),(197,2,'orv47','Ser oficial militar','adventure',0,'escala',47,1,'2026-10-02 20:52:24'),(198,2,'orv48','Conocer muchos idiomas','erudition',0,'escala',48,1,'2026-10-02 20:52:24'),(199,2,'orv49','Planear una campaña publicitaria','leadership',0,'escala',49,1,'2026-10-02 20:52:24'),(200,2,'orv50','Planear estrategias de inversión','organization',0,'escala',50,1,'2026-10-02 20:52:24'),(201,2,'orv51','Orientar a padres sobre el cuidado de sus hijos','altruism',0,'escala',51,1,'2026-10-02 20:52:24'),(202,2,'orv52','Seleccionar obras de arte para un museo','creativity',0,'escala',52,1,'2026-10-02 20:52:24'),(203,2,'orv53','Ser periodista científico','analysis',0,'escala',53,1,'2026-10-02 20:52:24'),(204,2,'orv54','Realizar trabajos de carpintería','production',0,'escala',54,1,'2026-10-02 20:52:24'),(205,2,'orv55','Competir en eventos deportivos','adventure',0,'escala',55,1,'2026-10-02 20:52:24'),(206,2,'orv56','Ser corresponsal en el extranjero','erudition',0,'escala',56,1,'2026-10-02 20:52:24'),(207,2,'orv57','Debatir temas en una reunión pública','leadership',0,'escala',57,1,'2026-10-02 20:52:24'),(208,2,'orv58','Establecer horarios de trabajo','organization',0,'escala',58,1,'2026-10-02 20:52:24'),(209,2,'orv59','Ser médico o enfermero','altruism',0,'escala',59,1,'2026-10-02 20:52:24'),(210,2,'orv60','Cantar profesionalmente','creativity',0,'escala',60,1,'2026-10-02 20:52:24'),(211,2,'orv61','Resolver acertijos complejos','analysis',0,'escala',61,1,'2026-10-02 20:52:24'),(212,2,'orv62','Cultivar flores','production',0,'escala',62,1,'2026-10-02 20:52:24'),(213,2,'orv63','Ser cazador de fugitivos','adventure',0,'escala',63,1,'2026-10-02 20:52:24'),(214,2,'orv64','Hablar con fluidez sobre cualquier tema','erudition',0,'escala',64,1,'2026-10-02 20:52:24'),(215,2,'orv65','Persuadir a otras personas para que cambien sus puntos de vista','leadership',0,'escala',65,1,'2026-10-02 20:52:24'),(216,2,'orv66','Supervisar los gastos de una empresa','organization',0,'escala',66,1,'2026-10-02 20:52:24'),(217,2,'orv67','Ser fisioterapeuta','altruism',0,'escala',67,1,'2026-10-02 20:52:24'),(218,2,'orv68','Ser actor o actriz','creativity',0,'escala',68,1,'2026-10-02 20:52:24'),(219,2,'orv69','Desarrollar un programa de computadora','analysis',0,'escala',69,1,'2026-10-02 20:52:24'),(220,2,'orv70','Reparar automóviles o camiones','production',0,'escala',70,1,'2026-10-02 20:52:24'),(221,2,'orv71','Practicar ciclismo de larga distancia','adventure',0,'escala',71,1,'2026-10-02 20:52:24'),(222,2,'orv72','Leer muchos libros','erudition',0,'escala',72,1,'2026-10-02 20:52:24'),(223,2,'orv73','Ser gobernador o senador','leadership',0,'escala',73,1,'2026-10-02 20:52:24'),(224,2,'orv74','Ser agente de compras','organization',0,'escala',74,1,'2026-10-02 20:52:24'),(225,2,'orv75','Brindar consuelo y apoyo a otras personas','altruism',0,'escala',75,1,'2026-10-02 20:52:24'),(226,2,'orv76','Ser artista o arquitecto','creativity',0,'escala',76,1,'2026-10-02 20:52:24'),(227,2,'orv77','Ser estadístico o estadística','analysis',0,'escala',77,1,'2026-10-02 20:52:24'),(228,2,'orv78','Trabajar con herramientas y maquinaria','production',0,'escala',78,1,'2026-10-02 20:52:24'),(229,2,'orv79','Ser oficial de policía','adventure',0,'escala',79,1,'2026-10-02 20:52:24'),(230,2,'orv80','Llevar un diario personal','erudition',0,'escala',80,1,'2026-10-02 20:52:24'),(231,2,'orv81','Postularse para un cargo político','leadership',0,'escala',81,1,'2026-10-02 20:52:24'),(232,2,'orv82','Llevar el control del inventario de una empresa','organization',0,'escala',82,1,'2026-10-02 20:52:24'),(233,2,'orv83','Participar en eventos de beneficencia','altruism',0,'escala',83,1,'2026-10-02 20:52:24'),(234,2,'orv84','Actuar en una obra de teatro','creativity',0,'escala',84,1,'2026-10-02 20:52:24'),(235,2,'orv85','Diseñar páginas web','creativity',0,'escala',85,1,'2026-10-02 20:52:24'),(236,2,'orv86','Tomar decisiones que afectan a muchas personas','leadership',0,'escala',86,1,'2026-10-02 20:52:24'),(237,2,'orv87','Administrar una base de datos','organization',0,'escala',87,1,'2026-10-02 20:52:24'),(238,2,'orv88','Ayudar a las personas a tomar decisiones sobre su carrera','altruism',0,'escala',88,1,'2026-10-02 20:52:24'),(239,2,'orv89','Escribir canciones','creativity',0,'escala',89,1,'2026-10-02 20:52:24'),(240,2,'orv90','Mantener registros detallados','organization',0,'escala',90,1,'2026-10-02 20:52:24'),(241,2,'orv91','Ser orientador, consejero o terapeuta','altruism',0,'escala',91,1,'2026-10-02 20:52:24'),(242,2,'orv92','Pintar o dibujar','creativity',0,'escala',92,1,'2026-10-02 20:52:24'),(248,5,NULL,'Me he sentido alegre y de buen ánimo.',NULL,0,'opcion',1,1,'2026-10-30 17:15:28'),(249,5,NULL,'Me he sentido tranquilo(a) y relajado(a).',NULL,0,'opcion',2,1,'2026-10-30 17:15:28'),(250,5,NULL,'Me he sentido activo(a) y con energía.',NULL,0,'opcion',3,1,'2026-10-30 17:15:29'),(251,5,NULL,'Me he despertado sintiéndome descansado(a) y renovado(a).',NULL,0,'opcion',4,1,'2026-10-30 17:15:29'),(252,5,NULL,'Mi vida diaria ha estado llena de cosas que me interesan.',NULL,0,'opcion',5,1,'2026-10-30 17:15:29'),(253,6,NULL,'Sentirse nervioso/a, intranquilo/a o con los nervios de punta',NULL,0,'opcion',1,1,'2026-10-30 17:20:40'),(254,6,NULL,'No poder dejar de preocuparse o no poder controlar la preocupación',NULL,0,'opcion',2,1,'2026-10-30 17:20:40'),(255,6,NULL,'Preocuparse demasiado por diferentes cosas',NULL,0,'opcion',3,1,'2026-10-30 17:20:40'),(256,6,NULL,'Dificultad para relajarse',NULL,0,'opcion',4,1,'2026-10-30 17:20:41'),(257,6,NULL,'Estar tan inquieto/a que es difícil permanecer sentado/a tranquilamente',NULL,0,'opcion',5,1,'2026-10-30 17:20:41'),(258,6,NULL,'Molestarse o ponerse irritable fácilmente',NULL,0,'opcion',6,1,'2026-10-30 17:20:41'),(259,6,NULL,'Sentir miedo como si algo terrible pudiera pasar',NULL,0,'opcion',7,1,'2026-10-30 17:20:41');
/*!40000 ALTER TABLE `preguntas_prueba_rh` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `profesionales_externos`
--

DROP TABLE IF EXISTS `profesionales_externos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `profesionales_externos` (
  `id_profesional_externo` int(11) NOT NULL AUTO_INCREMENT,
  `nombre` varchar(180) NOT NULL,
  `especialidad` varchar(200) DEFAULT NULL,
  `descripcion` text DEFAULT NULL,
  `modalidad_presencial` tinyint(1) NOT NULL DEFAULT 0,
  `modalidad_videollamada` tinyint(1) NOT NULL DEFAULT 0,
  `precio_presencial` decimal(10,2) DEFAULT NULL,
  `precio_videollamada` decimal(10,2) DEFAULT NULL,
  `estado` varchar(100) DEFAULT NULL,
  `municipio` varchar(150) DEFAULT NULL,
  `direccion` varchar(255) DEFAULT NULL,
  `telefono` varchar(30) DEFAULT NULL,
  `correo` varchar(180) DEFAULT NULL,
  `activo` tinyint(1) NOT NULL DEFAULT 1,
  `id_usuario_registro` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_profesional_externo`),
  KEY `idx_prof_externo_activo` (`activo`),
  KEY `idx_prof_externo_estado` (`estado`),
  KEY `idx_prof_externo_municipio` (`municipio`),
  KEY `fk_prof_externo_usuario` (`id_usuario_registro`),
  CONSTRAINT `fk_prof_externo_usuario` FOREIGN KEY (`id_usuario_registro`) REFERENCES `usuarios` (`id_usuario`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `profesionales_externos`
--

LOCK TABLES `profesionales_externos` WRITE;
/*!40000 ALTER TABLE `profesionales_externos` DISABLE KEYS */;
/*!40000 ALTER TABLE `profesionales_externos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `prospectos`
--

DROP TABLE IF EXISTS `prospectos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `prospectos` (
  `id_prospecto` int(11) NOT NULL AUTO_INCREMENT,
  `id_admin_padre` int(11) DEFAULT NULL,
  `nombre` varchar(150) NOT NULL,
  `edad` int(11) DEFAULT NULL,
  `sexo` enum('F','M') DEFAULT NULL,
  `id_mirror` varchar(30) DEFAULT NULL,
  `correo` varchar(150) NOT NULL,
  `telefono` varchar(30) DEFAULT NULL,
  `puesto` varchar(150) DEFAULT NULL,
  `direccion` varchar(255) DEFAULT NULL,
  `estatus` enum('prospecto','en_proceso','evaluacion','aprobado','contratado','no_contratado') NOT NULL DEFAULT 'prospecto',
  `fecha_registro` timestamp NOT NULL DEFAULT current_timestamp(),
  `fecha_actualizacion` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_prospecto`),
  UNIQUE KEY `uq_prospectos_id_mirror` (`id_mirror`),
  KEY `idx_prospectos_admin` (`id_admin_padre`),
  KEY `idx_prospectos_correo` (`correo`),
  CONSTRAINT `fk_prospectos_admin` FOREIGN KEY (`id_admin_padre`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `prospectos`
--

LOCK TABLES `prospectos` WRITE;
/*!40000 ALTER TABLE `prospectos` DISABLE KEYS */;
INSERT INTO `prospectos` VALUES (1,15,'JUAN',25,'M','MS-2026-25-MA-002','cortina88@gmail.com','5546513125','secretario','carretera sor juana','contratado','2026-09-16 19:11:10','2026-10-08 16:28:22'),(2,15,'ARELY HERNANDEZ LUCAS',24,'F','MS-2026-24-FE-003','jupiter1014@gmail.com','5574415515','sistemas','CDMX','no_contratado','2026-10-08 16:49:12','2026-10-20 17:52:26'),(3,15,'Abraham Rivera Salinas',30,'M','MS-2026-30-MA-004','salinas@gmail.com','5546464646','sistemas','CDMX','no_contratado','2026-10-20 18:16:41','2026-10-20 21:31:01'),(4,15,'Abraham salinas rivera',29,'M','MS-2026-29-MA-005','salinasabram@gmail.com','5546455555','sistemas','CDMX','contratado','2026-10-20 22:44:46','2026-10-26 17:38:08'),(5,15,'ARELY HERNANDEZ LUCAS',30,'F','MS-2026-30-FE-006','ary789456@gmail.com','5546478963','sistemas','CDMX','contratado','2026-10-26 18:57:03','2026-10-26 20:11:20'),(6,15,'María Pérez',36,'F','MS-2026-36-FE-008','jupiter1@gmail.com','5512124010','secretaria','CDMX','en_proceso','2026-10-27 18:46:24','2026-10-27 18:46:24'),(7,19,'Alicia Lopez',38,'F','MS-2026-38-FE-009','laura23@gmail.com','55127485','administracion','CDMX','en_proceso','2026-10-27 20:57:04','2026-10-27 20:57:04'),(8,36,'MARI GARCIA',35,'F','MS-2026-35-FE-011','prueba36@gmail.com','5546232323','ventas','Villada CDMX','no_contratado','2026-11-12 16:11:33','2026-11-12 18:41:51'),(9,36,'MARILU PEREZ',25,'F','MS-2026-25-FE-012','mar588@gmail.com','5546525256','ventas','la paz','contratado','2026-11-12 18:46:47','2026-11-12 18:57:50'),(10,36,'PEDRO PEREZ',35,'M','MS-2026-35-MA-013','per25@gmail.com','5525262423','ventas','la paz','no_contratado','2026-11-12 19:02:02','2026-11-12 19:02:51');
/*!40000 ALTER TABLE `prospectos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `pruebas`
--

DROP TABLE IF EXISTS `pruebas`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pruebas` (
  `id_prueba` int(11) NOT NULL AUTO_INCREMENT,
  `nombre` varchar(150) NOT NULL,
  `descripcion` text DEFAULT NULL,
  `tipo` varchar(50) DEFAULT NULL,
  `version` varchar(30) DEFAULT NULL,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `activo` tinyint(1) DEFAULT 1,
  PRIMARY KEY (`id_prueba`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pruebas`
--

LOCK TABLES `pruebas` WRITE;
/*!40000 ALTER TABLE `pruebas` DISABLE KEYS */;
INSERT INTO `pruebas` VALUES (1,'Inventario de Depresión de Beck (BDI-II)','Evalúa la intensidad de síntomas depresivos','depresion','1.0','2025-10-09 17:51:15',1),(2,'Escala de Estrés Percibido (PSS-14)','Mide la percepción de estrés en el último mes','estres','1.0','2025-10-09 17:51:15',1),(3,'GAD-7','Cuestionario de ansiedad generalizada','ansiedad','1.0','2025-10-09 17:51:15',1),(4,'Cleaver','Evaluación conductual mediante selección de palabras MÁS y MENOS.','cleaver','CLEAVER','2026-10-08 19:08:23',1);
/*!40000 ALTER TABLE `pruebas` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `pruebas_empleados_habilitadas`
--

DROP TABLE IF EXISTS `pruebas_empleados_habilitadas`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pruebas_empleados_habilitadas` (
  `id_habilitacion` int(11) NOT NULL AUTO_INCREMENT,
  `id_empleado` int(11) NOT NULL,
  `id_prueba_rh` int(11) NOT NULL,
  `id_usuario_registro` int(11) DEFAULT NULL,
  `token_publico` varchar(120) NOT NULL,
  `motivo` varchar(200) DEFAULT NULL,
  `tipo_evaluacion` enum('periodica','seguimiento','bienestar','prevencion','riesgo_psicosocial','otro') NOT NULL DEFAULT 'periodica',
  `estatus` enum('habilitada','iniciada','completada','cancelada') NOT NULL DEFAULT 'habilitada',
  `fecha_habilitacion` datetime NOT NULL DEFAULT current_timestamp(),
  `fecha_inicio` datetime DEFAULT NULL,
  `fecha_completada` datetime DEFAULT NULL,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `actualizado_en` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_habilitacion`),
  UNIQUE KEY `uq_peh_token` (`token_publico`),
  KEY `idx_peh_empleado` (`id_empleado`),
  KEY `idx_peh_prueba` (`id_prueba_rh`),
  KEY `idx_peh_estatus` (`estatus`),
  KEY `fk_peh_usuario` (`id_usuario_registro`),
  CONSTRAINT `fk_peh_empleado` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id_empleado`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_peh_prueba` FOREIGN KEY (`id_prueba_rh`) REFERENCES `pruebas_rh` (`id_prueba_rh`) ON UPDATE CASCADE,
  CONSTRAINT `fk_peh_usuario` FOREIGN KEY (`id_usuario_registro`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pruebas_empleados_habilitadas`
--

LOCK TABLES `pruebas_empleados_habilitadas` WRITE;
/*!40000 ALTER TABLE `pruebas_empleados_habilitadas` DISABLE KEYS */;
INSERT INTO `pruebas_empleados_habilitadas` VALUES (3,3,6,19,'120aa760381df563112121497e6619ea8c73c48acbf5f56c3a62e38718ac3fd5','xc','periodica','completada','2026-10-30 12:17:23','2026-10-30 12:32:39','2026-10-30 12:37:35','2026-10-30 18:17:23','2026-10-30 18:37:35'),(4,3,5,19,'83d7392b4028be49ac367e742c9a2d825102eb318a8ab244b063c8a3f3cda3f0','55','periodica','completada','2026-10-30 12:43:56','2026-10-30 12:44:07','2026-10-30 12:47:13','2026-10-30 18:43:56','2026-10-30 18:47:13'),(6,3,5,19,'8da1113e4215ae317b39320fef25a1242d9b319ffaf7072a264db952a5e4ee5c','df','periodica','completada','2026-10-30 12:49:23','2026-10-30 12:49:29','2026-10-30 12:49:41','2026-10-30 18:49:23','2026-10-30 18:49:41'),(7,3,5,19,'69b56948c80da55caebc43487446a942c738233d0e51ad7a997e25455960fc21','rt','periodica','completada','2026-10-30 12:56:01','2026-10-30 12:56:10','2026-10-30 12:56:20','2026-10-30 18:56:01','2026-10-30 18:56:20'),(8,3,5,19,'bd0df8a87ef4f55ffeabd612777a419a22a5d152f42ad976ab99d3a1267dccf7','sss','periodica','completada','2026-10-30 12:57:18','2026-10-30 12:57:24','2026-10-30 12:57:36','2026-10-30 18:57:18','2026-10-30 18:57:36'),(9,3,8,19,'58d04191df1580b478639597289a8bf30508770f5269885aa29dd5cf146fcecd','no','periodica','cancelada','2026-11-03 15:40:59','2026-11-03 15:41:05',NULL,'2026-11-03 21:40:59','2026-11-03 21:41:15'),(10,3,6,19,'c5f004dbefbbcd5cd6ce3fd23321102838f0e910ef1dcc5461da776950096ae0','n','periodica','completada','2026-11-03 15:41:32','2026-11-03 15:41:44','2026-11-03 15:41:59','2026-11-03 21:41:32','2026-11-03 21:41:59'),(11,4,6,36,'740f416568ba71b9039651bdd33edfdf5a33a1da1d244ec8d2ddf2ab26ca5376','protocolo','bienestar','completada','2026-11-12 14:05:28','2026-11-12 14:05:50','2026-11-12 14:06:10','2026-11-12 20:05:28','2026-11-12 20:06:10');
/*!40000 ALTER TABLE `pruebas_empleados_habilitadas` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `pruebas_habilitadas`
--

DROP TABLE IF EXISTS `pruebas_habilitadas`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pruebas_habilitadas` (
  `id_habilitacion` int(11) NOT NULL AUTO_INCREMENT,
  `id_paciente` int(11) NOT NULL,
  `id_sesion` int(11) DEFAULT NULL,
  `id_prueba` int(11) NOT NULL,
  `id_psicologo` int(11) NOT NULL,
  `notas` text DEFAULT NULL,
  `fecha` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_habilitacion`)
) ENGINE=InnoDB AUTO_INCREMENT=22 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pruebas_habilitadas`
--

LOCK TABLES `pruebas_habilitadas` WRITE;
/*!40000 ALTER TABLE `pruebas_habilitadas` DISABLE KEYS */;
INSERT INTO `pruebas_habilitadas` VALUES (1,1,NULL,3,1,NULL,'2026-09-03 03:23:45'),(2,1,NULL,2,1,NULL,'2026-09-05 01:11:22'),(3,1,NULL,1,1,NULL,'2026-09-05 01:15:09'),(4,1,2,3,1,NULL,'2026-09-05 04:58:50'),(5,1,6,3,1,NULL,'2026-09-07 18:01:45'),(6,1,8,3,1,NULL,'2026-09-07 18:42:20'),(7,1,9,2,1,NULL,'2026-09-07 19:27:15'),(8,1,NULL,3,1,NULL,'2026-09-23 19:18:59'),(9,1,NULL,2,1,NULL,'2026-10-05 18:06:53'),(10,1,NULL,4,1,NULL,'2026-10-08 21:34:40'),(11,1,19,4,1,NULL,'2026-10-08 21:36:08'),(12,1,19,4,1,NULL,'2026-10-08 21:54:05'),(13,2,20,3,10,NULL,'2026-10-27 16:42:36'),(14,1,NULL,3,1,NULL,'2026-11-05 19:37:16'),(15,3,22,4,19,NULL,'2026-11-09 23:54:29'),(16,3,NULL,2,19,NULL,'2026-11-10 16:18:19'),(17,3,22,2,19,NULL,'2026-11-10 16:20:15'),(18,3,23,2,19,NULL,'2026-11-10 21:08:13'),(19,3,23,4,19,NULL,'2026-11-10 21:08:18'),(20,3,24,4,19,NULL,'2026-11-10 21:25:15'),(21,3,24,3,19,NULL,'2026-11-10 21:26:12');
/*!40000 ALTER TABLE `pruebas_habilitadas` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `pruebas_prospectos_habilitadas`
--

DROP TABLE IF EXISTS `pruebas_prospectos_habilitadas`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pruebas_prospectos_habilitadas` (
  `id_habilitacion` int(11) NOT NULL AUTO_INCREMENT,
  `id_prospecto` int(11) NOT NULL,
  `id_prueba_rh` int(11) NOT NULL,
  `id_usuario_registro` int(11) DEFAULT NULL,
  `token_publico` varchar(120) DEFAULT NULL,
  `estatus` enum('habilitada','iniciada','completada','cancelada') NOT NULL DEFAULT 'habilitada',
  `fecha_habilitacion` datetime NOT NULL DEFAULT current_timestamp(),
  `fecha_inicio` datetime DEFAULT NULL,
  `fecha_completada` datetime DEFAULT NULL,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `actualizado_en` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_habilitacion`),
  UNIQUE KEY `uq_prueba_prospecto_activa` (`id_prospecto`,`id_prueba_rh`,`estatus`),
  KEY `idx_pph_prospecto` (`id_prospecto`),
  KEY `idx_pph_prueba` (`id_prueba_rh`),
  KEY `idx_pph_usuario` (`id_usuario_registro`),
  KEY `idx_pph_token` (`token_publico`),
  CONSTRAINT `fk_pph_prospecto` FOREIGN KEY (`id_prospecto`) REFERENCES `prospectos` (`id_prospecto`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_pph_prueba_rh` FOREIGN KEY (`id_prueba_rh`) REFERENCES `pruebas_rh` (`id_prueba_rh`) ON UPDATE CASCADE,
  CONSTRAINT `fk_pph_usuario` FOREIGN KEY (`id_usuario_registro`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pruebas_prospectos_habilitadas`
--

LOCK TABLES `pruebas_prospectos_habilitadas` WRITE;
/*!40000 ALTER TABLE `pruebas_prospectos_habilitadas` DISABLE KEYS */;
INSERT INTO `pruebas_prospectos_habilitadas` VALUES (1,1,1,15,'c8dcb249663a5f6668c3af289eefd8f86dbd7cf2095704a5d051b78c6ea07ea6','completada','2026-10-02 14:18:26','2026-10-02 14:30:49','2026-10-02 19:22:06','2026-10-02 20:18:26','2026-10-03 01:22:06'),(2,1,2,15,'9d88588091fe3e5b06415abb1c953a386023cfee8a9d22d532af41b2e01310f2','completada','2026-10-02 15:06:32','2026-10-02 15:07:09','2026-10-02 15:21:31','2026-10-02 21:06:32','2026-10-02 21:21:31');
/*!40000 ALTER TABLE `pruebas_prospectos_habilitadas` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `pruebas_rh`
--

DROP TABLE IF EXISTS `pruebas_rh`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pruebas_rh` (
  `id_prueba_rh` int(11) NOT NULL AUTO_INCREMENT,
  `nombre` varchar(150) NOT NULL,
  `descripcion` text DEFAULT NULL,
  `categoria` varchar(100) DEFAULT NULL,
  `contexto` enum('seleccion','empleado','ambos') NOT NULL DEFAULT 'seleccion',
  `version` varchar(50) DEFAULT NULL,
  `activo` tinyint(1) NOT NULL DEFAULT 1,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `actualizado_en` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_prueba_rh`),
  KEY `idx_pruebas_rh_activo` (`activo`),
  KEY `idx_pruebas_rh_categoria` (`categoria`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pruebas_rh`
--

LOCK TABLES `pruebas_rh` WRITE;
/*!40000 ALTER TABLE `pruebas_rh` DISABLE KEYS */;
INSERT INTO `pruebas_rh` VALUES (1,'IPIP-50 Big Five','Inventario de 50 reactivos para evaluar cinco grandes dimensiones de personalidad. Uso como apoyo descriptivo dentro del proceso de Recursos Humanos.','Personalidad','seleccion','IPIP-BFFM-50 ES-MX',1,'2026-10-01 23:19:32','2026-10-01 23:19:32'),(2,'ORVIS - Oregon Vocational Interest Scales','Inventario de intereses vocacionales de 92 reactivos que evalúa ocho áreas de interés: liderazgo, organización, altruismo, creatividad, análisis, producción, aventura y erudición.','Intereses vocacionales','seleccion','ORVIS-92 ES-MX',1,'2026-10-02 20:47:24','2026-10-02 20:47:24'),(3,'Matrices Progresivas de Raven - Escala General','Prueba psicométrica de razonamiento abstracto y capacidad para identificar relaciones y completar matrices.','Aptitudes cognitivas','seleccion','RAVEN-SPM',1,'2026-10-09 19:04:46','2026-10-09 19:04:46'),(4,'Beta III','Prueba psicométrica no verbal de capacidad intelectual compuesta por cinco subpruebas.','Aptitudes cognitivas','seleccion','BETA-III',1,'2026-10-12 17:58:06','2026-10-12 17:58:06'),(5,'WHO-5 Índice de Bienestar','Tamizaje preventivo breve de bienestar mental durante las últimas dos semanas. No constituye diagnóstico.','bienestar','empleado','WHO-5',1,'2026-10-30 17:11:52','2026-10-30 17:11:52'),(6,'GAD-7 Ansiedad','Tamizaje preventivo de síntomas relacionados con ansiedad durante las últimas dos semanas. No constituye diagnóstico.','ansiedad','empleado','GAD-7',1,'2026-10-30 17:11:52','2026-10-30 17:11:52'),(7,'PHQ-9 Estado de ánimo','Tamizaje preventivo de síntomas relacionados con estado de ánimo y depresión durante las últimas dos semanas. No constituye diagnóstico.','estado_animo','empleado','PHQ-9',1,'2026-10-30 17:11:52','2026-10-30 17:11:52'),(8,'ASQ Prevención de riesgo suicida','Tamizaje preventivo para identificar señales que requieren valoración profesional de seguridad. No constituye diagnóstico.','prevencion_suicidio','empleado','ASQ-NIMH',1,'2026-10-30 17:11:52','2026-10-30 17:11:52');
/*!40000 ALTER TABLE `pruebas_rh` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `psicologo_areas_atencion`
--

DROP TABLE IF EXISTS `psicologo_areas_atencion`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `psicologo_areas_atencion` (
  `id_psicologo_area` int(11) NOT NULL AUTO_INCREMENT,
  `id_psicologo` int(11) NOT NULL,
  `id_area` int(11) NOT NULL,
  PRIMARY KEY (`id_psicologo_area`),
  UNIQUE KEY `uk_psicologo_area` (`id_psicologo`,`id_area`),
  KEY `fk_psicologo_area_area` (`id_area`),
  CONSTRAINT `fk_psicologo_area_area` FOREIGN KEY (`id_area`) REFERENCES `catalogo_areas_atencion` (`id_area`) ON DELETE CASCADE,
  CONSTRAINT `fk_psicologo_area_psicologo` FOREIGN KEY (`id_psicologo`) REFERENCES `psicologos` (`id_psicologo`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=51 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `psicologo_areas_atencion`
--

LOCK TABLES `psicologo_areas_atencion` WRITE;
/*!40000 ALTER TABLE `psicologo_areas_atencion` DISABLE KEYS */;
INSERT INTO `psicologo_areas_atencion` VALUES (6,1,1),(7,1,2),(8,1,9),(9,1,14),(10,1,18),(24,8,5),(25,8,8),(23,8,10),(26,8,11),(27,8,12),(22,8,14),(28,8,16),(11,9,1),(12,9,2),(13,9,3),(14,9,7),(19,9,9),(18,9,13),(20,9,14),(15,9,15),(17,9,16),(16,9,20),(21,9,21),(30,12,2),(29,12,3),(31,12,4),(32,12,5),(45,19,1),(46,19,2),(47,19,3),(48,19,8),(49,19,12),(50,19,21);
/*!40000 ALTER TABLE `psicologo_areas_atencion` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `psicologos`
--

DROP TABLE IF EXISTS `psicologos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `psicologos` (
  `id_psicologo` int(11) NOT NULL AUTO_INCREMENT,
  `id_usuario` int(11) NOT NULL,
  `telefono` varchar(30) DEFAULT NULL,
  `cedula_profesional` varchar(50) NOT NULL,
  `especialidad` varchar(100) DEFAULT NULL,
  `foto_url` varchar(255) DEFAULT NULL,
  `descripcion_profesional` text DEFAULT NULL,
  `anos_experiencia` int(11) DEFAULT NULL,
  `modalidad_presencial` tinyint(1) NOT NULL DEFAULT 0,
  `modalidad_videollamada` tinyint(1) NOT NULL DEFAULT 0,
  `precio_presencial` decimal(10,2) DEFAULT NULL,
  `precio_videollamada` decimal(10,2) DEFAULT NULL,
  `estado` varchar(100) DEFAULT NULL,
  `municipio` varchar(150) DEFAULT NULL,
  `colonia` varchar(150) DEFAULT NULL,
  `codigo_postal` varchar(10) DEFAULT NULL,
  `direccion_consultorio` varchar(255) DEFAULT NULL,
  `disponibilidad` text DEFAULT NULL,
  `perfil_profesional_completo` tinyint(1) NOT NULL DEFAULT 0,
  `activo_canalizacion` tinyint(1) NOT NULL DEFAULT 0,
  `direccion` varchar(200) DEFAULT NULL,
  `fecha_nacimiento` date DEFAULT NULL,
  PRIMARY KEY (`id_psicologo`)
) ENGINE=InnoDB AUTO_INCREMENT=20 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `psicologos`
--

LOCK TABLES `psicologos` WRITE;
/*!40000 ALTER TABLE `psicologos` DISABLE KEYS */;
INSERT INTO `psicologos` VALUES (1,2,'5512345678','13658996','psicologa conductual','/uploads/imagenes/psicologos/psicologo-2-1793748392457.png','Psicóloga con experiencia en atención clínica, acompañamiento emocional y orientación psicológica. Trabajo con un enfoque empático y profesional, brindando atención presencial y en línea de acuerdo con las necesidades de cada persona.',5,1,1,600.00,400.00,'México','Nezahualcóyotl','Benito Juárez (La Aurora)','57000','Nezahualcoyotl','lunes a viernes de 9:00am a 5:00pm',1,1,'Nezahualcóyotl',NULL),(2,3,NULL,'12671190','psicologa conductual',NULL,NULL,NULL,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,0,NULL,NULL),(3,4,NULL,'963258','psicologa conductual',NULL,NULL,NULL,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,0,NULL,NULL),(4,5,NULL,'12345678','trabajo social',NULL,NULL,NULL,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,0,NULL,NULL),(5,6,NULL,'12345620','Administrativa',NULL,NULL,NULL,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,0,NULL,NULL),(6,9,NULL,'14785236','administrador',NULL,NULL,NULL,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,0,NULL,NULL),(7,13,NULL,'12345777','psicologa',NULL,NULL,NULL,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,0,NULL,NULL),(8,16,'5517622321','8956998','conductual','/uploads/imagenes/psicologos/psicologo-16-1793896748457.png','Psicóloga con experiencia en atención individual, manejo de ansiedad, estrés, autoestima y dificultades emocionales. Brinda acompañamiento psicológico en modalidad presencial y por videollamada, con un enfoque profesional, empático y confidencial, adaptado a las necesidades de cada persona.',5,1,1,800.00,699.96,'México','Nezahualcóyotl','Benito Juárez (La Aurora)','57000','Nezahualcoyotl','de lunes a jueves de 12:00 am a 5:00pm',1,1,NULL,NULL),(9,17,'5525305512','89582456','conductual','/uploads/imagenes/psicologos/psicologo-17-1793895968182.png','Psicóloga con experiencia en atención individual, manejo de ansiedad, estrés, autoestima y dificultades emocionales. Brinda acompañamiento psicológico en modalidad presencial y por videollamada, con un enfoque profesional, empático y confidencial, adaptado a las necesidades de cada persona.',3,1,0,800.00,NULL,'México','Nezahualcóyotl','Benito Juárez (La Aurora)','57000','Nezahualcoyotl','de lunes a domingo de 1:00 pm a 5:00 pm',1,1,NULL,NULL),(10,18,'26490582','74102589','clinica',NULL,NULL,NULL,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,0,NULL,NULL),(11,21,'5546513169','877744411','clinica',NULL,NULL,NULL,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,0,NULL,NULL),(12,22,'5546545456','78941239','clinica','/uploads/imagenes/psicologos/psicologo-22-1793903406122.png','soy buena y tengo disponibilidad',4,1,1,400.00,500.00,'México','La Paz','Ampliación Los Reyes','56400','Nezahualcoyotl','toda la semana de 1:00pm a 6:00pm',1,1,'Los Reyes','2004-02-12'),(13,24,'5546513189','85236974','Psicología Clínica',NULL,NULL,NULL,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,0,'CDMX','1990-05-20'),(14,25,'5511111102','90000002','Psicología Clínica',NULL,NULL,NULL,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,0,'CDMX','1991-01-10'),(15,26,'5511111103','90000003','Psicología Clínica',NULL,NULL,NULL,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,0,'CDMX','1992-02-10'),(16,27,'5511111104','90000004','Psicología Clínica',NULL,NULL,NULL,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,0,'CDMX','1993-03-10'),(17,28,'5511111105','90000005','Psicología Clínica',NULL,NULL,NULL,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,0,'CDMX','1994-04-10'),(18,33,'5578451296','23212526','clinica',NULL,NULL,NULL,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,0,'la paz','2003-02-07'),(19,35,'5546513132','136589888','clinica',NULL,'no',2,1,1,800.00,499.94,'México','Chalco','Industrial Chalco','56600','16','lunes de 8:00am a 8:00pm\nmartes a sábado de 10:00am a 8:00pm',1,1,'Nezahualcoyotl',NULL);
/*!40000 ALTER TABLE `psicologos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `psicologos_backup`
--

DROP TABLE IF EXISTS `psicologos_backup`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `psicologos_backup` (
  `id_psicologo` int(11) NOT NULL DEFAULT 0,
  `id_usuario` int(11) NOT NULL,
  `nombre` varchar(120) NOT NULL,
  `correo` varchar(120) NOT NULL,
  `telefono` varchar(30) DEFAULT NULL,
  `cedula_profesional` varchar(50) NOT NULL,
  `especialidad` varchar(100) DEFAULT NULL,
  `direccion` varchar(200) DEFAULT NULL,
  `fecha_nacimiento` date DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `psicologos_backup`
--

LOCK TABLES `psicologos_backup` WRITE;
/*!40000 ALTER TABLE `psicologos_backup` DISABLE KEYS */;
INSERT INTO `psicologos_backup` VALUES (1,2,'lili','jp5247356@gmail.com',NULL,'13658996','psicologa conductual',NULL,NULL);
/*!40000 ALTER TABLE `psicologos_backup` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `reactivos_beta3`
--

DROP TABLE IF EXISTS `reactivos_beta3`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `reactivos_beta3` (
  `id_reactivo_beta3` int(11) NOT NULL AUTO_INCREMENT,
  `id_prueba_rh` int(11) NOT NULL,
  `id_subprueba` int(11) NOT NULL,
  `id_lamina_beta3` int(11) DEFAULT NULL,
  `numero` int(11) NOT NULL,
  `fila` int(11) DEFAULT NULL,
  `posicion_fila` int(11) DEFAULT NULL,
  `tipo_respuesta` varchar(50) NOT NULL,
  `imagen` varchar(255) DEFAULT NULL,
  `enunciado` text DEFAULT NULL,
  `total_opciones` int(11) DEFAULT NULL,
  `respuesta_correcta` varchar(100) DEFAULT NULL,
  `es_ejemplo` tinyint(1) NOT NULL DEFAULT 0,
  `activo` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id_reactivo_beta3`),
  UNIQUE KEY `uk_beta3_reactivo` (`id_prueba_rh`,`id_subprueba`,`numero`,`es_ejemplo`),
  KEY `idx_beta3_subprueba` (`id_subprueba`)
) ENGINE=InnoDB AUTO_INCREMENT=291 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `reactivos_beta3`
--

LOCK TABLES `reactivos_beta3` WRITE;
/*!40000 ALTER TABLE `reactivos_beta3` DISABLE KEYS */;
INSERT INTO `reactivos_beta3` VALUES (1,4,1,3,1,1,1,'numero','beta3/2.jpg',NULL,9,'5',1,1),(2,4,1,3,2,1,2,'numero','beta3/2.jpg',NULL,9,'3',1,1),(3,4,1,3,3,1,3,'numero','beta3/2.jpg',NULL,9,'1',1,1),(4,4,1,3,4,1,4,'numero','beta3/2.jpg',NULL,9,'4',0,1),(5,4,1,3,5,1,5,'numero','beta3/2.jpg',NULL,9,'2',0,1),(6,4,1,3,6,1,6,'numero','beta3/2.jpg',NULL,9,'5',0,1),(7,4,1,3,7,1,7,'numero','beta3/2.jpg',NULL,9,'1',0,1),(8,4,1,3,8,1,8,'numero','beta3/2.jpg',NULL,9,'4',0,1),(9,4,1,3,9,1,9,'numero','beta3/2.jpg',NULL,9,'3',0,1),(10,4,1,3,10,1,10,'numero','beta3/2.jpg',NULL,9,'2',0,1),(11,4,1,3,11,1,11,'numero','beta3/2.jpg',NULL,9,'5',0,1),(12,4,1,3,12,1,12,'numero','beta3/2.jpg',NULL,9,'1',0,1),(13,4,1,3,13,1,13,'numero','beta3/2.jpg',NULL,9,'4',0,1),(14,4,1,3,14,1,14,'numero','beta3/2.jpg',NULL,9,'3',0,1),(15,4,1,3,15,1,15,'numero','beta3/2.jpg',NULL,9,'5',0,1),(16,4,1,3,16,1,16,'numero','beta3/2.jpg',NULL,9,'2',0,1),(17,4,1,3,17,1,17,'numero','beta3/2.jpg',NULL,9,'4',0,1),(18,4,1,3,18,1,18,'numero','beta3/2.jpg',NULL,9,'3',0,1),(19,4,1,3,19,1,19,'numero','beta3/2.jpg',NULL,9,'1',0,1),(20,4,1,3,20,1,20,'numero','beta3/2.jpg',NULL,9,'2',0,1),(21,4,1,3,21,2,1,'numero','beta3/2.jpg',NULL,9,'7',0,1),(22,4,1,3,22,2,2,'numero','beta3/2.jpg',NULL,9,'2',0,1),(23,4,1,3,23,2,3,'numero','beta3/2.jpg',NULL,9,'5',0,1),(24,4,1,3,24,2,4,'numero','beta3/2.jpg',NULL,9,'6',0,1),(25,4,1,3,25,2,5,'numero','beta3/2.jpg',NULL,9,'8',0,1),(26,4,1,3,26,2,6,'numero','beta3/2.jpg',NULL,9,'7',0,1),(27,4,1,3,27,2,7,'numero','beta3/2.jpg',NULL,9,'4',0,1),(28,4,1,3,28,2,8,'numero','beta3/2.jpg',NULL,9,'3',0,1),(29,4,1,3,29,2,9,'numero','beta3/2.jpg',NULL,9,'6',0,1),(30,4,1,3,30,2,10,'numero','beta3/2.jpg',NULL,9,'4',0,1),(31,4,1,3,31,2,11,'numero','beta3/2.jpg',NULL,9,'9',0,1),(32,4,1,3,32,2,12,'numero','beta3/2.jpg',NULL,9,'7',0,1),(33,4,1,3,33,2,13,'numero','beta3/2.jpg',NULL,9,'6',0,1),(34,4,1,3,34,2,14,'numero','beta3/2.jpg',NULL,9,'1',0,1),(35,4,1,3,35,2,15,'numero','beta3/2.jpg',NULL,9,'9',0,1),(36,4,1,3,36,2,16,'numero','beta3/2.jpg',NULL,9,'8',0,1),(37,4,1,3,37,2,17,'numero','beta3/2.jpg',NULL,9,'2',0,1),(38,4,1,3,38,2,18,'numero','beta3/2.jpg',NULL,9,'9',0,1),(39,4,1,3,39,2,19,'numero','beta3/2.jpg',NULL,9,'3',0,1),(40,4,1,3,40,2,20,'numero','beta3/2.jpg',NULL,9,'8',0,1),(41,4,1,3,41,3,1,'numero','beta3/2.jpg',NULL,9,'8',0,1),(42,4,1,3,42,3,2,'numero','beta3/2.jpg',NULL,9,'4',0,1),(43,4,1,3,43,3,3,'numero','beta3/2.jpg',NULL,9,'6',0,1),(44,4,1,3,44,3,4,'numero','beta3/2.jpg',NULL,9,'7',0,1),(45,4,1,3,45,3,5,'numero','beta3/2.jpg',NULL,9,'9',0,1),(46,4,1,3,46,3,6,'numero','beta3/2.jpg',NULL,9,'8',0,1),(47,4,1,3,47,3,7,'numero','beta3/2.jpg',NULL,9,'6',0,1),(48,4,1,3,48,3,8,'numero','beta3/2.jpg',NULL,9,'1',0,1),(49,4,1,3,49,3,9,'numero','beta3/2.jpg',NULL,9,'9',0,1),(50,4,1,3,50,3,10,'numero','beta3/2.jpg',NULL,9,'7',0,1),(51,4,1,3,51,3,11,'numero','beta3/2.jpg',NULL,9,'5',0,1),(52,4,1,3,52,3,12,'numero','beta3/2.jpg',NULL,9,'9',0,1),(53,4,1,3,53,3,13,'numero','beta3/2.jpg',NULL,9,'8',0,1),(54,4,1,3,54,3,14,'numero','beta3/2.jpg',NULL,9,'2',0,1),(55,4,1,3,55,3,15,'numero','beta3/2.jpg',NULL,9,'7',0,1),(56,4,1,3,56,3,16,'numero','beta3/2.jpg',NULL,9,'6',0,1),(57,4,1,3,57,3,17,'numero','beta3/2.jpg',NULL,9,'5',0,1),(58,4,1,3,58,3,18,'numero','beta3/2.jpg',NULL,9,'8',0,1),(59,4,1,3,59,3,19,'numero','beta3/2.jpg',NULL,9,'7',0,1),(60,4,1,3,60,3,20,'numero','beta3/2.jpg',NULL,9,'3',0,1),(61,4,1,3,61,4,1,'numero','beta3/2.jpg',NULL,9,'9',0,1),(62,4,1,3,62,4,2,'numero','beta3/2.jpg',NULL,9,'5',0,1),(63,4,1,3,63,4,3,'numero','beta3/2.jpg',NULL,9,'2',0,1),(64,4,1,3,64,4,4,'numero','beta3/2.jpg',NULL,9,'6',0,1),(65,4,1,3,65,4,5,'numero','beta3/2.jpg',NULL,9,'7',0,1),(66,4,1,3,66,4,6,'numero','beta3/2.jpg',NULL,9,'3',0,1),(67,4,1,3,67,4,7,'numero','beta3/2.jpg',NULL,9,'1',0,1),(68,4,1,3,68,4,8,'numero','beta3/2.jpg',NULL,9,'5',0,1),(69,4,1,3,69,4,9,'numero','beta3/2.jpg',NULL,9,'3',0,1),(70,4,1,3,70,4,10,'numero','beta3/2.jpg',NULL,9,'7',0,1),(71,4,1,3,71,4,11,'numero','beta3/2.jpg',NULL,9,'9',0,1),(72,4,1,3,72,4,12,'numero','beta3/2.jpg',NULL,9,'2',0,1),(73,4,1,3,73,4,13,'numero','beta3/2.jpg',NULL,9,'8',0,1),(74,4,1,3,74,4,14,'numero','beta3/2.jpg',NULL,9,'4',0,1),(75,4,1,3,75,4,15,'numero','beta3/2.jpg',NULL,9,'6',0,1),(76,4,1,3,76,4,16,'numero','beta3/2.jpg',NULL,9,'9',0,1),(77,4,1,3,77,4,17,'numero','beta3/2.jpg',NULL,9,'1',0,1),(78,4,1,3,78,4,18,'numero','beta3/2.jpg',NULL,9,'6',0,1),(79,4,1,3,79,4,19,'numero','beta3/2.jpg',NULL,9,'4',0,1),(80,4,1,3,80,4,20,'numero','beta3/2.jpg',NULL,9,'8',0,1),(81,4,1,3,81,5,1,'numero','beta3/2.jpg',NULL,9,'5',0,1),(82,4,1,3,82,5,2,'numero','beta3/2.jpg',NULL,9,'3',0,1),(83,4,1,3,83,5,3,'numero','beta3/2.jpg',NULL,9,'9',0,1),(84,4,1,3,84,5,4,'numero','beta3/2.jpg',NULL,9,'1',0,1),(85,4,1,3,85,5,5,'numero','beta3/2.jpg',NULL,9,'6',0,1),(86,4,1,3,86,5,6,'numero','beta3/2.jpg',NULL,9,'7',0,1),(87,4,1,3,87,5,7,'numero','beta3/2.jpg',NULL,9,'2',0,1),(88,4,1,3,88,5,8,'numero','beta3/2.jpg',NULL,9,'8',0,1),(89,4,1,3,89,5,9,'numero','beta3/2.jpg',NULL,9,'4',0,1),(90,4,1,3,90,5,10,'numero','beta3/2.jpg',NULL,9,'1',0,1),(91,4,1,3,91,5,11,'numero','beta3/2.jpg',NULL,9,'8',0,1),(92,4,1,3,92,5,12,'numero','beta3/2.jpg',NULL,9,'9',0,1),(93,4,1,3,93,5,13,'numero','beta3/2.jpg',NULL,9,'3',0,1),(94,4,1,3,94,5,14,'numero','beta3/2.jpg',NULL,9,'7',0,1),(95,4,1,3,95,5,15,'numero','beta3/2.jpg',NULL,9,'5',0,1),(96,4,1,3,96,5,16,'numero','beta3/2.jpg',NULL,9,'4',0,1),(97,4,1,3,97,5,17,'numero','beta3/2.jpg',NULL,9,'8',0,1),(98,4,1,3,98,5,18,'numero','beta3/2.jpg',NULL,9,'2',0,1),(99,4,1,3,99,5,19,'numero','beta3/2.jpg',NULL,9,'6',0,1),(100,4,1,3,100,5,20,'numero','beta3/2.jpg',NULL,9,'3',0,1),(101,4,1,3,101,6,1,'numero','beta3/2.jpg',NULL,9,'4',0,1),(102,4,1,3,102,6,2,'numero','beta3/2.jpg',NULL,9,'1',0,1),(103,4,1,3,103,6,3,'numero','beta3/2.jpg',NULL,9,'5',0,1),(104,4,1,3,104,6,4,'numero','beta3/2.jpg',NULL,9,'2',0,1),(105,4,1,3,105,6,5,'numero','beta3/2.jpg',NULL,9,'9',0,1),(106,4,1,3,106,6,6,'numero','beta3/2.jpg',NULL,9,'5',0,1),(107,4,1,3,107,6,7,'numero','beta3/2.jpg',NULL,9,'1',0,1),(108,4,1,3,108,6,8,'numero','beta3/2.jpg',NULL,9,'7',0,1),(109,4,1,3,109,6,9,'numero','beta3/2.jpg',NULL,9,'3',0,1),(110,4,1,3,110,6,10,'numero','beta3/2.jpg',NULL,9,'8',0,1),(111,4,1,3,111,6,11,'numero','beta3/2.jpg',NULL,9,'4',0,1),(112,4,1,3,112,6,12,'numero','beta3/2.jpg',NULL,9,'6',0,1),(113,4,1,3,113,6,13,'numero','beta3/2.jpg',NULL,9,'2',0,1),(114,4,1,3,114,6,14,'numero','beta3/2.jpg',NULL,9,'7',0,1),(115,4,1,3,115,6,15,'numero','beta3/2.jpg',NULL,9,'9',0,1),(116,4,1,3,116,6,16,'numero','beta3/2.jpg',NULL,9,'3',0,1),(117,4,1,3,117,6,17,'numero','beta3/2.jpg',NULL,9,'6',0,1),(118,4,1,3,118,6,18,'numero','beta3/2.jpg',NULL,9,'4',0,1),(119,4,1,3,119,6,19,'numero','beta3/2.jpg',NULL,9,'6',0,1),(120,4,1,3,120,6,20,'numero','beta3/2.jpg',NULL,9,'8',0,1),(121,4,1,3,121,7,1,'numero','beta3/2.jpg',NULL,9,'7',0,1),(122,4,1,3,122,7,2,'numero','beta3/2.jpg',NULL,9,'1',0,1),(123,4,1,3,123,7,3,'numero','beta3/2.jpg',NULL,9,'5',0,1),(124,4,1,3,124,7,4,'numero','beta3/2.jpg',NULL,9,'8',0,1),(125,4,1,3,125,7,5,'numero','beta3/2.jpg',NULL,9,'2',0,1),(126,4,1,3,126,7,6,'numero','beta3/2.jpg',NULL,9,'8',0,1),(127,4,1,3,127,7,7,'numero','beta3/2.jpg',NULL,9,'7',0,1),(128,4,1,3,128,7,8,'numero','beta3/2.jpg',NULL,9,'4',0,1),(129,4,1,3,129,7,9,'numero','beta3/2.jpg',NULL,9,'9',0,1),(130,4,1,3,130,7,10,'numero','beta3/2.jpg',NULL,9,'2',0,1),(131,4,1,3,131,7,11,'numero','beta3/2.jpg',NULL,9,'6',0,1),(132,4,1,3,132,7,12,'numero','beta3/2.jpg',NULL,9,'3',0,1),(133,4,1,3,133,7,13,'numero','beta3/2.jpg',NULL,9,'6',0,1),(134,4,1,3,134,7,14,'numero','beta3/2.jpg',NULL,9,'4',0,1),(135,4,1,3,135,7,15,'numero','beta3/2.jpg',NULL,9,'1',0,1),(136,4,1,3,136,7,16,'numero','beta3/2.jpg',NULL,9,'7',0,1),(137,4,1,3,137,7,17,'numero','beta3/2.jpg',NULL,9,'9',0,1),(138,4,1,3,138,7,18,'numero','beta3/2.jpg',NULL,9,'2',0,1),(139,4,1,3,139,7,19,'numero','beta3/2.jpg',NULL,9,'5',0,1),(140,4,1,3,140,7,20,'numero','beta3/2.jpg',NULL,9,'3',0,1),(141,4,2,5,1,1,1,'figura_incompleta','beta3/4.jpg','Indica la parte que falta en la figura.',NULL,'4,33.90,8.11',0,1),(142,4,2,5,2,1,2,'figura_incompleta','beta3/4.jpg','Indica la parte que falta en la figura.',NULL,'4,27.31,39.08',0,1),(143,4,2,5,3,1,3,'figura_incompleta','beta3/4.jpg','Indica la parte que falta en la figura.',NULL,'4,33.73,56.19',0,1),(144,4,2,5,4,1,4,'figura_incompleta','beta3/4.jpg','Indica la parte que falta en la figura.',NULL,'4,31.00,86.60',0,1),(145,4,2,5,5,1,5,'figura_incompleta','beta3/4.jpg','Indica la parte que falta en la figura.',NULL,'4,74.31,20.75',0,1),(146,4,2,5,6,1,6,'figura_incompleta','beta3/4.jpg','Indica la parte que falta en la figura.',NULL,'4,77.58,40.57',0,1),(147,4,2,5,7,1,7,'figura_incompleta','beta3/4.jpg','Indica la parte que falta en la figura.',NULL,'4,77.58,53.48',0,1),(148,4,2,5,8,1,8,'figura_incompleta','beta3/4.jpg','Indica la parte que falta en la figura.',NULL,'4,69.69,78.01',0,1),(149,4,2,6,9,2,1,'figura_incompleta','beta3/5.jpg','Indica la parte que falta en la figura.',NULL,'5,23.31,17.07',0,1),(150,4,2,6,10,2,2,'figura_incompleta','beta3/5.jpg','Indica la parte que falta en la figura.',NULL,'5,33.05,43.06',0,1),(151,4,2,6,11,2,3,'figura_incompleta','beta3/5.jpg','Indica la parte que falta en la figura.',NULL,'5,28.05,66.10',0,1),(152,4,2,6,12,2,4,'figura_incompleta','beta3/5.jpg','Indica la parte que falta en la figura.',NULL,'5,30.40,79.87',0,1),(153,4,2,6,13,2,5,'figura_incompleta','beta3/5.jpg','Indica la parte que falta en la figura.',NULL,'5,73.56,20.96',0,1),(154,4,2,6,14,2,6,'figura_incompleta','beta3/5.jpg','Indica la parte que falta en la figura.',NULL,'5,69.61,39.56',0,1),(155,4,2,6,15,2,7,'figura_incompleta','beta3/5.jpg','Indica la parte que falta en la figura.',NULL,'5,70.24,62.84',0,1),(156,4,2,6,16,2,8,'figura_incompleta','beta3/5.jpg','Indica la parte que falta en la figura.',NULL,'5,74.77,74.32',0,1),(157,4,2,7,17,3,1,'figura_incompleta','beta3/6.jpg','Indica la parte que falta en la figura.',NULL,'6,27.39,13.53',0,1),(158,4,2,7,18,3,2,'figura_incompleta','beta3/6.jpg','Indica la parte que falta en la figura.',NULL,'6,27.13,42.63',0,1),(159,4,2,7,19,3,3,'figura_incompleta','beta3/6.jpg','Indica la parte que falta en la figura.',NULL,'6,30.44,62.80',0,1),(160,4,2,7,20,3,4,'figura_incompleta','beta3/6.jpg','Indica la parte que falta en la figura.',NULL,'6,28.66,81.84',0,1),(161,4,2,7,21,3,5,'figura_incompleta','beta3/6.jpg','Indica la parte que falta en la figura.',NULL,'6,67.96,23.44',0,1),(162,4,2,7,22,3,6,'figura_incompleta','beta3/6.jpg','Indica la parte que falta en la figura.',NULL,'6,71.02,41.61',0,1),(163,4,2,7,23,3,7,'figura_incompleta','beta3/6.jpg','Indica la parte que falta en la figura.',NULL,'6,69.23,66.77',0,1),(164,4,2,7,24,3,8,'figura_incompleta','beta3/6.jpg','Indica la parte que falta en la figura.',NULL,'6,78.05,82.86',0,1),(172,4,3,9,1,1,1,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(173,4,3,9,2,1,2,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(174,4,3,9,3,1,3,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(175,4,3,9,4,1,4,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(176,4,3,9,5,1,5,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(177,4,3,9,6,1,6,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(178,4,3,9,7,1,7,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(179,4,3,9,8,1,8,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(180,4,3,9,9,1,9,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(181,4,3,9,10,1,10,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(182,4,3,9,11,1,11,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(183,4,3,9,12,1,12,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(184,4,3,9,13,1,13,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(185,4,3,9,14,1,14,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(186,4,3,9,15,1,15,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(187,4,3,9,16,1,16,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(188,4,3,9,17,1,17,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(189,4,3,9,18,1,18,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(190,4,3,9,19,1,19,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(191,4,3,9,20,1,20,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(192,4,3,9,21,1,21,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(193,4,3,9,22,1,22,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(194,4,3,9,23,1,23,'igual_desigual','beta3/8.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(195,4,3,10,24,2,1,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(196,4,3,10,25,2,2,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(197,4,3,10,26,2,3,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(198,4,3,10,27,2,4,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(199,4,3,10,28,2,5,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(200,4,3,10,29,2,6,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(201,4,3,10,30,2,7,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(202,4,3,10,31,2,8,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(203,4,3,10,32,2,9,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(204,4,3,10,33,2,10,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(205,4,3,10,34,2,11,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(206,4,3,10,35,2,12,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(207,4,3,10,36,2,13,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(208,4,3,10,37,2,14,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(209,4,3,10,38,2,15,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(210,4,3,10,39,2,16,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(211,4,3,10,40,2,17,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(212,4,3,10,41,2,18,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(213,4,3,10,42,2,19,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(214,4,3,10,43,2,20,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(215,4,3,10,44,2,21,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(216,4,3,10,45,2,22,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(217,4,3,10,46,2,23,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(218,4,3,10,47,2,24,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(219,4,3,10,48,2,25,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(220,4,3,10,49,2,26,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(221,4,3,10,50,2,27,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(222,4,3,10,51,2,28,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'!=',0,1),(223,4,3,10,52,2,29,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(224,4,3,10,53,2,30,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(225,4,3,10,54,2,31,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(226,4,3,10,55,2,32,'igual_desigual','beta3/9.jpg','Indica si los dos elementos son iguales o diferentes.',2,'=',0,1),(235,4,4,12,1,1,1,'seleccion_1_4','beta3/11.jpg','Selecciona el dibujo que está equivocado.',4,'2',0,1),(236,4,4,12,2,1,2,'seleccion_1_4','beta3/11.jpg','Selecciona el dibujo que está equivocado.',4,'4',0,1),(237,4,4,12,3,1,3,'seleccion_1_4','beta3/11.jpg','Selecciona el dibujo que está equivocado.',4,'3',0,1),(238,4,4,12,4,1,4,'seleccion_1_4','beta3/11.jpg','Selecciona el dibujo que está equivocado.',4,'1',0,1),(239,4,4,12,5,1,5,'seleccion_1_4','beta3/11.jpg','Selecciona el dibujo que está equivocado.',4,'4',0,1),(240,4,4,12,6,1,6,'seleccion_1_4','beta3/11.jpg','Selecciona el dibujo que está equivocado.',4,'3',0,1),(241,4,4,13,7,2,1,'seleccion_1_4','beta3/12.jpg','Selecciona el dibujo que está equivocado.',4,'1',0,1),(242,4,4,13,8,2,2,'seleccion_1_4','beta3/12.jpg','Selecciona el dibujo que está equivocado.',4,'2',0,1),(243,4,4,13,9,2,3,'seleccion_1_4','beta3/12.jpg','Selecciona el dibujo que está equivocado.',4,'4',0,1),(244,4,4,13,10,2,4,'seleccion_1_4','beta3/12.jpg','Selecciona el dibujo que está equivocado.',4,'3',0,1),(245,4,4,13,11,2,5,'seleccion_1_4','beta3/12.jpg','Selecciona el dibujo que está equivocado.',4,'3',0,1),(246,4,4,13,12,2,6,'seleccion_1_4','beta3/12.jpg','Selecciona el dibujo que está equivocado.',4,'3',0,1),(247,4,4,14,13,3,1,'seleccion_1_4','beta3/13.jpg','Selecciona el dibujo que está equivocado.',4,'4',0,1),(248,4,4,14,14,3,2,'seleccion_1_4','beta3/13.jpg','Selecciona el dibujo que está equivocado.',4,'1',0,1),(249,4,4,14,15,3,3,'seleccion_1_4','beta3/13.jpg','Selecciona el dibujo que está equivocado.',4,'4',0,1),(250,4,4,14,16,3,4,'seleccion_1_4','beta3/13.jpg','Selecciona el dibujo que está equivocado.',4,'2',0,1),(251,4,4,14,17,3,5,'seleccion_1_4','beta3/13.jpg','Selecciona el dibujo que está equivocado.',4,'4',0,1),(252,4,4,14,18,3,6,'seleccion_1_4','beta3/13.jpg','Selecciona el dibujo que está equivocado.',4,'1',0,1),(253,4,4,15,19,4,1,'seleccion_1_4','beta3/14.jpg','Selecciona el dibujo que está equivocado.',4,'4',0,1),(254,4,4,15,20,4,2,'seleccion_1_4','beta3/14.jpg','Selecciona el dibujo que está equivocado.',4,'3',0,1),(255,4,4,15,21,4,3,'seleccion_1_4','beta3/14.jpg','Selecciona el dibujo que está equivocado.',4,'1',0,1),(256,4,4,15,22,4,4,'seleccion_1_4','beta3/14.jpg','Selecciona el dibujo que está equivocado.',4,'4',0,1),(257,4,4,15,23,4,5,'seleccion_1_4','beta3/14.jpg','Selecciona el dibujo que está equivocado.',4,'1',0,1),(258,4,4,15,24,4,6,'seleccion_1_4','beta3/14.jpg','Selecciona el dibujo que está equivocado.',4,'2',0,1),(266,4,5,17,1,1,1,'seleccion_1_5','beta3/16.jpg','Selecciona la opción que completa correctamente la matriz.',5,'1',0,1),(267,4,5,17,2,1,2,'seleccion_1_5','beta3/16.jpg','Selecciona la opción que completa correctamente la matriz.',5,'5',0,1),(268,4,5,17,3,1,3,'seleccion_1_5','beta3/16.jpg','Selecciona la opción que completa correctamente la matriz.',5,'2',0,1),(269,4,5,17,4,1,4,'seleccion_1_5','beta3/16.jpg','Selecciona la opción que completa correctamente la matriz.',5,'4',0,1),(270,4,5,17,5,1,5,'seleccion_1_5','beta3/16.jpg','Selecciona la opción que completa correctamente la matriz.',5,'1',0,1),(271,4,5,18,6,2,1,'seleccion_1_5','beta3/17.jpg','Selecciona la opción que completa correctamente la matriz.',5,'3',0,1),(272,4,5,18,7,2,2,'seleccion_1_5','beta3/17.jpg','Selecciona la opción que completa correctamente la matriz.',5,'2',0,1),(273,4,5,18,8,2,3,'seleccion_1_5','beta3/17.jpg','Selecciona la opción que completa correctamente la matriz.',5,'1',0,1),(274,4,5,18,9,2,4,'seleccion_1_5','beta3/17.jpg','Selecciona la opción que completa correctamente la matriz.',5,'4',0,1),(275,4,5,18,10,2,5,'seleccion_1_5','beta3/17.jpg','Selecciona la opción que completa correctamente la matriz.',5,'2',0,1),(276,4,5,19,11,3,1,'seleccion_1_5','beta3/18.jpg','Selecciona la opción que completa correctamente la matriz.',5,'5',0,1),(277,4,5,19,12,3,2,'seleccion_1_5','beta3/18.jpg','Selecciona la opción que completa correctamente la matriz.',5,'1',0,1),(278,4,5,19,13,3,3,'seleccion_1_5','beta3/18.jpg','Selecciona la opción que completa correctamente la matriz.',5,'4',0,1),(279,4,5,19,14,3,4,'seleccion_1_5','beta3/18.jpg','Selecciona la opción que completa correctamente la matriz.',5,'2',0,1),(280,4,5,19,15,3,5,'seleccion_1_5','beta3/18.jpg','Selecciona la opción que completa correctamente la matriz.',5,'5',0,1),(281,4,5,20,16,4,1,'seleccion_1_5','beta3/19.jpg','Selecciona la opción que completa correctamente la matriz.',5,'3',0,1),(282,4,5,20,17,4,2,'seleccion_1_5','beta3/19.jpg','Selecciona la opción que completa correctamente la matriz.',5,'4',0,1),(283,4,5,20,18,4,3,'seleccion_1_5','beta3/19.jpg','Selecciona la opción que completa correctamente la matriz.',5,'1',0,1),(284,4,5,20,19,4,4,'seleccion_1_5','beta3/19.jpg','Selecciona la opción que completa correctamente la matriz.',5,'5',0,1),(285,4,5,20,20,4,5,'seleccion_1_5','beta3/19.jpg','Selecciona la opción que completa correctamente la matriz.',5,'3',0,1),(286,4,5,21,21,5,1,'seleccion_1_5','beta3/20.jpg','Selecciona la opción que completa correctamente la matriz.',5,'1',0,1),(287,4,5,21,22,5,2,'seleccion_1_5','beta3/20.jpg','Selecciona la opción que completa correctamente la matriz.',5,'2',0,1),(288,4,5,21,23,5,3,'seleccion_1_5','beta3/20.jpg','Selecciona la opción que completa correctamente la matriz.',5,'3',0,1),(289,4,5,21,24,5,4,'seleccion_1_5','beta3/20.jpg','Selecciona la opción que completa correctamente la matriz.',5,'5',0,1),(290,4,5,21,25,5,5,'seleccion_1_5','beta3/20.jpg','Selecciona la opción que completa correctamente la matriz.',5,'1',0,1);
/*!40000 ALTER TABLE `reactivos_beta3` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `reactivos_raven`
--

DROP TABLE IF EXISTS `reactivos_raven`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `reactivos_raven` (
  `id_reactivo` int(11) NOT NULL AUTO_INCREMENT,
  `id_prueba_rh` int(11) NOT NULL,
  `serie` enum('A','B','C','D','E') NOT NULL,
  `numero` int(11) NOT NULL,
  `imagen` varchar(255) NOT NULL,
  `total_opciones` int(11) NOT NULL,
  `respuesta_correcta` int(11) NOT NULL,
  `activo` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id_reactivo`),
  UNIQUE KEY `uk_raven_reactivo` (`id_prueba_rh`,`serie`,`numero`)
) ENGINE=InnoDB AUTO_INCREMENT=61 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `reactivos_raven`
--

LOCK TABLES `reactivos_raven` WRITE;
/*!40000 ALTER TABLE `reactivos_raven` DISABLE KEYS */;
INSERT INTO `reactivos_raven` VALUES (1,3,'A',1,'raven/A/03.jpg',6,4,1),(2,3,'A',2,'raven/A/04.jpg',6,5,1),(3,3,'A',3,'raven/A/05.jpg',6,1,1),(4,3,'A',4,'raven/A/06.jpg',6,2,1),(5,3,'A',5,'raven/A/07.jpg',6,6,1),(6,3,'A',6,'raven/A/08.jpg',6,3,1),(7,3,'A',7,'raven/A/09.jpg',6,6,1),(8,3,'A',8,'raven/A/10.jpg',6,2,1),(9,3,'A',9,'raven/A/11.jpg',6,1,1),(10,3,'A',10,'raven/A/12.jpg',6,3,1),(11,3,'A',11,'raven/A/13.jpg',6,4,1),(12,3,'A',12,'raven/A/14.jpg',6,5,1),(13,3,'B',1,'raven/B/15.jpg',6,2,1),(14,3,'B',2,'raven/B/16.jpg',6,6,1),(15,3,'B',3,'raven/B/17.jpg',6,1,1),(16,3,'B',4,'raven/B/18.jpg',6,2,1),(17,3,'B',5,'raven/B/19.jpg',6,1,1),(18,3,'B',6,'raven/B/20.jpg',6,3,1),(19,3,'B',7,'raven/B/21.jpg',6,5,1),(20,3,'B',8,'raven/B/22.jpg',6,6,1),(21,3,'B',9,'raven/B/23.jpg',6,4,1),(22,3,'B',10,'raven/B/24.jpg',6,3,1),(23,3,'B',11,'raven/B/25.jpg',6,4,1),(24,3,'B',12,'raven/B/26.jpg',6,5,1),(25,3,'C',1,'raven/C/27.jpg',8,8,1),(26,3,'C',2,'raven/C/28.jpg',8,2,1),(27,3,'C',3,'raven/C/29.jpg',8,3,1),(28,3,'C',4,'raven/C/30.jpg',8,8,1),(29,3,'C',5,'raven/C/31.jpg',8,7,1),(30,3,'C',6,'raven/C/32.jpg',8,4,1),(31,3,'C',7,'raven/C/33.jpg',8,5,1),(32,3,'C',8,'raven/C/34.jpg',8,1,1),(33,3,'C',9,'raven/C/35.jpg',8,7,1),(34,3,'C',10,'raven/C/36.jpg',8,6,1),(35,3,'C',11,'raven/C/37.jpg',8,1,1),(36,3,'C',12,'raven/C/38.jpg',8,2,1),(37,3,'D',1,'raven/D/39.jpg',8,3,1),(38,3,'D',2,'raven/D/40.jpg',8,4,1),(39,3,'D',3,'raven/D/41.jpg',8,3,1),(40,3,'D',4,'raven/D/42.jpg',8,7,1),(41,3,'D',5,'raven/D/43.jpg',8,8,1),(42,3,'D',6,'raven/D/44.jpg',8,6,1),(43,3,'D',7,'raven/D/45.jpg',8,5,1),(44,3,'D',8,'raven/D/46.jpg',8,4,1),(45,3,'D',9,'raven/D/47.jpg',8,1,1),(46,3,'D',10,'raven/D/48.jpg',8,2,1),(47,3,'D',11,'raven/D/49.jpg',8,5,1),(48,3,'D',12,'raven/D/50.jpg',8,6,1),(49,3,'E',1,'raven/E/51.jpg',8,7,1),(50,3,'E',2,'raven/E/52.jpg',8,6,1),(51,3,'E',3,'raven/E/53.jpg',8,8,1),(52,3,'E',4,'raven/E/54.jpg',8,2,1),(53,3,'E',5,'raven/E/55.jpg',8,1,1),(54,3,'E',6,'raven/E/56.jpg',8,5,1),(55,3,'E',7,'raven/E/57.jpg',8,1,1),(56,3,'E',8,'raven/E/58.jpg',8,6,1),(57,3,'E',9,'raven/E/59.jpg',8,3,1),(58,3,'E',10,'raven/E/60.jpg',8,2,1),(59,3,'E',11,'raven/E/61.jpg',8,4,1),(60,3,'E',12,'raven/E/62.jpg',8,5,1);
/*!40000 ALTER TABLE `reactivos_raven` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `recomendaciones_canalizacion`
--

DROP TABLE IF EXISTS `recomendaciones_canalizacion`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `recomendaciones_canalizacion` (
  `id_recomendacion` int(11) NOT NULL AUTO_INCREMENT,
  `id_empleado` int(11) NOT NULL,
  `origen` enum('nom035','estres_laboral','otra_prueba') NOT NULL,
  `id_referencia_origen` int(11) NOT NULL,
  `nivel_recomendacion` enum('no_requiere','seguimiento','canalizacion') NOT NULL,
  `resultado_detectado` varchar(255) DEFAULT NULL,
  `preevaluacion_ia` text DEFAULT NULL,
  `factores_detectados` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`factores_detectados`)),
  `revisada_rh` tinyint(1) NOT NULL DEFAULT 0,
  `decision_rh` enum('pendiente','canalizar','seguimiento','no_canalizar') NOT NULL DEFAULT 'pendiente',
  `id_usuario_revision` int(11) DEFAULT NULL,
  `observacion_rh` text DEFAULT NULL,
  `fecha_deteccion` datetime NOT NULL DEFAULT current_timestamp(),
  `fecha_revision` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_recomendacion`),
  KEY `idx_rec_empleado` (`id_empleado`),
  KEY `idx_rec_nivel` (`nivel_recomendacion`),
  KEY `idx_rec_revisada` (`revisada_rh`),
  KEY `fk_rec_usuario_revision` (`id_usuario_revision`),
  CONSTRAINT `fk_rec_empleado` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id_empleado`) ON DELETE CASCADE,
  CONSTRAINT `fk_rec_usuario_revision` FOREIGN KEY (`id_usuario_revision`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `recomendaciones_canalizacion`
--

LOCK TABLES `recomendaciones_canalizacion` WRITE;
/*!40000 ALTER TABLE `recomendaciones_canalizacion` DISABLE KEYS */;
INSERT INTO `recomendaciones_canalizacion` VALUES (3,3,'nom035',6,'canalizacion','La aplicación cumple al menos uno de los criterios de la Guía de Referencia I para requerir atención clínica.',NULL,'[{\"nombre\":\"Acontecimiento traumático severo\",\"respuestas_si\":2},{\"nombre\":\"Recuerdos persistentes\",\"respuestas_si\":2},{\"nombre\":\"Evitación\",\"respuestas_si\":5},{\"nombre\":\"Afectación\",\"respuestas_si\":5}]',1,'canalizar',19,NULL,'2026-10-30 09:52:52','2026-11-03 13:10:34','2026-10-30 15:58:25','2026-11-03 19:10:34'),(4,3,'otra_prueba',5,'no_requiere','El resultado no activa por sí mismo una recomendación preventiva adicional basada en el punto de referencia del instrumento. En términos prácticos, el nivel global de bienestar reportado no muestra una señal que requiera seguimiento adicional únicamente p','PRE-EVALUACIÓN IA\n\n**Interpretación:**\nEl WHO-5 Índice de Bienestar indica que el puntaje global de la persona (13/25) no se encuentra por debajo del punto de referencia para sugerir una revisión adicional. Se reporta una frecuencia suficiente de experiencias positivas recientes relacionadas con su bienestar general.\n\n**Atención sugerida:**\nRecursos Humanos puede integrar este resultado con otras fuentes de información laboral relevantes, según sea necesario. El WHO-5 por sí mismo no activa una recomendación preventiva adicional basada en su punto de referencia.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión administrativa final corresponde a Recursos Humanos.','{\"tipo_fuente\":\"evaluacion_rh\",\"id_resultado\":5,\"id_habilitacion\":8,\"id_prueba_rh\":5,\"prueba\":\"WHO-5 Índice de Bienestar\",\"descripcion\":\"Tamizaje preventivo breve de bienestar mental durante las últimas dos semanas. No constituye diagnóstico.\",\"version\":\"WHO-5\",\"categoria\":\"bienestar\",\"puntaje_total\":13,\"resultado_texto\":\"WHO-5 Índice de Bienestar\\n\\nPuntaje bruto: 13/25\\nPuntaje porcentual: 52/100\\n\\nEl resultado no se encuentra por debajo del punto de referencia utilizado para sugerir una revisión adicional.\\n\\nEn términos sencillos, la persona reportó una frecuencia suficiente\",\"interpretacion\":\"El resultado del WHO-5 no se encuentra por debajo del punto de referencia utilizado para sugerir una valoración adicional. En términos sencillos, la persona reportó una frecuencia suficiente de experiencias positivas relacionadas con su bienestar reciente, como buen ánimo, tranquilidad, energía, descanso e interés en sus actividades cotidianas. Esto no descarta dificultades específicas y debe interpretarse únicamente como información de tamizaje, no como diagnóstico.\",\"interpretacion_laboral\":\"El resultado no activa por sí mismo una recomendación preventiva adicional basada en el punto de referencia del instrumento. En términos prácticos, el nivel global de bienestar reportado no muestra una señal que requiera seguimiento adicional únicamente por WHO-5. Recursos Humanos puede integrarlo con otras fuentes de información laboral cuando sea necesario.\",\"ia_proveedor\":\"gemini\",\"ia_modelo\":\"gemini\",\"fecha_preevaluacion_ia\":\"2026-10-30T18:57:42.000Z\"}',1,'no_canalizar',19,'ninguno','2026-10-30 12:57:36','2026-11-03 13:08:42','2026-11-03 18:57:27','2026-11-05 19:25:09'),(5,3,'otra_prueba',4,'no_requiere','El resultado no activa por sí mismo una recomendación preventiva adicional basada en el punto de corte del instrumento. Recursos Humanos puede integrarlo con otras fuentes de información laboral cuando sea necesario.','PRE-EVALUACIÓN IA\n\n**Interpretación:**\nEl puntaje obtenido en el WHO-5 (17/25) indica que el bienestar general no se encuentra por debajo del punto de referencia que activaría una revisión adicional según este instrumento de tamizaje. No se identifica una señal de alerta inmediata basada en este corte específico.\n\n**Atención sugerida:**\nRecursos Humanos puede integrar este resultado con otras fuentes de información laboral disponibles para tener una perspectiva completa del bienestar del colaborador. La periodicidad de esta evaluación permite monitorear tendencias en el tiempo.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión final corresponde a Recursos Humanos.','{\"tipo_fuente\":\"evaluacion_rh\",\"id_resultado\":4,\"id_habilitacion\":7,\"id_prueba_rh\":5,\"prueba\":\"WHO-5 Índice de Bienestar\",\"descripcion\":\"Tamizaje preventivo breve de bienestar mental durante las últimas dos semanas. No constituye diagnóstico.\",\"version\":\"WHO-5\",\"categoria\":\"bienestar\",\"puntaje_total\":17,\"resultado_texto\":\"WHO-5 Índice de Bienestar\\n\\nPuntaje bruto: 17/25\\nPuntaje porcentual: 68/100\\n\\nEl resultado no se encuentra por debajo del punto de referencia utilizado para sugerir una revisión adicional.\\n\\nEste resultado corresponde a un instrumento de tamizaje y no consti\",\"interpretacion\":\"El resultado del WHO-5 no se encuentra por debajo del punto de referencia utilizado para sugerir una valoración adicional. Debe interpretarse como información de tamizaje sobre bienestar y no como diagnóstico.\",\"interpretacion_laboral\":\"El resultado no activa por sí mismo una recomendación preventiva adicional basada en el punto de corte del instrumento. Recursos Humanos puede integrarlo con otras fuentes de información laboral cuando sea necesario.\",\"ia_proveedor\":\"gemini\",\"ia_modelo\":\"gemini\",\"fecha_preevaluacion_ia\":\"2026-10-30T18:56:26.000Z\"}',1,'no_canalizar',19,'ninguno','2026-10-30 12:56:20','2026-11-03 13:08:49','2026-11-03 18:57:27','2026-11-05 19:25:09'),(6,3,'otra_prueba',3,'seguimiento','El tamizaje muestra indicadores que ameritan revisión preventiva. Recursos Humanos puede valorar seguimiento y, cuando corresponda, ofrecer opciones voluntarias de apoyo conforme a las políticas internas.','PRE-EVALUACIÓN IA\n\n**Interpretación:**\nEl WHO-5 Índice de Bienestar, un instrumento de tamizaje, muestra un puntaje de 12/25, que se encuentra por debajo del punto de referencia establecido. Esto sugiere la presencia de indicadores de bienestar reducido dentro de la escala del instrumento.\n\n**Atención sugerida:**\nRecursos Humanos puede considerar la valoración de un seguimiento preventivo del bienestar del evaluado. Se sugiere evaluar la pertinencia de ofrecer opciones voluntarias de apoyo, conforme a las políticas internas de la organización.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión administrativa final corresponde a Recursos Humanos.','{\"tipo_fuente\":\"evaluacion_rh\",\"id_resultado\":3,\"id_habilitacion\":6,\"id_prueba_rh\":5,\"prueba\":\"WHO-5 Índice de Bienestar\",\"descripcion\":\"Tamizaje preventivo breve de bienestar mental durante las últimas dos semanas. No constituye diagnóstico.\",\"version\":\"WHO-5\",\"categoria\":\"bienestar\",\"puntaje_total\":12,\"resultado_texto\":\"WHO-5 Índice de Bienestar\\n\\nPuntaje bruto: 12/25\\nPuntaje porcentual: 48/100\\n\\nEl resultado se encuentra por debajo del punto de referencia utilizado para sugerir una revisión adicional del bienestar.\\n\\nEste resultado corresponde a un instrumento de tamizaje \",\"interpretacion\":\"El resultado del WHO-5 muestra indicadores de bienestar reducido dentro del instrumento de tamizaje. La puntuación sugiere que conviene realizar una valoración adicional del bienestar, sin que esto represente por sí mismo un diagnóstico.\",\"interpretacion_laboral\":\"El tamizaje muestra indicadores que ameritan revisión preventiva. Recursos Humanos puede valorar seguimiento y, cuando corresponda, ofrecer opciones voluntarias de apoyo conforme a las políticas internas.\",\"ia_proveedor\":\"gemini\",\"ia_modelo\":\"gemini\",\"fecha_preevaluacion_ia\":\"2026-10-30T18:49:46.000Z\"}',1,'no_canalizar',19,'no','2026-10-30 12:49:41','2026-11-03 13:08:58','2026-11-03 18:57:27','2026-11-05 19:25:09'),(7,3,'otra_prueba',2,'seguimiento','Puntaje bruto obtenido: 9','PRE-EVALUACIÓN IA\n\n**Interpretación:**\nSe aplicó el WHO-5 Índice de Bienestar, obteniendo un puntaje bruto de 9. Para este instrumento, las interpretaciones técnicas y laborales no están configuradas, por lo que no es posible extraer conclusiones definitivas a partir de este resultado.\n\n**Atención sugerida:**\nDado que la interpretación configurada no está disponible, se sugiere a Recursos Humanos considerar este puntaje bruto en su contexto, junto con cualquier otra información relevante. Puede ser útil revisar evaluaciones periódicas previas o futuras para identificar patrones.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión final corresponde a Recursos Humanos.','{\"tipo_fuente\":\"evaluacion_rh\",\"id_resultado\":2,\"id_habilitacion\":4,\"id_prueba_rh\":5,\"prueba\":\"WHO-5 Índice de Bienestar\",\"descripcion\":\"Tamizaje preventivo breve de bienestar mental durante las últimas dos semanas. No constituye diagnóstico.\",\"version\":\"WHO-5\",\"categoria\":\"bienestar\",\"puntaje_total\":9,\"resultado_texto\":\"Puntaje bruto obtenido: 9\",\"interpretacion\":null,\"interpretacion_laboral\":null,\"ia_proveedor\":\"gemini\",\"ia_modelo\":\"gemini\",\"fecha_preevaluacion_ia\":\"2026-10-30T18:47:19.000Z\"}',1,'canalizar',19,NULL,'2026-10-30 12:47:13','2026-11-03 12:58:45','2026-11-03 18:57:27','2026-11-05 19:25:09'),(8,3,'otra_prueba',1,'canalizacion','El tamizaje muestra indicadores moderados que ameritan revisión preventiva. Recursos Humanos puede valorar la canalización voluntaria con un profesional.','PRE-EVALUACIÓN IA\n\n**Interpretación:**\nBasado en el tamizaje preventivo GAD-7, el resultado indica indicadores moderados dentro de la escala de puntuación del instrumento. Esta herramienta de cribado no constituye un diagnóstico médico o psicológico.\n\n**Atención sugerida:**\nRecursos Humanos puede considerar la revisión preventiva de estos indicadores moderados. Se sugiere valorar la canalización voluntaria con un profesional, según las políticas internas.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no es un diagnóstico médico o psicológico, y la decisión final corresponde a Recursos Humanos.','{\"tipo_fuente\":\"evaluacion_rh\",\"id_resultado\":1,\"id_habilitacion\":3,\"id_prueba_rh\":6,\"prueba\":\"GAD-7 Ansiedad\",\"descripcion\":\"Tamizaje preventivo de síntomas relacionados con ansiedad durante las últimas dos semanas. No constituye diagnóstico.\",\"version\":\"GAD-7\",\"categoria\":\"ansiedad\",\"puntaje_total\":11,\"resultado_texto\":\"GAD-7 — Tamizaje preventivo\\n\\nPuntaje técnico: 11/21\\nResultado preventivo: Indicadores moderados\\n\\nEl resultado corresponde a un instrumento de tamizaje.\\nNo constituye diagnóstico médico o psicológico.\",\"interpretacion\":\"El resultado del GAD-7 corresponde a indicadores moderados dentro de la escala de puntuación del instrumento. El resultado debe utilizarse únicamente como tamizaje preventivo y no como diagnóstico.\",\"interpretacion_laboral\":\"El tamizaje muestra indicadores moderados que ameritan revisión preventiva. Recursos Humanos puede valorar la canalización voluntaria con un profesional.\",\"ia_proveedor\":\"gemini\",\"ia_modelo\":\"gemini\",\"fecha_preevaluacion_ia\":\"2026-10-30T18:37:40.000Z\"}',1,'no_canalizar',19,'no','2026-10-30 12:37:35','2026-11-03 13:09:53','2026-11-03 18:57:27','2026-11-05 19:25:09'),(9,3,'otra_prueba',6,'canalizacion','El tamizaje muestra indicadores moderados que ameritan revisión preventiva. Recursos Humanos puede valorar la canalización voluntaria con un profesional.','PRE-EVALUACIÓN IA\n\n**Interpretación:**\nEl tamizaje GAD-7, realizado de forma periódica, indica indicadores moderados de ansiedad. Este resultado es preventivo y no constituye un diagnóstico médico o psicológico.\n\n**Atención sugerida:**\nRecursos Humanos podría considerar una revisión preventiva y valorar la canalización voluntaria con un profesional para un seguimiento adecuado.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión administrativa final corresponde a Recursos Humanos.','{\"tipo_fuente\":\"evaluacion_rh\",\"id_resultado\":6,\"id_habilitacion\":10,\"id_prueba_rh\":6,\"prueba\":\"GAD-7 Ansiedad\",\"descripcion\":\"Tamizaje preventivo de síntomas relacionados con ansiedad durante las últimas dos semanas. No constituye diagnóstico.\",\"version\":\"GAD-7\",\"categoria\":\"ansiedad\",\"puntaje_total\":13,\"resultado_texto\":\"GAD-7 — Tamizaje preventivo\\n\\nPuntaje técnico: 13/21\\nResultado preventivo: Indicadores moderados\\n\\nEl resultado corresponde a un instrumento de tamizaje.\\nNo constituye diagnóstico médico o psicológico.\",\"interpretacion\":\"El resultado del GAD-7 corresponde a indicadores moderados dentro de la escala de puntuación del instrumento. El resultado debe utilizarse únicamente como tamizaje preventivo y no como diagnóstico.\",\"interpretacion_laboral\":\"El tamizaje muestra indicadores moderados que ameritan revisión preventiva. Recursos Humanos puede valorar la canalización voluntaria con un profesional.\",\"ia_proveedor\":\"gemini\",\"ia_modelo\":\"gemini\",\"fecha_preevaluacion_ia\":\"2026-11-03T21:42:06.000Z\"}',1,'canalizar',19,'ok','2026-11-03 15:41:59','2026-11-03 15:45:10','2026-11-03 21:44:54','2026-11-05 19:25:09'),(10,4,'nom035',8,'canalizacion','La aplicación cumple al menos uno de los criterios de la Guía de Referencia I para requerir atención clínica.',NULL,'[{\"nombre\":\"Acontecimiento traumático severo\",\"respuestas_si\":2},{\"nombre\":\"Recuerdos persistentes\",\"respuestas_si\":1},{\"nombre\":\"Evitación\",\"respuestas_si\":4},{\"nombre\":\"Afectación\",\"respuestas_si\":1}]',0,'pendiente',NULL,NULL,'2026-11-12 14:30:05',NULL,'2026-11-12 20:31:35','2026-11-12 20:31:35'),(11,4,'otra_prueba',7,'canalizacion','El tamizaje muestra indicadores elevados que ameritan atención preventiva. Se recomienda que Recursos Humanos valore oportunamente la canalización con un profesional.','PRE-EVALUACIÓN IA\n\n**Interpretación:**\nEl tamizaje preventivo de bienestar GAD-7 para ansiedad indica la presencia de indicadores elevados según la escala de puntuación del instrumento. Este resultado se utiliza exclusivamente como tamizaje.\n\n**Atención sugerida:**\nRecursos Humanos debe considerar que los indicadores elevados ameritan atención preventiva. Se recomienda valorar la canalización con un profesional para una revisión adecuada.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión final corresponde a Recursos Humanos.','{\"tipo_fuente\":\"evaluacion_rh\",\"id_resultado\":7,\"id_habilitacion\":11,\"id_prueba_rh\":6,\"prueba\":\"GAD-7 Ansiedad\",\"descripcion\":\"Tamizaje preventivo de síntomas relacionados con ansiedad durante las últimas dos semanas. No constituye diagnóstico.\",\"version\":\"GAD-7\",\"categoria\":\"ansiedad\",\"puntaje_total\":15,\"resultado_texto\":\"GAD-7 — Tamizaje preventivo\\n\\nPuntaje técnico: 15/21\\nResultado preventivo: Indicadores elevados\\n\\nEl resultado corresponde a un instrumento de tamizaje.\\nNo constituye diagnóstico médico o psicológico.\",\"interpretacion\":\"El resultado del GAD-7 corresponde a indicadores elevados dentro de la escala de puntuación del instrumento. El resultado debe utilizarse únicamente como tamizaje preventivo y no como diagnóstico.\",\"interpretacion_laboral\":\"El tamizaje muestra indicadores elevados que ameritan atención preventiva. Se recomienda que Recursos Humanos valore oportunamente la canalización con un profesional.\",\"ia_proveedor\":\"gemini\",\"ia_modelo\":\"gemini\",\"fecha_preevaluacion_ia\":\"2026-11-12T20:06:16.000Z\"}',1,'canalizar',36,NULL,'2026-11-12 14:06:10','2026-11-12 14:31:46','2026-11-12 20:31:35','2026-11-12 23:07:46');
/*!40000 ALTER TABLE `recomendaciones_canalizacion` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `reportes_ia`
--

DROP TABLE IF EXISTS `reportes_ia`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `reportes_ia` (
  `id_reporte` int(11) NOT NULL AUTO_INCREMENT,
  `id_paciente` int(11) NOT NULL,
  `id_sesion` int(11) DEFAULT NULL,
  `fecha` timestamp NOT NULL DEFAULT current_timestamp(),
  `contenido` longtext NOT NULL,
  `ruta_pdf` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id_reporte`)
) ENGINE=InnoDB AUTO_INCREMENT=27 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `reportes_ia`
--

LOCK TABLES `reportes_ia` WRITE;
/*!40000 ALTER TABLE `reportes_ia` DISABLE KEYS */;
INSERT INTO `reportes_ia` VALUES (1,1,1,'2026-09-03 03:29:57','PREANÁLISIS CLÍNICO\n\nPaciente\nSUSANA, 25 años, Femenino.\n\nInformación relevante\n*   Paciente refiere dificultades para conciliar y mantener el sueño desde hace aproximadamente dos meses, las cuales han aumentado en periodos de preocupación y responsabilidades.\n*   Estas dificultades se asocian a cansancio diurno, dificultad ocasional para concentrarse y pensamientos recurrentes al momento de acostarse.\n*   Antecedentes de problemas para dormir, dificultad para expresar emociones, tristeza y enojo. Se observan indicadores de dificultades del sueño y posibles factores emocionales asociados.\n\nEvaluación y pruebas\nNo se registraron pruebas en esta sesión.\n\nAspectos para revisar\n*   La evolución de las dificultades de sueño, incluyendo la frecuencia de despertares y la dificultad para relajarse.\n*   El nivel de preocupación y los factores desencadenantes asociados a la rutina diaria.\n*   La efectividad de las estrategias implementadas para disminuir pensamientos recurrentes y mejorar hábitos de sueño.\n\nRecomendaciones de seguimiento\n*   Continuar con la valoración y seguimiento profesional de la paciente.\n*   Dar seguimiento a la evolución de los síntomas (cansancio, concentración) y hábitos de sueño.\n*   Revisar y ajustar las estrategias de relajación y hábitos de sueño saludables.\n\nMultimedia\nSe registró material multimedia: Grabación de sesión.\n\nConclusión preliminar\nSe conoce que la paciente experimenta dificultades de sueño ligadas a preocupaciones y pensamientos recurrentes, que afectan su concentración y energía. Es fundamental un seguimiento continuo para observar la evolución de estos síntomas y la respuesta a las estrategias propuestas. Conviene revisar periódicamente los hábitos de sueño y el manejo de la preocupación.\n\nNOTA:\nEste preanálisis es generado mediante inteligencia artificial. No constituye un diagnóstico y debe ser revisado por el psicólogo responsable.','/uploads/pdfs/reporte_1.pdf'),(2,1,2,'2026-09-05 02:37:46','PREANÁLISIS CLÍNICO\n\nPaciente\nSusana, 25 años, Femenino.\n\nInformación relevante\n1. La paciente refiere dificultades para conciliar y mantener el sueño, con despertares ocasionales, especialmente durante periodos de mayor carga de actividades o preocupaciones.\n2. Manifiesta cansancio diurno, dificultad ocasional para concentrarse, pensamientos recurrentes al momento de acostarse y dificultad para relajarse.\n3. Las dificultades de sueño se han intensificado en los últimos dos meses, asociadas a responsabilidades laborales y personales.\n\nEvaluación y pruebas\nNo se registraron pruebas en esta sesión.\n\nAspectos para revisión profesional\n1. Profundizar en los patrones específicos de los problemas de sueño y su impacto en el funcionamiento diario.\n2. Explorar las estrategias actuales de afrontamiento frente a la preocupación y las responsabilidades.\n3. Evaluar la adherencia y efectividad de los hábitos de sueño saludables y las estrategias de relajación recomendadas previamente.\n\nEvolución y antecedentes relevantes\nLa paciente presenta antecedentes de problemas para dormir y dificultad para expresar emociones, con periodos de preocupación y dificultad para relajarse desde la adolescencia. En la etapa adulta, las responsabilidades laborales y personales han incrementado sus niveles de preocupación, lo que se relaciona con el aumento de sus dificultades para dormir en los últimos meses, generando cansancio diurno y problemas de concentración.\n\nRecomendaciones de seguimiento\n1. Continuar con la valoración y seguimiento de la evolución de las dificultades del sueño y sus factores asociados.\n2. Revisar la implementación y respuesta a las estrategias de relajación y los hábitos de sueño establecidos.\n3. Evaluar el impacto de la gestión de responsabilidades y preocupaciones en el bienestar de la paciente.\n\nMultimedia\nNo se registró multimedia relevante.\n\nConclusión preliminar\nSe dispone de información sobre las dificultades de sueño de la paciente, las cuales se asocian a la preocupación y el aumento de responsabilidades. Es crucial continuar el seguimiento para valorar la evolución de estos indicadores y la efectividad de las estrategias implementadas, así como profundizar en los factores emocionales asociados durante el cierre clínico.\n\nNOTA FINAL OBLIGATORIA:\nEste preanálisis fue generado mediante inteligencia artificial como herramienta de apoyo. No constituye un diagnóstico y debe ser revisado por el psicólogo responsable.',NULL),(3,1,2,'2026-09-05 02:44:28','PREANÁLISIS CLÍNICO\n\nPaciente\nSusana, 25 años, Femenino.\n\nInformación relevante\n*   La paciente refiere dificultades para conciliar y mantener el sueño desde hace aproximadamente dos meses, las cuales han aumentado en periodos de preocupación y carga de responsabilidades.\n*   Experimenta pensamientos recurrentes al acostarse, dificultad para relajarse y presenta cansancio diurno y ocasional dificultad para concentrarse.\n*   Previamente, se registraron antecedentes de problemas para dormir, tristeza y enojo, además de una tendencia a la dificultad para expresar emociones.\n\nEvaluación y pruebas\nNo se registraron pruebas en esta sesión.\n\nAspectos para revisión profesional\n*   Persistencia y evolución de las dificultades para conciliar y mantener el sueño, así como su impacto en el funcionamiento diario.\n*   Identificación de los factores específicos que contribuyen a los pensamientos recurrentes y la dificultad para relajarse antes de dormir.\n*   Revisión de la implementación y efectividad de los hábitos de sueño saludables y estrategias de relajación recomendadas inicialmente.\n\nEvolución y antecedentes relevantes\nDurante la adolescencia, la paciente comenzó a experimentar periodos de preocupación y dificultad para relajarse, que se intensificaron en la etapa adulta con mayores responsabilidades laborales y personales. Actualmente, las dificultades para dormir han aumentado en los últimos meses, generando cansancio y problemas de concentración, lo cual se alinea con una historia de problemas para dormir y dificultades para expresar emociones.\n\nRecomendaciones de seguimiento\n*   Continuar con la valoración y seguimiento para conocer la evolución de los indicadores de sueño y preocupación.\n*   Evaluar la adherencia y respuesta a las estrategias de relajación y hábitos de sueño saludables.\n*   Revisar los factores asociados a los pensamientos recurrentes antes de dormir.\n\nMultimedia\nNo se registró multimedia relevante.\n\nConclusión preliminar\nSe dispone de información sobre las dificultades de sueño de la paciente, sus antecedentes y las recomendaciones iniciales. Es necesario revisar la evolución de estos aspectos, evaluar la respuesta a las estrategias propuestas y profundizar en los factores emocionales asociados durante el cierre clínico.\n\nNOTA FINAL OBLIGATORIA:\nEste preanálisis fue generado mediante inteligencia artificial como herramienta de apoyo. No constituye un diagnóstico y debe ser revisado por el psicólogo responsable.',NULL),(4,1,2,'2026-09-05 05:00:28','PREANÁLISIS CLÍNICO\n\nPaciente\nSusana, 25 años, Femenino.\n\nInformación relevante\n*   Dificultades para conciliar y mantener el sueño, exacerbadas por periodos de preocupación y carga de responsabilidades laborales y personales.\n*   Experimenta cansancio diurno y ocasional dificultad para concentrarse, acompañado de pensamientos recurrentes antes de dormir.\n*   Resultados de la prueba GAD-7 indican ansiedad moderada con un puntaje de 13.\n\nEvaluación y pruebas\n*   Prueba GAD-7: Puntaje 13, Interpretación registrada: Ansiedad moderada.\n\nAspectos para revisión profesional\n*   Patrones de sueño alterados, incluyendo dificultades para conciliar y mantener el sueño, y sus factores desencadenantes actuales.\n*   Nivel de preocupación y pensamientos recurrentes asociados a la dificultad para relajarse antes de dormir.\n*   Impacto de las dificultades del sueño en el funcionamiento diurno, como el cansancio y la concentración.\n\nEvolución y antecedentes relevantes\n*   Desde la adolescencia, la paciente ha experimentado periodos de preocupación y dificultad para relajarse, incrementando en la etapa adulta.\n*   Se registran antecedentes de \"problemas para dormir\", dificultad para expresar emociones, tristeza y enojo.\n*   Actualmente, refiere un aumento de sus dificultades para dormir en los últimos meses, lo que le ha generado cansancio y dificultad de concentración.\n\nRecomendaciones de seguimiento\n*   Valorar la evolución de los hábitos de sueño y la respuesta a las estrategias de relajación establecidas.\n*   Dar seguimiento a la disminución de pensamientos recurrentes y preocupaciones antes de dormir.\n*   Revisar la progresión del nivel de preocupación y su impacto en el bienestar general de la paciente.\n\nMultimedia\nNo se registró multimedia relevante.\n\nConclusión preliminar\nSe dispone de información sobre las dificultades de sueño de la paciente, sus niveles de ansiedad moderada y antecedentes de preocupación. Es fundamental revisar la eficacia de las estrategias implementadas y la evolución de los síntomas reportados. Se sugiere profundizar en la relación entre las preocupaciones, la regulación emocional y los patrones de sueño durante el cierre clínico.\n\nEste preanálisis fue generado mediante inteligencia artificial como herramienta de apoyo. No constituye un diagnóstico y debe ser revisado por el psicólogo responsable.','/uploads/pdfs/reporte_4.pdf'),(5,1,6,'2026-09-07 18:03:17','PREANÁLISIS CLÍNICO\n\nPaciente\nSusana, 25 años, Femenino.\n\nInformación relevante\n*   La paciente refiere dificultades para conciliar y mantener el sueño, que han aumentado en los últimos meses y se asocian a periodos de preocupación y carga de responsabilidades.\n*   Experimenta pensamientos recurrentes al momento de acostarse, dificultad para relajarse y sensación de cansancio diurno, con dificultad ocasional para concentrarse.\n*   El puntaje de la prueba GAD-7 indica ansiedad moderada.\n\nEvaluación y pruebas\n*   Prueba: GAD-7\n    Puntaje: 13\n    Interpretación registrada: Ansiedad moderada\n\nAspectos para revisión profesional\n*   Profundizar en los factores asociados a las dificultades para conciliar y mantener el sueño.\n*   Explorar los pensamientos recurrentes y las estrategias de relajación implementadas.\n*   Revisar los indicadores de ansiedad moderada y su impacto en el bienestar diario.\n\nEvolución y antecedentes relevantes\nLa paciente presenta antecedentes de problemas para dormir y dificultad para expresar emociones. Desde la adolescencia, ha experimentado periodos de preocupación y dificultad para relajarse, lo que se ha intensificado en la adultez con mayores responsabilidades. Actualmente, las dificultades de sueño son más marcadas, generando cansancio y problemas de concentración.\n\nRecomendaciones de seguimiento\n*   Continuar con la valoración y seguimiento de los hábitos de sueño y factores emocionales asociados.\n*   Revisar la implementación y efectividad de estrategias de relajación para disminuir pensamientos recurrentes.\n*   Evaluar la evolución de los indicadores de ansiedad y su impacto en la calidad de vida.\n\nMultimedia\nNo se registró multimedia relevante.\n\nConclusión preliminar\nSe cuenta con información sobre las dificultades de sueño de la paciente, los pensamientos recurrentes y un indicador de ansiedad moderada. Es importante revisar la progresión de sus síntomas, la efectividad de las estrategias implementadas y profundizar en la relación entre sus preocupaciones y los patrones de sueño durante el cierre clínico.\n\nEste preanálisis fue generado mediante inteligencia artificial como herramienta de apoyo. No constituye un diagnóstico y debe ser revisado por el psicólogo responsable.',NULL),(6,1,8,'2026-09-07 19:04:04','PREANÁLISIS CLÍNICO\n\nPaciente\nSUSANA, 25 años, Femenino.\n\nInformación relevante\n*   Paciente refiere dificultades para conciliar y mantener el sueño desde hace aproximadamente dos meses, exacerbándose con la preocupación y responsabilidades.\n*   Presenta cansancio diurno, dificultad ocasional para concentrarse y pensamientos recurrentes al momento de acostarse.\n*   La prueba GAD-7 de esta sesión arrojó un puntaje de 12, con una interpretación registrada de \"Ansiedad moderada\".\n\nEvaluación y pruebas\n*   Prueba: GAD-7\n    Puntaje: 12\n    Interpretación registrada: Ansiedad moderada\n\nAspectos para revisión profesional\n*   Dificultades persistentes en el sueño y patrones de pensamientos recurrentes asociados a la preocupación.\n*   La puntuación del GAD-7 sugiere un nivel de ansiedad que requiere revisión profesional en el contexto de sus síntomas de sueño.\n*   Factores asociados a la rutina diaria y la capacidad de relajación como áreas pendientes de evaluación.\n\nEvolución y antecedentes relevantes\nLa paciente presenta antecedentes de problemas para dormir y dificultad para expresar emociones. Desde la adolescencia, ha experimentado periodos de preocupación. Actualmente, sus dificultades para dormir han aumentado en los últimos meses, generando cansancio y problemas de concentración. La evaluación inicial recomendó establecer hábitos de sueño saludables y estrategias de relajación.\n\nRecomendaciones de seguimiento\n*   Continuar con la valoración y seguimiento de la evolución de los indicadores de sueño y preocupación.\n*   Revisar la implementación y efectividad de las estrategias de relajación y los hábitos de sueño establecidos.\n*   Evaluar la relación entre los niveles de ansiedad y las dificultades de sueño de la paciente.\n\nMultimedia\nNo se registró multimedia relevante.\n\nConclusión preliminar\nSe conoce que la paciente experimenta dificultades de sueño asociadas a preocupaciones y presenta indicadores de ansiedad moderada. La información sobre la evolución de los síntomas y la efectividad de las estrategias previas requiere mayor detalle para un cierre clínico. Es crucial revisar la interconexión entre la ansiedad y los patrones de sueño durante la sesión.\n\nEste preanálisis fue generado mediante inteligencia artificial como herramienta de apoyo. No constituye un diagnóstico y debe ser revisado por el psicólogo responsable.',NULL),(7,1,9,'2026-09-07 19:33:49','PREANÁLISIS CLÍNICO\n\nPaciente\nSUSANA, 25 años, Femenino.\n\nInformación relevante\n*   Paciente refiere dificultades para conciliar y mantener el sueño desde hace aproximadamente dos meses, con un aumento durante periodos de preocupación y carga de responsabilidades.\n*   Manifiesta pensamientos recurrentes al acostarse, dificultad para relajarse, cansancio diurno y ocasional dificultad para concentrarse.\n*   La Escala de Estrés Percibido (PSS-14) aplicada en esta sesión arrojó un puntaje de 47, interpretado como estrés alto.\n\nEvaluación y pruebas\n*   Prueba: Escala de Estrés Percibido (PSS-14)\n    Puntaje: 47\n    Interpretación registrada: Estrés alto\n\nAspectos para revisión profesional\n*   Persistencia de dificultades en la conciliación y mantenimiento del sueño, asociadas a preocupaciones y pensamientos recurrentes.\n*   Elevado nivel de estrés percibido, lo que podría estar influyendo en las dificultades del sueño y la concentración.\n*   La dificultad para expresar emociones y los antecedentes de tristeza y enojo como posibles factores a explorar.\n\nEvolución y antecedentes relevantes\nLa paciente presenta antecedentes de problemas para dormir y periodos de preocupación desde la adolescencia, los cuales se intensificaron en la etapa adulta. Inicialmente, se identificaron dificultades para conciliar y mantener el sueño, cansancio diurno y pensamientos recurrentes, recomendándose establecer hábitos de sueño saludables y estrategias de relajación. También se registra una dificultad para expresar sus emociones y antecedentes de tristeza y enojo.\n\nRecomendaciones de seguimiento\n*   Continuar con la valoración y seguimiento de la evolución de las dificultades de sueño y los indicadores asociados.\n*   Revisar la adherencia y efectividad de los hábitos de sueño saludables y horarios regulares de descanso.\n*   Evaluar el progreso en la aplicación de estrategias de relajación para disminuir pensamientos recurrentes antes de dormir.\n\nMultimedia\nExiste un archivo de video registrado como \"Grabación de sesión\".\n\nConclusión preliminar\nSe dispone de información sobre las dificultades de sueño de la paciente, factores asociados como el estrés y preocupaciones, y un antecedente de problemas similares desde la adolescencia. Falta información sobre la evolución de las estrategias de relajación y hábitos de sueño previamente recomendados. Convendría revisar la intensidad de los pensamientos recurrentes, las estrategias de afrontamiento del estrés y la adherencia a las recomendaciones iniciales durante el cierre clínico.\n\nEste preanálisis fue generado mediante inteligencia artificial como herramienta de apoyo. No constituye un diagnóstico y debe ser revisado por el psicólogo responsable.',NULL),(8,1,10,'2026-09-09 22:52:52','PREANÁLISIS CLÍNICO\n\nPaciente\nSUSANA, 25 años, Femenino.\n\nInformación relevante\n*   La paciente refiere dificultades para conciliar y mantener el sueño, así como despertares ocasionales, las cuales se han intensificado en los últimos meses.\n*   Las dificultades de sueño están asociadas a periodos de mayor carga de responsabilidades, preocupación y pensamientos recurrentes antes de dormir.\n*   Manifiesta cansancio durante el día y dificultad ocasional para concentrarse como consecuencia de los problemas de sueño.\n\nEvaluación y pruebas\nNo se registraron pruebas en esta sesión.\n\nAspectos para revisión profesional\n*   La persistencia y evolución de los indicadores de dificultades del sueño, incluyendo su impacto en la calidad de vida diurna.\n*   El grado de influencia de la preocupación y los pensamientos recurrentes en el inicio y mantenimiento del sueño.\n*   La efectividad y adherencia a las estrategias de relajación y hábitos de sueño recomendados previamente.\n\nEvolución y antecedentes relevantes\nSusana presenta antecedentes de problemas para dormir y dificultad para expresar sus emociones. Desde la adolescencia, experimentó periodos de preocupación y dificultad para relajarse, lo cual se ha acentuado en la etapa adulta. La evaluación inicial identificó dificultades para conciliar y mantener el sueño, cansancio diurno y pensamientos recurrentes. Se recomendó establecer hábitos de sueño saludables, mantener horarios regulares de descanso y trabajar en estrategias de relajación.\n\nRecomendaciones de seguimiento\n*   Seguimiento de la evolución de las dificultades del sueño y los síntomas asociados de cansancio y concentración.\n*   Evaluación de la implementación y respuesta a las estrategias de relajación y los hábitos de sueño establecidos.\n*   Revisión profesional de los factores subyacentes que contribuyen a la preocupación y los pensamientos recurrentes.\n\nMultimedia\nNo se registró multimedia relevante.\n\nConclusión preliminar\nSe conoce la presentación actual de Susana, caracterizada por dificultades de sueño asociadas a preocupación y pensamientos recurrentes, con impacto diurno. Falta información sobre el progreso desde las recomendaciones iniciales. Conviene revisar la evolución de los síntomas y la aplicación de las estrategias durante el cierre clínico.\n\nNOTA FINAL OBLIGATORIA:\nEste preanálisis fue generado mediante inteligencia artificial como herramienta de apoyo. No constituye un diagnóstico y debe ser revisado por el psicólogo responsable.',NULL),(9,1,11,'2026-09-09 22:55:33','PREANÁLISIS CLÍNICO\n\nPaciente\nSUSANA, 25 años, Femenino.\n\nInformación relevante\n*   La paciente refiere dificultades para conciliar y mantener el sueño desde hace aproximadamente dos meses, exacerbadas por periodos de preocupación y carga de responsabilidades.\n*   Presenta cansancio diurno, dificultad ocasional para concentrarse y pensamientos recurrentes al momento de acostarse.\n*   Se identifican antecedentes de dificultades para expresar emociones y periodos de preocupación desde la adolescencia.\n\nEvaluación y pruebas\nNo se registraron pruebas en esta sesión.\n\nAspectos para revisión profesional\n*   Patrón de dificultades del sueño asociado a niveles de preocupación y carga de responsabilidades.\n*   Presencia de pensamientos recurrentes y dificultad para relajarse antes de dormir.\n*   Área pendiente de evaluación: la relación entre la dificultad para expresar emociones y los niveles de preocupación o los problemas de sueño.\n\nEvolución y antecedentes relevantes\nLa paciente presenta un historial de \"problemas para dormir\" y dificultad para expresar emociones. Durante la adolescencia, experimentó preocupación y dificultad para relajarse, lo cual se ha acentuado en la adultez con responsabilidades laborales y personales. La paciente observa un aumento de sus dificultades para dormir en los últimos meses, generando cansancio y problemas de concentración. En la evaluación inicial, se identificaron dificultades para conciliar el sueño, acompañadas de cansancio diurno y pensamientos recurrentes al momento de dormir, siendo esto la identificación inicial de dificultades por el profesional.\n\nRecomendaciones de seguimiento\n*   Continuar con la valoración y seguimiento de los hábitos de sueño, el nivel de preocupación y los factores asociados a la rutina diaria.\n*   Evaluar la evolución de los síntomas del sueño y la respuesta a las estrategias de relajación y hábitos de sueño saludables.\n*   Revisar el impacto de la dificultad para expresar emociones en el bienestar general de la paciente.\n\nMultimedia\nExiste material multimedia asociado a esta sesión: un archivo de video (\"Grabación de sesión\").\n\nConclusión preliminar\nSe tiene información detallada sobre las dificultades de sueño actuales de la paciente y sus antecedentes de preocupación. Sin embargo, se requiere una mayor profundización en la relación entre sus emociones no expresadas y el patrón de sueño. Durante el cierre clínico, conviene revisar la evolución de los síntomas, la efectividad de las estrategias implementadas y explorar los factores emocionales subyacentes.\n\nEste preanálisis fue generado mediante inteligencia artificial como herramienta de apoyo. No constituye un diagnóstico y debe ser revisado por el psicólogo responsable.',NULL),(10,1,12,'2026-09-15 21:08:49','PREANÁLISIS CLÍNICO\n\nPaciente\nSusana, 25 años, Femenino.\n\nInformación relevante\n*   La paciente refiere dificultades para conciliar y mantener el sueño desde hace aproximadamente dos meses, aumentando con periodos de preocupación y responsabilidades.\n*   Presenta cansancio diurno, dificultad ocasional para concentrarse y pensamientos recurrentes al momento de acostarse.\n*   Se observan indicadores relacionados con dificultades del sueño y posibles factores emocionales asociados, como la dificultad para expresar emociones.\n\nEvaluación y pruebas\nNo se registraron pruebas en esta sesión.\n\nAspectos para revisión profesional\n*   Patrón de dificultades del sueño asociado a preocupaciones y pensamientos recurrentes.\n*   Impacto de los problemas de sueño en el funcionamiento diurno (cansancio, concentración).\n*   Revisión de la capacidad de expresión emocional y su relación con los niveles de preocupación.\n\nEvolución y antecedentes relevantes\nLa paciente tiene antecedentes de problemas para dormir y dificultad para expresar sus emociones. Durante la adolescencia experimentó periodos de preocupación y dificultad para relajarse. En la etapa adulta, las responsabilidades laborales y personales han incrementado sus niveles de preocupación, lo que ha coincidido con el aumento de las dificultades para dormir en los últimos meses.\n\nRecomendaciones de seguimiento\n*   Continuar con la valoración y seguimiento para conocer la evolución de los indicadores identificados.\n*   Revisar la implementación de hábitos de sueño saludables y horarios regulares de descanso.\n*   Explorar estrategias de relajación para disminuir pensamientos recurrentes antes de dormir.\n\nMultimedia\nExiste material multimedia asociado a esta sesión: un archivo de audio (grabación de sesión) en formato audio/webm, duración no registrada.\n\nConclusión preliminar\nSe dispone de información sobre las dificultades de sueño de la paciente, sus antecedentes y los factores emocionales asociados. Falta información actualizada sobre la adherencia o impacto de las estrategias de relajación y hábitos de sueño previamente recomendados. Conviene revisar el progreso y explorar más a fondo los factores de preocupación y la expresión emocional durante el cierre clínico.\n\nNOTA FINAL OBLIGATORIA:\nEste preanálisis fue generado mediante inteligencia artificial como herramienta de apoyo. No constituye un diagnóstico y debe ser revisado por el psicólogo responsable.',NULL),(11,1,13,'2026-09-15 21:57:07','PREANÁLISIS IA\n\nHoy: Se realizó una sesión presencial con la paciente Susana.\nCambio: No se registró información específica de esta sesión para identificar cambios respecto a los antecedentes.\nPruebas: No se registraron pruebas en esta sesión.\nAtención: Las dificultades para expresar emociones, los problemas de sueño y los niveles de preocupación elevados merecen atención.\nAntes del cierre: Conviene revisar los puntos clave abordados en la sesión y las percepciones actuales de la paciente.\nOrientación prediagnóstica IA: Los datos son compatibles con indicadores de ansiedad y dificultades en la gestión emocional, afectando el sueño y la concentración.\n\nApoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo.',NULL),(12,1,13,'2026-09-15 22:06:04','PREANÁLISIS IA\n\nHoy: La paciente manifestó una alteración en sus emociones y estado debido a problemas familiares.\n\nCambio: Su estado emocional se vio alterado por problemas familiares, lo que se relaciona con antecedentes de dificultad para expresar emociones y estados de tristeza/enojo.\n\nPruebas: No se registraron pruebas en esta sesión.\n\nAtención: El impacto de los problemas familiares en su estado emocional actual y la dificultad para expresarlo requieren atención profesional.\n\nAntes del cierre: Conviene aclarar la naturaleza específica de los problemas familiares y cómo la paciente percibe su impacto.\n\nOrientación prediagnóstica IA: Los datos son compatibles con una reactividad emocional significativa ante estresores familiares, lo que podría vincularse con su dificultad previa para expresar emociones.\n\nApoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo.',NULL),(13,1,14,'2026-09-15 23:32:13','PREANÁLISIS IA\n\nHoy: La paciente presenta un alto nivel de nerviosismo por problemas familiares y ha decidido abandonar su hogar buscando paz mental.\n\nCambio: No hay información suficiente de la sesión anterior para establecer cambios.\n\nPruebas: No se registraron pruebas en esta sesión.\n\nAtención: El nerviosismo agudo y la decisión de un cambio de vida significativo para buscar paz mental merecen atención prioritaria.\n\nAntes del cierre: Conviene revisar los detalles y el apoyo disponible para su decisión de mudanza y cómo esto impacta su bienestar emocional.\n\nOrientación prediagnóstica IA: La información sugiere un cuadro de estrés agudo o ansiedad, considerando el nerviosismo actual y los antecedentes de preocupación y problemas de sueño.\n\nApoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo.',NULL),(14,1,14,'2026-09-16 00:25:00','PREANÁLISIS IA\n\nHoy: La paciente se presenta nerviosa por problemas en casa, ha decidido salir de ella para su paz mental y se siente \"trastornada\" por los constantes regaños.\n\nCambio: La decisión de la paciente de salirse de casa por problemas familiares es un nuevo elemento registrado.\n\nPruebas: No se registraron pruebas en esta sesión.\n\nAtención: El alto nerviosismo, el sentir de estar \"trastornada\" por conflictos familiares y la decisión de abandonar el hogar requieren atención.\n\nAntes del cierre: Conviene revisar los detalles y las implicaciones de la decisión de la paciente de abandonar su casa.\n\nOrientación prediagnóstica IA: Los datos orientan a explorar estrés agudo, dificultades emocionales relacionadas con el entorno familiar y su impacto en el bienestar actual.\n\nApoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo.',NULL),(15,1,14,'2026-09-16 00:34:26','PREANÁLISIS IA\n\nHoy: Susana está muy nerviosa por problemas en casa, refiriendo la decisión de salir para su paz mental, con frustración por regaños evidente en la transcripción.\n\nCambio: Los problemas familiares, ya alteradores, han escalado hasta la decisión de la paciente de abandonar el hogar.\n\nPruebas: No se registraron pruebas en esta sesión.\n\nAtención: La decisión de abandonar el hogar por problemas familiares y el intenso nerviosismo/frustración manifestados.\n\nAntes del cierre: Aclarar detalles e implicaciones de su decisión de salir de casa y explorar expectativas de \"paz mental\".\n\nOrientación prediagnóstica IA: Indicadores de malestar emocional significativo por conflictos familiares, y la búsqueda de soluciones drásticas para el bienestar.\n\nApoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo.',NULL),(16,1,15,'2026-09-16 04:17:15','PREANÁLISIS IA\n\nHoy: La paciente concretó su decisión de salir de casa, reportando mayor tranquilidad pese a dificultades familiares y mostrando resiliencia.\n\nCambio: La decisión de la paciente de salir de casa, mencionada en la sesión anterior, se ha concretado, asociándose a una mayor sensación de tranquilidad.\n\nPruebas: No se registraron pruebas en esta sesión.\n\nAtención: La persistencia de las dificultades familiares y las implicaciones de su nueva situación de vivienda merecen atención profesional.\n\nAntes del cierre: Conviene revisar cómo ha evolucionado la situación familiar y si se identificaron personas de apoyo, según acuerdos previos.\n\nOrientación prediagnóstica IA: Se observan indicadores de malestar emocional asociado a conflictos familiares, junto con una conducta proactiva de autoafirmación y resiliencia.\n\nApoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo.',NULL),(17,1,16,'2026-09-16 05:11:41','PREANÁLISIS IA\n\nHoy: La sesión se realizó por videollamada, sin nota clínica del psicólogo, transcripción o pruebas registradas.\n\nCambio: No hay información suficiente de la sesión anterior para establecer cambios.\n\nPruebas: No se registraron pruebas en esta sesión.\n\nAtención: No se identifican aspectos clínicos relevantes para atención específica basados en la información actual de la sesión.\n\nAntes del cierre: No hay elementos específicos registrados en esta sesión que requieran aclaración o revisión antes del cierre.\n\nOrientación prediagnóstica IA: La información disponible sugiere explorar patrones de malestar emocional, dificultades para expresar emociones y desafíos en el entorno familiar, así como problemas de sueño.\n\nApoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo.',NULL),(18,1,17,'2026-09-16 05:40:22','PREANÁLISIS IA\n\nHoy: Se percibe mejoría en la paciente, aunque la situación familiar aún la afecta, evidenciado por sus expresiones de fuerza y aceptación en la transcripción.\nCambio: No hay información suficiente de la sesión anterior para establecer cambios.\nPruebas: No se registraron pruebas en esta sesión.\nAtención: El impacto persistente de la situación familiar, a pesar de la mejoría general, merece atención profesional.\nAntes del cierre: Conviene revisar la percepción de la paciente sobre su propia fuerza y la aceptación de la situación familiar.\nOrientación prediagnóstica IA: Se observan indicadores de malestar emocional asociados a la dinámica familiar y desafíos en la expresión de emociones.\n\nApoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo.',NULL),(19,1,18,'2026-09-17 01:23:17','PREANÁLISIS IA\n\nHoy: La paciente reporta mejoría en la calidad del sueño, aunque se registra \"contacto 0\".\n\nCambio: Se observa una continuidad en la mejoría general, destacando el progreso en el sueño, y un nuevo elemento de \"contacto 0\".\n\nPruebas: No se registraron pruebas en esta sesión.\n\nAtención: El registro de \"contacto 0\" y la posible relación con la asertividad y la expresión emocional requieren atención profesional.\n\nAntes del cierre: Conviene revisar el significado del \"contacto 0\" y el progreso con la tarea de \"decir no\".\n\nOrientación prediagnóstica IA: La información sugiere explorar la dinámica del \"contacto 0\" y patrones de comunicación asertiva, vinculándolos con la dificultad para expresar emociones previamente señalada.\n\nApoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo.',NULL),(20,1,18,'2026-09-17 01:31:25','PREANÁLISIS IA\n\nHoy: La sesión se centró en la mejora del sueño de la paciente y un \"contacto 0\", junto a la reacción a una historia sobre una invitación.\nCambio: Se observa una mejora en el patrón de sueño de la paciente; un elemento nuevo registrado es el \"contacto 0\".\nPruebas: No se registraron pruebas en esta sesión.\nAtención: Es crucial indagar sobre el significado y las implicaciones del \"contacto 0\" reportado.\nAntes del cierre: Conviene revisar el avance de las tareas de \"decir no\" y profundizar en el \"contacto 0\" reportado.\nOrientación prediagnóstica IA: Se observan indicadores de desafíos en la expresión emocional y el establecimiento de límites interpersonales.\n\nApoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo.',NULL),(21,2,20,'2026-10-27 16:43:33','PREANÁLISIS IA\n\nHoy: Se registra dificultad para la expresión emocional y una descripción de la paciente como depresiva, \"jodona\" y correctora.\n\nCambio: No hay información suficiente de la sesión anterior para establecer cambios.\n\nPruebas: Se realizó el GAD-7 obteniendo un puntaje de 13, lo que indica ansiedad moderada.\n\nAtención: La dificultad para expresar emociones, junto con los indicadores de ansiedad, merece especial atención profesional.\n\nAntes del cierre: Conviene revisar la relación entre la dificultad de expresión emocional, la ansiedad moderada y las características de interacción descritas.\n\nOrientación prediagnóstica IA: Los datos disponibles orientan a explorar indicadores de malestar emocional asociados a dificultades en la regulación y expresión afectiva, en el contexto de antecedentes de depresión y ansiedad.\n\nApoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo.',NULL),(22,3,21,'2026-11-09 23:27:25','PREANÁLISIS IA\n\nHoy: La sesión se encuentra activa y fue iniciada por videollamada.\nCambio: No hay información suficiente de la sesión anterior para establecer cambios.\nPruebas: No se registraron pruebas en esta sesión.\nAtención: La información clínica disponible es limitada para un preanálisis detallado.\nAntes del cierre: Conviene registrar el motivo de consulta y los temas abordados durante la sesión.\nOrientación prediagnóstica IA: Los datos actuales son insuficientes para una orientación clínica preliminar; se sugiere explorar áreas de malestar o necesidades iniciales del paciente.\n\nApoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo.',NULL),(23,3,22,'2026-11-10 19:58:18','PREANÁLISIS IA\n\nHoy: Se registraron los resultados de la Escala de Estrés Percibido (PSS-14) y la prueba Cleaver.\nCambio: No hay información suficiente de la sesión anterior para establecer cambios.\nPruebas: Se realizó la prueba Cleaver con puntaje 0 y la Escala de Estrés Percibido (PSS-14) con puntaje 37, interpretado como estrés alto.\nAtención: El puntaje de estrés alto en la PSS-14 es el aspecto más importante que requiere atención profesional.\nAntes del cierre: Conviene revisar el detalle D/I/S/C de la prueba Cleaver y abordar el nivel de estrés percibido.\nOrientación prediagnóstica IA: Se observan indicadores de malestar emocional asociados a un alto nivel de estrés percibido.\n\nApoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo.',NULL),(24,3,23,'2026-11-10 21:09:48','PREANÁLISIS IA\n\nHoy: La sesión presencial de hoy incluyó la administración de la prueba Cleaver y una nota del psicólogo sobre una computadora.\nCambio: No hay información suficiente de la sesión anterior para establecer cambios.\nPruebas: Se administró la prueba Cleaver con un puntaje de 0, cuya interpretación registrada indica la necesidad de consultar el detalle D/I/S/C.\nAtención: La interpretación detallada de la prueba Cleaver requiere atención profesional.\nAntes del cierre: Es importante revisar los detalles D/I/S/C de la prueba Cleaver antes de cerrar la sesión.\nOrientación prediagnóstica IA: La información disponible es limitada, y la orientación clínica preliminar dependerá del análisis detallado de los resultados de la prueba Cleaver.\n\nApoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo.',NULL),(25,3,24,'2026-11-10 21:26:53','PREANÁLISIS IA\n\nHoy: La sesión incluyó la aplicación de las pruebas Cleaver y GAD-7, registrando un perfil D/I Creatividad y ansiedad moderada.\n\nCambio: No hay información suficiente de la sesión anterior para establecer cambios.\n\nPruebas: Se aplicaron las pruebas Cleaver, con perfil D/I Creatividad (D 5 · I -3 · S -2 · C -4, lógico y crítico), y GAD-7, con puntaje 14 indicando ansiedad moderada.\n\nAtención: La presencia de ansiedad moderada, según el GAD-7, es un aspecto central que requiere atención profesional.\n\nAntes del cierre: Conviene integrar los resultados de las pruebas para comprender el origen de la ansiedad y su relación con el perfil conductual de la paciente.\n\nOrientación prediagnóstica IA: Se observan indicadores de malestar emocional manifestado como ansiedad moderada, lo que sugiere explorar sus causas y el impacto en el funcionamiento de la paciente.\n\nApoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo.',NULL),(26,3,24,'2026-11-10 21:30:27','PREANÁLISIS IA\n\nHoy: La sesión incluyó la aplicación y registro de los resultados de las pruebas Cleaver y GAD-7.\n\nCambio: No hay información suficiente de la sesión anterior para establecer cambios.\n\nPruebas: Se realizó Cleaver, con perfil principal D/I - Creatividad (D 5 · I -3 · S -2 · C -4) sugiriendo un enfoque lógico y crítico, y GAD-7 con puntaje 14, indicando ansiedad moderada.\n\nAtención: La interpretación del GAD-7 que señala ansiedad moderada es un aspecto clave que merece atención profesional.\n\nAntes del cierre: Es importante revisar y discutir con el paciente los resultados obtenidos en las pruebas Cleaver y GAD-7.\n\nOrientación prediagnóstica IA: Se observan indicadores de malestar emocional asociados a ansiedad moderada, que requieren exploración en el contexto del perfil conductual registrado.\n\nApoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo.',NULL);
/*!40000 ALTER TABLE `reportes_ia` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `reportes_ia_prospectos`
--

DROP TABLE IF EXISTS `reportes_ia_prospectos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `reportes_ia_prospectos` (
  `id_reporte` int(11) NOT NULL AUTO_INCREMENT,
  `id_prospecto` int(11) NOT NULL,
  `id_usuario_registro` int(11) DEFAULT NULL,
  `tipo_reporte` enum('preanalisis','reporte_laboral') NOT NULL DEFAULT 'preanalisis',
  `contenido` longtext NOT NULL,
  `modelo_ia` varchar(100) DEFAULT NULL,
  `generado_desde` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`generado_desde`)),
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `actualizado_en` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_reporte`),
  KEY `idx_ria_prospecto` (`id_prospecto`),
  KEY `idx_ria_usuario` (`id_usuario_registro`),
  KEY `idx_ria_tipo` (`tipo_reporte`),
  CONSTRAINT `fk_ria_prospecto` FOREIGN KEY (`id_prospecto`) REFERENCES `prospectos` (`id_prospecto`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_ria_usuario` FOREIGN KEY (`id_usuario_registro`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `reportes_ia_prospectos`
--

LOCK TABLES `reportes_ia_prospectos` WRITE;
/*!40000 ALTER TABLE `reportes_ia_prospectos` DISABLE KEYS */;
INSERT INTO `reportes_ia_prospectos` VALUES (1,1,15,'preanalisis','PREANÁLISIS LABORAL — MIRRORSOUL\n\nDATOS DEL PROSPECTO\n\nNombre: JUAN\nID MirrorSoul: MS-2026-25-MA-002\nEdad: 25\nSexo: M\nPuesto solicitado: secretario\nEstatus actual: en_proceso\n\n==================================================\nSEGUIMIENTO DEL PROCESO\n==================================================\n\nSeguimiento 1\nEtapa: registro\nActividad: se revisa el perfiil\nResultado: pendiente\nObservación: se muestra nervioso pero trae un buen cv\nPróxima acción: seguiremos con pruebas\n\nSeguimiento 2\nEtapa: revision\nActividad: se revisa el perfiil\nResultado: pendiente\nObservación: es bueno para trabaja bajo presión\nPróxima acción: ya se aplicaro\n\n==================================================\nENTREVISTAS\n==================================================\n\nEntrevista 1\nTipo: Entrevista inicial\nModalidad: presencial\nResultado: continua\nEstado: realizada\nMotivo: trabaja bajo presion es puntual\nObservaciones: es muy tranquilo, tiene un buen perfil\nTranscripción disponible: No\n\nEntrevista 2\nTipo: Entrevista inicial\nModalidad: videollamada\nResultado: pendiente\nEstado: programada\nMotivo: seguimiento\nObservaciones: AUN NO\nTranscripción disponible: Sí\nTranscripción:\nNo sé cuándo. [inaudible] con. Ah, vaya. La mancha que [inaudible] no me dejan. Tienes que. Mmm. Mhm. Mhm. Tiene, recomendarles. Ni. Oye, no sé si me entiendan.\n\nEntrevista 3\nTipo: Entrevista de seguimiento\nModalidad: presencial\nResultado: pendiente\nEstado: realizada\nMotivo: seguimiento\nObservaciones: Sin observaciones\nTranscripción disponible: No\n\n==================================================\nPRUEBAS PSICOMÉTRICAS\n==================================================\n\nNo se registran pruebas psicométricas completadas.\n\n==================================================\nOBSERVACIONES RH\n==================================================\n\nObservación 1\nTipo: entrevista\nTítulo: trabajo bajo presion y es responsablo y puntual\nRelevancia: informativa\nContenido: gffhfsrf\n\n==================================================\nSÍNTESIS DE APOYO PARA RH\n==================================================\n\nLa información anterior reúne los datos disponibles del proceso de selección del prospecto.\n\nEl análisis debe considerar de manera conjunta:\n- experiencia y seguimiento del proceso;\n- resultados de entrevistas;\n- resultados psicométricos;\n- fortalezas observadas;\n- áreas que requieren revisión;\n- relación de los indicadores con el puesto solicitado.\n\nEste documento es una herramienta de apoyo para Recursos Humanos.\n\nNo constituye un diagnóstico clínico ni sustituye el criterio profesional del responsable del proceso de selección.','estructura-local','{\"seguimientos\":2,\"entrevistas\":3,\"pruebas\":0,\"observaciones\":1}','2026-10-01 23:06:07','2026-10-01 23:06:07'),(2,1,15,'preanalisis','PREANÁLISIS LABORAL — MIRRORSOUL\n\n**1. RESUMEN DEL PROCESO DE SELECCIÓN**\nEl prospecto, JUAN (ID MirrorSoul: MS-2026-25-MA-002), está participando en un proceso de selección para el puesto de secretario. El estatus del proceso es \"en_proceso\". Se han registrado cuatro entrevistas, de las cuales dos han sido realizadas (Entrevista 1 y 3), y dos están programadas (Entrevista 2 y 4). Se completaron dos pruebas psicométricas (ORVIS y IPIP-50). Se ha documentado un seguimiento del proceso con dos actividades y se ha cargado un CV.\n\n**2. PERFIL GENERAL OBSERVADO**\nSegún observaciones registradas por Recursos Humanos, el prospecto es descrito como \"muy tranquilo\", \"puntual\" y \"responsable\". Se ha notado que \"trabaja bajo presión\" y que \"tiene un buen perfil\". Inicialmente, se observó \"nerviosismo\" al inicio del proceso, pero también se destacó la presencia de un \"buen cv\".\nLos resultados descriptivos de las pruebas psicométricas indican intereses vocacionales más pronunciados en las áreas de Creatividad, Organización y Altruismo, y, en menor medida, en Liderazgo, Producción, Análisis y Erudición. En cuanto a las dimensiones de personalidad, las puntuaciones descriptivas más altas se observan en Amabilidad e Intelecto/Apertura, seguidas de Responsabilidad y Estabilidad emocional.\n\n**3. INFORMACIÓN RELEVANTE DE ENTREVISTAS**\n*   **Entrevista 1 (Presencial, Realizada):** El motivo registrado fue que \"trabaja bajo presion es puntual\". RH observó que \"es muy tranquilo, tiene un buen perfil\" y el resultado fue \"continua\". La transcripción textual disponible es muy fragmentada y no proporciona contenido conversacional claro para el análisis (\"para que te tranquilizarte mi amor. Para que puedas pensar en lo que Ahora\").\n*   **Entrevista 2 (Videollamada, Programada):** Registrada como \"programada\" con observación \"AUN NO\", pero existe una transcripción textual disponible para una grabación asociada. Esta transcripción también es fragmentada e inaudible en partes, sin aportar información sustantiva del prospecto (\"No sé cuándo. [inaudible] con. Ah, vaya. La mancha que [inaudible] no me dejan. Tienes que. Mmm. Mhm. Mhm. Tiene, recomendarles. Ni. Oye, no sé si me entiendan.\"). Esto sugiere una posible inconsistencia en el registro del estado de la entrevista.\n*   **Entrevista 3 (Presencial, Realizada):** El motivo fue \"seguimiento\", y se registró \"Sin observaciones\". El resultado está \"pendiente\". La transcripción es igualmente fragmentada e ininteligible en partes, centrándose en el acto de grabar (\"grabar el audio para que él tenga todo lo que va a hacer aquí. Se va a echarle la [inaudible] [inaudible]\").\n*   **Entrevista 4 (Presencial, Programada):** Motivo \"seguimiento\" con observación \"ninguna\". No existe transcripción disponible.\n\n**4. RESULTADOS PSICOMÉTRICOS**\n*   **ORVIS - Oregon Vocational Interest Scales (Puntaje total: 337.00):**\n    *   Intereses con promedios más altos (en escala de 1 a 5): Creatividad (3.86), Organización (3.85), Altruismo (3.77).\n    *   Otros intereses: Liderazgo (3.67), Producción / actividades prácticas (3.7), Análisis (3.6), Erudición (3.6).\n    *   Interés con promedio más bajo: Aventura (3.1).\n    *   *Nota:* Estos resultados son descriptivos y no se aplicaron puntos de corte ni categorías. No se registraron fortalezas, áreas de atención, compatibilidad con el puesto ni recomendaciones por parte de RH.\n*   **IPIP-50 Big Five (Puntaje total: 178.00):**\n    *   Dimensiones de personalidad (en escala de 0 a 50): Amabilidad (38), Intelecto / Apertura (38), Responsabilidad (36), Estabilidad emocional (34), Extraversión (32).\n    *   *Nota:* Estos resultados son descriptivos y no se aplicaron puntos de corte ni categorías. No se registraron fortalezas, áreas de atención, compatibilidad con el puesto ni recomendaciones por parte de RH.\n\n**5. SEGUIMIENTO Y EVOLUCIÓN DEL PROCESO**\nEl proceso inició con la revisión del perfil, donde RH observó al prospecto \"nervioso\" pero con un \"buen cv\". La próxima acción definida fue \"seguiremos con pruebas\". Posteriormente, durante una etapa de revisión, se destacó que el prospecto \"es bueno para trabaja bajo presión\", y se indicó que \"ya se aplicaro\" pruebas, lo que sugiere el avance en esta fase. El estatus general del proceso sigue siendo \"en_proceso\".\n\n**6. DOCUMENTACIÓN DISPONIBLE**\nSe ha registrado la existencia de un documento tipo \"cv\" con el nombre \"cveli (1).pdf\". No se dispone de su contenido para este preanálisis.\n\n**7. FORTALEZAS OBSERVADAS**\nBasado en las observaciones de Recursos Humanos y los datos descriptivos de las pruebas:\n*   **Cualidades Conductuales:** Registrado como \"tranquilo\", \"puntual\" y \"responsable\", con capacidad para \"trabaja bajo presión\".\n*   **Intereses Vocacionales (descriptivo):** Muestra intereses relativamente altos en \"Organización\", \"Creatividad\" y \"Altruismo\", lo que podría indicar una inclinación hacia tareas estructuradas, resolución creativa y enfoque de servicio.\n*   **Personalidad (descriptivo):** Las puntuaciones descriptivas en \"Amabilidad\", \"Intelecto / Apertura\" y \"Responsabilidad\" sugieren características potencialmente positivas para la interacción, el aprendizaje y el cumplimiento de tareas.\n\n**8. ASPECTOS QUE REQUIEREN VALORACIÓN**\n*   **Inconsistencias en registros:** La Entrevista 2 está marcada como \"programada\" con observación \"AUN NO\", pero existe una transcripción \"completada\" asociada a una grabación. Esto requiere clarificación sobre el estado real de esta entrevista.\n*   **Contenido de transcripciones:** Las transcripciones disponibles de las entrevistas 1, 2 y 3 son extremadamente fragmentadas y no ofrecen información sustantiva o relevante para comprender las interacciones o las respuestas del prospecto.\n*   **Falta de detalle en observaciones de RH:** Algunas observaciones son muy generales (\"tiene un buen perfil\", \"sin observaciones\") o no informativas (\"gffhfsrf\").\n*   **Interpretación psicométrica:** Los resultados psicométricos son puramente descriptivos; RH no ha registrado interpretaciones específicas, fortalezas, áreas de atención ni compatibilidad con el puesto, lo que limita su integración directa en el perfil del candidato.\n*   **Detalle del CV:** No se tiene acceso al contenido del CV, lo cual podría ofrecer información valiosa sobre la experiencia y habilidades registradas.\n\n**9. CORRESPONDENCIA OBSERVADA CON EL PUESTO**\nPara el puesto de \"secretario\", las observaciones de Recursos Humanos sobre la \"puntualidad\", \"responsabilidad\" y la capacidad de \"trabajar bajo presión\" son características deseables y potencialmente relevantes. El interés vocacional descriptivo en \"Organización\" (3.85/5) y la dimensión de personalidad \"Responsabilidad\" (36/50) del IPIP-50 también podrían ser indicadores de afinidad con las responsabilidades administrativas del puesto. Sin embargo, la ausencia de información detallada del CV y la falta de contenido claro en las transcripciones de las entrevistas limitan una correlación más profunda y específica con los requerimientos del puesto.\n\n**10. PUNTOS QUE RH DEBE REVISAR**\n*   Validar y actualizar el estado de la Entrevista 2 (ID: 2) y, si fue realizada, extraer información relevante de su contenido.\n*   Revisar el contenido completo del CV (cveli (1).pdf) para conocer la experiencia, formación y habilidades específicas del prospecto.\n*   Profundizar en la información de las entrevistas, preferentemente mediante una nueva revisión o con anotaciones más detalladas, dado que las transcripciones son insuficientes.\n*   Aplicar un marco de referencia o puntos de corte para interpretar los resultados psicométricos (ORVIS e IPIP-50) en el contexto específico del puesto de \"secretario\" y registrar fortalezas, áreas de atención y compatibilidad.\n*   Obtener referencias laborales o profesionales para verificar las afirmaciones sobre \"trabajo bajo presión\", \"puntualidad\" y \"responsabilidad\".\n*   Asegurar que las observaciones de RH sean específicas y aporten valor al proceso de selección.\n\n**11. SÍNTESIS FINAL**\nJUAN es un prospecto en proceso de selección para el puesto de secretario, con observaciones iniciales de Recursos Humanos que destacan su tranquilidad, puntualidad, responsabilidad y capacidad para trabajar bajo presión. Los resultados descriptivos de las pruebas psicométricas sugieren intereses en áreas como Organización y Creatividad, y dimensiones de personalidad como Amabilidad y Responsabilidad. No obstante, el proceso presenta algunas inconsistencias en los registros de entrevistas y la información textual disponible de las mismas es muy fragmentada. Asimismo, los resultados psicométricos requieren una interpretación más profunda por parte de RH, y el contenido del CV aún no ha sido integrado. Es fundamental que Recursos Humanos revise y clarifique estos puntos para obtener una visión completa y robusta del perfil del prospecto en relación con el puesto.\n\nEste preanálisis es una herramienta de apoyo para Recursos Humanos. La valoración y decisión final corresponden al responsable humano del proceso de selección.','gemini:gemini','{\"seguimientos\":2,\"entrevistas\":4,\"grabaciones\":3,\"transcripciones\":3,\"pruebas\":2,\"documentos\":1,\"observaciones\":1}','2026-10-03 01:29:09','2026-10-03 01:29:09');
/*!40000 ALTER TABLE `reportes_ia_prospectos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `respuestas_beta3`
--

DROP TABLE IF EXISTS `respuestas_beta3`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `respuestas_beta3` (
  `id_respuesta_beta3` int(11) NOT NULL AUTO_INCREMENT,
  `id_habilitacion` int(11) NOT NULL,
  `id_prospecto` int(11) NOT NULL,
  `id_prueba_rh` int(11) NOT NULL DEFAULT 4,
  `id_subprueba` int(11) NOT NULL,
  `id_reactivo_beta3` int(11) NOT NULL,
  `respuesta` varchar(100) DEFAULT NULL,
  `correcta` tinyint(1) DEFAULT NULL,
  `tiempo_respuesta_ms` int(11) DEFAULT NULL,
  `fecha_respuesta` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_respuesta_beta3`),
  UNIQUE KEY `uk_beta3_respuesta` (`id_habilitacion`,`id_reactivo_beta3`),
  KEY `idx_beta3_habilitacion` (`id_habilitacion`),
  KEY `idx_beta3_prospecto` (`id_prospecto`),
  KEY `idx_beta3_subprueba` (`id_subprueba`)
) ENGINE=InnoDB AUTO_INCREMENT=2420 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `respuestas_beta3`
--

LOCK TABLES `respuestas_beta3` WRITE;
/*!40000 ALTER TABLE `respuestas_beta3` DISABLE KEYS */;
/*!40000 ALTER TABLE `respuestas_beta3` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `respuestas_cleaver`
--

DROP TABLE IF EXISTS `respuestas_cleaver`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `respuestas_cleaver` (
  `id_respuesta_cleaver` int(11) NOT NULL AUTO_INCREMENT,
  `id_paciente` int(11) NOT NULL,
  `id_prueba` int(11) NOT NULL,
  `id_habilitacion` int(11) NOT NULL,
  `id_sesion` int(11) DEFAULT NULL,
  `id_pregunta` int(11) NOT NULL,
  `id_opcion_mas` int(11) NOT NULL,
  `id_opcion_menos` int(11) NOT NULL,
  `fecha_respuesta` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_respuesta_cleaver`),
  UNIQUE KEY `uq_cleaver_habilitacion_pregunta` (`id_habilitacion`,`id_pregunta`),
  KEY `idx_cleaver_paciente` (`id_paciente`),
  KEY `idx_cleaver_prueba` (`id_prueba`),
  KEY `idx_cleaver_habilitacion` (`id_habilitacion`),
  KEY `fk_rc_pregunta` (`id_pregunta`),
  KEY `fk_rc_opcion_mas` (`id_opcion_mas`),
  KEY `fk_rc_opcion_menos` (`id_opcion_menos`),
  CONSTRAINT `fk_rc_habilitacion` FOREIGN KEY (`id_habilitacion`) REFERENCES `pruebas_habilitadas` (`id_habilitacion`) ON DELETE CASCADE,
  CONSTRAINT `fk_rc_opcion_mas` FOREIGN KEY (`id_opcion_mas`) REFERENCES `opciones_respuesta` (`id_opcion`),
  CONSTRAINT `fk_rc_opcion_menos` FOREIGN KEY (`id_opcion_menos`) REFERENCES `opciones_respuesta` (`id_opcion`),
  CONSTRAINT `fk_rc_pregunta` FOREIGN KEY (`id_pregunta`) REFERENCES `preguntas_prueba` (`id_pregunta`) ON DELETE CASCADE,
  CONSTRAINT `fk_rc_prueba` FOREIGN KEY (`id_prueba`) REFERENCES `pruebas` (`id_prueba`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=97 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `respuestas_cleaver`
--

LOCK TABLES `respuestas_cleaver` WRITE;
/*!40000 ALTER TABLE `respuestas_cleaver` DISABLE KEYS */;
INSERT INTO `respuestas_cleaver` VALUES (1,1,4,12,19,78,275,278,'2026-10-09 16:09:32'),(2,1,4,12,19,79,280,279,'2026-10-09 16:09:32'),(3,1,4,12,19,80,283,284,'2026-10-09 16:09:32'),(4,1,4,12,19,81,288,290,'2026-10-09 16:09:32'),(5,1,4,12,19,82,293,292,'2026-10-09 16:09:32'),(6,1,4,12,19,83,295,297,'2026-10-09 16:09:32'),(7,1,4,12,19,84,300,299,'2026-10-09 16:09:32'),(8,1,4,12,19,85,305,303,'2026-10-09 16:09:32'),(9,1,4,12,19,86,307,309,'2026-10-09 16:09:32'),(10,1,4,12,19,87,314,313,'2026-10-09 16:09:32'),(11,1,4,12,19,88,315,318,'2026-10-09 16:09:32'),(12,1,4,12,19,89,320,321,'2026-10-09 16:09:32'),(13,1,4,12,19,90,323,325,'2026-10-09 16:09:32'),(14,1,4,12,19,91,327,329,'2026-10-09 16:09:32'),(15,1,4,12,19,92,332,333,'2026-10-09 16:09:32'),(16,1,4,12,19,93,335,338,'2026-10-09 16:09:32'),(17,1,4,12,19,94,341,342,'2026-10-09 16:09:32'),(18,1,4,12,19,95,344,343,'2026-10-09 16:09:32'),(19,1,4,12,19,96,349,347,'2026-10-09 16:09:32'),(20,1,4,12,19,97,354,352,'2026-10-09 16:09:32'),(21,1,4,12,19,98,358,355,'2026-10-09 16:09:32'),(22,1,4,12,19,99,362,359,'2026-10-09 16:09:32'),(23,1,4,12,19,100,364,363,'2026-10-09 16:09:32'),(24,1,4,12,19,101,367,370,'2026-10-09 16:09:32'),(25,3,4,15,22,78,277,275,'2026-11-09 23:55:55'),(26,3,4,15,22,79,281,279,'2026-11-09 23:55:55'),(27,3,4,15,22,80,283,286,'2026-11-09 23:55:55'),(28,3,4,15,22,81,290,287,'2026-11-09 23:55:55'),(29,3,4,15,22,82,292,291,'2026-11-09 23:55:55'),(30,3,4,15,22,83,298,295,'2026-11-09 23:55:55'),(31,3,4,15,22,84,300,299,'2026-11-09 23:55:55'),(32,3,4,15,22,85,304,306,'2026-11-09 23:55:55'),(33,3,4,15,22,86,308,309,'2026-11-09 23:55:55'),(34,3,4,15,22,87,312,313,'2026-11-09 23:55:55'),(35,3,4,15,22,88,315,317,'2026-11-09 23:55:55'),(36,3,4,15,22,89,320,321,'2026-11-09 23:55:55'),(37,3,4,15,22,90,324,325,'2026-11-09 23:55:55'),(38,3,4,15,22,91,327,330,'2026-11-09 23:55:55'),(39,3,4,15,22,92,331,333,'2026-11-09 23:55:55'),(40,3,4,15,22,93,335,337,'2026-11-09 23:55:55'),(41,3,4,15,22,94,340,341,'2026-11-09 23:55:55'),(42,3,4,15,22,95,344,346,'2026-11-09 23:55:55'),(43,3,4,15,22,96,347,350,'2026-11-09 23:55:55'),(44,3,4,15,22,97,352,354,'2026-11-09 23:55:55'),(45,3,4,15,22,98,356,358,'2026-11-09 23:55:55'),(46,3,4,15,22,99,362,359,'2026-11-09 23:55:55'),(47,3,4,15,22,100,364,366,'2026-11-09 23:55:55'),(48,3,4,15,22,101,367,370,'2026-11-09 23:55:55'),(49,3,4,19,23,78,278,276,'2026-11-10 21:09:16'),(50,3,4,19,23,79,279,282,'2026-11-10 21:09:16'),(51,3,4,19,23,80,284,286,'2026-11-10 21:09:16'),(52,3,4,19,23,81,289,290,'2026-11-10 21:09:16'),(53,3,4,19,23,82,293,294,'2026-11-10 21:09:16'),(54,3,4,19,23,83,296,298,'2026-11-10 21:09:16'),(55,3,4,19,23,84,301,302,'2026-11-10 21:09:16'),(56,3,4,19,23,85,303,306,'2026-11-10 21:09:16'),(57,3,4,19,23,86,309,310,'2026-11-10 21:09:16'),(58,3,4,19,23,87,314,312,'2026-11-10 21:09:16'),(59,3,4,19,23,88,317,315,'2026-11-10 21:09:16'),(60,3,4,19,23,89,321,319,'2026-11-10 21:09:16'),(61,3,4,19,23,90,323,325,'2026-11-10 21:09:16'),(62,3,4,19,23,91,327,329,'2026-11-10 21:09:16'),(63,3,4,19,23,92,332,333,'2026-11-10 21:09:16'),(64,3,4,19,23,93,338,335,'2026-11-10 21:09:16'),(65,3,4,19,23,94,339,341,'2026-11-10 21:09:16'),(66,3,4,19,23,95,344,345,'2026-11-10 21:09:16'),(67,3,4,19,23,96,348,350,'2026-11-10 21:09:16'),(68,3,4,19,23,97,354,353,'2026-11-10 21:09:16'),(69,3,4,19,23,98,358,357,'2026-11-10 21:09:16'),(70,3,4,19,23,99,362,361,'2026-11-10 21:09:16'),(71,3,4,19,23,100,366,364,'2026-11-10 21:09:16'),(72,3,4,19,23,101,368,370,'2026-11-10 21:09:16'),(73,3,4,20,24,78,275,277,'2026-11-10 21:26:03'),(74,3,4,20,24,79,279,281,'2026-11-10 21:26:03'),(75,3,4,20,24,80,286,283,'2026-11-10 21:26:03'),(76,3,4,20,24,81,287,290,'2026-11-10 21:26:03'),(77,3,4,20,24,82,293,291,'2026-11-10 21:26:03'),(78,3,4,20,24,83,295,297,'2026-11-10 21:26:03'),(79,3,4,20,24,84,301,302,'2026-11-10 21:26:03'),(80,3,4,20,24,85,305,306,'2026-11-10 21:26:03'),(81,3,4,20,24,86,310,308,'2026-11-10 21:26:03'),(82,3,4,20,24,87,312,314,'2026-11-10 21:26:03'),(83,3,4,20,24,88,318,317,'2026-11-10 21:26:03'),(84,3,4,20,24,89,322,321,'2026-11-10 21:26:03'),(85,3,4,20,24,90,325,326,'2026-11-10 21:26:03'),(86,3,4,20,24,91,328,330,'2026-11-10 21:26:03'),(87,3,4,20,24,92,331,334,'2026-11-10 21:26:03'),(88,3,4,20,24,93,335,338,'2026-11-10 21:26:03'),(89,3,4,20,24,94,341,342,'2026-11-10 21:26:03'),(90,3,4,20,24,95,345,346,'2026-11-10 21:26:03'),(91,3,4,20,24,96,348,350,'2026-11-10 21:26:03'),(92,3,4,20,24,97,352,354,'2026-11-10 21:26:03'),(93,3,4,20,24,98,358,357,'2026-11-10 21:26:03'),(94,3,4,20,24,99,359,362,'2026-11-10 21:26:03'),(95,3,4,20,24,100,363,366,'2026-11-10 21:26:03'),(96,3,4,20,24,101,367,370,'2026-11-10 21:26:03');
/*!40000 ALTER TABLE `respuestas_cleaver` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `respuestas_prueba`
--

DROP TABLE IF EXISTS `respuestas_prueba`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `respuestas_prueba` (
  `id_respuesta` int(11) NOT NULL AUTO_INCREMENT,
  `id_paciente` int(11) NOT NULL,
  `id_prueba` int(11) NOT NULL,
  `id_habilitacion` int(11) DEFAULT NULL,
  `id_pregunta` int(11) NOT NULL,
  `id_opcion` int(11) DEFAULT NULL,
  `respuesta_abierta` text DEFAULT NULL,
  `id_sesion` int(11) DEFAULT NULL,
  `fecha_respuesta` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_respuesta`)
) ENGINE=InnoDB AUTO_INCREMENT=221 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `respuestas_prueba`
--

LOCK TABLES `respuestas_prueba` WRITE;
/*!40000 ALTER TABLE `respuestas_prueba` DISABLE KEYS */;
INSERT INTO `respuestas_prueba` VALUES (1,1,3,100,71,249,NULL,NULL,'2025-10-29 01:33:23'),(2,1,3,100,72,253,NULL,NULL,'2025-10-29 01:33:23'),(3,1,3,100,73,257,NULL,NULL,'2025-10-29 01:33:23'),(4,1,3,100,74,262,NULL,NULL,'2025-10-29 01:33:23'),(5,1,3,100,75,266,NULL,NULL,'2025-10-29 01:33:23'),(6,1,3,100,76,270,NULL,NULL,'2025-10-29 01:33:23'),(7,1,3,100,77,274,NULL,NULL,'2025-10-29 01:33:23'),(8,4,3,102,71,249,NULL,NULL,'2025-10-30 00:14:19'),(9,4,3,102,72,254,NULL,NULL,'2025-10-30 00:14:19'),(10,4,3,102,73,258,NULL,NULL,'2025-10-30 00:14:19'),(11,4,3,102,74,261,NULL,NULL,'2025-10-30 00:14:19'),(12,4,3,102,75,265,NULL,NULL,'2025-10-30 00:14:19'),(13,4,3,102,76,269,NULL,NULL,'2025-10-30 00:14:19'),(14,4,3,102,77,273,NULL,NULL,'2025-10-30 00:14:19'),(15,4,2,103,36,95,NULL,NULL,'2025-11-10 19:30:33'),(16,4,2,103,37,102,NULL,NULL,'2025-11-10 19:30:33'),(17,4,2,103,38,107,NULL,NULL,'2025-11-10 19:30:33'),(18,4,2,103,39,112,NULL,NULL,'2025-11-10 19:30:33'),(19,4,2,103,40,117,NULL,NULL,'2025-11-10 19:30:33'),(20,4,2,103,41,122,NULL,NULL,'2025-11-10 19:30:33'),(21,4,2,103,42,127,NULL,NULL,'2025-11-10 19:30:33'),(22,4,2,103,43,131,NULL,NULL,'2025-11-10 19:30:33'),(23,4,2,103,44,136,NULL,NULL,'2025-11-10 19:30:33'),(24,4,2,103,45,141,NULL,NULL,'2025-11-10 19:30:33'),(25,4,2,103,46,145,NULL,NULL,'2025-11-10 19:30:33'),(26,4,2,103,47,149,NULL,NULL,'2025-11-10 19:30:33'),(27,4,2,103,48,157,NULL,NULL,'2025-11-10 19:30:33'),(28,4,2,103,49,162,NULL,NULL,'2025-11-10 19:30:33'),(29,4,1,104,50,164,NULL,NULL,'2025-11-12 23:42:27'),(30,4,1,104,51,170,NULL,NULL,'2025-11-12 23:42:27'),(31,4,1,104,52,174,NULL,NULL,'2025-11-12 23:42:27'),(32,4,1,104,53,178,NULL,NULL,'2025-11-12 23:42:27'),(33,4,1,104,54,181,NULL,NULL,'2025-11-12 23:42:27'),(34,4,1,104,55,184,NULL,NULL,'2025-11-12 23:42:27'),(35,4,1,104,56,189,NULL,NULL,'2025-11-12 23:42:27'),(36,4,1,104,57,193,NULL,NULL,'2025-11-12 23:42:27'),(37,4,1,104,58,195,NULL,NULL,'2025-11-12 23:42:27'),(38,4,1,104,59,200,NULL,NULL,'2025-11-12 23:42:27'),(39,4,1,104,60,204,NULL,NULL,'2025-11-12 23:42:27'),(40,4,1,104,61,210,NULL,NULL,'2025-11-12 23:42:27'),(41,4,1,104,62,213,NULL,NULL,'2025-11-12 23:42:27'),(42,4,1,104,63,218,NULL,NULL,'2025-11-12 23:42:27'),(43,4,1,104,64,221,NULL,NULL,'2025-11-12 23:42:27'),(44,4,1,104,65,225,NULL,NULL,'2025-11-12 23:42:27'),(45,4,1,104,66,230,NULL,NULL,'2025-11-12 23:42:27'),(46,4,1,104,67,234,NULL,NULL,'2025-11-12 23:42:27'),(47,4,1,104,68,237,NULL,NULL,'2025-11-12 23:42:27'),(48,4,1,104,69,242,NULL,NULL,'2025-11-12 23:42:27'),(49,4,1,104,70,246,NULL,NULL,'2025-11-12 23:42:27'),(50,4,3,109,71,247,NULL,NULL,'2026-08-04 18:13:07'),(51,4,3,109,72,252,NULL,NULL,'2026-08-04 18:13:07'),(52,4,3,109,73,257,NULL,NULL,'2026-08-04 18:13:07'),(53,4,3,109,74,260,NULL,NULL,'2026-08-04 18:13:07'),(54,4,3,109,75,265,NULL,NULL,'2026-08-04 18:13:07'),(55,4,3,109,76,270,NULL,NULL,'2026-08-04 18:13:07'),(56,4,3,109,77,271,NULL,NULL,'2026-08-04 18:13:07'),(57,4,2,110,36,95,NULL,NULL,'2026-08-21 04:36:57'),(58,4,2,110,37,99,NULL,NULL,'2026-08-21 04:36:57'),(59,4,2,110,38,106,NULL,NULL,'2026-08-21 04:36:57'),(60,4,2,110,39,112,NULL,NULL,'2026-08-21 04:36:57'),(61,4,2,110,40,114,NULL,NULL,'2026-08-21 04:36:57'),(62,4,2,110,41,119,NULL,NULL,'2026-08-21 04:36:57'),(63,4,2,110,42,123,NULL,NULL,'2026-08-21 04:36:57'),(64,4,2,110,43,128,NULL,NULL,'2026-08-21 04:36:57'),(65,4,2,110,44,135,NULL,NULL,'2026-08-21 04:36:57'),(66,4,2,110,45,140,NULL,NULL,'2026-08-21 04:36:57'),(67,4,2,110,46,146,NULL,NULL,'2026-08-21 04:36:57'),(68,4,2,110,47,150,NULL,NULL,'2026-08-21 04:36:57'),(69,4,2,110,48,155,NULL,NULL,'2026-08-21 04:36:57'),(70,4,2,110,49,159,NULL,NULL,'2026-08-21 04:36:57'),(71,4,3,112,71,249,NULL,NULL,'2026-08-21 04:50:44'),(72,4,3,112,72,253,NULL,NULL,'2026-08-21 04:50:44'),(73,4,3,112,73,257,NULL,NULL,'2026-08-21 04:50:44'),(74,4,3,112,74,261,NULL,NULL,'2026-08-21 04:50:44'),(75,4,3,112,75,266,NULL,NULL,'2026-08-21 04:50:44'),(76,4,3,112,76,270,NULL,NULL,'2026-08-21 04:50:44'),(77,4,3,112,77,273,NULL,NULL,'2026-08-21 04:50:44'),(78,4,3,112,71,248,NULL,NULL,'2026-08-21 21:16:08'),(79,4,3,112,72,254,NULL,NULL,'2026-08-21 21:16:08'),(80,4,3,112,73,257,NULL,NULL,'2026-08-21 21:16:08'),(81,4,3,112,74,262,NULL,NULL,'2026-08-21 21:16:08'),(82,4,3,112,75,264,NULL,NULL,'2026-08-21 21:16:08'),(83,4,3,112,76,270,NULL,NULL,'2026-08-21 21:16:08'),(84,4,3,112,77,273,NULL,NULL,'2026-08-21 21:16:08'),(85,1,3,1,71,248,NULL,NULL,'2026-09-03 03:24:07'),(86,1,3,1,72,252,NULL,NULL,'2026-09-03 03:24:07'),(87,1,3,1,73,256,NULL,NULL,'2026-09-03 03:24:07'),(88,1,3,1,74,261,NULL,NULL,'2026-09-03 03:24:07'),(89,1,3,1,75,264,NULL,NULL,'2026-09-03 03:24:07'),(90,1,3,1,76,270,NULL,NULL,'2026-09-03 03:24:07'),(91,1,3,1,77,274,NULL,NULL,'2026-09-03 03:24:07'),(92,1,2,2,36,94,NULL,NULL,'2026-09-05 01:15:39'),(93,1,2,2,37,102,NULL,NULL,'2026-09-05 01:15:39'),(94,1,2,2,38,107,NULL,NULL,'2026-09-05 01:15:39'),(95,1,2,2,39,110,NULL,NULL,'2026-09-05 01:15:39'),(96,1,2,2,40,116,NULL,NULL,'2026-09-05 01:15:39'),(97,1,2,2,41,121,NULL,NULL,'2026-09-05 01:15:39'),(98,1,2,2,42,125,NULL,NULL,'2026-09-05 01:15:39'),(99,1,2,2,43,132,NULL,NULL,'2026-09-05 01:15:39'),(100,1,2,2,44,137,NULL,NULL,'2026-09-05 01:15:39'),(101,1,2,2,45,142,NULL,NULL,'2026-09-05 01:15:39'),(102,1,2,2,46,147,NULL,NULL,'2026-09-05 01:15:39'),(103,1,2,2,47,151,NULL,NULL,'2026-09-05 01:15:39'),(104,1,2,2,48,156,NULL,NULL,'2026-09-05 01:15:39'),(105,1,2,2,49,160,NULL,NULL,'2026-09-05 01:15:39'),(106,1,1,3,50,165,NULL,NULL,'2026-09-05 02:43:18'),(107,1,1,3,51,169,NULL,NULL,'2026-09-05 02:43:18'),(108,1,1,3,52,174,NULL,NULL,'2026-09-05 02:43:18'),(109,1,1,3,53,177,NULL,NULL,'2026-09-05 02:43:18'),(110,1,1,3,54,182,NULL,NULL,'2026-09-05 02:43:18'),(111,1,1,3,55,183,NULL,NULL,'2026-09-05 02:43:18'),(112,1,1,3,56,190,NULL,NULL,'2026-09-05 02:43:18'),(113,1,1,3,57,194,NULL,NULL,'2026-09-05 02:43:18'),(114,1,1,3,58,198,NULL,NULL,'2026-09-05 02:43:18'),(115,1,1,3,59,200,NULL,NULL,'2026-09-05 02:43:18'),(116,1,1,3,60,205,NULL,NULL,'2026-09-05 02:43:18'),(117,1,1,3,61,207,NULL,NULL,'2026-09-05 02:43:18'),(118,1,1,3,62,214,NULL,NULL,'2026-09-05 02:43:18'),(119,1,1,3,63,216,NULL,NULL,'2026-09-05 02:43:18'),(120,1,1,3,64,222,NULL,NULL,'2026-09-05 02:43:18'),(121,1,1,3,65,223,NULL,NULL,'2026-09-05 02:43:18'),(122,1,1,3,66,229,NULL,NULL,'2026-09-05 02:43:18'),(123,1,1,3,67,234,NULL,NULL,'2026-09-05 02:43:18'),(124,1,1,3,68,238,NULL,NULL,'2026-09-05 02:43:18'),(125,1,1,3,69,239,NULL,NULL,'2026-09-05 02:43:18'),(126,1,1,3,70,243,NULL,NULL,'2026-09-05 02:43:18'),(127,1,3,4,71,249,NULL,2,'2026-09-05 04:59:18'),(128,1,3,4,72,253,NULL,2,'2026-09-05 04:59:18'),(129,1,3,4,73,256,NULL,2,'2026-09-05 04:59:18'),(130,1,3,4,74,262,NULL,2,'2026-09-05 04:59:18'),(131,1,3,4,75,266,NULL,2,'2026-09-05 04:59:18'),(132,1,3,4,76,269,NULL,2,'2026-09-05 04:59:18'),(133,1,3,4,77,271,NULL,2,'2026-09-05 04:59:18'),(134,1,3,5,71,249,NULL,6,'2026-09-07 18:02:08'),(135,1,3,5,72,254,NULL,6,'2026-09-07 18:02:08'),(136,1,3,5,73,257,NULL,6,'2026-09-07 18:02:08'),(137,1,3,5,74,261,NULL,6,'2026-09-07 18:02:08'),(138,1,3,5,75,264,NULL,6,'2026-09-07 18:02:08'),(139,1,3,5,76,269,NULL,6,'2026-09-07 18:02:08'),(140,1,3,5,77,272,NULL,6,'2026-09-07 18:02:08'),(141,1,3,6,71,248,NULL,8,'2026-09-07 18:42:35'),(142,1,3,6,72,254,NULL,8,'2026-09-07 18:42:35'),(143,1,3,6,73,256,NULL,8,'2026-09-07 18:42:35'),(144,1,3,6,74,262,NULL,8,'2026-09-07 18:42:35'),(145,1,3,6,75,264,NULL,8,'2026-09-07 18:42:35'),(146,1,3,6,76,269,NULL,8,'2026-09-07 18:42:35'),(147,1,3,6,77,272,NULL,8,'2026-09-07 18:42:35'),(148,1,2,7,36,95,NULL,9,'2026-09-07 19:27:56'),(149,1,2,7,37,102,NULL,9,'2026-09-07 19:27:56'),(150,1,2,7,38,105,NULL,9,'2026-09-07 19:27:56'),(151,1,2,7,39,110,NULL,9,'2026-09-07 19:27:56'),(152,1,2,7,40,117,NULL,9,'2026-09-07 19:27:56'),(153,1,2,7,41,122,NULL,9,'2026-09-07 19:27:56'),(154,1,2,7,42,126,NULL,9,'2026-09-07 19:27:56'),(155,1,2,7,43,132,NULL,9,'2026-09-07 19:27:56'),(156,1,2,7,44,137,NULL,9,'2026-09-07 19:27:56'),(157,1,2,7,45,141,NULL,9,'2026-09-07 19:27:56'),(158,1,2,7,46,147,NULL,9,'2026-09-07 19:27:56'),(159,1,2,7,47,152,NULL,9,'2026-09-07 19:27:56'),(160,1,2,7,48,156,NULL,9,'2026-09-07 19:27:56'),(161,1,2,7,49,162,NULL,9,'2026-09-07 19:27:56'),(162,1,3,8,71,250,NULL,NULL,'2026-09-23 19:19:16'),(163,1,3,8,72,253,NULL,NULL,'2026-09-23 19:19:16'),(164,1,3,8,73,256,NULL,NULL,'2026-09-23 19:19:16'),(165,1,3,8,74,261,NULL,NULL,'2026-09-23 19:19:16'),(166,1,3,8,75,265,NULL,NULL,'2026-09-23 19:19:16'),(167,1,3,8,76,269,NULL,NULL,'2026-09-23 19:19:16'),(168,1,3,8,77,273,NULL,NULL,'2026-09-23 19:19:16'),(169,1,4,11,78,277,NULL,19,'2026-10-08 21:37:36'),(170,1,4,11,79,280,NULL,19,'2026-10-08 21:37:36'),(171,1,4,11,80,284,NULL,19,'2026-10-08 21:37:36'),(172,1,4,11,81,288,NULL,19,'2026-10-08 21:37:36'),(173,1,4,11,82,293,NULL,19,'2026-10-08 21:37:36'),(174,1,4,11,83,297,NULL,19,'2026-10-08 21:37:36'),(175,1,4,11,84,301,NULL,19,'2026-10-08 21:37:36'),(176,1,4,11,85,306,NULL,19,'2026-10-08 21:37:36'),(177,1,4,11,86,308,NULL,19,'2026-10-08 21:37:36'),(178,1,4,11,87,314,NULL,19,'2026-10-08 21:37:36'),(179,1,4,11,88,318,NULL,19,'2026-10-08 21:37:36'),(180,1,4,11,89,319,NULL,19,'2026-10-08 21:37:36'),(181,1,4,11,90,325,NULL,19,'2026-10-08 21:37:36'),(182,1,4,11,91,330,NULL,19,'2026-10-08 21:37:36'),(183,1,4,11,92,332,NULL,19,'2026-10-08 21:37:36'),(184,1,4,11,93,338,NULL,19,'2026-10-08 21:37:36'),(185,1,4,11,94,342,NULL,19,'2026-10-08 21:37:36'),(186,1,4,11,95,344,NULL,19,'2026-10-08 21:37:36'),(187,1,4,11,96,348,NULL,19,'2026-10-08 21:37:36'),(188,1,4,11,97,354,NULL,19,'2026-10-08 21:37:36'),(189,1,4,11,98,358,NULL,19,'2026-10-08 21:37:36'),(190,1,4,11,99,361,NULL,19,'2026-10-08 21:37:36'),(191,1,4,11,100,366,NULL,19,'2026-10-08 21:37:36'),(192,1,4,11,101,368,NULL,19,'2026-10-08 21:37:36'),(193,2,3,13,71,249,NULL,20,'2026-10-27 16:42:57'),(194,2,3,13,72,252,NULL,20,'2026-10-27 16:42:57'),(195,2,3,13,73,256,NULL,20,'2026-10-27 16:42:57'),(196,2,3,13,74,262,NULL,20,'2026-10-27 16:42:57'),(197,2,3,13,75,265,NULL,20,'2026-10-27 16:42:57'),(198,2,3,13,76,269,NULL,20,'2026-10-27 16:42:57'),(199,2,3,13,77,273,NULL,20,'2026-10-27 16:42:57'),(200,3,2,17,36,94,NULL,22,'2026-11-10 16:20:41'),(201,3,2,17,37,100,NULL,22,'2026-11-10 16:20:41'),(202,3,2,17,38,106,NULL,22,'2026-11-10 16:20:41'),(203,3,2,17,39,110,NULL,22,'2026-11-10 16:20:41'),(204,3,2,17,40,115,NULL,22,'2026-11-10 16:20:41'),(205,3,2,17,41,121,NULL,22,'2026-11-10 16:20:41'),(206,3,2,17,42,127,NULL,22,'2026-11-10 16:20:41'),(207,3,2,17,43,131,NULL,22,'2026-11-10 16:20:41'),(208,3,2,17,44,137,NULL,22,'2026-11-10 16:20:41'),(209,3,2,17,45,142,NULL,22,'2026-11-10 16:20:41'),(210,3,2,17,46,144,NULL,22,'2026-11-10 16:20:41'),(211,3,2,17,47,149,NULL,22,'2026-11-10 16:20:41'),(212,3,2,17,48,156,NULL,22,'2026-11-10 16:20:41'),(213,3,2,17,49,162,NULL,22,'2026-11-10 16:20:41'),(214,3,3,21,71,249,NULL,24,'2026-11-10 21:26:25'),(215,3,3,21,72,253,NULL,24,'2026-11-10 21:26:25'),(216,3,3,21,73,256,NULL,24,'2026-11-10 21:26:25'),(217,3,3,21,74,259,NULL,24,'2026-11-10 21:26:25'),(218,3,3,21,75,266,NULL,24,'2026-11-10 21:26:25'),(219,3,3,21,76,270,NULL,24,'2026-11-10 21:26:25'),(220,3,3,21,77,274,NULL,24,'2026-11-10 21:26:25');
/*!40000 ALTER TABLE `respuestas_prueba` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `respuestas_prueba_empleado`
--

DROP TABLE IF EXISTS `respuestas_prueba_empleado`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `respuestas_prueba_empleado` (
  `id_respuesta` int(11) NOT NULL AUTO_INCREMENT,
  `id_habilitacion` int(11) NOT NULL,
  `id_empleado` int(11) NOT NULL,
  `id_prueba_rh` int(11) NOT NULL,
  `id_pregunta_rh` int(11) NOT NULL,
  `respuesta` text DEFAULT NULL,
  `valor_respuesta` decimal(10,2) DEFAULT NULL,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_respuesta`),
  UNIQUE KEY `uq_rpe_pregunta` (`id_habilitacion`,`id_pregunta_rh`),
  KEY `idx_rpe_empleado` (`id_empleado`),
  KEY `idx_rpe_prueba` (`id_prueba_rh`),
  KEY `fk_rpe_pregunta` (`id_pregunta_rh`),
  CONSTRAINT `fk_rpe_empleado` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id_empleado`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_rpe_habilitacion` FOREIGN KEY (`id_habilitacion`) REFERENCES `pruebas_empleados_habilitadas` (`id_habilitacion`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_rpe_pregunta` FOREIGN KEY (`id_pregunta_rh`) REFERENCES `preguntas_prueba_rh` (`id_pregunta_rh`) ON UPDATE CASCADE,
  CONSTRAINT `fk_rpe_prueba` FOREIGN KEY (`id_prueba_rh`) REFERENCES `pruebas_rh` (`id_prueba_rh`) ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=42 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `respuestas_prueba_empleado`
--

LOCK TABLES `respuestas_prueba_empleado` WRITE;
/*!40000 ALTER TABLE `respuestas_prueba_empleado` DISABLE KEYS */;
INSERT INTO `respuestas_prueba_empleado` VALUES (1,3,3,6,253,'Varios días',1.00,'2026-10-30 18:37:35'),(2,3,3,6,254,'Más de la mitad de los días',2.00,'2026-10-30 18:37:35'),(3,3,3,6,255,'Varios días',1.00,'2026-10-30 18:37:35'),(4,3,3,6,256,'Varios días',1.00,'2026-10-30 18:37:35'),(5,3,3,6,257,'Nunca',0.00,'2026-10-30 18:37:35'),(6,3,3,6,258,'Casi todos los días',3.00,'2026-10-30 18:37:35'),(7,3,3,6,259,'Casi todos los días',3.00,'2026-10-30 18:37:35'),(8,4,3,5,248,'Menos de la mitad del tiempo',2.00,'2026-10-30 18:47:13'),(9,4,3,5,249,'Menos de la mitad del tiempo',2.00,'2026-10-30 18:47:13'),(10,4,3,5,250,'Alguna vez',1.00,'2026-10-30 18:47:13'),(11,4,3,5,251,'Menos de la mitad del tiempo',2.00,'2026-10-30 18:47:13'),(12,4,3,5,252,'Menos de la mitad del tiempo',2.00,'2026-10-30 18:47:13'),(13,6,3,5,248,'Menos de la mitad del tiempo',2.00,'2026-10-30 18:49:41'),(14,6,3,5,249,'Menos de la mitad del tiempo',2.00,'2026-10-30 18:49:41'),(15,6,3,5,250,'Menos de la mitad del tiempo',2.00,'2026-10-30 18:49:41'),(16,6,3,5,251,'Más de la mitad del tiempo',3.00,'2026-10-30 18:49:41'),(17,6,3,5,252,'Más de la mitad del tiempo',3.00,'2026-10-30 18:49:41'),(18,7,3,5,248,'Menos de la mitad del tiempo',2.00,'2026-10-30 18:56:20'),(19,7,3,5,249,'Alguna vez',1.00,'2026-10-30 18:56:20'),(20,7,3,5,250,'Todo el tiempo',5.00,'2026-10-30 18:56:20'),(21,7,3,5,251,'Todo el tiempo',5.00,'2026-10-30 18:56:20'),(22,7,3,5,252,'La mayor parte del tiempo',4.00,'2026-10-30 18:56:20'),(23,8,3,5,248,'Más de la mitad del tiempo',3.00,'2026-10-30 18:57:36'),(24,8,3,5,249,'Más de la mitad del tiempo',3.00,'2026-10-30 18:57:36'),(25,8,3,5,250,'Alguna vez',1.00,'2026-10-30 18:57:36'),(26,8,3,5,251,'Menos de la mitad del tiempo',2.00,'2026-10-30 18:57:36'),(27,8,3,5,252,'La mayor parte del tiempo',4.00,'2026-10-30 18:57:36'),(28,10,3,6,253,'Varios días',1.00,'2026-11-03 21:41:59'),(29,10,3,6,254,'Más de la mitad de los días',2.00,'2026-11-03 21:41:59'),(30,10,3,6,255,'Casi todos los días',3.00,'2026-11-03 21:41:59'),(31,10,3,6,256,'Varios días',1.00,'2026-11-03 21:41:59'),(32,10,3,6,257,'Más de la mitad de los días',2.00,'2026-11-03 21:41:59'),(33,10,3,6,258,'Más de la mitad de los días',2.00,'2026-11-03 21:41:59'),(34,10,3,6,259,'Más de la mitad de los días',2.00,'2026-11-03 21:41:59'),(35,11,4,6,253,'Varios días',1.00,'2026-11-12 20:06:10'),(36,11,4,6,254,'Casi todos los días',3.00,'2026-11-12 20:06:10'),(37,11,4,6,255,'Casi todos los días',3.00,'2026-11-12 20:06:10'),(38,11,4,6,256,'Varios días',1.00,'2026-11-12 20:06:10'),(39,11,4,6,257,'Más de la mitad de los días',2.00,'2026-11-12 20:06:10'),(40,11,4,6,258,'Casi todos los días',3.00,'2026-11-12 20:06:10'),(41,11,4,6,259,'Más de la mitad de los días',2.00,'2026-11-12 20:06:10');
/*!40000 ALTER TABLE `respuestas_prueba_empleado` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `respuestas_prueba_prospecto`
--

DROP TABLE IF EXISTS `respuestas_prueba_prospecto`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `respuestas_prueba_prospecto` (
  `id_respuesta` int(11) NOT NULL AUTO_INCREMENT,
  `id_habilitacion` int(11) NOT NULL,
  `id_prospecto` int(11) NOT NULL,
  `id_prueba_rh` int(11) NOT NULL,
  `id_pregunta_rh` int(11) DEFAULT NULL,
  `respuesta` text DEFAULT NULL,
  `valor_respuesta` decimal(10,2) DEFAULT NULL,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_respuesta`),
  KEY `idx_rpp_habilitacion` (`id_habilitacion`),
  KEY `idx_rpp_prospecto` (`id_prospecto`),
  KEY `idx_rpp_prueba` (`id_prueba_rh`),
  KEY `fk_rpp_pregunta_rh` (`id_pregunta_rh`),
  CONSTRAINT `fk_rpp_habilitacion` FOREIGN KEY (`id_habilitacion`) REFERENCES `pruebas_prospectos_habilitadas` (`id_habilitacion`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_rpp_pregunta_rh` FOREIGN KEY (`id_pregunta_rh`) REFERENCES `preguntas_prueba_rh` (`id_pregunta_rh`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_rpp_prospecto` FOREIGN KEY (`id_prospecto`) REFERENCES `prospectos` (`id_prospecto`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_rpp_prueba_rh` FOREIGN KEY (`id_prueba_rh`) REFERENCES `pruebas_rh` (`id_prueba_rh`) ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=694 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `respuestas_prueba_prospecto`
--

LOCK TABLES `respuestas_prueba_prospecto` WRITE;
/*!40000 ALTER TABLE `respuestas_prueba_prospecto` DISABLE KEYS */;
INSERT INTO `respuestas_prueba_prospecto` VALUES (277,2,1,2,151,'Me gusta',4.00,'2026-10-02 21:21:30'),(278,2,1,2,152,'Me gusta',4.00,'2026-10-02 21:21:30'),(279,2,1,2,153,'Me gusta',4.00,'2026-10-02 21:21:30'),(280,2,1,2,154,'Me gusta',4.00,'2026-10-02 21:21:30'),(281,2,1,2,155,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(282,2,1,2,156,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(283,2,1,2,157,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(284,2,1,2,158,'Me gusta',4.00,'2026-10-02 21:21:30'),(285,2,1,2,159,'Me gusta mucho',5.00,'2026-10-02 21:21:30'),(286,2,1,2,160,'Me gusta',4.00,'2026-10-02 21:21:30'),(287,2,1,2,161,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(288,2,1,2,162,'Me gusta',4.00,'2026-10-02 21:21:30'),(289,2,1,2,163,'Me gusta',4.00,'2026-10-02 21:21:30'),(290,2,1,2,164,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(291,2,1,2,165,'Me gusta',4.00,'2026-10-02 21:21:30'),(292,2,1,2,166,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(293,2,1,2,167,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(294,2,1,2,168,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(295,2,1,2,169,'Me gusta',4.00,'2026-10-02 21:21:30'),(296,2,1,2,170,'Me gusta',4.00,'2026-10-02 21:21:30'),(297,2,1,2,171,'Me gusta',4.00,'2026-10-02 21:21:30'),(298,2,1,2,172,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(299,2,1,2,173,'Me gusta',4.00,'2026-10-02 21:21:30'),(300,2,1,2,174,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(301,2,1,2,175,'Me gusta',4.00,'2026-10-02 21:21:30'),(302,2,1,2,176,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(303,2,1,2,177,'Me gusta mucho',5.00,'2026-10-02 21:21:30'),(304,2,1,2,178,'Me gusta',4.00,'2026-10-02 21:21:30'),(305,2,1,2,179,'Me gusta',4.00,'2026-10-02 21:21:30'),(306,2,1,2,180,'Me gusta',4.00,'2026-10-02 21:21:30'),(307,2,1,2,181,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(308,2,1,2,182,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(309,2,1,2,183,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(310,2,1,2,184,'Me gusta mucho',5.00,'2026-10-02 21:21:30'),(311,2,1,2,185,'Me desagrada',2.00,'2026-10-02 21:21:30'),(312,2,1,2,186,'Me gusta',4.00,'2026-10-02 21:21:30'),(313,2,1,2,187,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(314,2,1,2,188,'Me gusta mucho',5.00,'2026-10-02 21:21:30'),(315,2,1,2,189,'Me desagrada',2.00,'2026-10-02 21:21:30'),(316,2,1,2,190,'Me gusta',4.00,'2026-10-02 21:21:30'),(317,2,1,2,191,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(318,2,1,2,192,'Me gusta',4.00,'2026-10-02 21:21:30'),(319,2,1,2,193,'Me gusta mucho',5.00,'2026-10-02 21:21:30'),(320,2,1,2,194,'Me gusta',4.00,'2026-10-02 21:21:30'),(321,2,1,2,195,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(322,2,1,2,196,'Me gusta mucho',5.00,'2026-10-02 21:21:30'),(323,2,1,2,197,'Me desagrada',2.00,'2026-10-02 21:21:30'),(324,2,1,2,198,'Me gusta',4.00,'2026-10-02 21:21:30'),(325,2,1,2,199,'Me gusta',4.00,'2026-10-02 21:21:30'),(326,2,1,2,200,'Me es indiferente',3.00,'2026-10-02 21:21:30'),(327,2,1,2,201,'Me gusta mucho',5.00,'2026-10-02 21:21:30'),(328,2,1,2,202,'Me gusta',4.00,'2026-10-02 21:21:30'),(329,2,1,2,203,'Me es indiferente',3.00,'2026-10-02 21:21:31'),(330,2,1,2,204,'Me gusta',4.00,'2026-10-02 21:21:31'),(331,2,1,2,205,'Me es indiferente',3.00,'2026-10-02 21:21:31'),(332,2,1,2,206,'Me es indiferente',3.00,'2026-10-02 21:21:31'),(333,2,1,2,207,'Me gusta',4.00,'2026-10-02 21:21:31'),(334,2,1,2,208,'Me gusta',4.00,'2026-10-02 21:21:31'),(335,2,1,2,209,'Me desagrada',2.00,'2026-10-02 21:21:31'),(336,2,1,2,210,'Me gusta',4.00,'2026-10-02 21:21:31'),(337,2,1,2,211,'Me gusta',4.00,'2026-10-02 21:21:31'),(338,2,1,2,212,'Me gusta',4.00,'2026-10-02 21:21:31'),(339,2,1,2,213,'Me gusta',4.00,'2026-10-02 21:21:31'),(340,2,1,2,214,'Me gusta',4.00,'2026-10-02 21:21:31'),(341,2,1,2,215,'Me gusta',4.00,'2026-10-02 21:21:31'),(342,2,1,2,216,'Me es indiferente',3.00,'2026-10-02 21:21:31'),(343,2,1,2,217,'Me es indiferente',3.00,'2026-10-02 21:21:31'),(344,2,1,2,218,'Me es indiferente',3.00,'2026-10-02 21:21:31'),(345,2,1,2,219,'Me gusta mucho',5.00,'2026-10-02 21:21:31'),(346,2,1,2,220,'Me es indiferente',3.00,'2026-10-02 21:21:31'),(347,2,1,2,221,'Me es indiferente',3.00,'2026-10-02 21:21:31'),(348,2,1,2,222,'Me gusta',4.00,'2026-10-02 21:21:31'),(349,2,1,2,223,'Me es indiferente',3.00,'2026-10-02 21:21:31'),(350,2,1,2,224,'Me gusta',4.00,'2026-10-02 21:21:31'),(351,2,1,2,225,'Me gusta',4.00,'2026-10-02 21:21:31'),(352,2,1,2,226,'Me es indiferente',3.00,'2026-10-02 21:21:31'),(353,2,1,2,227,'Me es indiferente',3.00,'2026-10-02 21:21:31'),(354,2,1,2,228,'Me es indiferente',3.00,'2026-10-02 21:21:31'),(355,2,1,2,229,'Me es indiferente',3.00,'2026-10-02 21:21:31'),(356,2,1,2,230,'Me gusta',4.00,'2026-10-02 21:21:31'),(357,2,1,2,231,'Me es indiferente',3.00,'2026-10-02 21:21:31'),(358,2,1,2,232,'Me gusta',4.00,'2026-10-02 21:21:31'),(359,2,1,2,233,'Me gusta',4.00,'2026-10-02 21:21:31'),(360,2,1,2,234,'Me es indiferente',3.00,'2026-10-02 21:21:31'),(361,2,1,2,235,'Me gusta mucho',5.00,'2026-10-02 21:21:31'),(362,2,1,2,236,'Me gusta',4.00,'2026-10-02 21:21:31'),(363,2,1,2,237,'Me gusta mucho',5.00,'2026-10-02 21:21:31'),(364,2,1,2,238,'Me gusta',4.00,'2026-10-02 21:21:31'),(365,2,1,2,239,'Me gusta',4.00,'2026-10-02 21:21:31'),(366,2,1,2,240,'Me gusta',4.00,'2026-10-02 21:21:31'),(367,2,1,2,241,'Me gusta',4.00,'2026-10-02 21:21:31'),(368,2,1,2,242,'Me gusta',4.00,'2026-10-02 21:21:31'),(369,1,1,1,101,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:05'),(370,1,1,1,102,'En desacuerdo',2.00,'2026-10-03 01:22:05'),(371,1,1,1,103,'De acuerdo',4.00,'2026-10-03 01:22:05'),(372,1,1,1,104,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:05'),(373,1,1,1,105,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:05'),(374,1,1,1,106,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:05'),(375,1,1,1,107,'De acuerdo',4.00,'2026-10-03 01:22:05'),(376,1,1,1,108,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:05'),(377,1,1,1,109,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:05'),(378,1,1,1,110,'En desacuerdo',2.00,'2026-10-03 01:22:05'),(379,1,1,1,111,'De acuerdo',4.00,'2026-10-03 01:22:05'),(380,1,1,1,112,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:05'),(381,1,1,1,113,'De acuerdo',4.00,'2026-10-03 01:22:05'),(382,1,1,1,114,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:06'),(383,1,1,1,115,'De acuerdo',4.00,'2026-10-03 01:22:06'),(384,1,1,1,116,'De acuerdo',4.00,'2026-10-03 01:22:06'),(385,1,1,1,117,'De acuerdo',4.00,'2026-10-03 01:22:06'),(386,1,1,1,118,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:06'),(387,1,1,1,119,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:06'),(388,1,1,1,120,'En desacuerdo',2.00,'2026-10-03 01:22:06'),(389,1,1,1,121,'De acuerdo',4.00,'2026-10-03 01:22:06'),(390,1,1,1,122,'En desacuerdo',2.00,'2026-10-03 01:22:06'),(391,1,1,1,123,'De acuerdo',4.00,'2026-10-03 01:22:06'),(392,1,1,1,124,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:06'),(393,1,1,1,125,'De acuerdo',4.00,'2026-10-03 01:22:06'),(394,1,1,1,126,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:06'),(395,1,1,1,127,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:06'),(396,1,1,1,128,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:06'),(397,1,1,1,129,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:06'),(398,1,1,1,130,'En desacuerdo',2.00,'2026-10-03 01:22:06'),(399,1,1,1,131,'De acuerdo',4.00,'2026-10-03 01:22:06'),(400,1,1,1,132,'En desacuerdo',2.00,'2026-10-03 01:22:06'),(401,1,1,1,133,'De acuerdo',4.00,'2026-10-03 01:22:06'),(402,1,1,1,134,'En desacuerdo',2.00,'2026-10-03 01:22:06'),(403,1,1,1,135,'De acuerdo',4.00,'2026-10-03 01:22:06'),(404,1,1,1,136,'De acuerdo',4.00,'2026-10-03 01:22:06'),(405,1,1,1,137,'De acuerdo',4.00,'2026-10-03 01:22:06'),(406,1,1,1,138,'En desacuerdo',2.00,'2026-10-03 01:22:06'),(407,1,1,1,139,'En desacuerdo',2.00,'2026-10-03 01:22:06'),(408,1,1,1,140,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:06'),(409,1,1,1,141,'De acuerdo',4.00,'2026-10-03 01:22:06'),(410,1,1,1,142,'De acuerdo',4.00,'2026-10-03 01:22:06'),(411,1,1,1,143,'De acuerdo',4.00,'2026-10-03 01:22:06'),(412,1,1,1,144,'En desacuerdo',2.00,'2026-10-03 01:22:06'),(413,1,1,1,145,'De acuerdo',4.00,'2026-10-03 01:22:06'),(414,1,1,1,146,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:06'),(415,1,1,1,147,'De acuerdo',4.00,'2026-10-03 01:22:06'),(416,1,1,1,148,'Ni de acuerdo ni en desacuerdo',3.00,'2026-10-03 01:22:06'),(417,1,1,1,149,'En desacuerdo',2.00,'2026-10-03 01:22:06'),(418,1,1,1,150,'De acuerdo',4.00,'2026-10-03 01:22:06');
/*!40000 ALTER TABLE `respuestas_prueba_prospecto` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `respuestas_raven`
--

DROP TABLE IF EXISTS `respuestas_raven`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `respuestas_raven` (
  `id_respuesta_raven` int(11) NOT NULL AUTO_INCREMENT,
  `id_habilitacion` int(11) NOT NULL,
  `id_prospecto` int(11) NOT NULL,
  `id_prueba_rh` int(11) NOT NULL,
  `id_reactivo` int(11) NOT NULL,
  `respuesta` int(11) NOT NULL,
  `correcta` tinyint(1) NOT NULL DEFAULT 0,
  `fecha_respuesta` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_respuesta_raven`),
  UNIQUE KEY `uk_raven_respuesta` (`id_habilitacion`,`id_reactivo`),
  KEY `idx_raven_habilitacion` (`id_habilitacion`),
  KEY `idx_raven_prospecto` (`id_prospecto`)
) ENGINE=InnoDB AUTO_INCREMENT=181 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `respuestas_raven`
--

LOCK TABLES `respuestas_raven` WRITE;
/*!40000 ALTER TABLE `respuestas_raven` DISABLE KEYS */;
/*!40000 ALTER TABLE `respuestas_raven` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `resultados_beta3`
--

DROP TABLE IF EXISTS `resultados_beta3`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `resultados_beta3` (
  `id_resultado_beta3` int(11) NOT NULL AUTO_INCREMENT,
  `id_resultado` int(11) DEFAULT NULL,
  `id_habilitacion` int(11) NOT NULL,
  `id_prospecto` int(11) NOT NULL,
  `id_prueba_rh` int(11) NOT NULL DEFAULT 4,
  `claves_bruto` int(11) DEFAULT NULL,
  `figuras_bruto` int(11) DEFAULT NULL,
  `pares_bruto` int(11) DEFAULT NULL,
  `objetos_bruto` int(11) DEFAULT NULL,
  `matrices_bruto` int(11) DEFAULT NULL,
  `claves_escalar` decimal(6,2) DEFAULT NULL,
  `figuras_escalar` decimal(6,2) DEFAULT NULL,
  `pares_escalar` decimal(6,2) DEFAULT NULL,
  `objetos_escalar` decimal(6,2) DEFAULT NULL,
  `matrices_escalar` decimal(6,2) DEFAULT NULL,
  `suma_escalar` decimal(6,2) DEFAULT NULL,
  `edad_aplicacion` int(11) DEFAULT NULL,
  `ci` int(11) DEFAULT NULL,
  `percentil` decimal(6,2) DEFAULT NULL,
  `clasificacion` varchar(100) DEFAULT NULL,
  `interpretacion` text DEFAULT NULL,
  `tiempo_total_segundos` int(11) DEFAULT NULL,
  `fecha` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_resultado_beta3`),
  UNIQUE KEY `uk_beta3_habilitacion` (`id_habilitacion`),
  KEY `idx_beta3_resultado` (`id_resultado`),
  KEY `idx_beta3_prospecto` (`id_prospecto`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `resultados_beta3`
--

LOCK TABLES `resultados_beta3` WRITE;
/*!40000 ALTER TABLE `resultados_beta3` DISABLE KEYS */;
/*!40000 ALTER TABLE `resultados_beta3` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `resultados_cleaver`
--

DROP TABLE IF EXISTS `resultados_cleaver`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `resultados_cleaver` (
  `id_resultado_cleaver` int(11) NOT NULL AUTO_INCREMENT,
  `id_resultado` int(11) DEFAULT NULL,
  `id_paciente` int(11) NOT NULL,
  `id_prueba` int(11) NOT NULL,
  `id_habilitacion` int(11) NOT NULL,
  `id_sesion` int(11) DEFAULT NULL,
  `m_d_bruto` int(11) DEFAULT NULL,
  `m_i_bruto` int(11) DEFAULT NULL,
  `m_s_bruto` int(11) DEFAULT NULL,
  `m_c_bruto` int(11) DEFAULT NULL,
  `l_d_bruto` int(11) DEFAULT NULL,
  `l_i_bruto` int(11) DEFAULT NULL,
  `l_s_bruto` int(11) DEFAULT NULL,
  `l_c_bruto` int(11) DEFAULT NULL,
  `t_d_bruto` int(11) DEFAULT NULL,
  `t_i_bruto` int(11) DEFAULT NULL,
  `t_s_bruto` int(11) DEFAULT NULL,
  `t_c_bruto` int(11) DEFAULT NULL,
  `m_d_percentil` int(11) DEFAULT NULL,
  `m_d_posicion` decimal(6,2) DEFAULT NULL,
  `m_i_percentil` int(11) DEFAULT NULL,
  `m_i_posicion` decimal(6,2) DEFAULT NULL,
  `m_s_percentil` int(11) DEFAULT NULL,
  `m_s_posicion` decimal(6,2) DEFAULT NULL,
  `m_c_percentil` int(11) DEFAULT NULL,
  `m_c_posicion` decimal(6,2) DEFAULT NULL,
  `l_d_percentil` int(11) DEFAULT NULL,
  `l_d_posicion` decimal(6,2) DEFAULT NULL,
  `l_i_percentil` int(11) DEFAULT NULL,
  `l_i_posicion` decimal(6,2) DEFAULT NULL,
  `l_s_percentil` int(11) DEFAULT NULL,
  `l_s_posicion` decimal(6,2) DEFAULT NULL,
  `l_c_percentil` int(11) DEFAULT NULL,
  `l_c_posicion` decimal(6,2) DEFAULT NULL,
  `t_d_percentil` int(11) DEFAULT NULL,
  `t_d_posicion` decimal(6,2) DEFAULT NULL,
  `t_i_percentil` int(11) DEFAULT NULL,
  `t_i_posicion` decimal(6,2) DEFAULT NULL,
  `t_s_percentil` int(11) DEFAULT NULL,
  `t_s_posicion` decimal(6,2) DEFAULT NULL,
  `t_c_percentil` int(11) DEFAULT NULL,
  `t_c_posicion` decimal(6,2) DEFAULT NULL,
  `perfil_principal` varchar(100) DEFAULT NULL,
  `interpretacion` text DEFAULT NULL,
  `fecha` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_resultado_cleaver`),
  UNIQUE KEY `uq_resultado_cleaver_habilitacion` (`id_habilitacion`),
  UNIQUE KEY `uq_resultado_cleaver_general` (`id_resultado`),
  KEY `idx_resultado_cleaver_paciente` (`id_paciente`),
  KEY `fk_resultado_cleaver_prueba` (`id_prueba`),
  CONSTRAINT `fk_resultado_cleaver_general` FOREIGN KEY (`id_resultado`) REFERENCES `resultados_prueba` (`id_resultado`) ON DELETE CASCADE,
  CONSTRAINT `fk_resultado_cleaver_habilitacion` FOREIGN KEY (`id_habilitacion`) REFERENCES `pruebas_habilitadas` (`id_habilitacion`) ON DELETE CASCADE,
  CONSTRAINT `fk_resultado_cleaver_prueba` FOREIGN KEY (`id_prueba`) REFERENCES `pruebas` (`id_prueba`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `resultados_cleaver`
--

LOCK TABLES `resultados_cleaver` WRITE;
/*!40000 ALTER TABLE `resultados_cleaver` DISABLE KEYS */;
INSERT INTO `resultados_cleaver` VALUES (1,10,1,4,12,19,6,5,6,3,6,4,3,6,0,1,3,-3,NULL,45.00,NULL,72.00,NULL,64.00,NULL,31.00,NULL,45.00,NULL,59.00,NULL,88.00,NULL,58.00,NULL,47.00,NULL,61.00,NULL,75.00,NULL,40.00,'S/C - Persistencia','Tiende a ser perseverante y, una vez tomada una decisión, procura mantener el objetivo establecido. Suele adoptar un ritmo de trabajo y apegarse a él, pudiendo mostrar resistencia cuando se le presiona para cambiar.','2026-10-09 17:52:10'),(6,12,3,4,15,22,5,1,6,5,9,3,7,4,-4,-2,-1,1,NULL,40.00,NULL,10.00,NULL,64.00,NULL,72.00,NULL,22.00,NULL,74.00,NULL,39.00,NULL,82.00,NULL,27.00,NULL,34.00,NULL,45.00,NULL,77.00,'C/D - Adaptabilidad','Tiende a actuar de manera cuidadosa y conservadora. Puede modificar su posición cuando considera que esto facilita el logro de sus objetivos y suele preferir ambientes con poco antagonismo.','2026-11-09 23:55:55'),(7,14,3,4,19,23,2,8,7,3,6,5,4,3,-4,3,3,0,NULL,10.00,NULL,95.00,NULL,75.00,NULL,31.00,NULL,45.00,NULL,43.00,NULL,78.00,NULL,91.00,NULL,27.00,NULL,78.00,NULL,75.00,NULL,67.00,'I/D - Buena Voluntad','Tiende a mostrarse cordial y equilibrado en sus relaciones. Busca establecer un ambiente favorable y relaciones armoniosas desde el contacto inicial.','2026-11-10 21:09:16'),(8,15,3,4,20,24,8,2,4,5,3,5,6,9,5,-3,-2,-4,NULL,67.00,NULL,22.00,NULL,40.00,NULL,72.00,NULL,78.00,NULL,43.00,NULL,57.00,NULL,22.00,NULL,70.00,NULL,28.00,NULL,40.00,NULL,32.00,'D/I - Creatividad','Tiende a ser lógico, crítico e incisivo en sus enfoques hacia la obtención de metas. Puede sentirse retado por problemas que requieren análisis y originalidad, mostrando franqueza y una actitud crítica ante las situaciones.','2026-11-10 21:26:03');
/*!40000 ALTER TABLE `resultados_cleaver` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `resultados_prueba`
--

DROP TABLE IF EXISTS `resultados_prueba`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `resultados_prueba` (
  `id_resultado` int(11) NOT NULL AUTO_INCREMENT,
  `id_paciente` int(11) NOT NULL,
  `id_prueba` int(11) NOT NULL,
  `id_habilitacion` int(11) NOT NULL,
  `id_sesion` int(11) DEFAULT NULL,
  `puntaje_total` int(11) NOT NULL,
  `interpretacion` varchar(255) NOT NULL,
  `reporte_ia` longtext DEFAULT NULL,
  `fecha` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_resultado`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `resultados_prueba`
--

LOCK TABLES `resultados_prueba` WRITE;
/*!40000 ALTER TABLE `resultados_prueba` DISABLE KEYS */;
INSERT INTO `resultados_prueba` VALUES (1,1,3,1,1,12,'Ansiedad moderada',NULL,'2026-09-03 03:24:07'),(2,1,2,2,NULL,43,'Estrés alto',NULL,'2026-09-05 01:15:39'),(3,1,1,3,NULL,39,'Depresión severa',NULL,'2026-09-05 02:43:18'),(4,1,3,4,2,13,'Ansiedad moderada',NULL,'2026-09-05 04:59:18'),(5,1,3,5,6,13,'Ansiedad moderada',NULL,'2026-09-07 18:02:08'),(6,1,3,6,8,12,'Ansiedad moderada',NULL,'2026-09-07 18:42:35'),(7,1,2,7,9,47,'Estrés alto',NULL,'2026-09-07 19:27:56'),(8,1,3,8,NULL,14,'Ansiedad moderada',NULL,'2026-09-23 19:19:16'),(9,1,4,11,19,0,'Sin interpretación',NULL,'2026-10-08 21:37:36'),(10,1,4,12,19,0,'Resultado multidimensional Cleaver. Consulte el detalle D/I/S/C.',NULL,'2026-10-09 17:52:10'),(11,2,3,13,20,13,'Ansiedad moderada',NULL,'2026-10-27 16:42:57'),(12,3,4,15,22,0,'Resultado multidimensional Cleaver. Consulte el detalle D/I/S/C.',NULL,'2026-11-09 23:55:55'),(13,3,2,17,22,37,'Estrés alto',NULL,'2026-11-10 16:20:41'),(14,3,4,19,23,0,'Resultado multidimensional Cleaver. Consulte el detalle D/I/S/C.',NULL,'2026-11-10 21:09:16'),(15,3,4,20,24,0,'Resultado multidimensional Cleaver. Consulte el detalle D/I/S/C.',NULL,'2026-11-10 21:26:03'),(16,3,3,21,24,14,'Ansiedad moderada',NULL,'2026-11-10 21:26:25');
/*!40000 ALTER TABLE `resultados_prueba` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `resultados_prueba_empleado`
--

DROP TABLE IF EXISTS `resultados_prueba_empleado`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `resultados_prueba_empleado` (
  `id_resultado` int(11) NOT NULL AUTO_INCREMENT,
  `id_habilitacion` int(11) NOT NULL,
  `id_empleado` int(11) NOT NULL,
  `id_prueba_rh` int(11) NOT NULL,
  `puntaje_total` decimal(10,2) DEFAULT NULL,
  `resultado_texto` varchar(255) DEFAULT NULL,
  `interpretacion` longtext DEFAULT NULL,
  `interpretacion_laboral` longtext DEFAULT NULL,
  `fortalezas` longtext DEFAULT NULL,
  `areas_atencion` longtext DEFAULT NULL,
  `indicadores_prevencion` longtext DEFAULT NULL,
  `recomendaciones` longtext DEFAULT NULL,
  `preevaluacion_ia` text DEFAULT NULL,
  `ia_proveedor` varchar(50) DEFAULT NULL,
  `ia_modelo` varchar(100) DEFAULT NULL,
  `fecha_preevaluacion_ia` datetime DEFAULT NULL,
  `generado_por_ia` tinyint(1) NOT NULL DEFAULT 0,
  `fecha_resultado` datetime NOT NULL DEFAULT current_timestamp(),
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `actualizado_en` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_resultado`),
  UNIQUE KEY `uq_rpe_habilitacion` (`id_habilitacion`),
  KEY `idx_resultado_empleado` (`id_empleado`),
  KEY `idx_resultado_prueba` (`id_prueba_rh`),
  KEY `idx_resultado_fecha` (`fecha_resultado`),
  CONSTRAINT `fk_resultado_empleado` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id_empleado`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_resultado_empleado_habilitacion` FOREIGN KEY (`id_habilitacion`) REFERENCES `pruebas_empleados_habilitadas` (`id_habilitacion`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_resultado_empleado_prueba` FOREIGN KEY (`id_prueba_rh`) REFERENCES `pruebas_rh` (`id_prueba_rh`) ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `resultados_prueba_empleado`
--

LOCK TABLES `resultados_prueba_empleado` WRITE;
/*!40000 ALTER TABLE `resultados_prueba_empleado` DISABLE KEYS */;
INSERT INTO `resultados_prueba_empleado` VALUES (1,3,3,6,11.00,'GAD-7 — Tamizaje preventivo\n\nPuntaje técnico: 11/21\nResultado preventivo: Indicadores moderados\n\nEl resultado corresponde a un instrumento de tamizaje.\nNo constituye diagnóstico médico o psicológico.','El resultado del GAD-7 corresponde a indicadores moderados dentro de la escala de puntuación del instrumento. El resultado debe utilizarse únicamente como tamizaje preventivo y no como diagnóstico.','El tamizaje muestra indicadores moderados que ameritan revisión preventiva. Recursos Humanos puede valorar la canalización voluntaria con un profesional.',NULL,NULL,NULL,NULL,'PRE-EVALUACIÓN IA\n\n**Interpretación:**\nBasado en el tamizaje preventivo GAD-7, el resultado indica indicadores moderados dentro de la escala de puntuación del instrumento. Esta herramienta de cribado no constituye un diagnóstico médico o psicológico.\n\n**Atención sugerida:**\nRecursos Humanos puede considerar la revisión preventiva de estos indicadores moderados. Se sugiere valorar la canalización voluntaria con un profesional, según las políticas internas.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no es un diagnóstico médico o psicológico, y la decisión final corresponde a Recursos Humanos.','gemini','gemini','2026-10-30 12:37:40',0,'2026-10-30 12:37:35','2026-10-30 18:37:35','2026-10-30 18:37:40'),(2,4,3,5,9.00,'Puntaje bruto obtenido: 9',NULL,NULL,NULL,NULL,NULL,NULL,'PRE-EVALUACIÓN IA\n\n**Interpretación:**\nSe aplicó el WHO-5 Índice de Bienestar, obteniendo un puntaje bruto de 9. Para este instrumento, las interpretaciones técnicas y laborales no están configuradas, por lo que no es posible extraer conclusiones definitivas a partir de este resultado.\n\n**Atención sugerida:**\nDado que la interpretación configurada no está disponible, se sugiere a Recursos Humanos considerar este puntaje bruto en su contexto, junto con cualquier otra información relevante. Puede ser útil revisar evaluaciones periódicas previas o futuras para identificar patrones.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión final corresponde a Recursos Humanos.','gemini','gemini','2026-10-30 12:47:19',0,'2026-10-30 12:47:13','2026-10-30 18:47:13','2026-10-30 18:47:19'),(3,6,3,5,12.00,'WHO-5 Índice de Bienestar\n\nPuntaje bruto: 12/25\nPuntaje porcentual: 48/100\n\nEl resultado se encuentra por debajo del punto de referencia utilizado para sugerir una revisión adicional del bienestar.\n\nEste resultado corresponde a un instrumento de tamizaje ','El resultado del WHO-5 muestra indicadores de bienestar reducido dentro del instrumento de tamizaje. La puntuación sugiere que conviene realizar una valoración adicional del bienestar, sin que esto represente por sí mismo un diagnóstico.','El tamizaje muestra indicadores que ameritan revisión preventiva. Recursos Humanos puede valorar seguimiento y, cuando corresponda, ofrecer opciones voluntarias de apoyo conforme a las políticas internas.',NULL,NULL,NULL,NULL,'PRE-EVALUACIÓN IA\n\n**Interpretación:**\nEl WHO-5 Índice de Bienestar, un instrumento de tamizaje, muestra un puntaje de 12/25, que se encuentra por debajo del punto de referencia establecido. Esto sugiere la presencia de indicadores de bienestar reducido dentro de la escala del instrumento.\n\n**Atención sugerida:**\nRecursos Humanos puede considerar la valoración de un seguimiento preventivo del bienestar del evaluado. Se sugiere evaluar la pertinencia de ofrecer opciones voluntarias de apoyo, conforme a las políticas internas de la organización.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión administrativa final corresponde a Recursos Humanos.','gemini','gemini','2026-10-30 12:49:46',0,'2026-10-30 12:49:41','2026-10-30 18:49:41','2026-10-30 18:49:46'),(4,7,3,5,17.00,'WHO-5 Índice de Bienestar\n\nPuntaje bruto: 17/25\nPuntaje porcentual: 68/100\n\nEl resultado no se encuentra por debajo del punto de referencia utilizado para sugerir una revisión adicional.\n\nEste resultado corresponde a un instrumento de tamizaje y no consti','El resultado del WHO-5 no se encuentra por debajo del punto de referencia utilizado para sugerir una valoración adicional. Debe interpretarse como información de tamizaje sobre bienestar y no como diagnóstico.','El resultado no activa por sí mismo una recomendación preventiva adicional basada en el punto de corte del instrumento. Recursos Humanos puede integrarlo con otras fuentes de información laboral cuando sea necesario.',NULL,NULL,NULL,NULL,'PRE-EVALUACIÓN IA\n\n**Interpretación:**\nEl puntaje obtenido en el WHO-5 (17/25) indica que el bienestar general no se encuentra por debajo del punto de referencia que activaría una revisión adicional según este instrumento de tamizaje. No se identifica una señal de alerta inmediata basada en este corte específico.\n\n**Atención sugerida:**\nRecursos Humanos puede integrar este resultado con otras fuentes de información laboral disponibles para tener una perspectiva completa del bienestar del colaborador. La periodicidad de esta evaluación permite monitorear tendencias en el tiempo.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión final corresponde a Recursos Humanos.','gemini','gemini','2026-10-30 12:56:26',0,'2026-10-30 12:56:20','2026-10-30 18:56:20','2026-10-30 18:56:26'),(5,8,3,5,13.00,'WHO-5 Índice de Bienestar\n\nPuntaje bruto: 13/25\nPuntaje porcentual: 52/100\n\nEl resultado no se encuentra por debajo del punto de referencia utilizado para sugerir una revisión adicional.\n\nEn términos sencillos, la persona reportó una frecuencia suficiente','El resultado del WHO-5 no se encuentra por debajo del punto de referencia utilizado para sugerir una valoración adicional. En términos sencillos, la persona reportó una frecuencia suficiente de experiencias positivas relacionadas con su bienestar reciente, como buen ánimo, tranquilidad, energía, descanso e interés en sus actividades cotidianas. Esto no descarta dificultades específicas y debe interpretarse únicamente como información de tamizaje, no como diagnóstico.','El resultado no activa por sí mismo una recomendación preventiva adicional basada en el punto de referencia del instrumento. En términos prácticos, el nivel global de bienestar reportado no muestra una señal que requiera seguimiento adicional únicamente por WHO-5. Recursos Humanos puede integrarlo con otras fuentes de información laboral cuando sea necesario.',NULL,NULL,NULL,NULL,'PRE-EVALUACIÓN IA\n\n**Interpretación:**\nEl WHO-5 Índice de Bienestar indica que el puntaje global de la persona (13/25) no se encuentra por debajo del punto de referencia para sugerir una revisión adicional. Se reporta una frecuencia suficiente de experiencias positivas recientes relacionadas con su bienestar general.\n\n**Atención sugerida:**\nRecursos Humanos puede integrar este resultado con otras fuentes de información laboral relevantes, según sea necesario. El WHO-5 por sí mismo no activa una recomendación preventiva adicional basada en su punto de referencia.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión administrativa final corresponde a Recursos Humanos.','gemini','gemini','2026-10-30 12:57:42',0,'2026-10-30 12:57:36','2026-10-30 18:57:36','2026-10-30 18:57:42'),(6,10,3,6,13.00,'GAD-7 — Tamizaje preventivo\n\nPuntaje técnico: 13/21\nResultado preventivo: Indicadores moderados\n\nEl resultado corresponde a un instrumento de tamizaje.\nNo constituye diagnóstico médico o psicológico.','El resultado del GAD-7 corresponde a indicadores moderados dentro de la escala de puntuación del instrumento. El resultado debe utilizarse únicamente como tamizaje preventivo y no como diagnóstico.','El tamizaje muestra indicadores moderados que ameritan revisión preventiva. Recursos Humanos puede valorar la canalización voluntaria con un profesional.',NULL,NULL,NULL,NULL,'PRE-EVALUACIÓN IA\n\n**Interpretación:**\nEl tamizaje GAD-7, realizado de forma periódica, indica indicadores moderados de ansiedad. Este resultado es preventivo y no constituye un diagnóstico médico o psicológico.\n\n**Atención sugerida:**\nRecursos Humanos podría considerar una revisión preventiva y valorar la canalización voluntaria con un profesional para un seguimiento adecuado.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión administrativa final corresponde a Recursos Humanos.','gemini','gemini','2026-11-03 15:42:06',0,'2026-11-03 15:41:59','2026-11-03 21:41:59','2026-11-03 21:42:06'),(7,11,4,6,15.00,'GAD-7 — Tamizaje preventivo\n\nPuntaje técnico: 15/21\nResultado preventivo: Indicadores elevados\n\nEl resultado corresponde a un instrumento de tamizaje.\nNo constituye diagnóstico médico o psicológico.','El resultado del GAD-7 corresponde a indicadores elevados dentro de la escala de puntuación del instrumento. El resultado debe utilizarse únicamente como tamizaje preventivo y no como diagnóstico.','El tamizaje muestra indicadores elevados que ameritan atención preventiva. Se recomienda que Recursos Humanos valore oportunamente la canalización con un profesional.',NULL,NULL,NULL,NULL,'PRE-EVALUACIÓN IA\n\n**Interpretación:**\nEl tamizaje preventivo de bienestar GAD-7 para ansiedad indica la presencia de indicadores elevados según la escala de puntuación del instrumento. Este resultado se utiliza exclusivamente como tamizaje.\n\n**Atención sugerida:**\nRecursos Humanos debe considerar que los indicadores elevados ameritan atención preventiva. Se recomienda valorar la canalización con un profesional para una revisión adecuada.\n\n**Nota:**\nEsta pre-evaluación es orientativa, no constituye un diagnóstico médico o psicológico, y la decisión final corresponde a Recursos Humanos.','gemini','gemini','2026-11-12 14:06:16',0,'2026-11-12 14:06:10','2026-11-12 20:06:10','2026-11-12 20:06:16');
/*!40000 ALTER TABLE `resultados_prueba_empleado` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `resultados_prueba_prospecto`
--

DROP TABLE IF EXISTS `resultados_prueba_prospecto`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `resultados_prueba_prospecto` (
  `id_resultado` int(11) NOT NULL AUTO_INCREMENT,
  `id_habilitacion` int(11) NOT NULL,
  `id_prospecto` int(11) NOT NULL,
  `id_prueba_rh` int(11) NOT NULL,
  `puntaje_total` decimal(10,2) DEFAULT NULL,
  `resultado_texto` text DEFAULT NULL,
  `interpretacion` text DEFAULT NULL,
  `interpretacion_laboral` text DEFAULT NULL,
  `fortalezas` text DEFAULT NULL,
  `areas_atencion` text DEFAULT NULL,
  `compatibilidad_puesto` text DEFAULT NULL,
  `recomendaciones` text DEFAULT NULL,
  `generado_por_ia` tinyint(1) NOT NULL DEFAULT 0,
  `fecha_resultado` datetime NOT NULL DEFAULT current_timestamp(),
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `actualizado_en` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_resultado`),
  UNIQUE KEY `uq_resultado_habilitacion` (`id_habilitacion`),
  KEY `idx_rpr_prospecto` (`id_prospecto`),
  KEY `idx_rpr_prueba` (`id_prueba_rh`),
  CONSTRAINT `fk_rpr_habilitacion` FOREIGN KEY (`id_habilitacion`) REFERENCES `pruebas_prospectos_habilitadas` (`id_habilitacion`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_rpr_prospecto` FOREIGN KEY (`id_prospecto`) REFERENCES `prospectos` (`id_prospecto`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_rpr_prueba_rh` FOREIGN KEY (`id_prueba_rh`) REFERENCES `pruebas_rh` (`id_prueba_rh`) ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `resultados_prueba_prospecto`
--

LOCK TABLES `resultados_prueba_prospecto` WRITE;
/*!40000 ALTER TABLE `resultados_prueba_prospecto` DISABLE KEYS */;
INSERT INTO `resultados_prueba_prospecto` VALUES (1,2,1,2,337.00,'ORVIS-92 — perfil de intereses vocacionales\n\nLiderazgo: suma 44/60 | promedio 3.67/5 | 12 reactivos\nOrganización: suma 50/65 | promedio 3.85/5 | 13 reactivos\nAltruismo: suma 49/65 | promedio 3.77/5 | 13 reactivos\nCreatividad: suma 54/70 | promedio 3.86/5 | 14 reactivos\nAnálisis: suma 36/50 | promedio 3.6/5 | 10 reactivos\nProducción / actividades prácticas: suma 37/50 | promedio 3.7/5 | 10 reactivos\nAventura: suma 31/50 | promedio 3.1/5 | 10 reactivos\nErudición: suma 36/50 | promedio 3.6/5 | 10 reactivos\n\nLas ocho escalas tienen diferente número de reactivos; por eso MirrorSoul conserva tanto la suma bruta como el promedio 1–5 de cada dimensión.\nNo se aplicaron puntos de corte ni categorías alto/medio/bajo.\nEl perfil describe intereses expresados y no determina por sí solo aptitud, contratación, rechazo ni diagnóstico psicológico.','Resultados calculados por las ocho escalas configuradas para ORVIS-92. Cada respuesta conserva su valor directo de 1 a 5; se reportan suma bruta y promedio por dimensión.','Uso descriptivo como apoyo para Recursos Humanos. El perfil puede ayudar a explorar áreas de interés laboral y vocacional, pero no constituye por sí solo una decisión de contratación ni una medida diagnóstica.',NULL,NULL,NULL,NULL,0,'2026-10-02 15:21:31','2026-10-02 21:21:31','2026-10-02 21:21:31'),(2,1,1,1,178.00,'IPIP-50 Big Five — puntuación por dimensiones\n\nExtraversión: 32/50\nAmabilidad: 38/50\nResponsabilidad: 36/50\nEstabilidad emocional: 34/50\nIntelecto / Apertura: 38/50\n\nLos reactivos invertidos fueron recodificados antes de calcular cada dimensión.\nEl IPIP-50 se interpreta por dimensiones. El puntaje acumulado no debe utilizarse como una medida global de personalidad, aptitud ni decisión de contratación.\nNo se aplicaron puntos de corte ni categorías bajo/medio/alto sin una referencia normativa definida para la población evaluada.','Resultados calculados conforme a la clave de puntuación del IPIP-50: reactivos directos 1–5, reactivos invertidos 5–1 y suma independiente de los 10 reactivos de cada dimensión.','Uso descriptivo como apoyo para Recursos Humanos. Estos resultados no determinan por sí solos idoneidad, contratación, rechazo ni diagnóstico psicológico.',NULL,NULL,NULL,NULL,0,'2026-10-02 19:22:06','2026-10-03 01:22:06','2026-10-03 01:22:06');
/*!40000 ALTER TABLE `resultados_prueba_prospecto` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `resultados_raven`
--

DROP TABLE IF EXISTS `resultados_raven`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `resultados_raven` (
  `id_resultado_raven` int(11) NOT NULL AUTO_INCREMENT,
  `id_resultado` int(11) DEFAULT NULL,
  `id_habilitacion` int(11) NOT NULL,
  `id_prospecto` int(11) NOT NULL,
  `id_prueba_rh` int(11) NOT NULL,
  `serie_a` int(11) NOT NULL DEFAULT 0,
  `serie_b` int(11) NOT NULL DEFAULT 0,
  `serie_c` int(11) NOT NULL DEFAULT 0,
  `serie_d` int(11) NOT NULL DEFAULT 0,
  `serie_e` int(11) NOT NULL DEFAULT 0,
  `puntaje_total` int(11) NOT NULL DEFAULT 0,
  `edad_aplicacion` int(11) DEFAULT NULL,
  `percentil` int(11) DEFAULT NULL,
  `rango` varchar(50) DEFAULT NULL,
  `clasificacion` varchar(150) DEFAULT NULL,
  `interpretacion` text DEFAULT NULL,
  `tiempo_segundos` int(11) DEFAULT NULL,
  `fecha` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_resultado_raven`),
  UNIQUE KEY `uk_raven_resultado` (`id_habilitacion`),
  KEY `idx_raven_resultado_prospecto` (`id_prospecto`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `resultados_raven`
--

LOCK TABLES `resultados_raven` WRITE;
/*!40000 ALTER TABLE `resultados_raven` DISABLE KEYS */;
/*!40000 ALTER TABLE `resultados_raven` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `resumen_prospectos_cerrados`
--

DROP TABLE IF EXISTS `resumen_prospectos_cerrados`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `resumen_prospectos_cerrados` (
  `id_resumen` int(11) NOT NULL AUTO_INCREMENT,
  `id_prospecto` int(11) NOT NULL,
  `id_admin_padre` int(11) DEFAULT NULL,
  `id_mirror` varchar(30) DEFAULT NULL,
  `nombre` varchar(150) NOT NULL,
  `puesto` varchar(150) DEFAULT NULL,
  `decision` enum('no_contratar') NOT NULL DEFAULT 'no_contratar',
  `motivo` text DEFAULT NULL,
  `resumen_pruebas` longtext DEFAULT NULL,
  `observacion_final` text DEFAULT NULL,
  `fecha_decision` datetime DEFAULT NULL,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_resumen`),
  UNIQUE KEY `uq_resumen_prospecto` (`id_prospecto`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `resumen_prospectos_cerrados`
--

LOCK TABLES `resumen_prospectos_cerrados` WRITE;
/*!40000 ALTER TABLE `resumen_prospectos_cerrados` DISABLE KEYS */;
INSERT INTO `resumen_prospectos_cerrados` VALUES (1,2,15,'MS-2026-24-FE-003','ARELY HERNANDEZ LUCAS','sistemas','no_contratar','falta experiencia','[{\"prueba\":\"Matrices Progresivas de Raven - Escala General\",\"puntaje_total\":\"45.00\",\"resultado\":\"Matrices Progresivas de Raven - Escala General\\n\\nSerie A: 10/12\\nSerie B: 11/12\\nSerie C: 11/12\\nSerie D: 9/12\\nSerie E: 4/12\\n\\nPuntaje bruto total: 45/60\\n\\nBanda percentilar: P50 – <P75\\nRango: III\\nClasificación: Término medio\",\"interpretacion\":\"Puntaje bruto: 45/60. Edad de aplicación: 24 años. Banda percentilar: P50 – <P75. Rango: III. Clasificación: Término medio. Baremo: Aguascalientes México - muestra total. Fuente normativa: Aguascalientes 1999-2000.\",\"interpretacion_laboral\":\"Resultado psicométrico de apoyo para Recursos Humanos. Debe interpretarse junto con la entrevista, experiencia, competencias y demás información del proceso de selección. No determina por sí solo contratación, rechazo o idoneidad laboral.\",\"fortalezas\":null,\"areas_atencion\":null,\"compatibilidad_puesto\":null,\"recomendaciones\":null,\"fecha_resultado\":\"2026-10-09T22:25:08.000Z\"},{\"prueba\":\"Beta III\",\"puntaje_total\":\"129.00\",\"resultado\":\"Beta III\\n\\nPuntuaciones naturales:\\nClaves: 123\\nFiguras incompletas: 24\\nPares iguales/desiguales: 24\\nObjetos equivocados: 24\\nMatrices: 25\\n\\nPuntuaciones escalares:\\nClaves: 18\\nFiguras incompletas: 18\\nPares: 4\\nObjetos: 14\\nMatrices: 16\\n\\nSuma escalar: 70\\nCI: 129\\nPercentil: 97.00\\nClasificación: Superior\\nIC 90%: 122-136\\nIC 95%: 120-138\",\"interpretacion\":\"Beta III obtuvo una puntuación de CI de 129. El resultado corresponde al percentil 97.00. Clasificación: Superior. Intervalo de confianza al 90%: 122-136. Intervalo de confianza al 95%: 120-138.\",\"interpretacion_laboral\":\"Resultado psicométrico de apoyo para Recursos Humanos. El resultado Beta III debe interpretarse junto con la entrevista, experiencia, competencias y demás información del proceso de selección. No debe utilizarse de manera aislada para decidir contratación, rechazo o idoneidad laboral.\",\"fortalezas\":null,\"areas_atencion\":null,\"compatibilidad_puesto\":null,\"recomendaciones\":null,\"fecha_resultado\":\"2026-10-15T18:21:58.000Z\"}]','ninguna','2026-10-20 11:52:25','2026-10-20 17:52:25'),(2,3,15,'MS-2026-30-MA-004','Abraham Rivera Salinas','sistemas','no_contratar','falta experiencia','[{\"prueba\":\"Beta III\",\"puntaje_total\":\"112.00\",\"resultado\":\"Beta III\\n\\nPuntuaciones naturales:\\nClaves: 79\\nFiguras incompletas: 24\\nPares iguales/desiguales: 31\\nObjetos equivocados: 24\\nMatrices: 19\\n\\nPuntuaciones escalares:\\nClaves: 11\\nFiguras incompletas: 18\\nPares: 6\\nObjetos: 14\\nMatrices: 11\\n\\nSuma escalar: 60\\nCI: 112\\nPercentil: 79.00\\nClasificación: Promedio alto\\nIC 90%: 105-119\\nIC 95%: 103-121\",\"interpretacion\":\"Beta III obtuvo una puntuación de CI de 112. El resultado corresponde al percentil 79.00. Clasificación: Promedio alto. Intervalo de confianza al 90%: 105-119. Intervalo de confianza al 95%: 103-121.\",\"interpretacion_laboral\":\"Resultado psicométrico de apoyo para Recursos Humanos. El resultado Beta III debe interpretarse junto con la entrevista, experiencia, competencias y demás información del proceso de selección. No debe utilizarse de manera aislada para decidir contratación, rechazo o idoneidad laboral.\",\"fortalezas\":null,\"areas_atencion\":null,\"compatibilidad_puesto\":null,\"recomendaciones\":null,\"fecha_resultado\":\"2026-10-20T18:30:58.000Z\"},{\"prueba\":\"ORVIS - Oregon Vocational Interest Scales\",\"puntaje_total\":\"344.00\",\"resultado\":\"ORVIS-92 — perfil de intereses vocacionales\\n\\nLiderazgo: suma 41/60 | promedio 3.42/5 | 12 reactivos\\nOrganización: suma 54/65 | promedio 4.15/5 | 13 reactivos\\nAltruismo: suma 48/65 | promedio 3.69/5 | 13 reactivos\\nCreatividad: suma 53/70 | promedio 3.79/5 | 14 reactivos\\nAnálisis: suma 41/50 | promedio 4.1/5 | 10 reactivos\\nProducción / actividades prácticas: suma 37/50 | promedio 3.7/5 | 10 reactivos\\nAventura: suma 32/50 | promedio 3.2/5 | 10 reactivos\\nErudición: suma 38/50 | promedio 3.8/5 | 10 reactivos\\n\\nLas ocho escalas tienen diferente número de reactivos; por eso MirrorSoul conserva tanto la suma bruta como el promedio 1–5 de cada dimensión.\\nNo se aplicaron puntos de corte ni categorías alto/medio/bajo.\\nEl perfil describe intereses expresados y no determina por sí solo aptitud, contratación, rechazo ni diagnóstico psicológico.\",\"interpretacion\":\"Resultados calculados por las ocho escalas configuradas para ORVIS-92. Cada respuesta conserva su valor directo de 1 a 5; se reportan suma bruta y promedio por dimensión.\",\"interpretacion_laboral\":\"Uso descriptivo como apoyo para Recursos Humanos. El perfil puede ayudar a explorar áreas de interés laboral y vocacional, pero no constituye por sí solo una decisión de contratación ni una medida diagnóstica.\",\"fortalezas\":null,\"areas_atencion\":null,\"compatibilidad_puesto\":null,\"recomendaciones\":null,\"fecha_resultado\":\"2026-10-20T18:56:07.000Z\"}]','paso todo solo le falta experiencia','2026-10-20 15:31:01','2026-10-20 21:31:01'),(3,8,36,'MS-2026-35-FE-011','MARI GARCIA','ventas','no_contratar','pruebas reprobadas','[{\"prueba\":\"Beta III\",\"puntaje_total\":\"99.00\",\"resultado\":\"Beta III\\n\\nPuntuaciones naturales:\\nClaves: 70\\nFiguras incompletas: 23\\nPares iguales/desiguales: 29\\nObjetos equivocados: 18\\nMatrices: 16\\n\\nPuntuaciones escalares:\\nClaves: 10\\nFiguras incompletas: 17\\nPares: 6\\nObjetos: 7\\nMatrices: 10\\n\\nSuma escalar: 50\\nCI: 99\\nPercentil: 47.00\\nClasificación: Promedio\\nIC 90%: 92-106\\nIC 95%: 90-108\",\"interpretacion\":\"Beta III obtuvo una puntuación de CI de 99. El resultado corresponde al percentil 47.00. Clasificación: Promedio. Intervalo de confianza al 90%: 92-106. Intervalo de confianza al 95%: 90-108.\",\"interpretacion_laboral\":\"Resultado psicométrico de apoyo para Recursos Humanos. El resultado Beta III debe interpretarse junto con la entrevista, experiencia, competencias y demás información del proceso de selección. No debe utilizarse de manera aislada para decidir contratación, rechazo o idoneidad laboral.\",\"fortalezas\":null,\"areas_atencion\":null,\"compatibilidad_puesto\":null,\"recomendaciones\":null,\"fecha_resultado\":\"2026-11-12T16:44:07.000Z\"},{\"prueba\":\"Matrices Progresivas de Raven - Escala General\",\"puntaje_total\":\"28.00\",\"resultado\":\"Matrices Progresivas de Raven - Escala General\\n\\nSerie A: 11/12\\nSerie B: 11/12\\nSerie C: 3/12\\nSerie D: 1/12\\nSerie E: 2/12\\n\\nPuntaje bruto total: 28/60\\n\\nBanda percentilar: P5 – <P10\\nRango: IV\\nClasificación: Inferior al término medio\",\"interpretacion\":\"Puntaje bruto: 28/60. Edad de aplicación: 35 años. Banda percentilar: P5 – <P10. Rango: IV. Clasificación: Inferior al término medio. Baremo: Aguascalientes México - muestra total. Fuente normativa: Aguascalientes 1999-2000.\",\"interpretacion_laboral\":\"Resultado psicométrico de apoyo para Recursos Humanos. Debe interpretarse junto con la entrevista, experiencia, competencias y demás información del proceso de selección. No determina por sí solo contratación, rechazo o idoneidad laboral.\",\"fortalezas\":null,\"areas_atencion\":null,\"compatibilidad_puesto\":null,\"recomendaciones\":null,\"fecha_resultado\":\"2026-11-12T17:35:25.000Z\"}]','ninguna','2026-11-12 12:41:51','2026-11-12 18:41:51'),(4,10,36,'MS-2026-35-MA-013','PEDRO PEREZ','ventas','no_contratar','mo','[]','no','2026-11-12 13:02:51','2026-11-12 19:02:51');
/*!40000 ALTER TABLE `resumen_prospectos_cerrados` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `resumen_seleccion_empleados`
--

DROP TABLE IF EXISTS `resumen_seleccion_empleados`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `resumen_seleccion_empleados` (
  `id_resumen` int(11) NOT NULL AUTO_INCREMENT,
  `id_empleado` int(11) NOT NULL,
  `id_prospecto_origen` int(11) DEFAULT NULL,
  `decision` enum('contratar','no_contratar') NOT NULL,
  `motivo` text DEFAULT NULL,
  `observacion_final` text DEFAULT NULL,
  `resumen_pruebas` longtext DEFAULT NULL,
  `fecha_decision` datetime DEFAULT NULL,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_resumen`),
  UNIQUE KEY `uq_resumen_empleado` (`id_empleado`),
  CONSTRAINT `fk_resumen_empleado` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id_empleado`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `resumen_seleccion_empleados`
--

LOCK TABLES `resumen_seleccion_empleados` WRITE;
/*!40000 ALTER TABLE `resumen_seleccion_empleados` DISABLE KEYS */;
INSERT INTO `resumen_seleccion_empleados` VALUES (1,2,4,'contratar','buen elemento tiene experiencia y cartas de referencia','ninguna','[{\"prueba\":\"Beta III\",\"puntaje_total\":\"105.00\",\"resultado\":\"Beta III\\n\\nPuntuaciones naturales:\\nClaves: 95\\nFiguras incompletas: 23\\nPares iguales/desiguales: 26\\nObjetos equivocados: 20\\nMatrices: 17\\n\\nPuntuaciones escalares:\\nClaves: 15\\nFiguras incompletas: 17\\nPares: 5\\nObjetos: 8\\nMatrices: 9\\n\\nSuma escalar: 54\\nCI: 105\\nPercentil: 63.00\\nClasificación: Promedio\\nIC 90%: 98-112\\nIC 95%: 96-114\",\"interpretacion\":\"Beta III obtuvo una puntuación de CI de 105. El resultado corresponde al percentil 63.00. Clasificación: Promedio. Intervalo de confianza al 90%: 98-112. Intervalo de confianza al 95%: 96-114.\",\"interpretacion_laboral\":\"Resultado psicométrico de apoyo para Recursos Humanos. El resultado Beta III debe interpretarse junto con la entrevista, experiencia, competencias y demás información del proceso de selección. No debe utilizarse de manera aislada para decidir contratación, rechazo o idoneidad laboral.\",\"fortalezas\":null,\"areas_atencion\":null,\"compatibilidad_puesto\":null,\"recomendaciones\":null,\"fecha_resultado\":\"2026-10-20T23:00:43.000Z\"}]','2026-10-26 11:38:08','2026-10-26 17:38:08'),(2,3,5,'contratar','tiene experiencia limitada pero aprende rápido','prueba','[{\"prueba\":\"Beta III\",\"puntaje_total\":\"107.00\",\"resultado\":\"Beta III\\n\\nPuntuaciones naturales:\\nClaves: 107\\nFiguras incompletas: 23\\nPares iguales/desiguales: 30\\nObjetos equivocados: 18\\nMatrices: 18\\n\\nPuntuaciones escalares:\\nClaves: 16\\nFiguras incompletas: 17\\nPares: 6\\nObjetos: 7\\nMatrices: 10\\n\\nSuma escalar: 56\\nCI: 107\\nPercentil: 68.00\\nClasificación: Promedio\\nIC 90%: 100-114\\nIC 95%: 98-116\",\"interpretacion\":\"Beta III obtuvo una puntuación de CI de 107. El resultado corresponde al percentil 68.00. Clasificación: Promedio. Intervalo de confianza al 90%: 100-114. Intervalo de confianza al 95%: 98-116.\",\"interpretacion_laboral\":\"Resultado psicométrico de apoyo para Recursos Humanos. El resultado Beta III debe interpretarse junto con la entrevista, experiencia, competencias y demás información del proceso de selección. No debe utilizarse de manera aislada para decidir contratación, rechazo o idoneidad laboral.\",\"fortalezas\":null,\"areas_atencion\":null,\"compatibilidad_puesto\":null,\"recomendaciones\":null,\"fecha_resultado\":\"2026-10-26T19:09:04.000Z\"}]','2026-10-26 14:11:20','2026-10-26 20:11:20'),(3,4,9,'contratar','buena en vetantas','tiene experiencia se le haran mas pruebas de inteligencia posteriormente','[{\"prueba\":\"Matrices Progresivas de Raven - Escala General\",\"puntaje_total\":\"13.00\",\"resultado\":\"Matrices Progresivas de Raven - Escala General\\n\\nSerie A: 5/12\\nSerie B: 3/12\\nSerie C: 2/12\\nSerie D: 1/12\\nSerie E: 2/12\\n\\nPuntaje bruto total: 13/60\\n\\nBanda percentilar: < P5\\nRango: V\\nClasificación: Inferior al percentil 5\",\"interpretacion\":\"Puntaje bruto: 13/60. Edad de aplicación: 25 años. Banda percentilar: < P5. Rango: V. Clasificación: Inferior al percentil 5. Baremo: Aguascalientes México - muestra total. Fuente normativa: Aguascalientes 1999-2000.\",\"interpretacion_laboral\":\"Resultado psicométrico de apoyo para Recursos Humanos. Debe interpretarse junto con la entrevista, experiencia, competencias y demás información del proceso de selección. No determina por sí solo contratación, rechazo o idoneidad laboral.\",\"fortalezas\":null,\"areas_atencion\":null,\"compatibilidad_puesto\":null,\"recomendaciones\":null,\"fecha_resultado\":\"2026-11-12T18:50:36.000Z\"},{\"prueba\":\"ORVIS - Oregon Vocational Interest Scales\",\"puntaje_total\":\"346.00\",\"resultado\":\"ORVIS-92 — perfil de intereses vocacionales\\n\\nLiderazgo: suma 48/60 | promedio 4/5 | 12 reactivos\\nOrganización: suma 51/65 | promedio 3.92/5 | 13 reactivos\\nAltruismo: suma 51/65 | promedio 3.92/5 | 13 reactivos\\nCreatividad: suma 51/70 | promedio 3.64/5 | 14 reactivos\\nAnálisis: suma 32/50 | promedio 3.2/5 | 10 reactivos\\nProducción / actividades prácticas: suma 34/50 | promedio 3.4/5 | 10 reactivos\\nAventura: suma 37/50 | promedio 3.7/5 | 10 reactivos\\nErudición: suma 42/50 | promedio 4.2/5 | 10 reactivos\\n\\nLas ocho escalas tienen diferente número de reactivos; por eso MirrorSoul conserva tanto la suma bruta como el promedio 1–5 de cada dimensión.\\nNo se aplicaron puntos de corte ni categorías alto/medio/bajo.\\nEl perfil describe intereses expresados y no determina por sí solo aptitud, contratación, rechazo ni diagnóstico psicológico.\",\"interpretacion\":\"Resultados calculados por las ocho escalas configuradas para ORVIS-92. Cada respuesta conserva su valor directo de 1 a 5; se reportan suma bruta y promedio por dimensión.\",\"interpretacion_laboral\":\"Uso descriptivo como apoyo para Recursos Humanos. El perfil puede ayudar a explorar áreas de interés laboral y vocacional, pero no constituye por sí solo una decisión de contratación ni una medida diagnóstica.\",\"fortalezas\":null,\"areas_atencion\":null,\"compatibilidad_puesto\":null,\"recomendaciones\":null,\"fecha_resultado\":\"2026-11-12T18:53:46.000Z\"}]','2026-11-12 12:57:50','2026-11-12 18:57:50');
/*!40000 ALTER TABLE `resumen_seleccion_empleados` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `seguimiento_empleados`
--

DROP TABLE IF EXISTS `seguimiento_empleados`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `seguimiento_empleados` (
  `id_seguimiento` int(11) NOT NULL AUTO_INCREMENT,
  `id_empleado` int(11) NOT NULL,
  `id_usuario_registro` int(11) DEFAULT NULL,
  `fecha` datetime NOT NULL DEFAULT current_timestamp(),
  `tipo` enum('general','desempeno','bienestar','incidencia','adaptacion','seguimiento','prevencion') NOT NULL DEFAULT 'seguimiento',
  `prioridad` enum('baja','media','alta') NOT NULL DEFAULT 'media',
  `motivo` varchar(200) DEFAULT NULL,
  `participantes` text DEFAULT NULL,
  `version_empleado` text DEFAULT NULL,
  `version_supervisor` text DEFAULT NULL,
  `observacion` text NOT NULL,
  `accion_realizada` text DEFAULT NULL,
  `acuerdo` text DEFAULT NULL,
  `compromiso_empresa` text DEFAULT NULL,
  `compromiso_empleado` text DEFAULT NULL,
  `resultado` enum('pendiente','continua','resuelto','requiere_atencion','canalizacion_sugerida') NOT NULL DEFAULT 'pendiente',
  `estado` enum('abierto','en_seguimiento','cerrado','anulado') NOT NULL DEFAULT 'abierto',
  `proxima_accion` text DEFAULT NULL,
  `fecha_proxima_accion` datetime DEFAULT NULL,
  `fecha_cierre` datetime DEFAULT NULL,
  `id_usuario_cierre` int(11) DEFAULT NULL,
  `motivo_anulacion` text DEFAULT NULL,
  `fecha_anulacion` datetime DEFAULT NULL,
  `id_usuario_anulacion` int(11) DEFAULT NULL,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `actualizado_en` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_seguimiento`),
  KEY `idx_seg_empleado` (`id_empleado`),
  KEY `idx_seg_usuario` (`id_usuario_registro`),
  KEY `idx_seg_fecha` (`fecha`),
  KEY `idx_seg_resultado` (`resultado`),
  KEY `idx_seg_estado` (`estado`),
  KEY `idx_seg_prioridad` (`prioridad`),
  KEY `idx_seg_usuario_cierre` (`id_usuario_cierre`),
  KEY `idx_seg_usuario_anulacion` (`id_usuario_anulacion`),
  CONSTRAINT `fk_seg_empleado` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id_empleado`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_seg_empleado_usuario` FOREIGN KEY (`id_usuario_registro`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_seg_usuario_anulacion` FOREIGN KEY (`id_usuario_anulacion`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_seg_usuario_cierre` FOREIGN KEY (`id_usuario_cierre`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `seguimiento_empleados`
--

LOCK TABLES `seguimiento_empleados` WRITE;
/*!40000 ALTER TABLE `seguimiento_empleados` DISABLE KEYS */;
INSERT INTO `seguimiento_empleados` VALUES (1,3,19,'2026-10-27 14:01:00','incidencia','media','diferencia de opiniones','2 empleados','petra lo agredió primero','ambos se agredieron pero comenzo petra','se pelearon por que petra se comió su comida','petra le pagará su comida, y si vuelve a pasar habrá una suspensión','no volverán agarrar pertenencias que no son suyas','estar al pendiente y revisar primero','no tomar lo que no es de el','resuelto','cerrado','aun no','2026-10-27 14:04:00','2026-10-27 14:04:24',19,NULL,NULL,NULL,'2026-10-27 20:04:24','2026-10-27 20:04:24'),(2,4,36,'2026-11-12 13:50:00','incidencia','media','conflicto','2 empleados','El empleado marco a gredio al empleado Marilu','todos confirman que marco empezo','se hicieron de palabras por comentario machista','una suspencion a marco','se fue suspendido sin goce de sueldo 7 dias','la siguiente se va despedido','comenta que no volvera a pasar','pendiente','abierto','seguimiento','2026-11-18 13:54:00',NULL,NULL,NULL,NULL,NULL,'2026-11-12 19:54:48','2026-11-12 19:54:48');
/*!40000 ALTER TABLE `seguimiento_empleados` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `seguimiento_prospectos`
--

DROP TABLE IF EXISTS `seguimiento_prospectos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `seguimiento_prospectos` (
  `id_seguimiento` int(11) NOT NULL AUTO_INCREMENT,
  `id_prospecto` int(11) NOT NULL,
  `id_usuario_registro` int(11) DEFAULT NULL,
  `fecha` datetime NOT NULL DEFAULT current_timestamp(),
  `etapa` varchar(80) NOT NULL DEFAULT 'seguimiento',
  `actividad` varchar(150) NOT NULL,
  `observacion` text DEFAULT NULL,
  `resultado` enum('pendiente','continua','detenido','aprobado','no_aprobado') NOT NULL DEFAULT 'pendiente',
  `proxima_accion` text DEFAULT NULL,
  `fecha_proxima_accion` datetime DEFAULT NULL,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `actualizado_en` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id_seguimiento`),
  KEY `idx_seg_prospecto` (`id_prospecto`),
  KEY `idx_seg_usuario` (`id_usuario_registro`),
  KEY `idx_seg_fecha` (`fecha`),
  CONSTRAINT `fk_seg_prospecto` FOREIGN KEY (`id_prospecto`) REFERENCES `prospectos` (`id_prospecto`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_seg_usuario` FOREIGN KEY (`id_usuario_registro`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `seguimiento_prospectos`
--

LOCK TABLES `seguimiento_prospectos` WRITE;
/*!40000 ALTER TABLE `seguimiento_prospectos` DISABLE KEYS */;
INSERT INTO `seguimiento_prospectos` VALUES (1,1,15,'2026-09-16 21:24:17','registro','se revisa el perfiil','se muestra nervioso pero trae un buen cv','pendiente','seguiremos con pruebas','2026-09-16 21:24:00','2026-09-17 03:24:17','2026-09-17 03:24:17'),(2,1,15,'2026-09-22 11:25:52','revision','se revisa el perfiil','es bueno para trabaja bajo presión','pendiente','ya se aplicaro','2026-09-22 13:27:00','2026-09-22 17:25:52','2026-09-22 17:25:52');
/*!40000 ALTER TABLE `seguimiento_prospectos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sesiones`
--

DROP TABLE IF EXISTS `sesiones`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `sesiones` (
  `id_sesion` int(11) NOT NULL AUTO_INCREMENT,
  `id_cita` int(11) DEFAULT NULL,
  `id_paciente` int(11) NOT NULL,
  `numero_sesion` int(11) DEFAULT NULL,
  `modalidad` enum('presencial','videollamada') NOT NULL DEFAULT 'presencial',
  `notas` text DEFAULT NULL,
  `fecha` datetime DEFAULT current_timestamp(),
  `fecha_fin` datetime DEFAULT NULL,
  `link_videollamada` text DEFAULT NULL,
  `estado` enum('activa','finalizada') DEFAULT 'activa',
  PRIMARY KEY (`id_sesion`)
) ENGINE=InnoDB AUTO_INCREMENT=25 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sesiones`
--

LOCK TABLES `sesiones` WRITE;
/*!40000 ALTER TABLE `sesiones` DISABLE KEYS */;
INSERT INTO `sesiones` VALUES (1,NULL,1,1,'presencial','Sesión iniciada desde videollamada','2026-09-02 21:27:48','2026-09-02 21:28:37','https://www.reflejoyalma.com/SalaVideollamada/sala-1-1-1788406068786','finalizada'),(2,NULL,1,2,'presencial','Sesión presencial','2026-09-02 22:43:26','2026-09-05 00:09:12',NULL,'finalizada'),(6,NULL,1,3,'presencial','Sesión presencial','2026-09-07 12:01:36','2026-09-07 12:03:58',NULL,'finalizada'),(7,NULL,1,4,'videollamada','Sesión por videollamada','2026-09-07 12:41:04','2026-09-07 12:41:50','https://www.reflejoyalma.com/SalaVideollamada/sala-7-1-1788806464676','finalizada'),(8,NULL,1,5,'presencial','Sesión presencial','2026-09-07 12:42:13','2026-09-07 13:04:45',NULL,'finalizada'),(9,NULL,1,6,'videollamada','Sesión por videollamada','2026-09-07 13:26:12','2026-09-07 13:36:49','https://www.reflejoyalma.com/SalaVideollamada/sala-9-1-1788809172247','finalizada'),(10,NULL,1,7,'videollamada','Sesión iniciada desde videollamada','2026-09-07 14:29:02','2026-09-09 16:53:22','https://www.reflejoyalma.com/SalaVideollamada/sala-10-1-1788812942565','finalizada'),(11,NULL,1,8,'videollamada','Sesión por videollamada','2026-09-09 16:54:04','2026-09-14 13:18:21','https://www.reflejoyalma.com/SalaVideollamada/sala-11-1-1788994444212','finalizada'),(12,NULL,1,9,'presencial','Sesión presencial','2026-09-15 13:40:43','2026-09-15 15:50:06',NULL,'finalizada'),(13,NULL,1,10,'presencial','Sesión presencial','2026-09-15 15:55:24','2026-09-15 17:23:51',NULL,'finalizada'),(14,NULL,1,11,'presencial','Sesión presencial','2026-09-15 17:24:09','2026-09-15 22:10:30',NULL,'finalizada'),(15,NULL,1,12,'presencial','Sesión presencial','2026-09-15 22:10:41','2026-09-15 22:25:08',NULL,'finalizada'),(16,NULL,1,13,'videollamada','Sesión por videollamada','2026-09-15 22:25:22','2026-09-15 23:12:47','https://www.reflejoyalma.com/SalaVideollamada/sala-16-1-1789532723043','finalizada'),(17,NULL,1,14,'videollamada','Sesión por videollamada','2026-09-15 23:13:05','2026-09-15 23:43:30','https://www.reflejoyalma.com/SalaVideollamada/sala-17-1-1789535586043','finalizada'),(18,NULL,1,15,'presencial','Sesión presencial','2026-09-16 19:15:37','2026-10-05 12:04:03',NULL,'finalizada'),(19,NULL,1,16,'videollamada','Sesión presencial','2026-10-05 12:14:12',NULL,'http://192.168.100.21:5175/SalaVideollamada/sala-19-1-1792106770674','activa'),(20,NULL,2,1,'presencial','Sesión presencial','2026-10-27 10:40:50','2026-10-27 10:47:13',NULL,'finalizada'),(21,NULL,3,1,'videollamada','Sesión iniciada desde videollamada','2026-11-09 17:04:59','2026-11-09 17:28:14','https://www.reflejoyalma.com/SalaVideollamada/sala-21-3-1794265499685','finalizada'),(22,NULL,3,2,'videollamada','Sesión por videollamada','2026-11-09 17:29:49','2026-11-10 14:08:58','https://www.reflejoyalma.com/SalaVideollamada/sala-22-3-1794266989744','finalizada'),(23,NULL,3,3,'presencial','Sesión presencial','2026-11-10 14:37:55','2026-11-10 15:10:52',NULL,'finalizada'),(24,NULL,3,4,'presencial','Sesión presencial','2026-11-10 15:24:17',NULL,NULL,'activa');
/*!40000 ALTER TABLE `sesiones` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `subpruebas_beta3`
--

DROP TABLE IF EXISTS `subpruebas_beta3`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `subpruebas_beta3` (
  `id_subprueba` int(11) NOT NULL AUTO_INCREMENT,
  `id_prueba_rh` int(11) NOT NULL,
  `codigo` varchar(30) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `orden` int(11) NOT NULL,
  `tiempo_segundos` int(11) DEFAULT NULL,
  `descripcion` text DEFAULT NULL,
  `activo` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id_subprueba`),
  UNIQUE KEY `uk_beta3_subprueba` (`id_prueba_rh`,`codigo`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `subpruebas_beta3`
--

LOCK TABLES `subpruebas_beta3` WRITE;
/*!40000 ALTER TABLE `subpruebas_beta3` DISABLE KEYS */;
INSERT INTO `subpruebas_beta3` VALUES (1,4,'CLAVES','Claves',1,120,'Subprueba de asociación entre símbolos y claves.',1),(2,4,'FIGURAS_INCOMPLETAS','Figuras incompletas',2,150,'Identificación de elementos faltantes en figuras.',1),(3,4,'PARES','Pares iguales y pares desiguales',3,120,'Comparación visual de pares para identificar igualdad o diferencia.',1),(4,4,'OBJETOS_EQUIVOCADOS','Objetos equivocados',4,180,'Identificación de elementos incongruentes o incorrectos.',1),(5,4,'MATRICES','Matrices',5,300,'Resolución de relaciones y patrones visuales mediante matrices.',1);
/*!40000 ALTER TABLE `subpruebas_beta3` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `suscripciones`
--

DROP TABLE IF EXISTS `suscripciones`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `suscripciones` (
  `id_suscripcion` int(11) NOT NULL AUTO_INCREMENT,
  `id_organizacion` int(11) NOT NULL,
  `id_plan` int(11) NOT NULL,
  `estado` enum('prueba','activa','vencida','cancelada') NOT NULL DEFAULT 'prueba',
  `fecha_inicio` date NOT NULL,
  `fecha_fin` date DEFAULT NULL,
  `proxima_renovacion` date DEFAULT NULL,
  `licencias_totales` int(11) NOT NULL DEFAULT 1,
  `origen_suscripcion` enum('compra','manual','cortesia','prueba') NOT NULL DEFAULT 'manual',
  `motivo_beneficio` varchar(255) DEFAULT NULL,
  `otorgado_por` int(11) DEFAULT NULL,
  `fecha_otorgamiento` datetime DEFAULT NULL,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_suscripcion`),
  KEY `fk_suscripcion_organizacion` (`id_organizacion`),
  KEY `fk_suscripcion_plan` (`id_plan`),
  KEY `idx_suscripciones_origen` (`origen_suscripcion`),
  KEY `idx_suscripciones_otorgado_por` (`otorgado_por`),
  CONSTRAINT `fk_suscripcion_organizacion` FOREIGN KEY (`id_organizacion`) REFERENCES `organizaciones` (`id_organizacion`),
  CONSTRAINT `fk_suscripcion_plan` FOREIGN KEY (`id_plan`) REFERENCES `planes` (`id_plan`),
  CONSTRAINT `fk_suscripciones_otorgado_por` FOREIGN KEY (`otorgado_por`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `suscripciones`
--

LOCK TABLES `suscripciones` WRITE;
/*!40000 ALTER TABLE `suscripciones` DISABLE KEYS */;
INSERT INTO `suscripciones` VALUES (1,1,1,'activa','2026-11-05','2026-11-06','2026-12-07',5,'manual',NULL,NULL,NULL,'2026-11-05 23:23:17'),(2,2,2,'activa','2026-11-09',NULL,'2026-12-09',4,'prueba','Prueba gratuita comercial',1,'2026-11-09 13:00:56','2026-11-06 19:25:20'),(3,3,4,'activa','2026-11-09',NULL,'2026-12-09',1,'manual',NULL,NULL,NULL,'2026-11-09 18:06:31'),(4,4,4,'activa','2026-11-09',NULL,'2026-12-09',1,'prueba','prueba',1,'2026-11-09 16:59:45','2026-11-09 22:59:45'),(5,5,4,'activa','2026-11-12',NULL,'2026-12-12',1,'cortesia','prueba',1,'2026-11-12 09:43:59','2026-11-12 15:43:59');
/*!40000 ALTER TABLE `suscripciones` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `transferencias_empleados`
--

DROP TABLE IF EXISTS `transferencias_empleados`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `transferencias_empleados` (
  `id_transferencia` int(11) NOT NULL AUTO_INCREMENT,
  `id_empleado` int(11) NOT NULL,
  `id_usuario_responsable_anterior` int(11) DEFAULT NULL,
  `id_usuario_responsable_nuevo` int(11) NOT NULL,
  `id_usuario_autor` int(11) NOT NULL,
  `id_admin_padre` int(11) NOT NULL,
  `motivo` varchar(500) NOT NULL,
  `fecha_transferencia` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_transferencia`),
  KEY `idx_te_empleado` (`id_empleado`),
  KEY `idx_te_admin` (`id_admin_padre`),
  KEY `idx_te_fecha` (`fecha_transferencia`),
  KEY `fk_te_resp_anterior` (`id_usuario_responsable_anterior`),
  KEY `fk_te_resp_nuevo` (`id_usuario_responsable_nuevo`),
  KEY `fk_te_autor` (`id_usuario_autor`),
  CONSTRAINT `fk_te_autor` FOREIGN KEY (`id_usuario_autor`) REFERENCES `usuarios` (`id_usuario`) ON UPDATE CASCADE,
  CONSTRAINT `fk_te_empleado` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id_empleado`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_te_resp_anterior` FOREIGN KEY (`id_usuario_responsable_anterior`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_te_resp_nuevo` FOREIGN KEY (`id_usuario_responsable_nuevo`) REFERENCES `usuarios` (`id_usuario`) ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `transferencias_empleados`
--

LOCK TABLES `transferencias_empleados` WRITE;
/*!40000 ALTER TABLE `transferencias_empleados` DISABLE KEYS */;
INSERT INTO `transferencias_empleados` VALUES (1,3,15,19,15,14,'Ausencia temporal','2026-10-27 12:06:03'),(2,2,15,20,15,14,'Reorganización interna','2026-10-27 12:37:56');
/*!40000 ALTER TABLE `transferencias_empleados` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `transferencias_pacientes`
--

DROP TABLE IF EXISTS `transferencias_pacientes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `transferencias_pacientes` (
  `id_transferencia` int(11) NOT NULL AUTO_INCREMENT,
  `id_paciente` int(11) NOT NULL,
  `id_psicologo_anterior` int(11) DEFAULT NULL,
  `id_psicologo_nuevo` int(11) NOT NULL,
  `id_usuario_autor` int(11) NOT NULL,
  `id_admin_padre` int(11) NOT NULL,
  `motivo` varchar(500) NOT NULL,
  `fecha_transferencia` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_transferencia`),
  KEY `idx_tp_paciente` (`id_paciente`),
  KEY `idx_tp_admin` (`id_admin_padre`),
  KEY `idx_tp_fecha` (`fecha_transferencia`),
  KEY `fk_tp_psico_anterior` (`id_psicologo_anterior`),
  KEY `fk_tp_psico_nuevo` (`id_psicologo_nuevo`),
  KEY `fk_tp_autor` (`id_usuario_autor`),
  CONSTRAINT `fk_tp_autor` FOREIGN KEY (`id_usuario_autor`) REFERENCES `usuarios` (`id_usuario`) ON UPDATE CASCADE,
  CONSTRAINT `fk_tp_paciente` FOREIGN KEY (`id_paciente`) REFERENCES `pacientes` (`id_paciente`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_tp_psico_anterior` FOREIGN KEY (`id_psicologo_anterior`) REFERENCES `psicologos` (`id_psicologo`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_tp_psico_nuevo` FOREIGN KEY (`id_psicologo_nuevo`) REFERENCES `psicologos` (`id_psicologo`) ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `transferencias_pacientes`
--

LOCK TABLES `transferencias_pacientes` WRITE;
/*!40000 ALTER TABLE `transferencias_pacientes` DISABLE KEYS */;
INSERT INTO `transferencias_pacientes` VALUES (1,2,10,9,18,12,'Solicitud del paciente','2026-10-26 17:47:27'),(2,2,9,10,17,12,'Solicitud del paciente','2026-10-27 10:38:02'),(3,2,10,9,18,12,'Solicitud del paciente','2026-10-27 10:48:06'),(4,2,9,10,17,12,'Solicitud del paciente','2026-10-27 12:42:05'),(5,2,10,9,18,12,'Solicitud del paciente','2026-10-27 12:51:57');
/*!40000 ALTER TABLE `transferencias_pacientes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `usuarios`
--

DROP TABLE IF EXISTS `usuarios`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `usuarios` (
  `id_usuario` int(11) NOT NULL AUTO_INCREMENT,
  `nombre` varchar(120) NOT NULL,
  `puesto` varchar(150) DEFAULT NULL,
  `telefono` varchar(30) DEFAULT NULL,
  `direccion` varchar(255) DEFAULT NULL,
  `correo` varchar(120) DEFAULT NULL,
  `matricula` varchar(40) DEFAULT NULL,
  `password` varchar(255) NOT NULL,
  `debe_cambiar_password` tinyint(1) NOT NULL DEFAULT 0,
  `rol` enum('admin','psicologo','rh','educativo','independiente') NOT NULL,
  `tipo_admin` enum('master','normal') DEFAULT NULL,
  `area` enum('clinica','rh','educativo','independiente') DEFAULT NULL,
  `id_admin_padre` int(11) DEFAULT NULL,
  `id_organizacion` int(11) DEFAULT NULL,
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  `estado` enum('activo','inactivo') NOT NULL DEFAULT 'activo',
  PRIMARY KEY (`id_usuario`),
  UNIQUE KEY `matricula` (`matricula`),
  KEY `fk_usuario_organizacion` (`id_organizacion`),
  CONSTRAINT `fk_usuario_organizacion` FOREIGN KEY (`id_organizacion`) REFERENCES `organizaciones` (`id_organizacion`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=37 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `usuarios`
--

LOCK TABLES `usuarios` WRITE;
/*!40000 ALTER TABLE `usuarios` DISABLE KEYS */;
INSERT INTO `usuarios` VALUES (1,'Elizabeth',NULL,NULL,NULL,'lizma883@gmail.com',NULL,'$2b$10$hi1Mkmqx2kqZih3a3K/15OsWUkDsuKMUdVUDodnJv2yZ2cnfSk.uq',0,'admin','master',NULL,NULL,NULL,'2025-10-08 18:34:39','activo'),(2,'Liliana',NULL,'5512345678','Nezahualcóyotl','jp5247356@gmail.com',NULL,'$2b$10$Jc0bf1ibrNPdDMwcy4omeuWsIJIcoca4cN1r3Lo6lvvyRq9UYy2WC',0,'psicologo',NULL,NULL,NULL,NULL,'2025-10-08 19:13:28','activo'),(12,'SUSANA',NULL,NULL,NULL,'celic25@gmail.com',NULL,'$2b$10$y535luvcXnCzIWq8/BqYh.DtDngNox9FDJs4N02vHyCkRQ7zKXp.u',0,'admin','normal','clinica',1,1,'2026-08-26 03:22:18','activo'),(14,'Marisol',NULL,NULL,NULL,'marisol8989@gmail.com',NULL,'$2b$10$FJWVT4qqolk8fZib6/j8P.lYJGLc2O8QtsUgdQTfQLzAYazK83GWi',0,'admin','normal','rh',1,2,'2026-08-26 03:39:43','activo'),(15,'JUAN','Administrador','55465578889','la paz','juan89@gmail.com',NULL,'$2b$10$d2ZJtx3PEWyfvGbGGKa2/ORuYl5LpjiqVhUxdBtbccZVyC/okcm2O',0,'rh',NULL,'rh',14,NULL,'2026-08-26 04:50:24','activo'),(16,'Abraham Rivera Salinas',NULL,NULL,NULL,'riverasalinas@gmail.com',NULL,'$2b$10$aHgbMGFAMtZyV5wRdPkOIe22Sjd.C8oYiQTUImQJ7sWbTTsBKuUQG',0,'psicologo',NULL,'clinica',1,NULL,'2026-10-15 23:29:39','activo'),(17,'ARELY HERNANDEZ LUCAS',NULL,NULL,'5578963214','ary88@gmail.com',NULL,'$2b$10$J/CSpXt5/n7F1rgef6yxC.uwPKRsUPlDPmpDNTBfec5nlRFjRA0kC',0,'psicologo',NULL,'clinica',12,NULL,'2026-10-26 23:34:44','activo'),(18,'Abraham Rivera Salinas',NULL,NULL,'5546123214','abram45@gmail.com',NULL,'$2b$10$MH1glmjNdTqzj2jheq9M/.3rnbsSqS1n/2bm50kJK7Qyk4l5JtTHq',0,'psicologo',NULL,'clinica',12,NULL,'2026-10-26 23:36:33','activo'),(19,'Alberto González','Rh','5512141516','Villada CDMX','alb123@gmail.com',NULL,'$2b$10$E0N7tJi/xXha8DQI5.Fm0.Toc7VJfun4R71e/JL3yM1qaVA.ktiKG',0,'rh',NULL,'rh',14,NULL,'2026-10-27 17:18:53','activo'),(20,'elizabeth','Rh','5547787779','CDMX','eliza89@gmail.com',NULL,'$2b$10$AdKcNxnFApxuBiNtydW5CuggRNPVRZjkjEWbtVcQu76LSaRkzVAaW',0,'rh',NULL,'rh',14,NULL,'2026-10-27 17:19:48','activo'),(21,'julieta sandoval',NULL,NULL,NULL,'juli85@gmail.com',NULL,'$2b$10$EYvZvI0HDIywUEAlKUvom.zV0YYSCYCUBJhqws53ZY1roaHwtg5X6',0,'psicologo',NULL,'clinica',12,NULL,'2026-11-05 17:11:52','activo'),(22,'julieta lopez',NULL,'5546545456','Los Reyes','juli@gmail.com',NULL,'$2b$10$o2m1NZzcWQOAcQiDU5JcoeiXSEslbm63TyPbI96vS00pp9Z7yQaYu',0,'psicologo',NULL,'clinica',12,NULL,'2026-11-05 17:42:31','activo'),(23,'Laura Pérez','Administrador','5512345678','CDMX','laura.admin@clinicaprueba.com',NULL,'$2b$10$kC9R8y1zDtts8s85UKR37OVbeIpgE3.5oZiyrotXEJQGZ0UCaqRO2',0,'admin','normal','clinica',1,1,'2026-11-05 23:23:17','activo'),(24,'Psicólogo Prueba',NULL,'5546513189','CDMX','psicologo.prueba@mirrorsoul.com',NULL,'$2b$10$g.3mrdehPyeZsATfAYjoXOxa0PDCjpPxs138UG/wzO8CeAQn1pIHG',0,'psicologo',NULL,'clinica',23,1,'2026-11-05 23:46:07','activo'),(25,'Psicólogo Prueba 2',NULL,'5511111102','CDMX','psicologo2@mirrorsoul.com',NULL,'$2b$10$6sV35qk1DqhxeBKBpf.lquvO9/gxia4s/ocEtl0dNVLpgyeW2pcwK',0,'psicologo',NULL,'clinica',23,1,'2026-11-06 18:17:20','activo'),(26,'Psicólogo Prueba 3',NULL,'5511111103','CDMX','psicologo3@mirrorsoul.com',NULL,'$2b$10$SQS9OjS60i2nGsk4qYdCW.C1J8dvkJK3IvMkFf.VORjU4ge172rme',0,'psicologo',NULL,'clinica',23,1,'2026-11-06 18:17:35','activo'),(27,'Psicólogo Prueba 4',NULL,'5511111104','CDMX','psicologo4@mirrorsoul.com',NULL,'$2b$10$uXh4J51oBINrjJTAwhIdUO/9KYB1Lye4ynCKHOqukhSJQDXTic11e',0,'psicologo',NULL,'clinica',23,1,'2026-11-06 18:17:50','activo'),(28,'Psicólogo Prueba 5',NULL,'5511111105','CDMX','psicologo5@mirrorsoul.com',NULL,'$2b$10$lMq7T9HqFo/9QHEnhPdmpuCm2RQgDY8IPcHVXhn4HX/ayh6QD7RSe',0,'psicologo',NULL,'clinica',23,1,'2026-11-06 18:18:10','inactivo'),(29,'Andrea Martínez','Administrador','5512349900','CDMX','andrea.rh@mirrorsoul.com',NULL,'$2b$10$wxi3yCo16K0MtQi2SPFzlO8Ovj7FhKHJWePciFtDHBbHcGf6CCRoG',0,'admin','normal','rh',1,2,'2026-11-06 19:25:20','activo'),(31,'Usuario RH Prueba','Recursos Humanos','5511122233','CDMX','usuario.rh.prueba@mirrorsoul.com',NULL,'$2b$10$3wtGBGEdN2em.OTOajh4uuokSu2CPWd57YXNlIfuC36t5BnBhc0B2',0,'rh',NULL,'rh',29,2,'2026-11-07 03:20:00','activo'),(32,'vanessa celic sandoval','Rh','5647820757','Los Reyes',NULL,'MS-RH-002-0001','$2b$10$NSIYTIuohxsSyZzRyW97Se2/eMBVDJK5RIndJ3wl3W/uo29V8nNtu',0,'rh',NULL,'rh',14,2,'2026-11-07 07:13:55','activo'),(33,'Pedro López',NULL,'5578451296','la paz',NULL,'MS-CLI-001-0001','$2b$10$kNa2lvY34PU1DmXw6EdRO.Qcg41CTZMhP4.miFgtb1c6QRKVuBMAy',0,'psicologo',NULL,'clinica',12,1,'2026-11-07 08:07:29','activo'),(34,'Profesional Independiente Prueba',NULL,'5578451296','La Paz','independiente.prueba@correo.com',NULL,'$2b$10$42AzKMEZfGzidWe8SI0vLezgr15W3Y8803Q7jS4S1LGBCCkL0Lk7G',0,'independiente',NULL,'independiente',NULL,3,'2026-11-07 19:43:59','activo'),(35,'Patricia Perez',NULL,'5546513132','Nezahualcoyotl','paty89@gmail.com',NULL,'$2b$10$Q8BG.APRhSo.TxkfOlPGG.QoFsHsulX4iK01KrrkVgvVTMBwIrjXK',0,'independiente',NULL,'independiente',NULL,4,'2026-11-09 21:08:17','activo'),(36,'PONCE',NULL,'5517878963','Los Reyes','nany69@gmail.com',NULL,'$2b$10$nqEvFNS0NpF.Kt/vyFPlO.OxY9cIf5J1e1LGkMYzWSfNKxKDujd2m',0,'independiente',NULL,'independiente',NULL,5,'2026-11-12 15:43:05','activo');
/*!40000 ALTER TABLE `usuarios` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `videos_entrevista_rh`
--

DROP TABLE IF EXISTS `videos_entrevista_rh`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `videos_entrevista_rh` (
  `id_video_rh` int(11) NOT NULL AUTO_INCREMENT,
  `id_prospecto` int(11) NOT NULL,
  `id_entrevista` int(11) NOT NULL,
  `id_usuario_registro` int(11) DEFAULT NULL,
  `ruta_video` varchar(500) NOT NULL,
  `tipo` enum('audio','video') NOT NULL DEFAULT 'video',
  `descripcion` varchar(255) DEFAULT NULL,
  `duracion_segundos` int(11) DEFAULT NULL,
  `formato` varchar(120) DEFAULT NULL,
  `transcripcion` longtext DEFAULT NULL,
  `transcripcion_estado` enum('pendiente','procesando','completada','error') NOT NULL DEFAULT 'pendiente',
  `transcripcion_fecha` datetime DEFAULT NULL,
  `transcripcion_modelo` varchar(120) DEFAULT NULL,
  `fecha_subida` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_video_rh`),
  KEY `idx_video_rh_prospecto` (`id_prospecto`),
  KEY `idx_video_rh_entrevista` (`id_entrevista`),
  KEY `idx_video_rh_usuario` (`id_usuario_registro`),
  KEY `idx_video_rh_fecha` (`fecha_subida`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `videos_entrevista_rh`
--

LOCK TABLES `videos_entrevista_rh` WRITE;
/*!40000 ALTER TABLE `videos_entrevista_rh` DISABLE KEYS */;
INSERT INTO `videos_entrevista_rh` VALUES (1,1,2,15,'/uploads/multimedia/1789778905593-video-grabacion-1789778905567.webm','video','Grabación de entrevista RH',0,'video/webm','No sé cuándo. [inaudible] con. Ah, vaya. La mancha que [inaudible] no me dejan. Tienes que. Mmm. Mhm. Mhm. Tiene, recomendarles. Ni. Oye, no sé si me entiendan.','completada','2026-09-18 18:48:50','gemini-2.5-flash','2026-09-18 18:48:25'),(2,1,1,15,'/uploads/multimedia/1789783384654-audio-grabacion-1789783384642.webm','audio','Grabación de entrevista RH',0,'audio/webm','para que te tranquilizarte mi amor. Para que puedas pensar en lo que\nAhora','completada','2026-09-18 20:04:44','gemini-2.5-flash','2026-09-18 20:03:04'),(3,1,3,15,'/uploads/multimedia/1790097868295-audio-grabacion-1790097868276.webm','audio','Grabación de entrevista RH',0,'audio/webm','grabar el audio\npara que él tenga todo lo que va a hacer aquí.\nSe va a echarle la [inaudible] [inaudible]','completada','2026-09-22 11:25:40','gemini-2.5-flash','2026-09-22 11:24:28');
/*!40000 ALTER TABLE `videos_entrevista_rh` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `videos_sesion`
--

DROP TABLE IF EXISTS `videos_sesion`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `videos_sesion` (
  `id_video` int(11) NOT NULL AUTO_INCREMENT,
  `id_sesion` int(11) NOT NULL,
  `ruta_video` varchar(255) NOT NULL,
  `descripcion` text DEFAULT NULL,
  `duracion_segundos` int(11) DEFAULT NULL,
  `formato` varchar(20) DEFAULT NULL,
  `transcripcion` longtext DEFAULT NULL,
  `transcripcion_estado` varchar(30) NOT NULL DEFAULT 'pendiente',
  `transcripcion_fecha` datetime DEFAULT NULL,
  `transcripcion_modelo` varchar(100) DEFAULT NULL,
  `fecha_subida` timestamp NOT NULL DEFAULT current_timestamp(),
  `tipo` enum('video','audio') DEFAULT 'video',
  PRIMARY KEY (`id_video`)
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `videos_sesion`
--

LOCK TABLES `videos_sesion` WRITE;
/*!40000 ALTER TABLE `videos_sesion` DISABLE KEYS */;
INSERT INTO `videos_sesion` VALUES (1,1,'/uploads/multimedia/1788406110969-video-grabacion-1788406110618.webm','Grabación de sesión',0,'video/webm',NULL,'pendiente',NULL,NULL,'2026-09-03 03:28:31','video'),(2,3,'/uploads/multimedia/1788410788419-video-grabacion-1788410788026.webm','Grabación de sesión',0,'video/webm',NULL,'pendiente',NULL,NULL,'2026-09-03 04:46:28','video'),(3,7,'/uploads/multimedia/1788806497783-video-grabacion-1788806497757.webm','Grabación de sesión',0,'video/webm',NULL,'pendiente',NULL,NULL,'2026-09-07 18:41:37','video'),(4,9,'/uploads/multimedia/1788809222830-video-grabacion-1788809222820.webm','Grabación de sesión',0,'video/webm',NULL,'pendiente',NULL,NULL,'2026-09-07 19:27:02','video'),(5,11,'/uploads/multimedia/1788994491391-video-grabacion-1788994491066.webm','Grabación de sesión',0,'video/webm',NULL,'pendiente',NULL,NULL,'2026-09-09 22:54:51','video'),(6,12,'/uploads/multimedia/1789501282810-audio-grabacion-1789501282794.webm','Grabación de sesión',0,'audio/webm',NULL,'pendiente',NULL,NULL,'2026-09-15 19:41:22','audio'),(7,13,'/uploads/multimedia/1789509377297-audio-grabacion-1789509377280.webm','Grabación de sesión',0,'audio/webm',NULL,'pendiente',NULL,NULL,'2026-09-15 21:56:17','audio'),(8,14,'/uploads/multimedia/1789515065565-audio-grabacion-1789515065547.webm','Grabación de sesión',0,'audio/webm','Trastorno.\nPues claro que estoy trastornada.\n¿Saben cuánto cuesta ser positiva todo el tiempo?\nSi lo único que saben hacer es regañar y más y más. Es que yo no hago por no estresar.\nTrastorno.','completada','2026-09-15 18:11:09','gemini-2.5-flash','2026-09-15 23:31:05','audio'),(9,15,'/uploads/multimedia/1789532165947-audio-grabacion-1789532165928.webm','Grabación de sesión',0,'audio/webm','No, estoy bien como yo quisiera. Pero tampoco estoy mal como otros quisieran. Sigo aquí, de pie, dando pelea, y puede que me caiga, pero te aseguro que en el suelo no me quedo.','completada','2026-09-15 22:16:08','gemini-2.5-flash','2026-09-16 04:16:05','audio'),(10,16,'/uploads/multimedia/1789532827438-video-grabacion-1789532827425.webm','Grabación de sesión',0,'video/webm',NULL,'pendiente',NULL,NULL,'2026-09-16 04:27:07','video'),(11,17,'/uploads/multimedia/1789535659542-video-grabacion-1789535659520.webm','Grabación de sesión',0,'video/webm','No puede...\n...No puede ser que...\nA la mujer que tiene menos fuerza que yo, pues yo también tengo fuerza. La [inaudible] y yo somos [inaudible] con un tal [inaudible] mucho si la [inaudible] ahí, pues yo...\nIgual, por ejemplo, [inaudible] me siento para [inaudible] me hago mucho [inaudible] todo [inaudible] me hago. La pretención de [inaudible] también aceptando y yo [inaudible] y no es tú, no estás [inaudible] y tú también lo aceptaste.\nMucho mejor...','completada','2026-09-15 23:39:14','gemini-2.5-flash','2026-09-16 05:14:19','video'),(12,18,'/uploads/multimedia/1789607995062-audio-grabacion-1789607995032.webm','Grabación de sesión',0,'audio/webm','reaccionando a ñoños tacaños parte 35. Cuando estaba en la uni, un compañero me preguntó que si ya había cenado y le dije que no, que ahorita en mi casa. Me dijo, ¿no quieres ir aquí por unos tacos de los que venden afuera de la escuela? Y yo le dije, no, la verdad no traigo dinero. Y me dijo, yo te invito. Y bueno, pues me insistió un poco y fuimos. A la semana me invitó a un concierto y le dije que no me gustaba el grupo y me dijo que si le podía mandar lo de los tacos. No mames, güey, este vato.','completada','2026-09-16 19:21:49','gemini-2.5-flash','2026-09-17 01:19:55','audio'),(13,20,'/uploads/multimedia/1793119318588-audio-grabacion-1793119318574.webm','Grabación de sesión',23,'audio/webm','Areli es una paciente depresiva que tiene problemas para expresar sus emociones. Paciente.\nAh.\nEs jodona y siempre está corrigiendo como así de veras.\nSe puede editar?\nPuedo agregar cosas?\nAh, muy chafa.','completada','2026-10-27 10:42:03','gemini-2.5-flash','2026-10-27 16:41:58','audio'),(14,24,'/uploads/multimedia/1794350453538-audio-grabacion-1794350453514.webm','Grabación de sesión',23,'audio/webm','baby, I\'m sure\n[música]\n[música]\nand I just can\'t wait till the day when you knock on my door.\nQué bien, Maggie.\nNow every time I go for the mailbox gotta hold myself down.\nCamina.\ncause I just can\'t','completada','2026-11-10 16:40:55','gemini-2.5-flash','2026-11-10 22:40:53','audio');
/*!40000 ALTER TABLE `videos_sesion` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping events for database 'pred_diag_emocional'
--

--
-- Dumping routines for database 'pred_diag_emocional'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-11-13  9:10:54

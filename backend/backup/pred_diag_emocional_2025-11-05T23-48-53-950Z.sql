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
-- Table structure for table `citas`
--

DROP TABLE IF EXISTS `citas`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `citas` (
  `id_cita` int(11) NOT NULL AUTO_INCREMENT,
  `id_psicologo` int(11) NOT NULL,
  `id_paciente` int(11) NOT NULL,
  `fecha` date NOT NULL,
  `hora` time NOT NULL,
  `motivo` varchar(200) DEFAULT NULL,
  `notas` text DEFAULT NULL,
  `estado` enum('pendiente','realizada','cancelada') DEFAULT 'pendiente',
  PRIMARY KEY (`id_cita`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `citas`
--

LOCK TABLES `citas` WRITE;
/*!40000 ALTER TABLE `citas` DISABLE KEYS */;
INSERT INTO `citas` VALUES (4,1,1,'2025-10-08','13:42:00','seguimiento','prueba revisar',''),(6,1,1,'2025-10-29','19:42:00','seguimiento','dar un resultado ','cancelada'),(10,1,4,'2025-10-29','19:49:00','seguimiento','pruebas','');
/*!40000 ALTER TABLE `citas` ENABLE KEYS */;
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
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `historial_inicial`
--

LOCK TABLES `historial_inicial` WRITE;
/*!40000 ALTER TABLE `historial_inicial` DISABLE KEYS */;
INSERT INTO `historial_inicial` VALUES (1,1,'2025-10-28','soltero','empleada','preparatoria','ninguno','diabetes','no','problemas para controlar el sueño','no','a la pelusa','no','no','no','no','a un no','pruebas','pruebas','realizar pruebas ','2025-10-28 23:50:20'),(4,4,'2025-10-29','soltero','estudiante','primaria','ninguno','cancer','rinitis','depresion ','morderse los labios ','ninguna','calculos renales','metformina histofil','fractura de codo derecho','4. Desarrollo cognitivo y escolar\n\nControl de esfínteres: 2 años y medio.\n\nIngreso a preescolar: a los 3 años.\n\nAprendió a leer: a los 6 años (1er grado).\n\nAprendió a escribir: a los 6 años y medio.\n\nAprendió a sumar y restar: a los 7 años.\n\nDesempeño escolar: bueno, sin dificultades significativas.','depresion','ansiedad pero faltan pruebas','aun no hay ','realizar pruebas ','2025-10-30 00:13:25');
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
  PRIMARY KEY (`id_seguimiento`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `historial_seguimiento`
--

LOCK TABLES `historial_seguimiento` WRITE;
/*!40000 ALTER TABLE `historial_seguimiento` DISABLE KEYS */;
INSERT INTO `historial_seguimiento` VALUES (1,4,NULL,'2025-10-29','ansiedad severa','terapia ','inicio','derivacion a psiquiatria infantil');
/*!40000 ALTER TABLE `historial_seguimiento` ENABLE KEYS */;
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
) ENGINE=InnoDB AUTO_INCREMENT=275 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `opciones_respuesta`
--

LOCK TABLES `opciones_respuesta` WRITE;
/*!40000 ALTER TABLE `opciones_respuesta` DISABLE KEYS */;
INSERT INTO `opciones_respuesta` VALUES (93,36,'Nunca',0),(94,36,'Casi nunca',1),(95,36,'De vez en cuando',2),(96,36,'A menudo',3),(97,36,'Muy a menudo',4),(98,37,'Nunca',0),(99,37,'Casi nunca',1),(100,37,'De vez en cuando',2),(101,37,'A menudo',3),(102,37,'Muy a menudo',4),(103,38,'Nunca',0),(104,38,'Casi nunca',1),(105,38,'De vez en cuando',2),(106,38,'A menudo',3),(107,38,'Muy a menudo',4),(108,39,'Nunca',0),(109,39,'Casi nunca',1),(110,39,'De vez en cuando',2),(111,39,'A menudo',3),(112,39,'Muy a menudo',4),(113,40,'Nunca',0),(114,40,'Casi nunca',1),(115,40,'De vez en cuando',2),(116,40,'A menudo',3),(117,40,'Muy a menudo',4),(118,41,'Nunca',0),(119,41,'Casi nunca',1),(120,41,'De vez en cuando',2),(121,41,'A menudo',3),(122,41,'Muy a menudo',4),(123,42,'Nunca',0),(124,42,'Casi nunca',1),(125,42,'De vez en cuando',2),(126,42,'A menudo',3),(127,42,'Muy a menudo',4),(128,43,'Nunca',0),(129,43,'Casi nunca',1),(130,43,'De vez en cuando',2),(131,43,'A menudo',3),(132,43,'Muy a menudo',4),(133,44,'Nunca',0),(134,44,'Casi nunca',1),(135,44,'De vez en cuando',2),(136,44,'A menudo',3),(137,44,'Muy a menudo',4),(138,45,'Nunca',0),(139,45,'Casi nunca',1),(140,45,'De vez en cuando',2),(141,45,'A menudo',3),(142,45,'Muy a menudo',4),(143,46,'Nunca',0),(144,46,'Casi nunca',1),(145,46,'De vez en cuando',2),(146,46,'A menudo',3),(147,46,'Muy a menudo',4),(148,47,'Nunca',0),(149,47,'Casi nunca',1),(150,47,'De vez en cuando',2),(151,47,'A menudo',3),(152,47,'Muy a menudo',4),(153,48,'Nunca',0),(154,48,'Casi nunca',1),(155,48,'De vez en cuando',2),(156,48,'A menudo',3),(157,48,'Muy a menudo',4),(158,49,'Nunca',0),(159,49,'Casi nunca',1),(160,49,'De vez en cuando',2),(161,49,'A menudo',3),(162,49,'Muy a menudo',4),(163,50,'0 - No me siento triste',0),(164,50,'1 - Me siento triste gran parte del tiempo',1),(165,50,'2 - Estoy triste todo el tiempo',2),(166,50,'3 - Estoy tan triste o infeliz que no puedo soportarlo',3),(167,51,'0 - No estoy desalentado respecto al futuro',0),(168,51,'1 - Me siento más desalentado que antes',1),(169,51,'2 - No espero que las cosas mejoren para mí',2),(170,51,'3 - Siento que no hay esperanza para mi futuro',3),(171,52,'0 - No me siento como un fracasado',0),(172,52,'1 - He fracasado más de lo que debería',1),(173,52,'2 - Cuando miro atrás, veo muchos fracasos',2),(174,52,'3 - Me siento como una persona totalmente fracasada',3),(175,53,'0 - Disfruto tanto como antes',0),(176,53,'1 - No disfruto tanto como antes',1),(177,53,'2 - Disfruto poco de las cosas',2),(178,53,'3 - No puedo disfrutar de nada',3),(179,54,'0 - No me siento particularmente culpable',0),(180,54,'1 - Me siento culpable a menudo',1),(181,54,'2 - Me siento culpable la mayor parte del tiempo',2),(182,54,'3 - Me siento culpable todo el tiempo',3),(183,55,'0 - No siento que esté siendo castigado',0),(184,55,'1 - Siento que puedo ser castigado',1),(185,55,'2 - Espero ser castigado',2),(186,55,'3 - Siento que estoy siendo castigado',3),(187,56,'0 - Me siento satisfecho conmigo mismo',0),(188,56,'1 - Pierdo confianza en mí mismo',1),(189,56,'2 - Estoy decepcionado conmigo mismo',2),(190,56,'3 - Me odio a mí mismo',3),(191,57,'0 - No me critico ni me culpo más que lo habitual',0),(192,57,'1 - Estoy más crítico conmigo mismo',1),(193,57,'2 - Me critico por todos mis errores',2),(194,57,'3 - Me culpo de todo lo malo que sucede',3),(195,58,'0 - No tengo pensamientos suicidas',0),(196,58,'1 - Tengo pensamientos suicidas pero no los llevaría a cabo',1),(197,58,'2 - Quisiera suicidarme',2),(198,58,'3 - Me suicidaría si tuviera la oportunidad',3),(199,59,'0 - No lloro más de lo habitual',0),(200,59,'1 - Lloro más de lo habitual',1),(201,59,'2 - Lloro todo el tiempo',2),(202,59,'3 - Antes podía llorar, pero ahora no puedo aunque quiera',3),(203,60,'0 - No estoy más inquieto o agitado de lo habitual',0),(204,60,'1 - Estoy más inquieto de lo habitual',1),(205,60,'2 - Estoy tan inquieto o agitado que me cuesta estar quieto',2),(206,60,'3 - Estoy tan agitado que debo moverme o hacer algo constantemente',3),(207,61,'0 - No he perdido interés en otras personas o actividades',0),(208,61,'1 - Estoy menos interesado que antes',1),(209,61,'2 - He perdido la mayor parte de mi interés',2),(210,61,'3 - He perdido todo el interés en otras personas o cosas',3),(211,62,'0 - Tomo decisiones igual que siempre',0),(212,62,'1 - Me resulta más difícil tomar decisiones',1),(213,62,'2 - Me resulta muy difícil tomar decisiones',2),(214,62,'3 - No puedo tomar ninguna decisión',3),(215,63,'0 - No siento que valga menos que los demás',0),(216,63,'1 - Me critico por mis debilidades',1),(217,63,'2 - Me siento inferior a los demás',2),(218,63,'3 - Siento que no valgo nada',3),(219,64,'0 - Tengo tanta energía como siempre',0),(220,64,'1 - Tengo menos energía que antes',1),(221,64,'2 - No tengo suficiente energía para muchas cosas',2),(222,64,'3 - No tengo energía para nada',3),(223,65,'0 - Duermo igual que siempre',0),(224,65,'1 - Duermo más o menos de lo habitual',1),(225,65,'2 - Duermo mucho menos/más que antes',2),(226,65,'3 - Casi no duermo o duermo demasiado',3),(227,66,'0 - No estoy más irritable que de costumbre',0),(228,66,'1 - Estoy más irritable de lo habitual',1),(229,66,'2 - Estoy muy irritable la mayor parte del tiempo',2),(230,66,'3 - Estoy irritable todo el tiempo',3),(231,67,'0 - Mi apetito no ha cambiado',0),(232,67,'1 - Mi apetito es algo menor o mayor',1),(233,67,'2 - Mi apetito es mucho menor o mayor',2),(234,67,'3 - No tengo apetito o quiero comer todo el tiempo',3),(235,68,'0 - Me concentro tan bien como siempre',0),(236,68,'1 - Me cuesta un poco concentrarme',1),(237,68,'2 - Me resulta difícil concentrarme mucho tiempo',2),(238,68,'3 - No puedo concentrarme en nada',3),(239,69,'0 - No estoy más cansado de lo habitual',0),(240,69,'1 - Me canso más fácilmente que antes',1),(241,69,'2 - Estoy muy cansado para hacer muchas cosas',2),(242,69,'3 - Estoy demasiado cansado para hacer nada',3),(243,70,'0 - No he notado ningún cambio en mi interés sexual',0),(244,70,'1 - Estoy menos interesado en el sexo que antes',1),(245,70,'2 - Estoy mucho menos interesado en el sexo',2),(246,70,'3 - He perdido todo el interés en el sexo',3),(247,71,'0 - Nunca',0),(248,71,'1 - Varios días',1),(249,71,'2 - Más de la mitad de los días',2),(250,71,'3 - Casi todos los días',3),(251,72,'0 - Nunca',0),(252,72,'1 - Varios días',1),(253,72,'2 - Más de la mitad de los días',2),(254,72,'3 - Casi todos los días',3),(255,73,'0 - Nunca',0),(256,73,'1 - Varios días',1),(257,73,'2 - Más de la mitad de los días',2),(258,73,'3 - Casi todos los días',3),(259,74,'0 - Nunca',0),(260,74,'1 - Varios días',1),(261,74,'2 - Más de la mitad de los días',2),(262,74,'3 - Casi todos los días',3),(263,75,'0 - Nunca',0),(264,75,'1 - Varios días',1),(265,75,'2 - Más de la mitad de los días',2),(266,75,'3 - Casi todos los días',3),(267,76,'0 - Nunca',0),(268,76,'1 - Varios días',1),(269,76,'2 - Más de la mitad de los días',2),(270,76,'3 - Casi todos los días',3),(271,77,'0 - Nunca',0),(272,77,'1 - Varios días',1),(273,77,'2 - Más de la mitad de los días',2),(274,77,'3 - Casi todos los días',3);
/*!40000 ALTER TABLE `opciones_respuesta` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `pacientes`
--

DROP TABLE IF EXISTS `pacientes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pacientes` (
  `id_paciente` int(11) NOT NULL AUTO_INCREMENT,
  `id_psicologo` int(11) NOT NULL,
  `nombre` varchar(120) NOT NULL,
  `sexo` enum('M','F','X') DEFAULT NULL,
  `fecha_nacimiento` date DEFAULT NULL,
  `edad` int(11) DEFAULT NULL,
  `correo` varchar(120) DEFAULT NULL,
  `telefono` varchar(30) DEFAULT NULL,
  `direccion` varchar(200) DEFAULT NULL,
  `antecedentes` text DEFAULT NULL,
  PRIMARY KEY (`id_paciente`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pacientes`
--

LOCK TABLES `pacientes` WRITE;
/*!40000 ALTER TABLE `pacientes` DISABLE KEYS */;
INSERT INTO `pacientes` VALUES (1,1,'elizabeth','F','2007-10-28',18,'maria_2525@gmail.com','5588996633','LA PALMA MZA 2 CON1, CASA2','problemas para dormir '),(4,1,'luci','F','2014-04-29',11,'sistemas@primernivelmx.net','5546513169','av 602 no 22','depresion ');
/*!40000 ALTER TABLE `pacientes` ENABLE KEYS */;
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
) ENGINE=InnoDB AUTO_INCREMENT=78 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `preguntas_prueba`
--

LOCK TABLES `preguntas_prueba` WRITE;
/*!40000 ALTER TABLE `preguntas_prueba` DISABLE KEYS */;
INSERT INTO `preguntas_prueba` VALUES (36,2,'En el último mes, ¿con qué frecuencia se ha sentido incapaz de controlar las cosas importantes en su vida?','opcion'),(37,2,'En el último mes, ¿con qué frecuencia se ha sentido nervioso o estresado?','opcion'),(38,2,'En el último mes, ¿con qué frecuencia ha manejado con éxito los pequeños problemas irritantes de la vida?','opcion'),(39,2,'En el último mes, ¿con qué frecuencia ha sentido que estaba afrontando efectivamente los cambios importantes que estaban ocurriendo en su vida?','opcion'),(40,2,'En el último mes, ¿con qué frecuencia ha sentido confianza en su capacidad para manejar sus problemas personales?','opcion'),(41,2,'En el último mes, ¿con qué frecuencia ha sentido que las cosas le iban bien?','opcion'),(42,2,'En el último mes, ¿con qué frecuencia ha sentido que no podía afrontar todas las cosas que tenía que hacer?','opcion'),(43,2,'En el último mes, ¿con qué frecuencia ha podido controlar las dificultades de su vida?','opcion'),(44,2,'En el último mes, ¿con qué frecuencia ha sentido que tenía todo bajo control?','opcion'),(45,2,'En el último mes, ¿con qué frecuencia ha sentido que estaba enfadado porque las cosas que le han ocurrido estaban fuera de su control?','opcion'),(46,2,'En el último mes, ¿con qué frecuencia ha sentido que las dificultades se acumulaban tanto que no podía superarlas?','opcion'),(47,2,'En el último mes, ¿con qué frecuencia ha sentido que podía controlar la forma en que gastaba su tiempo?','opcion'),(48,2,'En el último mes, ¿con qué frecuencia ha sentido que las cosas estaban fuera de su control?','opcion'),(49,2,'En el último mes, ¿con qué frecuencia ha sentido que todo estaba bajo control?','opcion'),(50,1,'Tristeza','opcion'),(51,1,'Pesimismo','opcion'),(52,1,'Fracaso pasado','opcion'),(53,1,'Pérdida de placer','opcion'),(54,1,'Sentimientos de culpa','opcion'),(55,1,'Sentimientos de castigo','opcion'),(56,1,'Disconformidad con uno mismo','opcion'),(57,1,'Autocrítica','opcion'),(58,1,'Pensamientos o deseos suicidas','opcion'),(59,1,'Llanto','opcion'),(60,1,'Agitación','opcion'),(61,1,'Pérdida de interés','opcion'),(62,1,'Indecisión','opcion'),(63,1,'Desvalorización','opcion'),(64,1,'Pérdida de energía','opcion'),(65,1,'Cambios en los patrones de sueño','opcion'),(66,1,'Irritabilidad','opcion'),(67,1,'Cambios en el apetito','opcion'),(68,1,'Dificultad de concentración','opcion'),(69,1,'Cansancio o fatiga','opcion'),(70,1,'Pérdida de interés en el sexo','opcion'),(71,3,'En las últimas dos semanas, ¿con qué frecuencia se ha sentido nervioso o ansioso?','opcion'),(72,3,'En las últimas dos semanas, ¿con qué frecuencia no ha podido parar de preocuparse o controlar sus preocupaciones?','opcion'),(73,3,'En las últimas dos semanas, ¿con qué frecuencia se ha preocupado demasiado por diferentes cosas?','opcion'),(74,3,'En las últimas dos semanas, ¿con qué frecuencia ha tenido dificultades para relajarse?','opcion'),(75,3,'En las últimas dos semanas, ¿con qué frecuencia ha estado tan inquieto que no ha podido permanecer sentado?','opcion'),(76,3,'En las últimas dos semanas, ¿con qué frecuencia se ha irritado o enfadado fácilmente?','opcion'),(77,3,'En las últimas dos semanas, ¿con qué frecuencia ha sentido miedo como si algo terrible fuera a pasar?','opcion');
/*!40000 ALTER TABLE `preguntas_prueba` ENABLE KEYS */;
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
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pruebas`
--

LOCK TABLES `pruebas` WRITE;
/*!40000 ALTER TABLE `pruebas` DISABLE KEYS */;
INSERT INTO `pruebas` VALUES (1,'Inventario de Depresión de Beck (BDI-II)','Evalúa la intensidad de síntomas depresivos','depresion','1.0','2025-10-09 17:51:15',1),(2,'Escala de Estrés Percibido (PSS-14)','Mide la percepción de estrés en el último mes','estres','1.0','2025-10-09 17:51:15',1),(3,'GAD-7','Cuestionario de ansiedad generalizada','ansiedad','1.0','2025-10-09 17:51:15',1);
/*!40000 ALTER TABLE `pruebas` ENABLE KEYS */;
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
  `id_prueba` int(11) NOT NULL,
  `id_psicologo` int(11) NOT NULL,
  `notas` text DEFAULT NULL,
  `fecha` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_habilitacion`)
) ENGINE=InnoDB AUTO_INCREMENT=103 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pruebas_habilitadas`
--

LOCK TABLES `pruebas_habilitadas` WRITE;
/*!40000 ALTER TABLE `pruebas_habilitadas` DISABLE KEYS */;
INSERT INTO `pruebas_habilitadas` VALUES (100,1,3,1,NULL,'2025-10-29 01:33:03'),(101,1,2,1,NULL,'2025-10-29 01:36:32'),(102,4,3,1,NULL,'2025-10-30 00:13:51');
/*!40000 ALTER TABLE `pruebas_habilitadas` ENABLE KEYS */;
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
  `direccion` varchar(200) DEFAULT NULL,
  `fecha_nacimiento` date DEFAULT NULL,
  PRIMARY KEY (`id_psicologo`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `psicologos`
--

LOCK TABLES `psicologos` WRITE;
/*!40000 ALTER TABLE `psicologos` DISABLE KEYS */;
INSERT INTO `psicologos` VALUES (1,2,NULL,'13658996','psicologa conductual',NULL,NULL),(2,3,NULL,'12671190','psicologa conductual',NULL,NULL),(3,4,NULL,'963258','psicologa conductual',NULL,NULL);
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
  PRIMARY KEY (`id_reporte`)
) ENGINE=InnoDB AUTO_INCREMENT=59 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `reportes_ia`
--

LOCK TABLES `reportes_ia` WRITE;
/*!40000 ALTER TABLE `reportes_ia` DISABLE KEYS */;
INSERT INTO `reportes_ia` VALUES (56,1,NULL,'2025-10-29 23:31:59','## Resumen de Resultados Clínicos para el Paciente\n\n**Paciente:** Elizabeth, 18 años, F\n**Fecha del Reporte:** 28 de octubre de 2025\n\n---\n\nEstimada Elizabeth,\n\nAdjunto a continuación un resumen de los resultados de su reciente evaluación:\n\n### 1. Prueba Realizada: GAD-7 (Cuestionario de Ansiedad Generalizada - 7)\n\n*   **Fecha de la Prueba:** 28 de octubre de 2025\n*   **Propósito de la Prueba:** El GAD-7 es una herramienta utilizada para evaluar la presencia y la severidad de los síntomas de ansiedad generalizada que una persona puede haber experimentado en las últimas dos semanas.\n\n### 2. Resultados Obtenidos:\n\n*   **Puntaje Total:** 18 puntos\n*   **Interpretación del Puntaje:** Este puntaje se ubica en el rango de **\"Ansiedad Severa\"**.\n\n### 3. ¿Qué significa esto?\n\nUn puntaje de 18 en el GAD-7 sugiere que está experimentando un nivel significativo de síntomas relacionados con la ansiedad generalizada. Estos síntomas pueden incluir preocupación excesiva, dificultad para controlar la preocupación, inquietud, cansancio, dificultad para concentrarse, irritabilidad, tensión muscular y problemas de sueño.\n\n**Es importante recordar que el GAD-7 es una herramienta de cribado y no un diagnóstico definitivo.** Sin embargo, un puntaje como el suyo es un indicador importante de que está experimentando niveles de ansiedad que requieren atención y apoyo.\n\n### 4. Recomendaciones y Siguientes Pasos:\n\nDada esta interpretación, le recomendamos encarecidamente lo siguiente:\n\n*   **Programar una Cita de Seguimiento:** Es fundamental que tengamos una conversación detallada para discutir estos resultados, explorar sus síntomas con más profundidad y entender cómo están afectando su vida diaria.\n*   **Explorar Opciones de Apoyo:** Durante esta cita, podremos presentarle y discutir las diversas opciones de tratamiento y estrategias de afrontamiento que pueden ayudarle a manejar y reducir su ansiedad, como terapia psicológica (cognitivo-conductual), técnicas de relajación, manejo del estrés, y otras intervenciones adecuadas a su situación.\n\nQueremos asegurarnos de brindarle el apoyo necesario en este momento. Por favor, póngase en contacto con nuestra clínica a su conveniencia para coordinar esta importante cita. Estamos aquí para ayudarle.\n\nAtentamente,\n\nEl Equipo Clínico'),(57,4,NULL,'2025-10-30 00:14:53','## Reporte Clínico Resumido para el Paciente\n\n**Paciente:** Luci\n**Edad:** 11 años\n**Género:** Femenino\n**Fecha del Reporte:** [Fecha Actual de Generación del Reporte]\n\n---\n\n### Introducción\n\nEste reporte resume los hallazgos recientes de las evaluaciones realizadas a Luci, con el objetivo de proporcionar una visión clara de su estado actual y las recomendaciones para los próximos pasos en su cuidado.\n\n---\n\n### Resultados de Pruebas Clave\n\n**1. Evaluación de Ansiedad (GAD-7)**\n\n*   **Fecha de Realización:** 29 de octubre de 2025\n*   **Puntaje Obtenido:** 16 puntos\n*   **Interpretación:** Ansiedad severa\n\n---\n\n### Análisis y Consideraciones\n\nLa escala GAD-7 (Generalized Anxiety Disorder 7-item) es una herramienta de cribado utilizada para evaluar la presencia y severidad de los síntomas de ansiedad generalizada.\n\nEl puntaje de 16 obtenido por Luci se sitúa en el rango de **ansiedad severa**. Esto indica que está experimentando síntomas de ansiedad de manera significativa, los cuales podrían estar afectando su bienestar emocional, funcionamiento diario, rendimiento escolar, relaciones sociales y calidad de vida en general.\n\nEs importante recordar que este es un instrumento de detección y que un puntaje elevado sugiere la necesidad de una evaluación clínica más profunda para comprender la naturaleza específica de la ansiedad de Luci y sus posibles causas.\n\n---\n\n### Recomendaciones y Próximos Pasos\n\nDados estos resultados, se recomienda enfáticamente lo siguiente:\n\n1.  **Evaluación Clínica Detallada:** Se sugiere una consulta con un especialista en salud mental infantil y adolescente (psicólogo clínico o psiquiatra infantil). Esta evaluación permitirá:\n    *   Confirmar el diagnóstico de ansiedad.\n    *   Identificar los factores desencadenantes o contribuyentes.\n    *   Explorar el impacto de la ansiedad en las diferentes áreas de la vida de Luci.\n    *   Descartar otras condiciones que puedan coexistir.\n\n2.  **Desarrollo de un Plan de Tratamiento:** Basado en la evaluación detallada, se deberá elaborar un plan de tratamiento individualizado, que podría incluir:\n    *   **Terapia psicológica:** La terapia cognitivo-conductual (TCC) es altamente efectiva para la ansiedad en niños y adolescentes, enseñando estrategias para manejar pensamientos, emociones y comportamientos ansiosos.\n    *   **Estrategias de manejo del estrés:** Técnicas de relajación, mindfulness, y fomento de hábitos de vida saludables (sueño adecuado, nutrición, ejercicio).\n    *   **Apoyo familiar:** Orientación a los padres y familiares sobre cómo apoyar a Luci en casa y en su entorno.\n\n3.  **Monitoreo Continuo:** Es importante realizar un seguimiento periódico de los síntomas y el progreso de Luci para ajustar el plan de tratamiento según sea necesario.\n\n---\n\n### Conclusión\n\nEl resultado del GAD-7 resalta la presencia de ansiedad severa en Luci, lo que justifica una atención inmediata y especializada. Abordar estos síntomas de manera temprana es crucial para su desarrollo y bienestar a largo plazo. Animamos a la familia a discutir este reporte con el equipo médico para aclarar cualquier duda y coordinar los próximos pasos.\n\n---\n**[Nombre del Profesional o Departamento que Emite el Reporte]**\n[Título/Especialidad]'),(58,4,NULL,'2025-10-30 02:07:00','## Reporte Clínico Resumido - Para Luci y Familia\n\n**Paciente:** Luci\n**Edad:** 11 años\n**Género:** Femenino\n**Fecha del Reporte:** 2024-05-15\n\n---\n\n**Estimados Luci y familia,**\n\nEste reporte resume los resultados de tu reciente evaluación, específicamente la prueba GAD-7, realizada el 29 de octubre de 2025.\n\n**Resultados Clave de la Evaluación:**\n\n*   **Prueba Realizada:** GAD-7 (Cuestionario de Ansiedad Generalizada de 7 ítems)\n*   **Fecha de la Prueba:** 29 de octubre de 2025\n*   **Puntaje Obtenido:** 16 puntos\n*   **Interpretación:** Ansiedad severa\n\n**¿Qué significa este resultado para Luci?**\n\nEl puntaje de 16 en la prueba GAD-7 indica que Luci podría estar experimentando sentimientos de preocupación, nerviosismo o inquietud de manera más intensa y frecuente de lo habitual. Es importante entender que la ansiedad es una emoción común, pero cuando es \"severa\" puede interferir con la vida diaria, el rendimiento escolar, el sueño o las relaciones con amigos y familia.\n\n**Pasos Sugeridos a Seguir:**\n\nBasado en este resultado, **recomendamos encarecidamente una evaluación más profunda con un especialista en salud mental infantil y adolescente (como un psicólogo o psiquiatra)**. El objetivo será:\n\n1.  **Explorar con más detalle** cómo se siente Luci, qué la preocupa y cómo estos sentimientos afectan su día a día.\n2.  **Desarrollar estrategias y herramientas** para que Luci aprenda a manejar sus preocupaciones y a sentirse más tranquila y segura.\n3.  **Ofrecer apoyo y orientación** tanto a Luci como a la familia para comprender y afrontar la ansiedad.\n\n**Mensaje para Luci:**\n\nQuerida Luci, es importante que sepas que no estás sola en esto. Sentir preocupación o nerviosismo es algo que le pasa a mucha gente, y no es algo de lo que debas avergonzarte. La buena noticia es que hay muchas maneras de aprender a manejar estos sentimientos para que no te controlen. Estamos aquí para ayudarte a sentirte mejor y a encontrar las herramientas que necesitas para ser tú misma, sintiéndote tranquila y feliz.\n\n---\n\nPor favor, no duden en contactar al equipo médico para cualquier pregunta o para coordinar los próximos pasos.');
/*!40000 ALTER TABLE `reportes_ia` ENABLE KEYS */;
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
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `respuestas_prueba`
--

LOCK TABLES `respuestas_prueba` WRITE;
/*!40000 ALTER TABLE `respuestas_prueba` DISABLE KEYS */;
INSERT INTO `respuestas_prueba` VALUES (1,1,3,100,71,249,NULL,NULL,'2025-10-29 01:33:23'),(2,1,3,100,72,253,NULL,NULL,'2025-10-29 01:33:23'),(3,1,3,100,73,257,NULL,NULL,'2025-10-29 01:33:23'),(4,1,3,100,74,262,NULL,NULL,'2025-10-29 01:33:23'),(5,1,3,100,75,266,NULL,NULL,'2025-10-29 01:33:23'),(6,1,3,100,76,270,NULL,NULL,'2025-10-29 01:33:23'),(7,1,3,100,77,274,NULL,NULL,'2025-10-29 01:33:23'),(8,4,3,102,71,249,NULL,NULL,'2025-10-30 00:14:19'),(9,4,3,102,72,254,NULL,NULL,'2025-10-30 00:14:19'),(10,4,3,102,73,258,NULL,NULL,'2025-10-30 00:14:19'),(11,4,3,102,74,261,NULL,NULL,'2025-10-30 00:14:19'),(12,4,3,102,75,265,NULL,NULL,'2025-10-30 00:14:19'),(13,4,3,102,76,269,NULL,NULL,'2025-10-30 00:14:19'),(14,4,3,102,77,273,NULL,NULL,'2025-10-30 00:14:19');
/*!40000 ALTER TABLE `respuestas_prueba` ENABLE KEYS */;
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
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `resultados_prueba`
--

LOCK TABLES `resultados_prueba` WRITE;
/*!40000 ALTER TABLE `resultados_prueba` DISABLE KEYS */;
INSERT INTO `resultados_prueba` VALUES (1,1,3,100,NULL,18,'Ansiedad severa','⚠️ Sin respuesta de Gemini.','2025-10-29 01:33:26'),(2,4,3,102,NULL,16,'Ansiedad severa','⚠️ Sin respuesta de Gemini.','2025-10-30 00:14:21');
/*!40000 ALTER TABLE `resultados_prueba` ENABLE KEYS */;
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
  `notas` text DEFAULT NULL,
  `fecha` datetime DEFAULT current_timestamp(),
  `fecha_fin` datetime DEFAULT NULL,
  `link_videollamada` text DEFAULT NULL,
  `estado` enum('activa','finalizada') DEFAULT 'activa',
  PRIMARY KEY (`id_sesion`)
) ENGINE=InnoDB AUTO_INCREMENT=32 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sesiones`
--

LOCK TABLES `sesiones` WRITE;
/*!40000 ALTER TABLE `sesiones` DISABLE KEYS */;
INSERT INTO `sesiones` VALUES (5,0,1,'Sesión sin notas','2025-10-29 19:36:05',NULL,NULL,'activa'),(8,10,4,'Sesión desde cita - Motivo: seguimiento pruebas','2025-10-29 19:48:41',NULL,NULL,'activa'),(9,NULL,4,'Sesión con videollamada','2025-11-04 17:55:33',NULL,NULL,'activa'),(10,NULL,4,'Sesión con videollamada','2025-11-04 17:55:33',NULL,NULL,'activa'),(11,NULL,4,'Sesión con videollamada','2025-11-04 17:56:19',NULL,NULL,'activa'),(12,NULL,4,'Sesión con videollamada','2025-11-04 17:56:19',NULL,NULL,'activa'),(13,NULL,1,'Sesión con videollamada','2025-11-04 17:56:33',NULL,NULL,'activa'),(14,NULL,1,'Sesión con videollamada','2025-11-04 17:56:33',NULL,NULL,'activa'),(15,NULL,4,'Sesión con videollamada','2025-11-04 17:57:23',NULL,NULL,'activa'),(16,NULL,4,'Sesión con videollamada','2025-11-04 17:57:23',NULL,NULL,'activa'),(17,NULL,4,'Sesión con videollamada','2025-11-04 18:29:40',NULL,NULL,'activa'),(18,NULL,4,'Sesión con videollamada','2025-11-04 18:29:40',NULL,NULL,'activa'),(19,NULL,4,'Sesión con videollamada','2025-11-05 12:35:24',NULL,NULL,'activa'),(20,NULL,4,'Sesión con videollamada','2025-11-05 12:35:24',NULL,NULL,'activa'),(21,NULL,4,'Sesión con videollamada','2025-11-05 17:04:19',NULL,NULL,'activa'),(22,NULL,4,'Sesión con videollamada','2025-11-05 17:04:19',NULL,NULL,'activa'),(23,NULL,4,'Sesión con videollamada','2025-11-05 17:04:37',NULL,NULL,'activa'),(24,NULL,4,'Sesión con videollamada','2025-11-05 17:04:37',NULL,NULL,'activa'),(25,NULL,4,'Sesión con videollamada','2025-11-05 17:04:45',NULL,NULL,'activa'),(26,NULL,4,'Sesión con videollamada','2025-11-05 17:04:45',NULL,NULL,'activa'),(27,NULL,4,'Sesión con videollamada','2025-11-05 17:04:52',NULL,NULL,'activa'),(28,NULL,4,'Sesión con videollamada','2025-11-05 17:04:52',NULL,NULL,'activa'),(29,NULL,4,'Sesión con videollamada','2025-11-05 17:05:07',NULL,NULL,'activa'),(30,NULL,4,'Sesión con videollamada','2025-11-05 17:05:07',NULL,NULL,'activa'),(31,NULL,4,'Sesión con videollamada','2025-11-05 17:05:43',NULL,'http://localhost:5173/SalaVideollamada/sala-31-1762383943587','activa');
/*!40000 ALTER TABLE `sesiones` ENABLE KEYS */;
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
  `correo` varchar(120) NOT NULL,
  `password` varchar(255) NOT NULL,
  `rol` enum('admin','psicologo') DEFAULT 'psicologo',
  `creado_en` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id_usuario`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `usuarios`
--

LOCK TABLES `usuarios` WRITE;
/*!40000 ALTER TABLE `usuarios` DISABLE KEYS */;
INSERT INTO `usuarios` VALUES (1,'Elizabeth','lizma883@gmail.com','$2b$10$hi1Mkmqx2kqZih3a3K/15OsWUkDsuKMUdVUDodnJv2yZ2cnfSk.uq','admin','2025-10-08 18:34:39'),(2,'Liliana','jp5247356@gmail.com','$2b$10$tJjxG0nLt6HTzGBde8y7bOXWnNbvVQPLXUgnRCoB4EHbe53L00ET.','psicologo','2025-10-08 19:13:28'),(3,'luci','252271037@alumnos.utn.edu.mx','$2b$10$WrjdgI3pICwB3G4wXikQrelmS1ll9ZJJcWDoIGhW7R/9gTWVSuuia','psicologo','2025-10-09 00:39:59'),(4,'adamari','vanessacelicsandovallopez@gmail.com','$2b$10$870yMq0oC.DAyoFMV/j61uKMvEh0qVK2LTihb9ljSD9kXbrNsPyAO','psicologo','2025-11-05 00:31:19');
/*!40000 ALTER TABLE `usuarios` ENABLE KEYS */;
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
  `fecha_subida` timestamp NOT NULL DEFAULT current_timestamp(),
  `tipo` enum('video','audio') DEFAULT 'video',
  PRIMARY KEY (`id_video`)
) ENGINE=InnoDB AUTO_INCREMENT=31 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `videos_sesion`
--

LOCK TABLES `videos_sesion` WRITE;
/*!40000 ALTER TABLE `videos_sesion` DISABLE KEYS */;
INSERT INTO `videos_sesion` VALUES (7,34,'/uploads/multimedia/1760809180754-video-grabacion-1760809180731.webm','Grabación de sesión',NULL,'video/webm','2025-10-18 17:39:40','video'),(8,35,'/uploads/multimedia/1760809941893-video-grabacion-1760809941578.webm','Grabación de sesión',NULL,'video/webm','2025-10-18 17:52:21','video'),(9,41,'/uploads/multimedia/1760816210525-video-grabacion-1760816210503.webm','Grabación de sesión',NULL,'video/webm','2025-10-18 19:36:50','video'),(10,43,'/uploads/multimedia/1760826577993-video-grabacion-1760826577978.webm','Grabación de sesión',NULL,'video/webm','2025-10-18 22:29:38','video'),(11,44,'/uploads/multimedia/1760830037093-video-grabacion-1760830036763.webm','Grabación de sesión',NULL,'video/webm','2025-10-18 23:27:17','video'),(12,46,'/uploads/multimedia/1760830089790-video-grabacion-1760830089780.webm','Grabación de sesión',NULL,'video/webm','2025-10-18 23:28:09','video'),(13,49,'/uploads/multimedia/1760837643745-video-grabacion-1760837643424.webm','Grabación de sesión',NULL,'video/webm','2025-10-19 01:34:03','video'),(14,50,'/uploads/multimedia/1760842718815-video-grabacion-1760842718490.webm','Grabación de sesión',NULL,'video/webm','2025-10-19 02:58:38','video'),(15,50,'/uploads/multimedia/1760844154182-video-grabacion-1760844154172.webm','Grabación de sesión',NULL,'video/webm','2025-10-19 03:22:34','video'),(16,51,'/uploads/multimedia/1760905141159-video-grabacion-1760905141124.webm','Grabación de sesión',NULL,'video/webm','2025-10-19 20:19:01','video'),(17,0,'/uploads/multimedia/1761070251774-video-grabacion-1761070251452.webm','Grabación de sesión',NULL,'video/webm','2025-10-21 18:10:51','video'),(18,0,'/uploads/multimedia/1761175650998-video-grabacion-1761175650672.webm','Grabación de sesión',NULL,'video/webm','2025-10-22 23:27:31','video'),(19,0,'/uploads/multimedia/1761446001424-video-grabacion-1761446001403.webm','Grabación de sesión',NULL,'video/webm','2025-10-26 02:33:21','video'),(20,0,'/uploads/multimedia/1761701773346-video-grabacion-1761701773329.webm','Grabación de sesión',NULL,'video/webm','2025-10-29 01:36:13','video');
/*!40000 ALTER TABLE `videos_sesion` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-11-05 17:48:54

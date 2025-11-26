# ====================================================================
# STAGE 1: BUILD (Etapa de Construcción)
# Usamos una imagen que tiene el JDK y Maven preinstalados.
# '3-jdk-slim' es una etiqueta estable y ligera para el JDK 17.
# ====================================================================
FROM maven:3.9.5-eclipse-temurin-17-alpine AS builder

# Establece el directorio de trabajo dentro del contenedor para la construcción
WORKDIR /app

# Copia los archivos de configuración de Maven primero. 
# Esto permite que Docker cachee las dependencias si el pom.xml no cambia.
COPY pom.xml .

# Descarga las dependencias del proyecto.
RUN mvn dependency:go-offline

# Copia el resto del código fuente del proyecto.
COPY src /app/src

# Compila y empaqueta la aplicación en un JAR (el resultado irá a target/)
# Usamos -DskipTests si no queremos correr los tests en el contenedor
RUN mvn package -DskipTests

# ====================================================================
# STAGE 2: RUNTIME (Etapa de Ejecución)
# Usamos una imagen mucho más pequeña que solo tiene el Java Runtime Environment (JRE).
# ====================================================================
FROM eclipse-temurin:17-jre-alpine

# Establece el directorio de trabajo final
WORKDIR /app

# Obtén el JAR construido de la etapa 'builder'
# Asumimos que tu JAR se llama 'adso.jar' o similar.
# DEBES verificar el nombre exacto del JAR en la carpeta 'target/' después de compilar localmente.
# Aquí usamos un nombre genérico:
COPY --from=builder /app/target/*.jar /app/app.jar

# Define el puerto que expone tu aplicación (típico de Spring Boot)
EXPOSE 8080

# Comando para ejecutar la aplicación JAR cuando el contenedor se inicia
ENTRYPOINT ["java", "-jar", "app.jar"]
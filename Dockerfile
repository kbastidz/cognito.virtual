# Etapa de compilación
FROM eclipse-temurin:17-jdk-alpine as build
LABEL authors="aguero"

WORKDIR /workspace/app

COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .
COPY src src

RUN chmod +x mvnw
RUN ./mvnw clean package -DskipTests

# Etapa de ejecución
FROM eclipse-temurin:17-jre-alpine
VOLUME /tmp

# Copiar el jar final directamente
COPY --from=build /workspace/app/target/*.jar app.jar

# Ejecutar usando el manifest del jar (Start-Class)
ENTRYPOINT ["java", "-jar", "/app.jar"]

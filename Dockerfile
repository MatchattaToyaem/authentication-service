# Stage 1: Build
FROM eclipse-temurin:21-jdk AS build

WORKDIR /app

# Copy Gradle wrapper and build files
COPY gradlew settings.gradle build.gradle ./
COPY gradle/ gradle/

# Pre-download dependencies (layer cache)
ARG AZURE_ARTIFACTS_FEED_URL
ARG AZURE_ARTIFACTS_PAT
ENV AZURE_ARTIFACTS_FEED_URL=${AZURE_ARTIFACTS_FEED_URL}
ENV AZURE_ARTIFACTS_PAT=${AZURE_ARTIFACTS_PAT}
RUN chmod +x gradlew && ./gradlew dependencies --no-daemon || true

# Copy source and build
COPY src/ src/
RUN ./gradlew bootJar --no-daemon -x test

# Stage 2: Runtime
FROM eclipse-temurin:21-jre

WORKDIR /app

COPY --from=build /app/build/libs/*.jar app.jar

EXPOSE 8081

ENV SPRING_PROFILES_ACTIVE=prod

ENTRYPOINT ["java", "-jar", "app.jar"]

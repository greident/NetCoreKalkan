FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
USER $APP_UID
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

COPY ["KalkanCore/KalkanCore.csproj", "KalkanCore/"]
COPY ["CryptCore/CryptCore.csproj", "CryptCore/"]
RUN dotnet restore "KalkanCore/KalkanCore.csproj"
COPY . .
WORKDIR "/src/KalkanCore"
RUN dotnet build "./KalkanCore.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./KalkanCore.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "KalkanCore.dll"]

# Pure-managed crypto (CryptCore/BouncyCastle): no native libkalkancryptwr,
# so this image builds and runs natively on ARM as well as x64.

# Install the trusted NCA root/intermediate certificates into the system store.
USER root
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*
RUN chmod +x /app/Infra/Ca_Certs/install_test.sh && /app/Infra/Ca_Certs/install_test.sh

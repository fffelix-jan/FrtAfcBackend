# FrtAfcBackend

The backend of my university capstone project demonstration metro ticketing system (Falloway Rapid Transit / **FRT**).

This repository is a **Visual Studio solution** containing an **ASP.NET Core Web API** backend (targeting **.NET 8**) plus supporting utilities/scripts for database setup and data import.

## Projects in this solution

- **FrtAfcBackend** (`FrtAfcBackend/`)  
  ASP.NET Core Web API (Kestrel) that exposes the AFC (Automatic Fare Collection) backend endpoints.
  - Uses **Basic Authentication** backed by a SQL Server `ApiUsers` table.
  - Uses a SQL Server database (see `CreateFrtAfcDatabaseSimple.sql`).

- **BackendStressTestProgram** (`BackendStressTestProgram/`)  
  A test program for load/stress testing the backend API.

## What the backend does (high level)

- Provides API endpoints for the ticketing system clients (TVM / booth office machine / faregate).
- Stores and validates data in SQL Server (stations, fares, tickets, users, signing keys, etc.).
- Enforces per-client permissions using bit flags (see `ApiPermissions` enum in `FrtAfcBackend/Program.cs`).

## Tech stack

- **C# / ASP.NET Core Web API**
- **.NET 8** (`Microsoft.NET.Sdk.Web`)
- **SQL Server** (schema + stored procedures in `CreateFrtAfcDatabaseSimple.sql`)
- **Basic Authentication** with credentials stored in SQL Server
- Supporting utilities in:
  - **Python** (user management + station import)
  - **T-SQL** (schema and seed scripts)

## Prerequisites

- **Visual Studio 2022** (solution indicates Visual Studio Version 17)
- **.NET 8 SDK**
- **SQL Server** (local or remote)
- If using the Python helper scripts:
  - **Python 3**
  - `pyodbc`
  - **ODBC Driver 17 for SQL Server** installed

## Configuration

The API expects a SQL Server connection string in an environment variable:

- `SQLSERVER_CONNECTION_STRING`

The backend loads environment variables from a `.env` file at runtime (`DotNetEnv`), so during development you’ll typically create:

- `FrtAfcBackend/.env`

Example (adjust values to your setup):

```env
SQLSERVER_CONNECTION_STRING=Server=localhost;Database=frtafc;User Id=sa;Password=YOUR_PASSWORD;Encrypt=False;TrustServerCertificate=True;
```

> Note: the `.env` file is copied to output on build (see `FrtAfcBackend/FrtAfcBackend.csproj`), so local dev is straightforward.

## Database setup

1. Create the database + schema by running:
   - `CreateFrtAfcDatabaseSimple.sql`

   This creates (among others): `Stations`, `Tickets`, `FareRules`, `ApiUsers`, plus stored procedures/triggers.

2. Seed fare rules (optional) by running:
   - `InsertFrtFareZones.sql`

3. Import station data (optional):
   - Station data is provided in `FallowayStations.txt` (exported from Excel).
   - Use `FallowayStationsImporter.py` to load stations into the `Stations` table.

## Authentication / API users

The backend uses **HTTP Basic Auth**. Users live in the SQL Server table `ApiUsers`.

Helper script:

- `CreateApiUser.py` — create/deactivate/list users (and bulk-import via CSV)

Example command (from `CreateUserExample.txt`):

```bash
python CreateApiUser.py create lxz lxz654321 2147483647 --description "System Admin"
```

## Run

### Using Visual Studio
1. Open `FrtAfcBackend.sln`.
2. Make sure `FrtAfcBackend/.env` exists and contains `SQLSERVER_CONNECTION_STRING`.
3. Set `FrtAfcBackend` as the Startup Project.
4. Run.

### Using dotnet CLI
From the repo root:

```bash
dotnet run --project FrtAfcBackend/FrtAfcBackend.csproj
```

By default, Kestrel is configured for dual HTTP/HTTPS endpoints:

- HTTP: `http://0.0.0.0:5281`
- HTTPS: `https://0.0.0.0:7184`

(See `FrtAfcBackend/appsettings.json` and `FrtAfcBackend/Properties/launchSettings.json`.)

## License

Copyright (c) 2025 Felix An

All rights reserved.

This repository is published for portfolio/demo purposes only. No permission is granted to use, copy, modify, distribute, or sublicense this software (in source or binary form) for any commercial or production use.

If you are interested in licensing this work for real-world use, please contact me to discuss commercial licensing.

# IAM-Service

Identity and Access Management service for Account-Payables.

## Architecture & Module Structure

Yeh project Hexagonal / Clean Architecture follow karta hai:

- **`iam-api/`**: 
  - REST Controllers, Request/Response DTOs, API Interfaces, Swagger/OpenAPI docs.
  - Endpoints yahin define honge (e.g., `/api/v1/auth`, `/api/v1/users`).

- **`iam-domain/`**:
  - Pure Core Business Logic.
  - Entities, Domain Models, Value Objects, Domain Exceptions, Repository Interfaces (Ports).
  - Isme koi Spring/Database dependency nahi hoti.

- **`iam-infra/`**:
  - External adapters, Database implementations.
  - Spring Data JPA Repositories (DAO / ADO), Database Entities, External Client integrations, Security Configurations.

- **`iam-common/`**:
  - Shared Utilities, Common Constants, Global Error Handlers, Base Response formats.

- **`iam-app/`**:
  - Main application entry point (`IAMServiceApplication.java`).
  - `application.yml`, Spring Boot configurations, module wiring, dependency injection.

---

## Branching & Contribution Guidelines

- **Default Branch**: `Falcon-dev/23.11.0`
- Direct commits to `Falcon-dev/23.11.0` are strictly blocked.
- Create feature branches using: `feature/<feature-name>` or `bugfix/<issue-name>`.
- Raise a Pull Request (PR) against `Falcon-dev/23.11.0` and get it reviewed before merging.

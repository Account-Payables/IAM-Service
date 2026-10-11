# IAM Service — Auth Backend

A production-ready **authentication and authorization backend** built with **Spring Boot 3.5** and **Java 21**.  
Designed to be plugged into any application as a standalone auth service.

---

## Features

- JWT-based authentication (access + refresh tokens via HTTP-only cookies)
- OAuth2 social login (Google, GitHub)
- Role-based and permission-based access control
- Long-lived API token support
- Brute-force protection with account lockout
- Rate limiting and security headers
- Email verification and password reset flows
- Session management (revoke single or all sessions)
- Rich Spring application event system for loose coupling
- Extensibility hooks for custom login validation, registration logic, and token claims
- OpenAPI / Swagger UI documentation

---

## Tech Stack

- **Spring Boot 3.5.7**
- **Spring Security 6**
- **Spring Data JPA** (MySQL)
- **Spring OAuth2 Client**
- **JJWT 0.13** for JWT operations
- **Spring AOP** for annotation-driven authorization
- **Lombok**, **ModelMapper**
- **SpringDoc OpenAPI 2.8**

---

## Project Structure

```
auth-backend/
├── auth/
│   ├── config/          # Security config, JWT filter, OAuth2 success handler
│   ├── controllers/     # REST endpoints (auth, users, sessions, API tokens)
│   ├── entities/        # JPA entities (User, Role, Permission, RefreshToken, ...)
│   ├── payload/         # Request/response DTOs
│   ├── repositories/    # Spring Data JPA repositories
│   └── services/        # Business logic (interface + impl)
├── config/              # App-wide beans, OpenAPI config
├── core/
│   ├── annotations/     # @RequiresRole, @RequiresPermission
│   ├── aspects/         # AOP permission enforcement
│   ├── config/          # Rate limiting, security headers, API token filter
│   ├── context/         # AuthContext (current-user holder)
│   └── startup/         # DB seeder, startup validator
├── events/              # Spring application events (14 event types)
├── exceptions/          # Global exception handler
└── extension/           # Plugin interfaces for custom hooks
```

---

## Getting Started

### Prerequisites

- Java 21+
- Maven 3.9+
- MySQL 8+

### Configuration

Copy and fill in the required values in `application.yaml` (or use environment variables):

```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/iam_db
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}

security:
  jwt:
    secret: ${JWT_SECRET}
    access-ttl-seconds: 900
    refresh-ttl-seconds: 1209600

  oauth2:
    client:
      registration:
        google:
          client-id: ${GOOGLE_CLIENT_ID}
          client-secret: ${GOOGLE_CLIENT_SECRET}
        github:
          client-id: ${GITHUB_CLIENT_ID}
          client-secret: ${GITHUB_CLIENT_SECRET}
```

### Run

```bash
mvn spring-boot:run
```

Server starts on **http://localhost:8081**  
Swagger UI available at **http://localhost:8081/swagger-ui.html**

---

## API Overview

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/register` | Register a new user |
| `POST` | `/api/auth/login` | Login with email & password |
| `POST` | `/api/auth/refresh` | Refresh access token |
| `POST` | `/api/auth/logout` | Logout and clear tokens |
| `GET`  | `/api/auth/me` | Get current authenticated user |
| `GET`  | `/oauth2/authorization/google` | Redirect to Google OAuth2 |
| `GET`  | `/oauth2/authorization/github` | Redirect to GitHub OAuth2 |
| `GET`  | `/api/users` | List users (admin) |
| `GET`  | `/api/sessions` | List active sessions |
| `DELETE` | `/api/sessions` | Revoke all sessions |
| `GET`  | `/api/tokens` | List API tokens |
| `POST` | `/api/tokens` | Create an API token |
| `DELETE` | `/api/tokens/{id}` | Revoke an API token |

---

## Extensibility

Implement any of the following interfaces and register them as Spring beans to customize behavior without modifying core code:

| Interface | Purpose |
|-----------|---------|
| `LoginValidator` | Block or allow a login attempt |
| `PostLoginHook` | Run logic after a successful login |
| `RegistrationHook` | Run logic after a new user registers |
| `TokenClaimsProvider` | Add custom claims to the JWT |
| `UserEnrichmentHook` | Enrich the user object on load |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `DB_USERNAME` | MySQL username |
| `DB_PASSWORD` | MySQL password |
| `JWT_SECRET` | Secret key for signing JWTs |
| `GOOGLE_CLIENT_ID` | Google OAuth2 client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth2 client secret |
| `GITHUB_CLIENT_ID` | GitHub OAuth2 client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth2 client secret |

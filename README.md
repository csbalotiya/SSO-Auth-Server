# SSO Auth Server

A comprehensive OAuth 2.0 and OpenID Connect (OIDC) authorization server built with Spring Boot and Spring Security OAuth2 Authorization Server.

## 🚀 Features

- **OAuth 2.0 & OpenID Connect 1.0** compliant authorization server
- **Multiple client types** support (web, mobile, service-to-service)
- **JWT tokens** with RSA signature
- **Custom JWT claims** for extended user information
- **CORS support** for cross-origin requests
- **Multi-profile configuration** (dev/prod)

## 📋 Prerequisites

- Java 17 or higher
- Maven 3.6+
- Spring Boot 3.2+
- Optional: PostgreSQL for production

## 🛠️ Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/sso-auth-server.git
cd sso-auth-server
```

### 2. Build the Project

```bash
mvn clean install
```

### 3. Run the Application

#### Development Mode (Default)
```bash
mvn spring-boot:run
```

#### Production Mode
```bash
mvn spring-boot:run -Dspring-boot.run.profiles=prod
```

#### Using JAR
```bash
java -jar target/sso-auth-server-1.0.0.jar
```

The server will start on `http://localhost:9000`

## 📁 Project Structure

```
sso-auth-server/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── net/sso/sso_auth_server/
│   │   │       ├── config/
│   │   │       │   ├── AuthorizationServerConfig.java
│   │   │       │   └── SecurityConfig.java
│   │   │       ├── controller/
│   │   │       │   └── UserController.java
│   │   │       └── SsoAuthServerApplication.java
│   │   └── resources/
│   │       ├── application.yml
│   │       └── templates/
├── pom.xml
└── README.md
```

## ⚙️ Configuration

### Application Properties

The application uses YAML configuration with profile-specific settings:

#### Server Configuration
```yaml
server:
  port: 9000
  servlet:
    session:
      cookie:
        name: AUTH_SESSION
        same-site: lax
        secure: false  # true in production
        http-only: true
        max-age: 3600
```

#### OAuth2 Clients

The server supports multiple client types:

1. **Web Client** - Traditional web applications
2. **Mobile Client** - Public clients (SPAs, mobile apps)
3. **Service Client** - Machine-to-machine communication

### Environment Variables

For production deployment, use these environment variables:

```bash
# Database
export DB_URL=jdbc:postgresql://localhost:5432/sso_auth
export DB_USERNAME=sso_user
export DB_PASSWORD=your_secure_password

# Security
export JWT_SECRET=your-jwt-secret-key
export ENCRYPTION_KEY=your-32-character-key

# Server
export SERVER_PORT=9000
export ISSUER_URI=https://your-domain.com
```

## 🔐 Security Features

### JWT Token Configuration

- **Access Token TTL**: 1 hour
- **Refresh Token TTL**: 7 days
- **RSA 2048-bit** key pair for signing
- **Custom claims** support

### PKCE (Proof Key for Code Exchange)

PKCE is enabled for enhanced security, especially for public clients:

```yaml
require-proof-key: true
```

### CORS Configuration

Cross-origin requests are supported with configurable origins:

```yaml
app:
  auth:
    cors:
      allowed-origins:
        - http://localhost:3000
        - http://localhost:8081
```

## 📡 API Endpoints

### OAuth2 & OIDC Endpoints

| Endpoint | Description |
|----------|-------------|
| `/oauth2/authorize` | Authorization endpoint |
| `/oauth2/token` | Token endpoint |
| `/oauth2/revoke` | Token revocation |
| `/oauth2/introspect` | Token introspection |
| `/userinfo` | User information endpoint |
| `/connect/logout` | Logout endpoint |

### Well-Known Endpoints

| Endpoint | Description |
|----------|-------------|
| `/.well-known/openid-configuration` | OIDC Discovery |
| `/.well-known/jwks.json` | JSON Web Key Set |
| `/.well-known/oauth-authorization-server` | OAuth2 Server Metadata |

### Health & Monitoring

| Endpoint | Description |
|----------|-------------|
| `/actuator/health` | Health check |
| `/actuator/info` | Application info |
| `/actuator/metrics` | Application metrics |

## 🔧 Client Integration

### Authorization Code Flow

#### Step 1: Authorization Request

```http
GET /oauth2/authorize?response_type=code&client_id=web-client&redirect_uri=http://localhost:8081/login/oauth2/code/web-client&scope=openid%20profile&state=random-state
```

#### Step 2: Token Exchange

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic d2ViLWNsaWVudDp3ZWItc2VjcmV0

grant_type=authorization_code&code=AUTHORIZATION_CODE&redirect_uri=http://localhost:8081/login/oauth2/code/web-client
```

### Client Credentials Flow

For service-to-service communication:

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic c2VydmljZS1jbGllbnQ6c2VydmljZS1zZWNyZXQ=

grant_type=client_credentials&scope=read%20write
```

## 🧪 Testing

### Default Test Users

| Username | Password | Roles |
|----------|----------|-------|
| `user` | `password` | USER |
| `admin` | `admin` | USER, ADMIN |

### Testing Authorization Flow

1. **Start the server**:
   ```bash
   mvn spring-boot:run
   ```

2. **Open authorization URL**:
   ```
   http://localhost:9000/oauth2/authorize?response_type=code&client_id=web-client&redirect_uri=http://localhost:8081/login/oauth2/code/web-client&scope=openid%20profile
   ```

3. **Login with test credentials**

4. **Get authorization code** from redirect URI

5. **Exchange code for token** using `/oauth2/token` endpoint

### cURL Examples

#### Get Access Token

```bash
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'service-client:service-secret' | base64)" \
  -d "grant_type=client_credentials&scope=read"
```

#### Get User Info

```bash
curl -X GET http://localhost:9000/userinfo \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 🌐 Client Applications

### Spring Boot Client Configuration

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          sso-auth-server:
            client-id: web-client
            client-secret: web-secret
            scope: openid,profile,email
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
        provider:
          sso-auth-server:
            issuer-uri: http://localhost:9000
```

### JavaScript/SPA Client

```javascript
const config = {
  authority: 'http://localhost:9000',
  client_id: 'mobile-client',
  redirect_uri: 'http://localhost:3000/callback',
  response_type: 'code',
  scope: 'openid profile email',
  post_logout_redirect_uri: 'http://localhost:3000',
  automaticSilentRenew: true,
  silent_redirect_uri: 'http://localhost:3000/silent-callback'
};
```


## 🐛 Troubleshooting

### Common Issues

1. **CORS Errors**
    - Check `allowed-origins` in configuration
    - Verify client domain is whitelisted

2. **Token Validation Failures**
    - Ensure clock synchronization
    - Check JWT expiration times

3. **PKCE Errors**
    - Verify client supports PKCE
    - Check code_verifier/code_challenge generation

### Debug Logging

Enable debug logging:

```yaml
logging:
  level:
    org.springframework.security: DEBUG
    org.springframework.security.oauth2: DEBUG
```

## 📚 Resources

### Documentation

- [Spring Authorization Server Reference](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/)
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Specification](https://openid.net/connect/)

### Tools

- [JWT.io](https://jwt.io/) - JWT token decoder
- [OAuth.tools](https://oauth.tools/) - OAuth testing tools
- [Postman](https://www.postman.com/) - API testing

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

For support and questions:

- **Email**: support@yourcompany.com
- **Issues**: [GitHub Issues](https://github.com/yourusername/sso-auth-server/issues)
- **Documentation**: [Wiki](https://github.com/yourusername/sso-auth-server/wiki)

---

**Version**: 1.0.0  
**Last Updated**: July 2025  
**Maintainer**: Your Name <your.email@company.com>
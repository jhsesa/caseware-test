# System Prompt & Coding Standards

## Tech Stack
- C# 12 / .NET 10
- ASP.NET Core Minimal APIs
- `Microsoft.AspNetCore.Authentication.JwtBearer`

## Strict Rules for AI Generation
1. **NO CUSTOM CRYPTOGRAPHY:** Do NOT hand-roll token parsing, RSA/HMAC signature verification, or token validation. You MUST use the built-in `JwtSecurityTokenHandler` and `TokenValidationParameters`.
2. **Focus on Interfaces:** Emphasize contracts, middleware, and dependency injection. Mock external dependencies (like the database or external IdP).
3. **Simplicity:** Keep the code footprint small. Use Minimal APIs structure (`app.MapGet`, `app.MapPost`).
4. **Security:** Ensure standard OAuth2 claims (`sub`, `aud`, `iss`) are checked appropriately. 
5. **No Boilerplate Overload:** Only generate the code strictly necessary to demonstrate the authorization slice. Do not generate complex folder structures unless asked.

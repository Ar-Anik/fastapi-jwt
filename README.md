      1. Open /docs
             ↓
      2. Click Authorize 🔒
             ↓
      3. username = anik
         password = secret
             ↓
      4. Authorize
             ↓
      5. GET /auth/me
             ↓
      6. Execute
             ↓
      7. Swagger automatically sends:
         Authorization: Bearer <access_token>
             ↓
      8. Current user returned
             ↓
      9. Access Token expires
             ↓
      10. POST /auth/refresh
             ↓
      11. Give refresh_token
             ↓
      12. Receive new tokens

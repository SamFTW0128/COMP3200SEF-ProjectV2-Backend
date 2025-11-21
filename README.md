
# CottonWar Backend

Simple Node.js + Express + SQLite backend for the CottonWar food ordering/tracking demo.

## Local setup

```bash
npm install
npm start
```

The server will listen on `http://localhost:3000` by default.

### Environment variables

- `PORT` (optional): port to listen on (default: 3000)
- `JWT_SECRET` (recommended): secret string for signing JWT tokens

## API overview

- `GET /api/health` — health check
- `POST /api/register` — register a new user
  - body: `{ id, name, password, role, location?, deliveryMethod? }`
- `POST /api/login` — login
  - body: `{ id, password, role? }`
- `GET /api/me` — get current user (requires `Authorization: Bearer <token>`)
- `GET /api/orders` — list orders for current user (future use)
- `POST /api/orders` — create order (customer only)
- `PATCH /api/orders/:id` — update order status (restaurant/rider/admin)

The SQLite database is stored in `foodtrack.db` in the project root.

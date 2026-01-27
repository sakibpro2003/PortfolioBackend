# Backend API

## Setup

```sh
npm install
npm run dev
```

## Environment

Copy `.env.example` to `.env` and adjust as needed.

- `PORT`: API port (default: 5000)
- `CORS_ORIGIN`: comma-separated allowed origins
- `EMAILJS_SERVICE_ID`: EmailJS service id
- `EMAILJS_TEMPLATE_ID`: EmailJS template id
- `EMAILJS_PUBLIC_KEY`: EmailJS public key
- `CONTACT_EMAIL`: destination email used in template params

## Endpoints

- `GET /api/health`
- `POST /api/contact`

Request body for `/api/contact`:

```json
{
  "name": "Jane Doe",
  "email": "jane@example.com",
  "message": "Hello from the portfolio site."
}
```

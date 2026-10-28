# DEEPORA - Backend REST API & Database Service

[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg?logo=node.js)](https://nodejs.org/)
[![Database](https://img.shields.io/badge/MongoDB-Atlas%20%2F%20Local-emerald.svg?logo=mongodb)](https://www.mongodb.com/)
[![License](https://img.shields.io/badge/License-ISC-brightgreen.svg)](package.json)
[![Author](https://img.shields.io/badge/Author-Mayank%20Rana-blue)](https://github.com/MayankR-Codes)

The standalone backend REST API service for the **DEEPORA** handcrafted festive diya brand storefront. Built with Node.js, MongoDB Atlas driver, and Nodemailer transactional automated invoice dispatch.

---

## 🌟 Architecture & Features

- **Robust RESTful API**: Full CRUD endpoints for catalog management, shopping cart persistence, customer authentication, and order workflows.
- **MongoDB Atlas Integration**: Native MongoDB driver connection with automated collection indexing (`users`, `orders`, `products`, `sessions`, `feedback`).
- **Customer Authentication**: Secure salted `scrypt` password hashing, unique user identifiers (phone/email), and TTL-based automatic session cleanup.
- **Automated Transactional Emails**: Instant itemized invoice dispatch via Nodemailer using Gmail SMTP when orders are placed.
- **CORS & Rate Limiting**: Secure origin whitelisting with credential support for frontend communication and built-in abuse prevention.
- **Resilient Offline Mode**: Gracefully handles network blips or offline database states with automatic 30-second exponential retry attempts.

---

## 🏗️ Directory Structure

```
Deepora-BackEnd/
├── src/
│   ├── server.js             # REST API server: routing, authentication, email & orders
│   └── db.js                 # MongoDB connection manager, indexes & collection helpers
├── server.js                 # Main root entrypoint (runs src/server.js)
├── .env                      # Local secret environment variables (git-ignored)
├── .env.example              # Template environment configuration
├── .gitignore                # Git ignore rules for node_modules, secrets, logs
├── package.json              # Project dependencies and npm scripts
├── package-lock.json         # Locked dependency versions
└── README.md                 # Backend documentation
```

---

## ⚙️ Configuration (.env)

Copy `.env.example` to `.env` in the repository root:

```bash
cp .env.example .env
```

Configure your environment variables:

```ini
AUTH_HOST=127.0.0.1
AUTH_PORT=4175
DEEPORA_ALLOWED_ORIGINS=http://127.0.0.1:4173,http://localhost:4173

# Gmail Invoice Delivery Settings
ORDER_EMAIL_FROM=mayank.rana.mr12@gmail.com
ORDER_EMAIL_TO=mayank.rana.mr12@gmail.com

# SMTP Credentials (Use Gmail 16-character App Password)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=mayank.rana.mr12@gmail.com
SMTP_APP_PASSWORD=your_gmail_app_password_here

# MongoDB Connection String (Atlas or Local)
MONGODB_URI=mongodb+srv://<username>:<password>@cluster0.mongodb.net/deepora?retryWrites=true&w=majority
MONGODB_DB_NAME=deepora
```

---

## 🚀 Getting Started

### 1. Install Dependencies
```bash
npm install
```

### 2. Start the Backend API Server
```bash
npm start
```
*For development with automatic file restart (Node 18+):*
```bash
npm run dev
```

The API service runs at:
👉 **[http://127.0.0.1:4175](http://127.0.0.1:4175)**

Visiting the root endpoint `GET /` returns the service status and endpoint overview.

---

## 📡 REST API Reference

### Health & Diagnostics
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | API service overview and available endpoints |
| `GET` | `/api/health` | Service and MongoDB status check |
| `GET` | `/api/health/email` | SMTP email transport verification |

### Product Catalog
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/products` | Retrieve all active products with variant pricing |
| `GET` | `/api/products/:id` | Retrieve product details by ID/slug |
| `POST` | `/api/products` | Add a new product to the catalog |
| `PUT` | `/api/products/:id` | Update product details (price, stock, variants) |
| `DELETE` | `/api/products/:id` | Remove a product from the catalog |

### Authentication & Users
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/register` | Register new account with phone/email and password |
| `POST` | `/api/auth/login` | Log in and receive HTTP-only session cookie |
| `POST` | `/api/auth/logout` | Terminate session and clear cookie |
| `GET` | `/api/auth/me` | Retrieve current authenticated user profile & address |
| `PUT` | `/api/auth/profile` | Update user profile and delivery address |
| `POST` | `/api/auth/send-verification` | Send OTP challenge code to user email |
| `POST` | `/api/auth/verify-email` | Verify challenge code |

### Cart & Orders
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/cart` | Retrieve user shopping cart |
| `PUT` | `/api/cart` | Sync shopping cart items |
| `POST` | `/api/orders` | Place order, persist to MongoDB, send email invoice |
| `GET` | `/api/orders` | Retrieve authenticated customer's order history |
| `GET` | `/api/orders/:reference` | Get order details and tracking status |
| `POST` | `/api/orders/:reference/resend-invoice` | Resend itemized invoice email |
| `POST` | `/api/feedback` | Submit feedback for an order |

---

## 🗄️ MongoDB Collections

1. **`users`**: Customer profiles, phone numbers, delivery addresses, salted password hashes.
2. **`orders`**: Immutable order records, line items, pricing breakdown, tracking reference (`DP-XXXXXXXX`), delivery snapshot.
3. **`products`**: Catalog items with multi-tier variant pricing (e.g. Single, Pack of 2, Pack of 5).
4. **`sessions`**: Cryptographic tokens with automatic TTL index expiration.
5. **`feedback`**: Order reviews and ratings.

---

## 🚀 Deploying to Vercel

The backend is fully configured for serverless deployment on Vercel via [`api/index.js`](file:///C:/Users/KIIT/Documents/Deepora-BackEnd/api/index.js) and [`vercel.json`](file:///C:/Users/KIIT/Documents/Deepora-BackEnd/vercel.json).

### Method 1: Deploy with Vercel CLI
```bash
npm i -g vercel
vercel
```

### Method 2: Deploy via Vercel Web Dashboard
1. Push this backend repository to GitHub (e.g. `deepora-backend`).
2. Log into [vercel.com](https://vercel.com) and click **"Add New Project"**.
3. Import your `deepora-backend` repository.
4. Keep **Framework Preset** as **Other** (Root directory: `./`).
5. In **Environment Variables**, add:
   - `MONGODB_URI`: Your MongoDB Atlas cluster connection string.
   - `MONGODB_DB_NAME`: `deepora` (or your chosen database name).
   - `DEEPORA_ALLOWED_ORIGINS`: Comma-separated list of your frontend URLs (e.g. `https://deepora-storefront.vercel.app,http://localhost:4173`).
   - `AUTH_SECRET`: A secure random string for HMAC signatures.
   - `SMTP_USER` & `SMTP_APP_PASSWORD`: For email invoice & verification dispatch.
   - `ORDER_EMAIL_FROM` & `ORDER_EMAIL_TO`: Sender & receiver addresses for order invoices.
   - `NODE_ENV`: `production`
6. Click **Deploy**.

### Verification after Deployment
Once deployed, verify your live deployment endpoints:
- `GET https://your-backend.vercel.app/` -> Service status info
- `GET https://your-backend.vercel.app/api/health` -> `{ "ok": true, "database": "mongodb" }`
- `GET https://your-backend.vercel.app/api/products` -> Product catalog array

---

## 📦 Setting Up as a Separate Git Repository

To initialize this folder as its own independent git repository:

```bash
cd C:\Users\KIIT\Documents\Deepora-BackEnd
git init
git add .
git commit -m "feat: initial commit of Deepora Backend REST API service"
git branch -M main
# Add your GitHub remote:
# git remote add origin https://github.com/<your-username>/deepora-backend.git
# git push -u origin main
```

---

## 👤 Author
- **Developer**: [Mayank Rana](https://github.com/MayankR-Codes)
- **Email**: [mayank.rana.mr12@gmail.com](mailto:mayank.rana.mr12@gmail.com)
- **License**: ISC

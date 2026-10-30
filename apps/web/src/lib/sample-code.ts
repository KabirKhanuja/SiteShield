import type { UploadedFile } from "@/lib/api";

// A deliberately insecure sample project, bundled so the code scan can be demonstrated in one
// click without picking a folder. Every file here has planted mistakes on purpose; it mirrors
// demo/vulnerable-shop in the repository. Never ship any of this.
export const SAMPLE_CODE: UploadedFile[] = [
  {
    path: "vulnerable-shop/package.json",
    content: `{
  "name": "vulnerable-shop",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.11",
    "jsonwebtoken": "8.5.1",
    "cors": "2.8.5"
  }
}
`,
  },
  {
    path: "vulnerable-shop/.env",
    content: `DATABASE_PASSWORD=pr0d_Db_P@ss_9f3k2Lq
NEXT_PUBLIC_API_SECRET=a1b2c3d4e5f6a7b8c9d0e1f2
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_fakekeythatismeanttoship
`,
  },
  {
    path: "vulnerable-shop/server.js",
    content: `// Demo API for the vulnerable shop. Every route here has a planted flaw.
const express = require("express");
const cors = require("cors");
const { exec } = require("child_process");
const jwt = require("jsonwebtoken");
const https = require("https");
const db = require("./db");

const app = express();
app.use(express.json());

// CORS wide open while also sending credentials.
app.use(cors({ origin: "*", credentials: true }));

// Login endpoint with no rate limiting, so it can be brute forced.
app.post("/api/login", (req, res) => {
  const token = jwt.decode(req.body.token); // decode, never verifies the signature
  const row = db.query("SELECT * FROM users WHERE email = '" + req.body.email + "'");
  res.json({ ok: true, user: row, token });
});

// Order lookup with the id dropped straight into the query.
app.get("/api/orders/:id", (req, res) => {
  const order = db.query(\`SELECT * FROM orders WHERE id = \${req.params.id}\`);
  res.json(order);
});

// Deletes an account without checking who is asking.
app.delete("/api/users/:id", (req, res) => {
  db.query("DELETE FROM users WHERE id = " + req.params.id);
  res.json({ deleted: true });
});

// Runs a shell command built from the query string.
app.get("/api/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));
});

// Calls an upstream service with certificate checks turned off.
const agent = new https.Agent({ rejectUnauthorized: false });

app.listen(3000);
`,
  },
  {
    path: "vulnerable-shop/cart.js",
    content: `// Renders the cart in the browser. Writes untrusted values straight into the DOM.
function renderCart(items) {
  const list = document.getElementById("cart");
  items.forEach((item) => {
    const row = document.createElement("li");
    row.innerHTML = item.name + " - " + item.note; // note comes from the user
    list.appendChild(row);
  });
}

function showBanner(message) {
  document.getElementById("banner").innerHTML = message;
}
`,
  },
];

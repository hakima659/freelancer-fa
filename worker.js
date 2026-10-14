
const ALLOWED_ORIGINS = new Set([
  "https://hakima659.github.io"
]);

function getCorsHeaders(origin) {
  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, X-Admin-Token",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }

  return headers;
}

const CORS_HEADERS = getCorsHeaders(
  "https://hakima659.github.io"
);

const PLANS = {
  free: {
    id: "free",
    name: "رایگان",
    price: 0,
    projectLimit: 1,
    proposalLimit: 1,
    days: 0
  },
  bronze: {
    id: "bronze",
    name: "برنزی",
    price: 590000,
    projectLimit: 20,
    proposalLimit: 20,
    days: 30
  },
  silver: {
    id: "silver",
    name: "نقره‌ای",
    price: 990000,
    projectLimit: 100,
    proposalLimit: 60,
    days: 30
  },
  gold: {
    id: "gold",
    name: "طلایی",
    price: 1490000,
    projectLimit: 500,
    proposalLimit: 150,
    days: 30
  },
  professional: {
    id: "professional",
    name: "حرفه‌ای",
    price: 2490000,
    projectLimit: 1000000,
    proposalLimit: null,
    days: 30
  }
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS_HEADERS,
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function fail(message, status = 400) {
  return json({
    ok: false,
    error: message
  }, status);
}

function normalizePhone(value) {
  let phone = String(value || "").replace(/[\s-]/g, "");

  if (phone.startsWith("+98")) {
    phone = "0" + phone.slice(3);
  }

  if (phone.startsWith("0098")) {
    phone = "0" + phone.slice(4);
  }

  return phone;
}

function validPhone(phone) {
  return /^09\d{9}$/.test(phone);
}

function b64url(bytes) {
  let binary = "";

  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decodeB64url(text) {
  const base64 = text
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded =
    base64 + "=".repeat((4 - base64.length % 4) % 4);

  return Uint8Array.from(
    atob(padded),
    c => c.charCodeAt(0)
  );
}

async function passwordHash(password, salt) {
  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: decodeB64url(salt),
    iterations: 120000,
    hash: "SHA-256"
  }, key, 256);

  return b64url(new Uint8Array(bits));
}

async function signToken(payload, secret) {
  const enc = new TextEncoder();

  const data = b64url(
    enc.encode(JSON.stringify(payload))
  );

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(data)
  );

  return data + "." + b64url(
    new Uint8Array(signature)
  );
}

async function verifyToken(token, secret) {
  try {
    const parts = String(token || "").split(".");

    if (parts.length !== 2) {
      return null;
    }

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      decodeB64url(parts[1]),
      new TextEncoder().encode(parts[0])
    );

    if (!valid) {
      return null;
    }

    const payload = JSON.parse(
      new TextDecoder().decode(
        decodeB64url(parts[0])
      )
    );

    if (
      !payload.exp ||
      payload.exp <= Math.floor(Date.now() / 1000)
    ) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function getAuthSecret(env) {
  return env.AUTH_SECRET || env["رمز تایید"] || "";
}

function effectivePlan(user) {
  if (!user) {
    return PLANS.free;
  }

  const expires = user.subscription_expires_at
    ? Date.parse(user.subscription_expires_at)
    : 0;

  if (
    user.plan_id !== "free" &&
    expires &&
    expires > Date.now() &&
    PLANS[user.plan_id]
  ) {
    return PLANS[user.plan_id];
  }

  return PLANS.free;
}

async function getUser(request, env) {
  const header =
    request.headers.get("Authorization") || "";

  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  const secret = getAuthSecret(env);

  if (!token || !secret || !env.DB) {
    return null;
  }

  const payload = await verifyToken(token, secret);

  if (!payload || !payload.uid) {
    return null;
  }

  return await env.DB.prepare(
    `SELECT id, phone, plan_id, subscription_expires_at
     FROM users
     WHERE id = ?`
  ).bind(payload.uid).first();
}

async function adminAllowed(request, env) {
  const supplied =
    request.headers.get("X-Admin-Token") || "";

  const expected =
    env.ADMIN_TOKEN || env["کد_مدیر"] || "";

  if (
    !expected ||
    supplied.length !== expected.length
  ) {
    return false;
  }

  let mismatch = 0;

  for (let i = 0; i < supplied.length; i++) {
    mismatch |=
      supplied.charCodeAt(i) ^
      expected.charCodeAt(i);
  }

  return mismatch === 0;
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

async function countProjects(env, userId) {
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS n
     FROM project_owners
     WHERE user_id = ?`
  ).bind(userId).first();

  return Number(row?.n || 0);
}

async function countProposals(env, userId) {
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS n
     FROM proposal_owners
     WHERE user_id = ?`
  ).bind(userId).first();

  return Number(row?.n || 0);
}

async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method;

  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: CORS_HEADERS
    });
  }

  if (!env.DB) {
    return fail("اتصال پایگاه داده DB برقرار نیست.", 500);
  }

  if (path === "/health" && method === "GET") {
    await env.DB.prepare("SELECT 1").first();

    return json({
      ok: true,
      service: "freelanso",
      database: "connected"
    });
  }

  // بررسی ساختار جدول‌های D1؛ مسیر موقت عیب‌یابی
  if (path === "/api/db-check" && method === "GET") {
    const requiredSchema = {
      users: [
        "id",
        "phone",
        "password_hash",
        "password_salt",
        "plan_id",
        "subscription_expires_at"
      ],
      projects: [
        "id",
        "title",
        "category",
        "budget",
        "description",
        "created_at"
      ],
      project_owners: [
        "project_id",
        "user_id"
      ],
      proposals: [
        "id",
        "project_id",
        "freelancer_name",
        "description",
        "price"
      ],
      proposal_owners: [
        "proposal_id",
        "user_id"
      ],
      subscription_payments: [
        "id",
        "user_id",
        "plan_id",
        "amount",
        "phone",
        "payment_reference",
        "status",
        "admin_note",
        "created_at",
        "reviewed_at"
      ]
    };

    const tables = {};

    for (const [table, required] of Object.entries(requiredSchema)) {
      const exists = await env.DB.prepare(
        `SELECT name
         FROM sqlite_master
         WHERE type = 'table' AND name = ?`
      ).bind(table).first();

      if (!exists) {
        tables[table] = {
          exists: false,
          missing: required
        };

        continue;
      }

      const result = await env.DB.prepare(
        `PRAGMA table_info("${table}")`
      ).all();

      const actual = (result.results || []).map(
        column => column.name
      );

      tables[table] = {
        exists: true,
        columns: actual,
        missing: required.filter(
          column => !actual.includes(column)
        )
      };
    }

    const problems = Object.entries(tables)
      .filter(([, info]) =>
        !info.exists || info.missing.length > 0
      )
      .map(([table, info]) => ({
        table,
        ...info
      }));

    return json({
      ok: problems.length === 0,
      service: "freelanso",
      database: "connected",
      problems,
      tables
    });
  }

  // اطلاعات کارت
  if (path === "/api/payment-info" && method === "GET") {
    return json({
      ok: true,
      cardHolder:
        env.CARD_HOLDER ||
        env["دارنده کارت"] ||
        "",
      cardNumber:
        env.CARD_NUMBER ||
        env["شماره کارت"] ||
        ""
    });
  }

  // پلن‌ها
  if (path === "/api/plans" && method === "GET") {
    return json({
      ok: true,
      plans: Object.values(PLANS)
    });
  }

  // ثبت‌نام
  if (path === "/api/auth/register" && method === "POST") {
    const secret = getAuthSecret(env);

    if (!secret) {
      return fail("تنظیم AUTH_SECRET انجام نشده است.", 500);
    }

    const body = await readBody(request);

    if (!body) {
      return fail("اطلاعات ارسالی معتبر نیست.");
    }

    const phone = normalizePhone(body.phone);
    const password = String(body.password || "");

    if (!validPhone(phone)) {
      return fail(
        "شماره موبایل باید با 09 شروع شود و ۱۱ رقم داشته باشد."
      );
    }

    if (password.length < 8 || password.length > 128) {
      return fail(
        "رمز عبور باید بین ۸ تا ۱۲۸ نویسه باشد."
      );
    }

    const salt = b64url(
      crypto.getRandomValues(new Uint8Array(16))
    );

    const hash = await passwordHash(password, salt);

    try {
      const result = await env.DB.prepare(
        `INSERT INTO users
         (phone, password_hash, password_salt, plan_id)
         VALUES (?, ?, ?, 'free')`
      ).bind(phone, hash, salt).run();

      const userId = result.meta?.last_row_id;

      if (!userId) {
        return fail("ساخت حساب انجام نشد.", 500);
      }

      const token = await signToken({
        uid: userId,
        exp: Math.floor(Date.now() / 1000) +
          60 * 60 * 24 * 7
      }, secret);

      return json({
        ok: true,
        token,
        user: {
          id: userId,
          phone,
          plan_id: "free"
        }
      }, 201);
    } catch (error) {
      if (String(error).includes("UNIQUE")) {
        return fail(
          "این شماره قبلاً ثبت‌نام کرده است.",
          409
        );
      }

      throw error;
    }
  }

  // ورود
  if (path === "/api/auth/login" && method === "POST") {
    const secret = getAuthSecret(env);

    if (!secret) {
      return fail("تنظیم AUTH_SECRET انجام نشده است.", 500);
    }

    const body = await readBody(request);

    if (!body) {
      return fail("اطلاعات ارسالی معتبر نیست.");
    }

    const phone = normalizePhone(body.phone);
    const password = String(body.password || "");

    if (!validPhone(phone) || !password) {
      return fail(
        "شماره موبایل یا رمز عبور نادرست است.",
        401
      );
    }

    const user = await env.DB.prepare(
      `SELECT id, phone, password_hash, password_salt,
              plan_id, subscription_expires_at
       FROM users
       WHERE phone = ?`
    ).bind(phone).first();

    if (!user) {
      return fail(
        "شماره موبایل یا رمز عبور نادرست است.",
        401
      );
    }

    const candidate = await passwordHash(
      password,
      user.password_salt
    );

    if (candidate !== user.password_hash) {
      return fail(
        "شماره موبایل یا رمز عبور نادرست است.",
        401
      );
    }

    const token = await signToken({
      uid: user.id,
      exp: Math.floor(Date.now() / 1000) +
        60 * 60 * 24 * 7
    }, secret);

    return json({
      ok: true,
      token,
      user: {
        id: user.id,
        phone: user.phone,
        plan_id: user.plan_id,
        subscription_expires_at:
          user.subscription_expires_at
      }
    });
  }

  // اطلاعات حساب
  if (path === "/api/auth/me" && method === "GET") {
    const user = await getUser(request, env);

    if (!user) {
      return fail("برای ادامه وارد حساب شو.", 401);
    }

    return json({
      ok: true,
      user,
      plan: effectivePlan(user)
    });
  }

  // فهرست عمومی پروژه‌ها
  if (path === "/api/projects" && method === "GET") {
    const result = await env.DB.prepare(
      `SELECT id, title, category, budget,
              description, created_at
       FROM projects
       ORDER BY id DESC
       LIMIT 100`
    ).all();

    return json({
      ok: true,
      projects: result.results || []
    });
  }

  // ثبت پروژه
  if (path === "/api/projects" && method === "POST") {
    const user = await getUser(request, env);

    if (!user) {
      return fail(
        "برای ثبت پروژه ابتدا وارد حساب شو.",
        401
      );
    }

    const plan = effectivePlan(user);
    const body = await readBody(request);

    if (!body) {
      return fail("اطلاعات پروژه معتبر نیست.");
    }

    const title = String(body.title || "").trim();
    const category = String(body.category || "").trim();
    const description =
      String(body.description || "").trim();
    const budget = Number(body.budget);

    if (
      title.length < 3 ||
      title.length > 150 ||
      category.length < 2 ||
      category.length > 80 ||
      description.length < 10 ||
      description.length > 5000 ||
      !Number.isSafeInteger(budget) ||
      budget < 0
    ) {
      return fail(
        "عنوان، دسته‌بندی، توضیحات یا بودجه معتبر نیست."
      );
    }

    const count = await countProjects(env, user.id);

    if (count >= plan.projectLimit) {
      return fail(
        "سقف ثبت پروژه پلن شما تکمیل شده است. برای ادامه پلن خود را ارتقا بده.",
        403
      );
    }

    const result = await env.DB.prepare(
      `INSERT INTO projects
       (title, category, budget, description)
       VALUES (?, ?, ?, ?)`
    ).bind(
      title,
      category,
      budget,
      description
    ).run();

    const projectId = result.meta?.last_row_id;

    if (!projectId) {
      return fail("پروژه ساخته نشد.", 500);
    }

    await env.DB.prepare(
      `INSERT INTO project_owners
       (project_id, user_id)
       VALUES (?, ?)`
    ).bind(projectId, user.id).run();

    return json({
      ok: true,
      id: projectId,
      message: "پروژه ثبت شد."
    }, 201);
  }

  // ارسال پیشنهاد
  if (path === "/api/proposals" && method === "POST") {
    const user = await getUser(request, env);

    if (!user) {
      return fail(
        "برای ارسال پیشنهاد ابتدا وارد حساب شو.",
        401
      );
    }

    const plan = effectivePlan(user);
    const body = await readBody(request);

    if (!body) {
      return fail("اطلاعات پیشنهاد معتبر نیست.");
    }

    const projectId = Number(body.project_id);
    const description =
      String(body.description || "").trim();
    const price = Number(body.price);

    if (
      !Number.isSafeInteger(projectId) ||
      projectId < 1 ||
      description.length < 10 ||
      description.length > 4000 ||
      !Number.isSafeInteger(price) ||
      price < 0
    ) {
      return fail("اطلاعات پیشنهاد معتبر نیست.");
    }

    const project = await env.DB.prepare(
      "SELECT id FROM projects WHERE id = ?"
    ).bind(projectId).first();

    if (!project) {
      return fail("پروژه پیدا نشد.", 404);
    }

    const owner = await env.DB.prepare(
      "SELECT user_id FROM project_owners WHERE project_id = ?"
    ).bind(projectId).first();

    if (owner && owner.user_id === user.id) {
      return fail(
        "نمی‌توانی برای پروژه خودت پیشنهاد بفرستی.",
        403
      );
    }

    const count = await countProposals(env, user.id);

    if (
      plan.proposalLimit !== null &&
      count >= plan.proposalLimit
    ) {
      return fail(
        "سقف پیشنهادهای پلن شما تکمیل شده است. پلن خود را ارتقا بده.",
        403
      );
    }

    const result = await env.DB.prepare(
      `INSERT INTO proposals
       (project_id, freelancer_name, description, price)
       VALUES (?, ?, ?, ?)`
    ).bind(
      projectId,
      user.phone,
      description,
      price
    ).run();

    const proposalId = result.meta?.last_row_id;

    if (!proposalId) {
      return fail("پیشنهاد ثبت نشد.", 500);
    }

    await env.DB.prepare(
      `INSERT INTO proposal_owners
       (proposal_id, user_id)
       VALUES (?, ?)`
    ).bind(proposalId, user.id).run();

    return json({
      ok: true,
      id: proposalId,
      message: "پیشنهاد ثبت شد."
    }, 201);
  }

  // درخواست اشتراک
  if (
    path === "/api/subscriptions/request" &&
    method === "POST"
  ) {
    const user = await getUser(request, env);

    if (!user) {
      return fail("ابتدا وارد حساب شو.", 401);
    }

    const body = await readBody(request);

    if (!body) {
      return fail("اطلاعات پرداخت معتبر نیست.");
    }

    const planId = String(body.plan_id || "");
    const reference =
      String(body.payment_reference || "").trim();

    if (!PLANS[planId] || planId === "free") {
      return fail("پلن انتخاب‌شده معتبر نیست.");
    }

    if (
      reference.length < 3 ||
      reference.length > 150
    ) {
      return fail(
        "شماره پیگیری یا شناسه پرداخت را وارد کن."
      );
    }

    const existing = await env.DB.prepare(
      `SELECT id
       FROM subscription_payments
       WHERE user_id = ? AND status = 'pending'
       LIMIT 1`
    ).bind(user.id).first();

    if (existing) {
      return fail(
        "یک درخواست پرداخت شما هنوز در انتظار بررسی است.",
        409
      );
    }

    const plan = PLANS[planId];

    const result = await env.DB.prepare(
      `INSERT INTO subscription_payments
       (user_id, plan_id, amount, phone,
        payment_reference, status)
       VALUES (?, ?, ?, ?, ?, 'pending')`
    ).bind(
      user.id,
      planId,
      plan.price,
      user.phone,
      reference
    ).run();

    return json({
      ok: true,
      id: result.meta?.last_row_id,
      amount: plan.price,
      status: "pending",
      message:
        "درخواست ثبت شد و پس از بررسی مدیر تعیین تکلیف می‌شود."
    }, 201);
  }

  // درخواست‌های اشتراک کاربر
  if (
    path === "/api/subscriptions/mine" &&
    method === "GET"
  ) {
    const user = await getUser(request, env);

    if (!user) {
      return fail("ابتدا وارد حساب شو.", 401);
    }

    const result = await env.DB.prepare(
      `SELECT id, plan_id, amount, payment_reference,
              status, admin_note, created_at, reviewed_at
       FROM subscription_payments
       WHERE user_id = ?
       ORDER BY id DESC
       LIMIT 30`
    ).bind(user.id).all();

    return json({
      ok: true,
      plan: effectivePlan(user),
      payments: result.results || []
    });
  }

  // فهرست درخواست‌های پرداخت برای مدیر
  if (
    path === "/api/admin/subscription-payments" &&
    method === "GET"
  ) {
    if (!(await adminAllowed(request, env))) {
      return fail("دسترسی مدیر مجاز نیست.", 403);
    }

    const result = await env.DB.prepare(
      `SELECT sp.id, sp.user_id,
              u.phone AS account_phone,
              sp.plan_id, sp.amount, sp.phone,
              sp.payment_reference, sp.status,
              sp.admin_note, sp.created_at, sp.reviewed_at
       FROM subscription_payments sp
       JOIN users u ON u.id = sp.user_id
       ORDER BY
         CASE WHEN sp.status = 'pending' THEN 0 ELSE 1 END,
         sp.id DESC
       LIMIT 200`
    ).all();

    return json({
      ok: true,
      payments: result.results || []
    });
  }

  // تأیید یا رد درخواست پرداخت مدیر
  const reviewMatch = path.match(
    /^\/api\/admin\/subscription-payments\/(\d+)\/review$/
  );

  if (reviewMatch && method === "POST") {
    if (!(await adminAllowed(request, env))) {
      return fail("دسترسی مدیر مجاز نیست.", 403);
    }

    const id = Number(reviewMatch[1]);
    const body = await readBody(request);

    if (!body) {
      return fail("اطلاعات بررسی معتبر نیست.");
    }

    const decision = String(body.decision || "");
    const note = String(body.note || "")
      .trim()
      .slice(0, 500);

    if (!["approved", "rejected"].includes(decision)) {
      return fail(
        "تصمیم باید approved یا rejected باشد."
      );
    }

    const payment = await env.DB.prepare(
      `SELECT id, user_id, plan_id, amount, status
       FROM subscription_payments
       WHERE id = ?`
    ).bind(id).first();

    if (!payment) {
      return fail("درخواست پرداخت پیدا نشد.", 404);
    }

    if (payment.status !== "pending") {
      return fail(
        "این درخواست قبلاً بررسی شده است.",
        409
      );
    }

    const plan = PLANS[payment.plan_id];

    if (
      !plan ||
      plan.price !== payment.amount ||
      plan.id === "free"
    ) {
      return fail(
        "مبلغ یا پلن این درخواست معتبر نیست.",
        409
      );
    }

    const reviewedAt = new Date().toISOString();

    if (decision === "rejected") {
      const result = await env.DB.prepare(
        `UPDATE subscription_payments
         SET status = 'rejected',
             admin_note = ?,
             reviewed_at = ?
         WHERE id = ? AND status = 'pending'`
      ).bind(note, reviewedAt, id).run();

      if (!result.meta?.changes) {
        return fail(
          "وضعیت درخواست تغییر کرده است؛ فهرست را دوباره بررسی کن.",
          409
        );
      }

      return json({
        ok: true,
        message: "درخواست رد شد."
      });
    }

    const user = await env.DB.prepare(
      `SELECT subscription_expires_at, plan_id
       FROM users
       WHERE id = ?`
    ).bind(payment.user_id).first();

    if (!user) {
      return fail("حساب کاربر پیدا نشد.", 404);
    }

    const now = Date.now();

    const oldExpiry = user.subscription_expires_at
      ? Date.parse(user.subscription_expires_at)
      : 0;

    const start = Math.max(
      now,
      Number.isFinite(oldExpiry) ? oldExpiry : 0
    );

    const expires = new Date(
      start + plan.days * 24 * 60 * 60 * 1000
    ).toISOString();

    const results = await env.DB.batch([
      env.DB.prepare(
        `UPDATE subscription_payments
         SET status = 'approved',
             admin_note = ?,
             reviewed_at = ?
         WHERE id = ? AND status = 'pending'`
      ).bind(note, reviewedAt, id),

      env.DB.prepare(
        `UPDATE users
         SET plan_id = ?,
             subscription_expires_at = ?
         WHERE id = ?
           AND EXISTS (
             SELECT 1
             FROM subscription_payments
             WHERE id = ? AND status = 'approved'
           )`
      ).bind(
        plan.id,
        expires,
        payment.user_id,
        id
      )
    ]);

    if (!results[0]?.meta?.changes) {
      return fail(
        "درخواست قبلاً بررسی شده است.",
        409
      );
    }

    return json({
      ok: true,
      message: "پرداخت تأیید شد و اشتراک فعال شد.",
      plan: plan.name,
      expiresAt: expires
    });
  }

  return fail("مسیر API پیدا نشد.", 404);
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");

    try {
      // درخواست‌های preflight مرورگر
      if (request.method === "OPTIONS") {
        if (origin && !ALLOWED_ORIGINS.has(origin)) {
          return new Response(null, {
            status: 403,
            headers: {
              "Vary": "Origin",
              "Cache-Control": "no-store"
            }
          });
        }

        return new Response(null, {
          status: 204,
          headers: getCorsHeaders(origin)
        });
      }

      // رد کردن مبدأهای غیرمجاز
      if (origin && !ALLOWED_ORIGINS.has(origin)) {
        return new Response(
          JSON.stringify({
            ok: false,
            error: "مبدأ درخواست مجاز نیست."
          }),
          {
            status: 403,
            headers: {
              "Content-Type": "application/json; charset=utf-8",
              "Cache-Control": "no-store",
              "Vary": "Origin"
            }
          }
        );
      }

      // اجرای مسیر اصلی API
      const response = await handle(request, env);

      // افزودن هدر CORS به تمام پاسخ‌ها، حتی پاسخ‌های خطا
      const headers = new Headers(response.headers);

      for (const [key, value] of Object.entries(
        getCorsHeaders(origin)
      )) {
        headers.set(key, value);
      }

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers
      });
    } catch (error) {
      console.error("Freelanso API error:", error);

      const path = new URL(request.url).pathname
        .replace(/\/+$/, "") || "/";

      const message = path === "/api/db-check"
        ? "خطای بررسی D1: " +
          String(error?.message || error)
        : "خطای داخلی سرور رخ داد. تنظیمات و جدول‌های D1 را بررسی کن.";

      const headers = {
        ...getCorsHeaders(origin),
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store"
      };

      return new Response(
        JSON.stringify({
          ok: false,
          error: message
        }),
        {
          status: 500,
          headers
        }
      );
    }
  }
};

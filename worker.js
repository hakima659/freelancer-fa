const ALLOWED_ORIGIN = "https://hakima659.github.io";

const CORS_HEADERS = {
"Access-Control-Allow-Origin": ALLOWED_ORIGIN,
"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
"Access-Control-Allow-Headers": "Content-Type, X-Admin-Token",
"Vary": "Origin",
"Content-Type": "application/json; charset=utf-8",
"Cache-Control": "no-store"
};

function json(data, status = 200) {
return new Response(JSON.stringify(data), {
status,
headers: CORS_HEADERS
});
}

function validText(value, max = 2000) {
return typeof value === "string" &&
value.trim().length > 0 &&
value.trim().length <= max;
}

function positiveAmount(value) {
return Number.isSafeInteger(value) && value > 0;
}

async function readBody(request) {
try {
const data = await request.json();
return data && typeof data === "object" && !Array.isArray(data)
? data
: null;
} catch {
return null;
}
}

function isAdmin(request, env) {
const supplied = request.headers.get("X-Admin-Token");
return Boolean(
env.ADMIN_TOKEN &&
supplied &&
supplied.length <= 512 &&
supplied === env.ADMIN_TOKEN
);
}

function adminRequired(request, env) {
return isAdmin(request, env)
? null
: json({ error: "دسترسی غیرمجاز است." }, 401);
}

export default {
async fetch(request, env) {
const url = new URL(request.url);
const path = url.pathname;
const method = request.method;

if (method === "OPTIONS") {
  return new Response(null, {
    status: 204,
    headers: CORS_HEADERS
  });
}

if (!env.DB) {
  return json({ error: "اتصال دیتابیس DB تنظیم نشده است." }, 500);
}

try {
  // بررسی سلامت سرویس و دیتابیس
  if (path === "/health" && method === "GET") {
    await env.DB.prepare("SELECT 1").first();
    return json({
      ok: true,
      service: "freelanso",
      database: "connected"
    });
  }

  // اطلاعات کارت مقصد
  if (path === "/api/payment-info" && method === "GET") {
    return json({
      cardHolder: env.CARD_HOLDER || "",
      cardNumber: env.CARD_NUMBER || "",
      message: "پس از انتقال، شماره پیگیری را ثبت کنید."
    });
  }

  // فهرست پروژه‌ها
  if (path === "/api/projects" && method === "GET") {
    const result = await env.DB.prepare(
      `SELECT id, title, category, budget, description, created_at
       FROM projects ORDER BY id DESC LIMIT 100`
    ).all();

    return json({ projects: result.results || [] });
  }

  // ثبت پروژه
  if (path === "/api/projects" && method === "POST") {
    const data = await readBody(request);

    if (
      !data ||
      !validText(data.title, 160) ||
      !validText(data.category, 60) ||
      !validText(data.description, 4000) ||
      !positiveAmount(data.budget)
    ) {
      return json({ error: "اطلاعات پروژه معتبر نیست." }, 400);
    }

    const allowedCategories = ["برنامه‌نویسی", "طراحی", "محتوا"];

    if (!allowedCategories.includes(data.category.trim())) {
      return json({ error: "دسته‌بندی معتبر نیست." }, 400);
    }

    const result = await env.DB.prepare(
      `INSERT INTO projects (title, category, budget, description)
       VALUES (?, ?, ?, ?)`
    ).bind(
      data.title.trim(),
      data.category.trim(),
      data.budget,
      data.description.trim()
    ).run();

    return json({
      ok: true,
      id: result.meta.last_row_id,
      message: "پروژه در دیتابیس ثبت شد."
    }, 201);
  }

  // ثبت پیشنهاد فریلنسر
  if (path === "/api/proposals" && method === "POST") {
    const data = await readBody(request);

    if (
      !data ||
      !Number.isSafeInteger(data.projectId) ||
      data.projectId < 1 ||
      !validText(data.freelancerName, 120) ||
      !validText(data.description, 3000) ||
      !positiveAmount(data.price)
    ) {
      return json({ error: "اطلاعات پیشنهاد معتبر نیست." }, 400);
    }

    const project = await env.DB.prepare(
      "SELECT id FROM projects WHERE id = ?"
    ).bind(data.projectId).first();

    if (!project) {
      return json({ error: "پروژه پیدا نشد." }, 404);
    }

    const result = await env.DB.prepare(
      `INSERT INTO proposals
       (project_id, freelancer_name, description, price)
       VALUES (?, ?, ?, ?)`
    ).bind(
      data.projectId,
      data.freelancerName.trim(),
      data.description.trim(),
      data.price
    ).run();

    return json({
      ok: true,
      id: result.meta.last_row_id,
      message: "پیشنهاد در دیتابیس ثبت شد."
    }, 201);
  }

  // ثبت درخواست کارت‌به‌کارت عمومی
  if (path === "/api/payments" && method === "POST") {
    const data = await readBody(request);

    if (
      !data ||
      !validText(data.purpose, 160) ||
      !validText(data.customerName, 120) ||
      !validText(data.phone, 30) ||
      !positiveAmount(data.amount) ||
      !validText(data.paymentReference, 120)
    ) {
      return json({ error: "اطلاعات پرداخت معتبر نیست." }, 400);
    }

    const result = await env.DB.prepare(
      `INSERT INTO payment_requests
       (purpose, customer_name, phone, amount, payment_reference, status)
       VALUES (?, ?, ?, ?, ?, 'pending')`
    ).bind(
      data.purpose.trim(),
      data.customerName.trim(),
      data.phone.trim(),
      data.amount,
      data.paymentReference.trim()
    ).run();

    return json({
      ok: true,
      id: result.meta.last_row_id,
      status: "pending",
      message: "درخواست ثبت شد و منتظر بررسی مدیر است."
    }, 201);
  }

  // مشاهده وضعیت و مبلغ کارمزد
  const commissionView = path.match(
    /^\/api\/commissions\/([1-9][0-9]*)$/
  );

  if (commissionView && method === "GET") {
    const id = Number(commissionView[1]);

    const commission = await env.DB.prepare(
      `SELECT id, project_id, freelancer_name, agreed_amount,
              commission_rate, commission_amount, status, created_at
       FROM commissions WHERE id = ?`
    ).bind(id).first();

    if (!commission) {
      return json({ error: "کارمزد پیدا نشد." }, 404);
    }

    return json({ commission });
  }

  // فریلنسر شماره پیگیری پرداخت کارمزد را ثبت می‌کند
  const commissionPayment = path.match(
    /^\/api\/commissions\/([1-9][0-9]*)\/payment$/
  );

  if (commissionPayment && method === "POST") {
    const id = Number(commissionPayment[1]);
    const data = await readBody(request);

    if (
      !data ||
      !validText(data.phone, 30) ||
      !validText(data.paymentReference, 120)
    ) {
      return json({
        error: "شماره تماس و شماره پیگیری معتبر لازم است."
      }, 400);
    }

    const result = await env.DB.prepare(
      `UPDATE commissions
       SET phone = ?, payment_reference = ?, status = 'pending_review'
       WHERE id = ? AND status IN ('awaiting_payment', 'rejected')`
    ).bind(
      data.phone.trim(),
      data.paymentReference.trim(),
      id
    ).run();

    if (!result.meta.changes) {
      const current = await env.DB.prepare(
        "SELECT id, status FROM commissions WHERE id = ?"
      ).bind(id).first();

      if (!current) {
        return json({ error: "کارمزد پیدا نشد." }, 404);
      }

      return json({
        error: "این کارمزد در وضعیت قابل ثبت پرداخت نیست.",
        status: current.status
      }, 409);
    }

    return json({
      ok: true,
      status: "pending_review",
      message: "شماره پیگیری ثبت شد؛ پرداخت هنوز تأیید نشده است."
    }, 201);
  }

  // تمام مسیرهای مدیریتی به توکن محرمانه نیاز دارند
  if (path.startsWith("/api/admin/")) {
    const denied = adminRequired(request, env);
    if (denied) return denied;

    // فهرست درخواست‌های پرداخت قبلی
    if (path === "/api/admin/payments" && method === "GET") {
      const result = await env.DB.prepare(
        `SELECT id, purpose, customer_name, phone, amount,
                payment_reference, status, admin_note,
                created_at, reviewed_at
         FROM payment_requests ORDER BY id DESC LIMIT 200`
      ).all();

      return json({ payments: result.results || [] });
    }

    // تأیید یا رد درخواست پرداخت قبلی
    const oldPaymentReview = path.match(
      /^\/api\/admin\/payments\/([1-9][0-9]*)\/review$/
    );

    if (oldPaymentReview && method === "POST") {
      const id = Number(oldPaymentReview[1]);
      const data = await readBody(request);

      if (
        !data ||
        !["approved", "rejected"].includes(data.status) ||
        (data.note !== undefined &&
          (typeof data.note !== "string" || data.note.length > 500))
      ) {
        return json({ error: "اطلاعات بررسی معتبر نیست." }, 400);
      }

      const result = await env.DB.prepare(
        `UPDATE payment_requests
         SET status = ?, admin_note = ?, reviewed_at = CURRENT_TIMESTAMP
         WHERE id = ? AND status = 'pending'`
      ).bind(
        data.status,
        (data.note || "").trim(),
        id
      ).run();

      if (!result.meta.changes) {
        return json({
          error: "درخواست پیدا نشد یا قبلاً بررسی شده است."
        }, 409);
      }

      return json({ ok: true, status: data.status });
    }

    // مدیر پس از بررسی تکمیل پروژه، کارمزد را ایجاد می‌کند
    const completeProject = path.match(
      /^\/api\/admin\/projects\/([1-9][0-9]*)\/complete$/
    );

    if (completeProject && method === "POST") {
      const projectId = Number(completeProject[1]);
      const data = await readBody(request);

      if (
        !data ||
        !validText(data.freelancerName, 120) ||
        !positiveAmount(data.agreedAmount)
      ) {
        return json({
          error: "نام فریلنسر و مبلغ توافق‌شده معتبر لازم است."
        }, 400);
      }

      const project = await env.DB.prepare(
        "SELECT id FROM projects WHERE id = ?"
      ).bind(projectId).first();

      if (!project) {
        return json({ error: "پروژه پیدا نشد." }, 404);
      }

      const existing = await env.DB.prepare(
        "SELECT id FROM commissions WHERE project_id = ?"
      ).bind(projectId).first();

      if (existing) {
        return json({
          error: "برای این پروژه قبلاً کارمزد ایجاد شده است.",
          commissionId: existing.id
        }, 409);
      }

      const commissionAmount = Math.round(
        data.agreedAmount * 10 / 100
      );

      if (!positiveAmount(commissionAmount)) {
        return json({
          error: "مبلغ کارمزد قابل محاسبه نیست."
        }, 400);
      }

      const result = await env.DB.prepare(
        `INSERT INTO commissions
         (project_id, freelancer_name, agreed_amount,
          commission_rate, commission_amount, status)
         VALUES (?, ?, ?, 10, ?, 'awaiting_payment')`
      ).bind(
        projectId,
        data.freelancerName.trim(),
        data.agreedAmount,
        commissionAmount
      ).run();

      return json({
        ok: true,
        commissionId: result.meta.last_row_id,
        projectId,
        agreedAmount: data.agreedAmount,
        commissionRate: 10,
        commissionAmount,
        status: "awaiting_payment",
        message: "کارمزد ایجاد شد و منتظر پرداخت فریلنسر است."
      }, 201);
    }

    // مدیر فهرست کارمزدها را مشاهده می‌کند
    if (path === "/api/admin/commissions" && method === "GET") {
      const result = await env.DB.prepare(
        `SELECT id, project_id, freelancer_name, agreed_amount,
                commission_rate, commission_amount, status,
                payment_reference, phone, admin_note,
                created_at, paid_at
         FROM commissions ORDER BY id DESC LIMIT 200`
      ).all();

      return json({ commissions: result.results || [] });
    }

    // مدیر پرداخت کارمزد را تأیید یا رد می‌کند
    const commissionReview = path.match(
      /^\/api\/admin\/commissions\/([1-9][0-9]*)\/review$/
    );

    if (commissionReview && method === "POST") {
      const id = Number(commissionReview[1]);
      const data = await readBody(request);

      if (
        !data ||
        !["approved", "rejected"].includes(data.status) ||
        (data.note !== undefined &&
          (typeof data.note !== "string" || data.note.length > 500))
      ) {
        return json({ error: "اطلاعات بررسی معتبر نیست." }, 400);
      }

      const result = await env.DB.prepare(
        `UPDATE commissions
         SET status = ?,
             admin_note = ?,
             paid_at = CASE
               WHEN ? = 'approved' THEN CURRENT_TIMESTAMP
               ELSE NULL
             END
         WHERE id = ? AND status = 'pending_review'`
      ).bind(
        data.status === "approved" ? "paid" : "rejected",
        (data.note || "").trim(),
        data.status,
        id
      ).run();

      if (!result.meta.changes) {
        const current = await env.DB.prepare(
          "SELECT id, status FROM commissions WHERE id = ?"
        ).bind(id).first();

        if (!current) {
          return json({ error: "کارمزد پیدا نشد." }, 404);
        }

        return json({
          error: "این کارمزد در انتظار بررسی نیست.",
          status: current.status
        }, 409);
      }

      return json({
        ok: true,
        status: data.status === "approved" ? "paid" : "rejected",
        message: data.status === "approved"
          ? "پرداخت توسط مدیر تأیید شد."
          : "پرداخت رد شد."
      });
    }

    return json({ error: "مسیر مدیریتی پیدا نشد." }, 404);
  }

  return json({ error: "مسیر پیدا نشد." }, 404);
} catch (error) {
  console.error("Freelanso API error:", error);
  return json({
    error: "خطای داخلی سرور یا دیتابیس."
  }, 500);
}

}
};

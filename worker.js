
const ALLOWED_ORIGIN = "https://hakima659.github.io";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Admin-Token",
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
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

      // اطلاعات کارت مقصد؛ مقادیر در تنظیمات Worker قرار می‌گیرند
      if (path === "/api/payment-info" && method === "GET") {
        return json({
          cardHolder: env.CARD_HOLDER || "",
          cardNumber: env.CARD_NUMBER || "",
          message: "پس از انتقال، شماره پیگیری را ثبت کنید."
        });
      }

      // فهرست پروژه‌های منتشرشده
      if (path === "/api/projects" && method === "GET") {
        const result = await env.DB.prepare(
          `SELECT id, title, category, budget, description, created_at
           FROM projects ORDER BY id DESC LIMIT 100`
        ).all();

        return json({ projects: result.results || [] });
      }

      // ثبت پروژه در دیتابیس
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

      // ثبت درخواست کارت‌به‌کارت؛ تأیید خودکار وجود ندارد
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

      // مسیرهای مدیریتی؛ همه نیازمند توکن محرمانه هستند
      if (path.startsWith("/api/admin/")) {
        if (!isAdmin(request, env)) {
          return json({ error: "دسترسی غیرمجاز است." }, 401);
        }

        if (path === "/api/admin/payments" && method === "GET") {
          const result = await env.DB.prepare(
            `SELECT id, purpose, customer_name, phone, amount,
                    payment_reference, status, admin_note,
                    created_at, reviewed_at
             FROM payment_requests ORDER BY id DESC LIMIT 200`
          ).all();

          return json({ payments: result.results || [] });
        }

        const match = path.match(
          /^\/api\/admin\/payments\/([1-9][0-9]*)\/review$/
        );

        if (match && method === "POST") {
          const id = Number(match[1]);
          const data = await readBody(request);

          if (
            !Number.isSafeInteger(id) ||
            !data ||
            !["approved", "rejected"].includes(data.status) ||
            (data.note !== undefined &&
              (typeof data.note !== "string" || data.note.length > 500))
          ) {
            return json({ error: "اطلاعات بررسی معتبر نیست." }, 400);
          }

          const payment = await env.DB.prepare(
            "SELECT id, status FROM payment_requests WHERE id = ?"
          ).bind(id).first();

          if (!payment) {
            return json({ error: "درخواست پرداخت پیدا نشد." }, 404);
          }

          if (payment.status !== "pending") {
            return json({
              error: "این درخواست قبلاً بررسی شده است."
            }, 409);
          }

          await env.DB.prepare(
            `UPDATE payment_requests
             SET status = ?, admin_note = ?, reviewed_at = CURRENT_TIMESTAMP
             WHERE id = ? AND status = 'pending'`
          ).bind(
            data.status,
            (data.note || "").trim(),
            id
          ).run();

          return json({
            ok: true,
            status: data.status,
            message: "وضعیت درخواست به‌روزرسانی شد."
          });
        }

        return json({ error: "مسیر مدیریتی پیدا نشد." }, 404);
      }

      return json({ error: "مسیر پیدا نشد." }, 404);
    } catch (error) {
      // جزئیات خطا به بازدیدکننده نمایش داده نمی‌شود
      console.error("Freelanso API error:", error);
      return json({ error: "خطای داخلی سرور یا دیتابیس." }, 500);
    }
  }
};


const ROUTE_TTL_SECONDS = 3600;
const MAX_BODY = 16_384;
const MAX_DEFAULT_PAYLOAD = 8192;
const PREFIX = "/p/";

const HOP_HEADERS = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade"
];

const BLOCKED_METHODS = new Set(["CONNECT", "TRACE"]);

const APP_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,39}$/;
const TUNNEL_HOST_PATTERN =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.trycloudflare\.com$/i;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (
      !allowedOrigin(
        request.headers.get("Origin"),
        env.ALLOWED_ORIGIN
      )
    ) {
      return respond(
        { ok: false, error: "origin_not_allowed" },
        403,
        request,
        env
      );
    }

    // Handle CORS preflight.
    if (
      request.method === "OPTIONS" &&
      request.headers.has("Access-Control-Request-Method")
    ) {
      return new Response(null, {
        status: 204,
        headers: cors(request, env)
      });
    }

    if (url.pathname === "/health" && request.method === "GET") {
      return respond({
        ok: true,
        service: "apiyer-proxy",
        kv: !!env.ROUTES,
        keyConfigured: !!env.PROXY_API_KEY
      }, 200, request, env);
    }

    if (url.pathname === "/" && request.method === "GET") {
      return respond({
        ok: true,
        service: "apiyer-proxy",
        register: "POST /api/register",
        unregister: "POST /api/unregister",
        routes: "GET /api/routes",
        proxy: "/p/:appId/*"
      }, 200, request, env);
    }

    if (
      url.pathname === "/api/register" &&
      request.method === "POST"
    ) {
      return register(request, env);
    }

    if (
      url.pathname === "/api/unregister" &&
      request.method === "POST"
    ) {
      return unregister(request, env);
    }

    if (
      url.pathname === "/api/routes" &&
      request.method === "GET"
    ) {
      if (!authorized(request, env)) {
        return respond(
          { ok: false, error: "unauthorized" },
          401,
          request,
          env
        );
      }

      if (!env.ROUTES) {
        return respond(
          { ok: false, error: "kv_binding_missing" },
          503,
          request,
          env
        );
      }

      const result = await env.ROUTES.list({
        prefix: "route:",
        limit: 1000
      });

      return respond({
        ok: true,
        routes: result.keys.map((item) => ({
          appId: item.name.slice(6),
          metadata: item.metadata || {}
        })),
        listComplete: !!result.list_complete
      }, 200, request, env);
    }

    if (url.pathname.startsWith(PREFIX)) {
      return proxy(request, env, url);
    }

    return respond(
      { ok: false, error: "not_found" },
      404,
      request,
      env
    );
  }
};

// --------------------------------------------------
// RESPONSE AND CORS
// --------------------------------------------------

function respond(data, status, request, env) {
  const headers = new Headers({
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff"
  });

  addCors(headers, request, env);

  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}

function cors(request, env) {
  const headers = new Headers();
  addCors(headers, request, env);
  return headers;
}

function allowedOrigin(origin, configured) {
  if (!origin) return true;

  const value = (configured || "*").trim();

  return value === "*" ||
    value.split(",").map((item) => item.trim()).includes(origin);
}

function addCors(headers, request, env) {
  const configured = (env.ALLOWED_ORIGIN || "*").trim();
  const origin = request.headers.get("Origin");

  if (configured === "*") {
    headers.set("access-control-allow-origin", "*");
  } else if (
    origin &&
    configured.split(",").map((item) => item.trim()).includes(origin)
  ) {
    headers.set("access-control-allow-origin", origin);
    headers.append("vary", "Origin");
  }

  headers.set(
    "access-control-allow-methods",
    "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
  );

  headers.set(
    "access-control-allow-headers",
    "Content-Type, Authorization, X-API-Key, X-Proxy-Client-Key, X-Request-Id"
  );

  headers.set(
    "access-control-expose-headers",
    "X-Proxy-Backend, X-Request-Id"
  );

  headers.set("access-control-max-age", "86400");
}

// --------------------------------------------------
// AUTHENTICATION
// --------------------------------------------------

function authorized(request, env) {
  const expected = env.PROXY_API_KEY;

  if (typeof expected !== "string" || !expected) {
    return false;
  }

  const apiKey = request.headers.get("X-API-Key") || "";
  const authorization = request.headers.get("Authorization") || "";
  const bearer = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";

  return safeEqual(apiKey, expected) ||
    safeEqual(bearer, expected);
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);

  for (let i = 0; i < length; i++) {
    diff |= (a.charCodeAt(i) || 0) ^
      (b.charCodeAt(i) || 0);
  }

  return diff === 0;
}

async function hash(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

// --------------------------------------------------
// REGISTER OR REPLACE ROUTE
// --------------------------------------------------

async function register(request, env) {
  if (!env.ROUTES) {
    return respond(
      { ok: false, error: "kv_binding_missing" },
      503,
      request,
      env
    );
  }

  if (!env.PROXY_API_KEY) {
    return respond(
      { ok: false, error: "registration_key_not_configured" },
      503,
      request,
      env
    );
  }

  // Authenticate before processing registration data.
  if (!authorized(request, env)) {
    return respond(
      { ok: false, error: "unauthorized" },
      401,
      request,
      env
    );
  }

  let body;

  try {
    body = await readJson(request, MAX_BODY);
  } catch (error) {
    return respond(
      { ok: false, error: error.code || "invalid_json" },
      error.status || 400,
      request,
      env
    );
  }

  const rawUrl =
    body.url ?? body.Url ?? body.endpoint;

  if (typeof rawUrl !== "string") {
    return respond(
      { ok: false, error: "missing_upstream_url" },
      400,
      request,
      env
    );
  }

  let upstream;

  try {
    upstream = validateUpstream(rawUrl);
  } catch (error) {
    return respond(
      { ok: false, error: error.message },
      400,
      request,
      env
    );
  }

  // App ID takes priority over tunnel hostname.
  // Supports appId, appid and the legacy nama field.
  const requestedId =
    body.appId ??
    body.appid ??
    body.nama ??
    body.backend ??
    body.route ??
    body.name;

  let appId;

  if (
    requestedId === undefined ||
    requestedId === null ||
    requestedId === ""
  ) {
    // Backward-compatible fallback only.
    appId = upstream.hostname.slice(
      0,
      -".trycloudflare.com".length
    );
  } else if (typeof requestedId === "string") {
    appId = requestedId.trim().toLowerCase();
  } else {
    return respond(
      { ok: false, error: "invalid_app_id" },
      400,
      request,
      env
    );
  }

  if (!APP_ID_PATTERN.test(appId)) {
    return respond(
      {
        ok: false,
        error: "invalid_app_id",
        hint: "Use 1-40 lowercase letters, digits, hyphens or underscores; the first character must be a letter or digit."
      },
      400,
      request,
      env
    );
  }

  let defaultPayload = null;

  if (
    Object.prototype.hasOwnProperty.call(body, "payload")
  ) {
    let serialized;

    try {
      serialized = JSON.stringify(body.payload);
    } catch {
      return respond(
        { ok: false, error: "invalid_default_payload" },
        400,
        request,
        env
      );
    }

    if (
      typeof serialized !== "string" ||
      new TextEncoder().encode(serialized).byteLength >
        MAX_DEFAULT_PAYLOAD
    ) {
      return respond(
        { ok: false, error: "default_payload_too_large" },
        413,
        request,
        env
      );
    }

    defaultPayload = body.payload;
  }

  let clientKeyHash = null;

  if (
    body.clientKey !== undefined &&
    body.clientKey !== null &&
    body.clientKey !== ""
  ) {
    if (
      typeof body.clientKey !== "string" ||
      body.clientKey.length < 16 ||
      body.clientKey.length > 512
    ) {
      return respond(
        {
          ok: false,
          error: "client_key_must_be_16_to_512_characters"
        },
        400,
        request,
        env
      );
    }

    clientKeyHash = await hash(body.clientKey);
  }

  const kvKey = "route:" + appId;
  const previous = await env.ROUTES.get(kvKey, "json");
  const now = new Date().toISOString();

  const record = {
    version: 1,
    appId,
    baseUrl: upstream.toString().replace(/\/+$/, ""),
    createdAt: previous?.createdAt || now,
    updatedAt: now,
    defaultPayload,
    clientKeyHash
  };

  // Same App ID means the same logical route.
  // Registering again replaces its upstream URL.
  await env.ROUTES.put(
    kvKey,
    JSON.stringify(record),
    {
      expirationTtl: ROUTE_TTL_SECONDS,
      metadata: {
        appId,
        updatedAt: now,
        hasClientKey: !!clientKeyHash
      }
    }
  );

  const endpoint =
    new URL(request.url).origin + PREFIX + appId + "/";

  return respond({
    ok: true,
    message: previous
      ? "route_replaced"
      : "route_registered",
    appId,
    backend: appId,
    endpoint,
    expiresInSeconds: ROUTE_TTL_SECONDS,
    clientKeyRequired: !!clientKeyHash
  }, previous ? 200 : 201, request, env);
}

// --------------------------------------------------
// UNREGISTER ROUTE
// --------------------------------------------------

async function unregister(request, env) {
  if (!env.ROUTES) {
    return respond(
      { ok: false, error: "kv_binding_missing" },
      503,
      request,
      env
    );
  }

  if (!authorized(request, env)) {
    return respond(
      { ok: false, error: "unauthorized" },
      401,
      request,
      env
    );
  }

  let body;

  try {
    body = await readJson(request, MAX_BODY);
  } catch (error) {
    return respond(
      { ok: false, error: error.code || "invalid_json" },
      error.status || 400,
      request,
      env
    );
  }

  const requestedId =
    body.appId ??
    body.appid ??
    body.nama ??
    body.backend ??
    body.route ??
    body.name;

  if (typeof requestedId !== "string") {
    return respond(
      { ok: false, error: "invalid_app_id" },
      400,
      request,
      env
    );
  }

  const appId = requestedId.trim().toLowerCase();

  if (!APP_ID_PATTERN.test(appId)) {
    return respond(
      { ok: false, error: "invalid_app_id" },
      400,
      request,
      env
    );
  }

  await env.ROUTES.delete("route:" + appId);

  return respond({
    ok: true,
    message: "route_unregistered",
    appId
  }, 200, request, env);
}

// --------------------------------------------------
// JSON BODY READER
// --------------------------------------------------

async function readJson(request, maxBytes) {
  const contentLength = Number(
    request.headers.get("content-length") || 0
  );

  if (
    Number.isFinite(contentLength) &&
    contentLength > maxBytes
  ) {
    throw httpError("request_body_too_large", 413);
  }

  if (!request.body) {
    throw httpError("missing_json_body", 400);
  }

  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const item = await reader.read();

      if (item.done) break;

      total += item.value.byteLength;

      if (total > maxBytes) {
        await reader.cancel();
        throw httpError("request_body_too_large", 413);
      }

      chunks.push(item.value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;

  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  let value;

  try {
    value = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes)
    );
  } catch {
    throw httpError("invalid_json", 400);
  }

  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    throw httpError("json_object_required", 400);
  }

  return value;
}

function httpError(code, status) {
  const error = new Error(code);
  error.code = code;
  error.status = status;
  return error;
}

// --------------------------------------------------
// UPSTREAM VALIDATION
// --------------------------------------------------

function validateUpstream(value) {
  let upstream;

  try {
    upstream = new URL(value);
  } catch {
    throw new Error("invalid_upstream_url");
  }

  if (
    upstream.protocol !== "https:" ||
    !TUNNEL_HOST_PATTERN.test(upstream.hostname)
  ) {
    throw new Error("upstream_must_be_https_trycloudflare_com");
  }

  if (upstream.port && upstream.port !== "443") {
    throw new Error("upstream_port_not_allowed");
  }

  if (
    upstream.username ||
    upstream.password ||
    upstream.search ||
    upstream.hash
  ) {
    throw new Error(
      "upstream_must_not_include_credentials_query_or_fragment"
    );
  }

  upstream.hostname = upstream.hostname.toLowerCase();
  upstream.port = "";

  return upstream;
}

// --------------------------------------------------
// PROXY
// --------------------------------------------------

async function proxy(request, env, url) {
  if (!env.ROUTES) {
    return respond(
      { ok: false, error: "kv_binding_missing" },
      503,
      request,
      env
    );
  }

  if (BLOCKED_METHODS.has(request.method)) {
    return respond(
      { ok: false, error: "method_not_allowed" },
      405,
      request,
      env
    );
  }

  const parts = url.pathname.split("/");
  const rawId = parts[2];

  if (!rawId) {
    return respond(
      { ok: false, error: "missing_app_id" },
      400,
      request,
      env
    );
  }

  let appId;

  try {
    appId = decodeURIComponent(rawId).toLowerCase();
  } catch {
    return respond(
      { ok: false, error: "invalid_app_id" },
      400,
      request,
      env
    );
  }

  if (!APP_ID_PATTERN.test(appId)) {
    return respond(
      { ok: false, error: "invalid_app_id" },
      400,
      request,
      env
    );
  }

  const route = await env.ROUTES.get("route:" + appId, "json");

  if (!route || typeof route.baseUrl !== "string") {
    return respond(
      {
        ok: false,
        error: "backend_not_registered",
        appId
      },
      404,
      request,
      env
    );
  }

  if (route.clientKeyHash) {
    const suppliedKey =
      request.headers.get("X-Proxy-Client-Key") || "";

    if (
      !suppliedKey ||
      !safeEqual(await hash(suppliedKey), route.clientKeyHash)
    ) {
      return respond(
        { ok: false, error: "proxy_client_unauthorized" },
        401,
        request,
        env
      );
    }
  }

  let base;

  try {
    base = validateUpstream(route.baseUrl);
  } catch {
    return respond(
      { ok: false, error: "stored_upstream_invalid" },
      502,
      request,
      env
    );
  }

  const routePrefix = PREFIX + appId;
  let suffix = url.pathname.slice(routePrefix.length);

  if (!suffix) suffix = "/";
  if (!suffix.startsWith("/")) suffix = "/" + suffix;

  const target = new URL(base.toString());
  const basePath = target.pathname.replace(/\/+$/, "");

  target.pathname = (basePath + suffix) || "/";
  target.search = url.search;

  const headers = new Headers(request.headers);

  for (const header of HOP_HEADERS) {
    headers.delete(header);
  }

  // Never forward proxy management/client secrets.
  headers.delete("host");
  headers.delete("content-length");
  headers.delete("x-api-key");
  headers.delete("x-proxy-client-key");

  // Prevent clients from spoofing forwarding metadata.
  headers.delete("x-forwarded-host");
  headers.delete("x-forwarded-proto");
  headers.delete("x-proxy-backend");

  headers.set("x-forwarded-host", url.host);
  headers.set("x-forwarded-proto", url.protocol.slice(0, -1));
  headers.set("x-proxy-backend", appId);

  let body = request.body;

  const usesDefault =
    ["POST", "PUT", "PATCH"].includes(request.method) &&
    body === null &&
    route.defaultPayload !== null &&
    route.defaultPayload !== undefined;

  if (usesDefault) {
    body = JSON.stringify(route.defaultPayload);

    if (!headers.has("content-type")) {
      headers.set(
        "content-type",
        "application/json; charset=utf-8"
      );
    }
  }

  const init = {
    method: request.method,
    headers,
    redirect: "manual"
  };

  if (
    request.method !== "GET" &&
    request.method !== "HEAD" &&
    body !== null
  ) {
    init.body = body;
  }

  let upstream;

  try {
    upstream = await fetch(new Request(target.toString(), init));
  } catch {
    return respond(
      {
        ok: false,
        error: "upstream_unreachable",
        appId,
        hint: "Check the tunnel and register its latest URL again."
      },
      502,
      request,
      env
    );
  }

  const responseHeaders = new Headers(upstream.headers);

  for (const header of HOP_HEADERS) {
    responseHeaders.delete(header);
  }

  responseHeaders.delete("content-length");
  responseHeaders.set("cache-control", "no-store");
  responseHeaders.set("x-proxy-backend", appId);

  // Rewrite same-origin redirects to remain behind this proxy.
  const location = responseHeaders.get("location");

  if (
    location &&
    upstream.status >= 300 &&
    upstream.status < 400
  ) {
    try {
      const destination = new URL(location, target);

      if (destination.origin === base.origin) {
        let path = destination.pathname;

        if (
          basePath &&
          (path === basePath || path.startsWith(basePath + "/"))
        ) {
          path = path.slice(basePath.length) || "/";
        }

        responseHeaders.set(
          "location",
          url.origin +
            routePrefix +
            path +
            destination.search +
            destination.hash
        );
      }
    } catch {
      // Keep the original Location if it cannot be parsed.
    }
  }

  addCors(responseHeaders, request, env);

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: responseHeaders
  });
}

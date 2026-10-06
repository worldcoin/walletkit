import { NextResponse } from "next/server";

const FAUX_ISSUER_URL = "https://faux-issuer.us.id-infra.worldcoin.dev/issue";
const FIELD_ELEMENT_PATTERN = /^0x[0-9a-f]{64}$/;
/** The staging issuer answers in well under a second; never hold the request open. */
const ISSUER_TIMEOUT_MS = 15_000;

const error = (message: string, status: number) =>
  NextResponse.json({ error: message }, { status });

export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return error("The request body must be JSON", 400);
  }
  const sub =
    typeof body === "object" && body !== null
      ? (body as { sub?: unknown }).sub
      : undefined;
  if (typeof sub !== "string" || !FIELD_ELEMENT_PATTERN.test(sub)) {
    return error("sub must be a 32-byte lowercase hex field element", 400);
  }

  // The deadline covers reading the body too, so read it inside the same `try`.
  let response: Response;
  let responseBody: string;
  try {
    response = await fetch(FAUX_ISSUER_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sub }),
      cache: "no-store",
      signal: AbortSignal.timeout(ISSUER_TIMEOUT_MS),
    });
    responseBody = await response.text();
  } catch (cause) {
    const timedOut =
      cause instanceof DOMException && cause.name === "TimeoutError";
    console.error("Faux issuer request failed", { timedOut, cause });
    return timedOut
      ? error(
          `The faux issuer did not respond within ${ISSUER_TIMEOUT_MS} ms`,
          504,
        )
      : error("The faux issuer could not be reached", 502);
  }

  return new NextResponse(responseBody, {
    status: response.status,
    headers: {
      "content-type":
        response.headers.get("content-type") ?? "application/json",
    },
  });
}

import { NextResponse } from "next/server";

const FAUX_ISSUER_URL = "https://faux-issuer.us.id-infra.worldcoin.dev/issue";
const FIELD_ELEMENT_PATTERN = /^0x[0-9a-f]{64}$/;

export async function POST(request: Request) {
  const body = (await request.json()) as { sub?: unknown };
  if (typeof body.sub !== "string" || !FIELD_ELEMENT_PATTERN.test(body.sub)) {
    return NextResponse.json(
      { error: "sub must be a 32-byte lowercase hex field element" },
      { status: 400 },
    );
  }

  const response = await fetch(FAUX_ISSUER_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ sub: body.sub }),
    cache: "no-store",
  });
  const responseBody = await response.text();

  return new NextResponse(responseBody, {
    status: response.status,
    headers: {
      "content-type":
        response.headers.get("content-type") ?? "application/json",
    },
  });
}

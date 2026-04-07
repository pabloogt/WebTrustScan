import { NextRequest, NextResponse } from "next/server";
import { normalizeUrl } from "@/lib/normalizeUrl";

type CheckStatus = "pass" | "warn" | "fail";

type AuditCheck = {
  key: string;
  title: string;
  status: CheckStatus;
  description: string;
  fix: string | null;
};

type AuditResult = {
  url: string;
  score: number;
  summary: string;
  checks: AuditCheck[];
};

function calculateScore(checks: AuditCheck[]) {
  let score = 0;

  for (const check of checks) {
    if (check.status === "pass") score += 14;
    if (check.status === "warn") score += 7;
  }

  return Math.min(score, 100);
}

function buildSummary(score: number) {
  if (score >= 85) {
    return "Tu web tiene una base bastante buena a nivel de seguridad básica.";
  }

  if (score >= 60) {
    return "Tu web tiene una base aceptable, pero hay puntos importantes que deberías mejorar.";
  }

  return "Tu web muestra carencias básicas de seguridad y confianza que conviene corregir cuanto antes.";
}

async function checkHttpToHttpsRedirect(hostname: string) {
  try {
    const httpUrl = `http://${hostname}`;

    const response = await fetch(httpUrl, {
      method: "GET",
      redirect: "follow",
      cache: "no-store",
    });

    return response.url.startsWith("https://");
  } catch {
    return false;
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const rawUrl = body.url;

    if (!rawUrl || typeof rawUrl !== "string") {
      return NextResponse.json(
        { error: "La URL es obligatoria." },
        { status: 400 }
      );
    }

    const normalizedUrl = normalizeUrl(rawUrl);

    const response = await fetch(normalizedUrl, {
      method: "GET",
      redirect: "follow",
      cache: "no-store",
    });

    const finalUrl = response.url;
    const headers = response.headers;

    const parsedUrl = new URL(finalUrl);
    const hostname = parsedUrl.hostname;

    const isHttps = finalUrl.startsWith("https://");
    const hsts = headers.get("strict-transport-security");
    const csp = headers.get("content-security-policy");
    const xFrameOptions = headers.get("x-frame-options");
    const xContentTypeOptions = headers.get("x-content-type-options");
    const referrerPolicy = headers.get("referrer-policy");
    const permissionsPolicy = headers.get("permissions-policy");

    const redirectsToHttps = await checkHttpToHttpsRedirect(hostname);

    const checks: AuditCheck[] = [
      {
        key: "https",
        title: "HTTPS activo",
        status: isHttps ? "pass" : "fail",
        description: isHttps
          ? "La web usa HTTPS y cifra la conexión del visitante."
          : "La web no parece estar usando HTTPS en la URL final.",
        fix: isHttps
          ? null
          : "Instala un certificado SSL y fuerza el uso de HTTPS.",
      },
      {
        key: "http-redirect",
        title: "Redirección de HTTP a HTTPS",
        status: redirectsToHttps ? "pass" : "warn",
        description: redirectsToHttps
          ? "La versión insegura redirige correctamente a HTTPS."
          : "No se pudo confirmar una redirección correcta de HTTP a HTTPS.",
        fix: redirectsToHttps
          ? null
          : "Configura una redirección permanente de HTTP a HTTPS en tu servidor.",
      },
      {
        key: "hsts",
        title: "Protección HSTS",
        status: hsts ? "pass" : "warn",
        description: hsts
          ? "La web obliga al navegador a priorizar conexiones seguras."
          : "No se ha detectado la cabecera Strict-Transport-Security.",
        fix: hsts
          ? null
          : 'Añade la cabecera "Strict-Transport-Security" en tu servidor.',
      },
      {
        key: "csp",
        title: "Content Security Policy",
        status: csp ? "pass" : "fail",
        description: csp
          ? "La web define una política de seguridad para scripts y recursos."
          : "No se ha detectado una política Content-Security-Policy.",
        fix: csp
          ? null
          : 'Configura una cabecera "Content-Security-Policy" básica.',
      },
      {
        key: "x-frame-options",
        title: "Protección contra iframes maliciosos",
        status: xFrameOptions ? "pass" : "warn",
        description: xFrameOptions
          ? "La web limita cómo puede cargarse dentro de un iframe."
          : "No se ha detectado la cabecera X-Frame-Options.",
        fix: xFrameOptions
          ? null
          : 'Añade la cabecera "X-Frame-Options" con valor "SAMEORIGIN" o "DENY".',
      },
      {
        key: "x-content-type-options",
        title: "Protección de tipos MIME",
        status: xContentTypeOptions ? "pass" : "warn",
        description: xContentTypeOptions
          ? "La web evita que el navegador interprete tipos de archivo de forma insegura."
          : "No se ha detectado la cabecera X-Content-Type-Options.",
        fix: xContentTypeOptions
          ? null
          : 'Añade la cabecera "X-Content-Type-Options" con valor "nosniff".',
      },
      {
        key: "referrer-policy",
        title: "Control del referrer",
        status: referrerPolicy ? "pass" : "warn",
        description: referrerPolicy
          ? "La web controla qué información de referencia comparte el navegador."
          : "No se ha detectado una cabecera Referrer-Policy.",
        fix: referrerPolicy
          ? null
          : 'Añade una cabecera "Referrer-Policy", por ejemplo "strict-origin-when-cross-origin".',
      },
      {
        key: "permissions-policy",
        title: "Control de permisos del navegador",
        status: permissionsPolicy ? "pass" : "warn",
        description: permissionsPolicy
          ? "La web limita permisos sensibles del navegador."
          : "No se ha detectado una cabecera Permissions-Policy.",
        fix: permissionsPolicy
          ? null
          : 'Añade una cabecera "Permissions-Policy" para limitar funciones innecesarias.',
      },
    ];

    const score = calculateScore(checks);

    const result: AuditResult = {
      url: finalUrl,
      score,
      summary: buildSummary(score),
      checks,
    };

    return NextResponse.json(result);
  } catch (error) {
    console.error(error);

    return NextResponse.json(
      {
        error:
          "No se pudo analizar la web. Comprueba que la URL existe y responde correctamente.",
      },
      { status: 500 }
    );
  }
}
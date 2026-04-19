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
  const weights: Record<string, number> = {
    https: 20,
    "http-redirect": 10,
    hsts: 10,
    csp: 12,
    "x-frame-options": 10,
    "x-content-type-options": 10,
    "referrer-policy": 8,
    "permissions-policy": 8,
  };

  const maxScore = Object.values(weights).reduce(
    (sum, value) => sum + value,
    0,
  );

  let score = 0;

  for (const check of checks) {
    const weight = weights[check.key] ?? 0;

    if (check.status === "pass") {
      score += weight;
    } else if (check.status === "warn") {
      score += weight * 0.75;
    }
  }

  return Math.round((score / maxScore) * 100);
}

function buildSummary(score: number) {
  if (score >= 85) {
    return "Tu web tiene una base bastante sólida en seguridad básica y transmite una buena sensación de confianza.";
  }

  if (score >= 70) {
    return "Tu web tiene una base aceptable, aunque todavía hay varios puntos que conviene revisar.";
  }

  if (score >= 50) {
    return "Tu web cumple algunos mínimos, pero muestra varias carencias importantes en seguridad básica y configuración.";
  }

  return "Tu web presenta varias debilidades claras en seguridad básica y confianza. Conviene revisarla cuanto antes.";
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
        { status: 400 },
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
    const cspReportOnly = headers.get("content-security-policy-report-only");

    function hasFrameAncestors(policy: string | null) {
      if (!policy) return false;
      return /(^|;)\s*frame-ancestors\s+/i.test(policy);
    }
    const hasFrameProtection =
      Boolean(xFrameOptions) ||
      hasFrameAncestors(csp) ||
      hasFrameAncestors(cspReportOnly);
    const hasEnforcedCsp = Boolean(csp);
    const hasReportOnlyCsp = Boolean(cspReportOnly);
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
          ? "Tu web usa una conexión segura, lo que ayuda a proteger la información del usuario."
          : "Tu web no está usando una conexión segura en la URL final.",
        fix: isHttps
          ? null
          : "Activa HTTPS con un certificado SSL y configura la web para que cargue siempre en su versión segura.",
      },
      {
        key: "http-redirect",
        title: "Redirección de HTTP a HTTPS",
        status: redirectsToHttps ? "pass" : "warn",
        description: redirectsToHttps
          ? "Si alguien entra por una versión insegura, tu web lo redirige correctamente a la versión segura."
          : "No se ha podido confirmar que tu web redirija automáticamente desde HTTP a HTTPS.",
        fix: redirectsToHttps
          ? null
          : "Configura una redirección automática de HTTP a HTTPS para que nadie entre por una versión insegura.",
      },
      {
        key: "hsts",
        title: "Strict-Transport-Security",
        status: hsts ? "pass" : "warn",
        description: hsts
          ? "Tu web indica al navegador que debe usar siempre una conexión segura."
          : "Tu web no indica al navegador que recuerde abrirse siempre con conexión segura.",
        fix: hsts
          ? null
          : 'Añade la cabecera "Strict-Transport-Security" para reforzar el uso de HTTPS.',
      },
      {
        key: "csp",
        title: "Content-Security-Policy",
        status: hasEnforcedCsp ? "pass" : "warn",
        description: hasEnforcedCsp
          ? "Tu web limita qué scripts y recursos pueden cargarse."
          : hasReportOnlyCsp
            ? "Tu web parece estar probando una política CSP, pero no aplicándola todavía de forma estricta."
            : "Tu web no muestra una política CSP visible para limitar scripts y recursos.",
        fix: hasEnforcedCsp
          ? null
          : hasReportOnlyCsp
            ? 'Si ya estás usando "Content-Security-Policy-Report-Only", el siguiente paso es aplicar una política CSP real.'
            : 'Configura "Content-Security-Policy" para limitar scripts y recursos potencialmente peligrosos.',
      },
      /*{
        key: "x-frame-options",
        title: "X-Frame-Options",
        status: xFrameOptions ? "pass" : "warn",
        description: xFrameOptions
          ? "Tu web está protegida frente a que otras páginas intenten cargarla dentro de un iframe."
          : "Tu web no indica si puede cargarse dentro de otras páginas, lo que puede dar pie a usos maliciosos.",
        fix: xFrameOptions
          ? null
          : 'Añade la cabecera "X-Frame-Options" con un valor como "SAMEORIGIN" o "DENY".',
      },*/
      {
        key: "frame-protection",
        title: "Protección frente a iframes externos",
        status: hasFrameProtection ? "pass" : "warn",
        description: hasFrameProtection
          ? "Tu web define protección para limitar que otras páginas la carguen dentro de un iframe."
          : "Tu web no muestra una protección clara frente a carga en iframes de otras páginas.",
        fix: hasFrameProtection
          ? null
          : 'Añade "X-Frame-Options" o usa "frame-ancestors" dentro de Content-Security-Policy.',
      },
      {
        key: "x-content-type-options",
        title: "X-Content-Type-Options",
        status: xContentTypeOptions ? "pass" : "warn",
        description: xContentTypeOptions
          ? "Tu web evita que el navegador interprete ciertos archivos de una forma insegura."
          : "Tu web no está indicando al navegador que trate algunos archivos de forma estricta.",
        fix: xContentTypeOptions
          ? null
          : 'Añade la cabecera "X-Content-Type-Options" con el valor "nosniff".',
      },
      {
        key: "referrer-policy",
        title: "Referrer-Policy",
        status: referrerPolicy ? "pass" : "warn",
        description: referrerPolicy
          ? "Tu web controla mejor qué información comparte el navegador al visitar otras páginas."
          : "Tu web no está controlando qué información de navegación se comparte al salir hacia otras webs.",
        fix: referrerPolicy
          ? null
          : 'Añade una cabecera "Referrer-Policy", por ejemplo "strict-origin-when-cross-origin".',
      },
      {
        key: "permissions-policy",
        title: "Permissions-Policy",
        status: permissionsPolicy ? "pass" : "warn",
        description: permissionsPolicy
          ? "Tu web limita mejor permisos del navegador como cámara, micrófono o ubicación."
          : "Tu web no define restricciones para algunos permisos sensibles del navegador.",
        fix: permissionsPolicy
          ? null
          : 'Añade una cabecera "Permissions-Policy" para limitar funciones que no necesitas.',
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
      { status: 500 },
    );
  }
}

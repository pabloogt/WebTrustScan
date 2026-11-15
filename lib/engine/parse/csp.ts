export type CspPolicy = Map<string, string[]>;

/**
 * Parsea una cabecera CSP. Si el servidor envía varias cabeceras llegan
 * unidas por comas, y cada una es una política independiente.
 */
export function parseCsp(value: string | undefined | null): CspPolicy[] {
  if (!value) return [];

  return value
    .split(",")
    .map((policy) => {
      const directives: CspPolicy = new Map();

      for (const raw of policy.split(";")) {
        const [name, ...sources] = raw.trim().split(/\s+/);
        if (!name) continue;

        const key = name.toLowerCase();
        // Según la especificación, las directivas repetidas se ignoran.
        if (!directives.has(key)) {
          directives.set(
            key,
            sources.map((source) => source.toLowerCase()),
          );
        }
      }

      return directives;
    })
    .filter((directives) => directives.size > 0);
}

export type ScriptStrength = "strong" | "eval-only" | "weak" | "unrestricted";

export type ScriptAssessment = {
  strength: ScriptStrength;
  /** Motivos concretos por los que la política es débil. */
  issues: string[];
};

const RANK: Record<ScriptStrength, number> = {
  unrestricted: 0,
  weak: 1,
  "eval-only": 2,
  strong: 3,
};

function assessPolicy(policy: CspPolicy): ScriptAssessment {
  const sources = policy.get("script-src") ?? policy.get("default-src");

  if (!sources) {
    return {
      strength: "unrestricted",
      issues: ["no define script-src ni default-src"],
    };
  }

  const strictDynamic = sources.includes("'strict-dynamic'");
  const usesNonceOrHash =
    strictDynamic ||
    sources.some((source) => /^'(nonce-|sha(256|384|512)-)/.test(source));
  const issues: string[] = [];

  // Con nonce/hash los navegadores actuales ignoran 'unsafe-inline'.
  if (sources.includes("'unsafe-inline'") && !usesNonceOrHash) {
    issues.push("permite scripts en línea ('unsafe-inline')");
  }

  // Con 'strict-dynamic' se ignoran las listas de orígenes.
  const open = sources.filter((source) =>
    ["*", "http:", "https:", "data:"].includes(source),
  );
  if (open.length > 0 && !strictDynamic) {
    issues.push(`permite scripts de cualquier origen (${open.join(" ")})`);
  }

  if (issues.length > 0) return { strength: "weak", issues };

  if (sources.includes("'unsafe-eval'")) {
    return { strength: "eval-only", issues: ["permite eval() ('unsafe-eval')"] };
  }

  return { strength: "strong", issues: [] };
}

/**
 * Evalúa el control de scripts de un conjunto de políticas. El navegador las
 * aplica todas a la vez, así que la protección efectiva es la de la más
 * estricta.
 */
export function assessScripts(policies: CspPolicy[]): ScriptAssessment {
  return policies
    .map(assessPolicy)
    .reduce((best, current) =>
      RANK[current.strength] > RANK[best.strength] ? current : best,
    );
}

/** Protección de `frame-ancestors`: estricta, abierta o no declarada. */
export function frameAncestors(policies: CspPolicy[]): "strict" | "open" | null {
  let verdict: "strict" | "open" | null = null;

  for (const policy of policies) {
    const sources = policy.get("frame-ancestors");
    if (!sources) continue;

    const open = sources.some((source) =>
      ["*", "http:", "https:"].includes(source),
    );

    // Con varias políticas se aplican todas: basta una estricta.
    if (!open) return "strict";
    verdict = "open";
  }

  return verdict;
}

export function upgradesInsecureRequests(policies: CspPolicy[]): boolean {
  return policies.some(
    (policy) =>
      policy.has("upgrade-insecure-requests") ||
      policy.has("block-all-mixed-content"),
  );
}

/**
 * Primer valor de una cabecera que solo admite uno. Cuando origen y CDN
 * añaden la misma cabecera, Node las une con comas.
 */
export function firstHeaderValue(value: string | undefined): string | undefined {
  return value?.split(",")[0]?.trim() || undefined;
}

export function parseHstsMaxAge(value: string): number | null {
  const match = /(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?:;|$)/i.exec(value);
  return match ? Number(match[1]) : null;
}

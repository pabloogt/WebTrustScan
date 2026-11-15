import {
  errored,
  fail,
  info,
  notApplicable,
  pass,
  warning,
  type Check,
  type Outcome,
  type Probe,
  type ScanContext,
} from "../context";
import type { DnsFacts } from "../dnsClient";

const NO_DOMAIN = notApplicable(
  "El destino es una dirección IP, no un dominio: no hay registros DNS que evaluar.",
);

function withDns(
  context: ScanContext,
  evaluate: (dns: DnsFacts) => Outcome,
): Outcome {
  return context.dns ? evaluate(context.dns) : NO_DOMAIN;
}

function dnsError(probe: Probe<unknown>): Outcome {
  return errored(
    "La consulta DNS ha fallado (el resolvedor no ha respondido). Es un problema del análisis, no del dominio, y no se penaliza.",
    {
      evidence: [
        { label: "Motivo", value: probe.ok ? "" : (probe.reason ?? probe.code) },
      ],
    },
  );
}

function tag(record: string, name: string): string | null {
  const match = new RegExp(`(?:^|;)\\s*${name}\\s*=\\s*([^;\\s]+)`, "i").exec(
    record,
  );
  return match ? match[1].toLowerCase() : null;
}

function spfCheck(context: ScanContext) {
  return withDns(context, (dns) => {
    if (!dns.spf.ok) return dnsError(dns.spf);
    if (!dns.mx.ok) return dnsError(dns.mx);

    const records = dns.spf.value;
    const hasMail = dns.mx.value.length > 0;
    const evidence = [
      { label: "Dominio", value: dns.mailDomain },
      ...records.map((record) => ({ label: "TXT", value: record })),
    ];

    if (records.length === 0) {
      return hasMail
        ? fail(
            `${dns.mailDomain} recibe correo pero no publica SPF: cualquiera puede enviar correos haciéndose pasar por este dominio con más facilidad.`,
            'Publica un registro TXT SPF con tus servidores de envío, terminado en "-all" o "~all".',
            { evidence },
          )
        : info(
            `${dns.mailDomain} no tiene servidores de correo (MX) ni SPF. Si el dominio no envía correo, conviene declararlo.`,
            {
              evidence,
              remediation:
                'Si este dominio no envía correo, publica el TXT "v=spf1 -all".',
            },
          );
    }

    if (records.length > 1) {
      return fail(
        `${dns.mailDomain} publica ${records.length} registros SPF. Solo puede haber uno: con varios, la validación da error y SPF deja de funcionar.`,
        "Fusiona los registros SPF en un único registro TXT.",
        { evidence },
      );
    }

    const record = records[0].toLowerCase();
    const all = /(?:^|\s)([+\-~?]?)all(?:\s|$)/.exec(record);

    if (!all) {
      return /(?:^|\s)redirect=/.test(record)
        ? pass(
            "El dominio publica SPF y delega su política en otro dominio (redirect).",
            { evidence, confidence: "medium" },
          )
        : warning(
            0.5,
            'El registro SPF no termina con un mecanismo "all", así que no indica qué hacer con los remitentes no autorizados.',
            'Termina el registro con "-all" (rechazar) o "~all" (marcar como sospechoso).',
            { evidence },
          );
    }

    const qualifier = all[1] || "+";

    if (qualifier === "+") {
      return fail(
        'El registro SPF termina en "+all": autoriza a CUALQUIER servidor a enviar correo en nombre del dominio.',
        'Sustituye "+all" por "-all" o "~all".',
        { evidence },
      );
    }

    if (qualifier === "?") {
      return warning(
        0.4,
        'El registro SPF termina en "?all" (neutral): no pide ninguna acción frente a remitentes no autorizados.',
        'Cambia "?all" por "~all" o "-all".',
        { evidence },
      );
    }

    return pass(
      qualifier === "-"
        ? 'SPF está publicado y rechaza a los remitentes no autorizados ("-all").'
        : 'SPF está publicado y marca como sospechosos a los remitentes no autorizados ("~all").',
      { evidence },
    );
  });
}

function dmarcCheck(context: ScanContext) {
  return withDns(context, (dns) => {
    if (!dns.dmarc.ok) return dnsError(dns.dmarc);

    const { name, records, inherited } = dns.dmarc.value;
    const evidence = [
      { label: "Consulta", value: name },
      ...records.map((record) => ({ label: "TXT", value: record })),
    ];
    const remediation =
      'Publica un registro TXT en _dmarc.<dominio>. Empieza con "v=DMARC1; p=none; rua=mailto:…" para recibir informes y avanza hasta "p=quarantine" o "p=reject".';

    if (records.length === 0) {
      return fail(
        "El dominio no publica DMARC: los proveedores de correo no saben qué hacer con mensajes que suplantan tu dominio, y no recibes informes de ello.",
        remediation,
        { evidence },
      );
    }

    if (records.length > 1) {
      return fail(
        "Hay varios registros DMARC en el mismo nombre; los receptores los ignoran todos.",
        "Deja un único registro DMARC.",
        { evidence },
      );
    }

    const record = records[0];
    // En un subdominio que hereda la política manda `sp`, si existe.
    const policy = (inherited && tag(record, "sp")) || tag(record, "p");
    const pct = Number(tag(record, "pct") ?? "100");

    if (policy !== "none" && policy !== "quarantine" && policy !== "reject") {
      return fail(
        "El registro DMARC no tiene una política (p=) válida, así que no tiene efecto.",
        remediation,
        { evidence },
      );
    }

    if (policy === "none") {
      return warning(
        0.4,
        'DMARC está publicado en modo "p=none": solo monitoriza. Los correos que suplantan el dominio se siguen entregando.',
        'Cuando los informes confirmen que tu correo legítimo pasa SPF/DKIM, cambia a "p=quarantine" y después a "p=reject".',
        { evidence },
      );
    }

    if (Number.isFinite(pct) && pct < 100) {
      return warning(
        0.8,
        `DMARC aplica "${policy}" solo al ${pct}% de los mensajes.`,
        'Sube "pct" a 100 cuando termines el despliegue gradual.',
        { evidence, severity: "low" },
      );
    }

    return pass(
      `DMARC está publicado con política "${policy}": los correos que suplantan el dominio se ${policy === "reject" ? "rechazan" : "envían a spam"}.`,
      { evidence },
    );
  });
}

function caaCheck(context: ScanContext) {
  return withDns(context, (dns) => {
    if (!dns.caa.ok) return dnsError(dns.caa);

    const { name, records } = dns.caa.value;
    const issuers = records.filter((record) => /^issue(wild)?\s/.test(record));

    return issuers.length > 0
      ? pass(
          `El dominio limita qué autoridades pueden emitir certificados${name && name !== dns.domain ? ` (heredado de ${name})` : ""}.`,
          { evidence: records.map((record) => ({ label: "CAA", value: record })) },
        )
      : fail(
          "El dominio no publica registros CAA: cualquier autoridad de certificación puede emitir certificados para él.",
          'Añade un registro CAA con tu autoridad, por ejemplo: 0 issue "letsencrypt.org".',
          { evidence: [{ label: "CAA", value: "(sin registros)" }] },
        );
  });
}

export const dnsEmailChecks: Check[] = [
  { id: "email.spf", run: spfCheck },
  { id: "email.dmarc", run: dmarcCheck },
  { id: "dns.caa", run: caaCheck },
];

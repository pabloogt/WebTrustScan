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
            `${dns.mailDomain} recibe correo pero no publica SPF: los servidores que reciben un mensaje no pueden comprobar si quien lo envía está autorizado por el dominio, lo que facilita la suplantación.`,
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

    // "-all" (fail) y "~all" (softfail) NO son equivalentes: el primero pide
    // rechazar; el segundo, aceptar pero tratar como sospechoso.
    return pass(
      qualifier === "-"
        ? 'SPF está publicado y termina en "-all" (fail): declara que el correo enviado desde servidores no autorizados no es legítimo y pide a los receptores que lo rechacen.'
        : 'SPF está publicado y termina en "~all" (softfail): declara que el correo enviado desde servidores no autorizados probablemente no es legítimo, pero pide aceptarlo y tratarlo como sospechoso, no rechazarlo. Es una configuración habitual y válida, sobre todo combinada con DMARC; "-all" es más estricto.',
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
        "El dominio no publica DMARC: no indica a los servidores que reciben correo cómo tratar los mensajes que usan tu dominio y no superan SPF ni DKIM, y no recibes informes de ello. Cada receptor aplica entonces solo sus propios filtros.",
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
      const reports = tag(record, "rua") !== null;
      // Lo que p=none significa, sin afirmar qué hará cada receptor.
      const meaning =
        'Con "p=none" el dominio no pide a los receptores que pongan en cuarentena ni rechacen los mensajes que fallan DMARC. Eso no significa que esos mensajes se entreguen siempre: cada receptor sigue aplicando sus propios filtros antispam y de seguridad.';

      return reports
        ? warning(
            0.4,
            `DMARC está publicado en modo de supervisión. ${meaning} El registro sí indica una dirección para informes agregados (rua), así que el dominio puede ver quién envía correo en su nombre: es la primera fase normal de un despliegue.`,
            'Cuando los informes confirmen que tu correo legítimo supera SPF o DKIM, sube la política a "p=quarantine" y después a "p=reject".',
            { evidence },
          )
        : warning(
            0.25,
            `DMARC está publicado en modo de supervisión y sin destino para informes. ${meaning} Además, el registro no incluye "rua", es decir, no especifica ninguna dirección a la que enviar los informes agregados de DMARC, así que el dominio no obtiene de él ni protección solicitada ni visibilidad.`,
            'Añade una dirección de informes ("rua=mailto:…") para ver quién envía correo en nombre del dominio. Cuando compruebes que tu correo legítimo supera SPF o DKIM, sube la política a "p=quarantine" y después a "p=reject".',
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
      policy === "reject"
        ? 'DMARC está publicado con política "reject": pide a los receptores que rechacen los mensajes que usan el dominio y no superan SPF ni DKIM.'
        : 'DMARC está publicado con política "quarantine": pide a los receptores que traten como sospechosos (normalmente, carpeta de spam) los mensajes que usan el dominio y no superan SPF ni DKIM.',
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
      : info(
          "El dominio no publica registros CAA, así que cualquier autoridad de certificación reconocida puede emitir certificados para él. Es la situación por defecto y la de la mayoría de dominios: CAA es una medida opcional que reduce el riesgo de emisiones no deseadas, por lo que su ausencia no puntúa.",
          {
            evidence: [{ label: "CAA", value: "(sin registros)" }],
            remediation:
              'Si quieres restringirlo, añade un registro CAA con tu autoridad, por ejemplo: 0 issue "letsencrypt.org".',
          },
        );
  });
}

export const dnsEmailChecks: Check[] = [
  { id: "email.spf", run: spfCheck },
  { id: "email.dmarc", run: dmarcCheck },
  { id: "dns.caa", run: caaCheck },
];

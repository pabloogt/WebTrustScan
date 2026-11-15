import { describe, expect, it } from "vitest";
import {
  getClientIdentity,
  normalizeIpKey,
  SHARED_CLIENT_KEY,
} from "@/lib/clientIp";

const headers = (values: Record<string, string>) => new Headers(values);

describe("getClientIdentity", () => {
  it("sin proxy de confianza ignora X-Forwarded-For (clave compartida)", () => {
    const identity = getClientIdentity(
      headers({ "x-forwarded-for": "1.2.3.4", "x-real-ip": "1.2.3.4" }),
      {},
    );

    expect(identity).toEqual({ key: SHARED_CLIENT_KEY, source: "untrusted" });
  });

  it("en Vercel usa la cabecera de la plataforma, no la que manda el cliente", () => {
    const identity = getClientIdentity(
      headers({
        "x-forwarded-for": "6.6.6.6",
        "x-vercel-forwarded-for": "203.0.113.9",
        "x-real-ip": "203.0.113.9",
      }),
      { VERCEL: "1" },
    );

    expect(identity).toEqual({ key: "203.0.113.9", source: "vercel" });
  });

  it("fuera de Vercel no se fía de x-vercel-forwarded-for", () => {
    const identity = getClientIdentity(
      headers({ "x-vercel-forwarded-for": "203.0.113.9" }),
      {},
    );

    expect(identity.source).toBe("untrusted");
  });

  it("con un proxy de confianza toma la última IP, no la primera", () => {
    // El cliente envía "6.6.6.6" y el proxy añade la IP real al final.
    const identity = getClientIdentity(
      headers({ "x-forwarded-for": "6.6.6.6, 198.51.100.20" }),
      { TRUSTED_PROXY_HOPS: "1" },
    );

    expect(identity).toEqual({ key: "198.51.100.20", source: "trusted-proxy" });
  });

  it("con dos proxies de confianza toma la penúltima", () => {
    const identity = getClientIdentity(
      headers({ "x-forwarded-for": "6.6.6.6, 198.51.100.20, 10.0.0.1" }),
      { TRUSTED_PROXY_HOPS: "2" },
    );

    expect(identity.key).toBe("198.51.100.20");
  });

  it.each([
    ["cadena más corta que los saltos", "198.51.100.20", "3"],
    ["valor que no es una IP", "<script>alert(1)</script>", "1"],
    ["cabecera vacía", "", "1"],
    ["saltos no numéricos", "198.51.100.20", "muchos"],
    ["saltos negativos", "198.51.100.20", "-1"],
  ])("cae a la clave compartida con %s", (_name, forwarded, hops) => {
    const identity = getClientIdentity(
      headers({ "x-forwarded-for": forwarded }),
      { TRUSTED_PROXY_HOPS: hops },
    );

    expect(identity.key).toBe(SHARED_CLIENT_KEY);
  });

  it("en Vercel, una cabecera con basura no se usa como clave", () => {
    const identity = getClientIdentity(
      headers({ "x-vercel-forwarded-for": "no-es-ip" }),
      { VERCEL: "1" },
    );

    expect(identity.key).toBe(SHARED_CLIENT_KEY);
  });
});

describe("normalizeIpKey", () => {
  it("agrupa IPv6 por /64 para que rotar direcciones no dé cupo extra", () => {
    const a = normalizeIpKey("2001:db8:abcd:12:1111:2222:3333:4444");
    const b = normalizeIpKey("2001:db8:abcd:12::1");
    const other = normalizeIpKey("2001:db8:abcd:13::1");

    expect(a).toBe("2001:db8:abcd:12::/64");
    expect(b).toBe(a);
    expect(other).not.toBe(a);
  });

  it("trata igual una IPv4 y su forma mapeada en IPv6", () => {
    expect(normalizeIpKey("::ffff:203.0.113.9")).toBe("203.0.113.9");
    expect(normalizeIpKey(" 203.0.113.9 ")).toBe("203.0.113.9");
    expect(normalizeIpKey("[2001:db8::1]")).toBe("2001:db8:0:0::/64");
  });

  it("rechaza lo que no es una IP", () => {
    expect(normalizeIpKey("localhost")).toBeNull();
    expect(normalizeIpKey("1.2.3.4:80")).toBeNull();
    expect(normalizeIpKey("")).toBeNull();
  });
});

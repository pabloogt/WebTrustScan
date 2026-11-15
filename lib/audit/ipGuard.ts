import { BlockList, isIP } from "node:net";

/**
 * Rangos que nunca deben ser alcanzables desde el analizador: loopback,
 * redes privadas, link-local (incluye metadatos cloud 169.254.169.254),
 * CGNAT, multicast, reservados y documentación.
 */
const blocked = new BlockList();

const IPV4_RANGES: Array<[string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
];

const IPV6_RANGES: Array<[string, number]> = [
  ["::", 96], // sin especificar, loopback e IPv4-compatible (::a.b.c.d)
  ["64:ff9b::", 96], // NAT64: encapsula direcciones IPv4
  ["64:ff9b:1::", 48],
  ["100::", 64],
  ["2001::", 23], // asignaciones IETF: Teredo (encapsula IPv4), ORCHID, pruebas
  ["2001:db8::", 32],
  ["2002::", 16], // 6to4: encapsula direcciones IPv4
  ["3fff::", 20],
  ["fc00::", 7],
  ["fe80::", 10],
  ["fec0::", 10],
  ["ff00::", 8],
];

for (const [prefix, bits] of IPV4_RANGES) {
  blocked.addSubnet(prefix, bits, "ipv4");
}

for (const [prefix, bits] of IPV6_RANGES) {
  blocked.addSubnet(prefix, bits, "ipv6");
}

const MAPPED_IPV4_DOTTED = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i;
const MAPPED_IPV4_HEX = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i;

function unwrapMappedIpv4(address: string): string | null {
  const dotted = MAPPED_IPV4_DOTTED.exec(address);
  if (dotted) return dotted[1];

  const hex = MAPPED_IPV4_HEX.exec(address);
  if (!hex) return null;

  const high = parseInt(hex[1], 16);
  const low = parseInt(hex[2], 16);

  return [high >> 8, high & 0xff, low >> 8, low & 0xff].join(".");
}

/** Devuelve true solo si la IP es una dirección pública enrutable. */
export function isPublicAddress(address: string): boolean {
  const family = isIP(address);

  if (family === 4) {
    return !blocked.check(address, "ipv4");
  }

  if (family === 6) {
    const mapped = unwrapMappedIpv4(address);
    if (mapped) return isPublicAddress(mapped);

    return !blocked.check(address, "ipv6");
  }

  return false;
}

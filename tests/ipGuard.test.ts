import { describe, expect, it } from "vitest";
import { isPublicAddress } from "@/lib/audit/ipGuard";

describe("isPublicAddress", () => {
  it.each([
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "172.15.255.255",
    "172.32.0.1",
    "2606:4700:4700::1111",
    "2a00:1450:4003:80f::200e",
  ])("permite la IP pública %s", (address) => {
    expect(isPublicAddress(address)).toBe(true);
  });

  it.each([
    "127.0.0.1",
    "127.255.255.254",
    "0.0.0.0",
    "10.0.0.1",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "198.18.0.1",
    "224.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "fe80::1",
    "fc00::1",
    "fd12:3456:789a::1",
    "ff02::1",
    "::ffff:127.0.0.1",
    "::ffff:7f00:1",
    "::ffff:169.254.169.254",
    "::ffff:a00:1",
    "64:ff9b::7f00:1",
    "2002:7f00:1::",
  ])("bloquea la IP interna o reservada %s", (address) => {
    expect(isPublicAddress(address)).toBe(false);
  });

  it("bloquea cualquier cosa que no sea una IP", () => {
    expect(isPublicAddress("localhost")).toBe(false);
    expect(isPublicAddress("")).toBe(false);
    expect(isPublicAddress("999.1.1.1")).toBe(false);
  });
});

import HomePage from "@/components/HomePage";
import { accountsEnabled } from "@/lib/pro/config";

export default function Page() {
  // El enlace al panel solo existe si las cuentas están activadas en servidor.
  return <HomePage accountsEnabled={accountsEnabled()} />;
}

/**
 * Error esperado de la capa Pro. El mensaje es seguro para mostrarlo al
 * usuario y `status` es el código HTTP con el que se responde.
 */
export class ProError extends Error {
  constructor(
    readonly status: 400 | 401 | 403 | 404 | 409 | 429 | 503,
    message: string,
  ) {
    super(message);
    this.name = "ProError";
  }
}

/**
 * Un recurso de otra organización se trata igual que uno que no existe: así
 * no se revela que el identificador es válido.
 */
export const notFound = (what = "El recurso") =>
  new ProError(404, `${what} no existe.`);

import {Buffer} from "node:buffer";

export class ResponseLimitError extends Error {
  constructor() {super("Response bytes exceed their bound"); this.name = "ResponseLimitError";}
}

// Selection, authorization, response pins and interpretation belong to the caller.
export async function readResponse(body, {maximum, limitError = () => new ResponseLimitError()} = {}) {
  const parts = []; let length = 0;
  try {
    if (!Number.isSafeInteger(maximum) || maximum < 0 || typeof limitError !== "function") {
      throw new TypeError("Configure a finite binary response bound and error factory");
    }
    for await (const part of body) {
      if (!(part instanceof Uint8Array)) throw new TypeError("Response chunks must be binary bytes");
      length += part.byteLength;
      if (length > maximum) throw limitError();
      parts.push(Buffer.from(part));
    }
    return Buffer.concat(parts, length);
  } finally {body?.destroy?.();}
}

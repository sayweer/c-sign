/** A message or entry that breaks the C-Sign rules. */
export class CSignError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CSignError";
  }
}

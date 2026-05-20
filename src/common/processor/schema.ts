/**
 * Credential schema loader — Node port of
 * credential/common/processor/schema.go
 */
export class CredentialSchemaLoader {
  constructor(public readonly schema: string) {}

  loadJSON(): unknown {
    if (!this.schema) throw new Error('failed to load schema: schema string is empty');
    return JSON.parse(this.schema);
  }

  jsonSource(): string {
    return this.schema;
  }
}

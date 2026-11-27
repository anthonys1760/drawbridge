export class DrawbridgeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class ConfigError extends DrawbridgeError {}

export class AuditIntegrityError extends DrawbridgeError {}

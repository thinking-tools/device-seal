export {
  createCredential,
  listCredentials,
  accessCredential,
  removeCredential,
  wipeVault,
  createVault,
} from './_vault.js';
export type {
  CredentialMetadata,
  CreateCredentialOptions,
  AccessCredentialOptions,
  RemoveCredentialOptions,
  WipeVaultOptions,
  ListCredentialsFilter,
  CredentialResult,
  VaultConfig,
} from './_types.js';

import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { afterEach, vi } from 'vitest';
import { clearAppIdentityCache } from '../src/_app-identity.js';

// Hard isolation between tests: drop any stubbed globals (window/navigator/location/document), restore
// spies, clear the app-identity memo, and hand every test a fresh, empty IndexedDB.
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  clearAppIdentityCache();
  globalThis.indexedDB = new IDBFactory();
});

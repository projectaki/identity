export class StorageService {
  private storage: Storage = sessionStorage;

  setStorageStrategy(storage: Storage) {
    this.storage = storage;
  }

  get(key: string): any | null {
    const value = this.storage.getItem(key);
    if (!value) return null;
    return JSON.parse(value);
  }

  set(key: string, value: any): void {
    const stringified = JSON.stringify(value);
    this.storage.setItem(key, stringified);
  }

  remove(key: string): void {
    this.storage.removeItem(key);
  }

  clear(): void {
    this.storage.clear();
  }
}

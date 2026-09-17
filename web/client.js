/** A dedicated-worker client. No keys or match-token bytes are returned to the parent page. */
export class FlamingoWorker {
  #worker;
  #nextId = 0;
  #pending = new Map();
  #closed = false;

  constructor() {
    this.#worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
    this.#worker.onmessage = ({ data }) => {
      const pending = this.#pending.get(data.id);
      if (!pending) return;
      this.#pending.delete(data.id);
      if (data.error) {
        pending.reject(Object.assign(new Error(data.error.message), { code: data.error.code }));
      } else {
        pending.resolve(data.result);
      }
    };
    this.#worker.onerror = () => this.close('Browser worker failed to initialize');
    this.#worker.onmessageerror = () => this.close('Browser worker message failed');
  }

  initialize(config) { return this.#request('initialize', config); }
  match(input) { return this.#request('match', input); }
  release(verifiedHandle) { return this.#request('release', verifiedHandle); }

  #request(operation, payload) {
    if (this.#closed) return Promise.reject(new Error('Client is closed'));
    if (this.#pending.size) return Promise.reject(new Error('An operation is already in progress'));
    const id = ++this.#nextId;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      try {
        this.#worker.postMessage({ id, operation, payload });
      } catch (error) {
        this.#pending.delete(id);
        reject(error);
      }
    });
  }

  /** Cancels pending work and disposes all Rust handles by terminating the worker. */
  close(message = 'Client closed') {
    this.#closed = true;
    this.#worker.terminate();
    for (const pending of this.#pending.values()) pending.reject(new Error(message));
    this.#pending.clear();
  }
}

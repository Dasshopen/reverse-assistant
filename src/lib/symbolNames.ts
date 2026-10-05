export interface SymbolPresentation {
  raw_name: string;
  display_name: string;
  signature: string | null;
  rename_name: string | null;
  scheme: "msvc" | "itanium" | null;
  decoded: boolean;
}

export function isEncodedCppName(name: string): boolean {
  return name.startsWith("?") || name.startsWith("_Z") || name.startsWith("__Z");
}

export function displaySymbolName(name: string, presentation?: SymbolPresentation): string {
  return presentation?.decoded ? presentation.display_name : name;
}

export function decodedRenameName(name: string, presentation?: SymbolPresentation): string | null {
  if (!isEncodedCppName(name)) return null;
  const safe = presentation?.decoded ? presentation.rename_name : null;
  return safe && /^[A-Za-z_][A-Za-z0-9_]*$/.test(safe) && safe.length <= 200 ? safe : null;
}

/** One local IPC request at a time; no LLM, network or per-row requests. */
export class SymbolPresentationQueue {
  private known = new Set<string>();
  private pending = new Set<string>();
  private running = false;
  private generation = 0;
  private completion: Promise<void> = Promise.resolve();
  private fetchBatch: (names: string[]) => Promise<SymbolPresentation[]>;
  private onResults: (results: SymbolPresentation[]) => void;

  constructor(
    fetchBatch: (names: string[]) => Promise<SymbolPresentation[]>,
    onResults: (results: SymbolPresentation[]) => void,
  ) { this.fetchBatch = fetchBatch; this.onResults = onResults; }

  reset(): void {
    this.generation += 1;
    this.known.clear();
    this.pending.clear();
  }

  request(names: Iterable<string>): void {
    const encoder = new TextEncoder();
    const oversized: SymbolPresentation[] = [];
    for (const name of names) {
      if (!isEncodedCppName(name) || this.known.has(name)) continue;
      this.known.add(name);
      if (encoder.encode(name).length > 2048) {
        oversized.push(this.undecoded(name));
        continue;
      }
      this.pending.add(name);
    }
    if (oversized.length > 0) this.onResults(oversized);
    if (!this.running && this.pending.size > 0) this.completion = this.flush();
  }

  settled(): Promise<void> { return this.completion; }

  private async flush(): Promise<void> {
    this.running = true;
    try {
      while (this.pending.size > 0) {
        const generation = this.generation;
        const batch = [...this.pending].slice(0, 256);
        for (const name of batch) this.pending.delete(name);
        let results: SymbolPresentation[];
        try {
          const fetched = await this.fetchBatch(batch);
          // Missing or failed decodes stay lossless; never guess a rename.
          const byRawName = new Map(fetched.map((result) => [result.raw_name, result]));
          results = batch.map((raw_name) => byRawName.get(raw_name) ?? this.undecoded(raw_name));
        } catch {
          results = batch.map((raw_name) => this.undecoded(raw_name));
        }
        if (generation === this.generation) this.onResults(results);
      }
    } finally {
      this.running = false;
    }
  }

  private undecoded(raw_name: string): SymbolPresentation {
    return { raw_name, display_name: raw_name, signature: null, rename_name: null, scheme: null, decoded: false };
  }
}

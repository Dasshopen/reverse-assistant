export type UpdateStage = "idle" | "checking" | "current" | "available" | "downloading" | "ready" | "installing" | "installed" | "error";
export interface UpdateState {
  stage: UpdateStage;
  version: string | null;
  notes: string;
  downloaded: number;
  total: number | null;
  error: string;
}
export type UpdateProgress =
  | { event: "Started"; data: { contentLength?: number } }
  | { event: "Progress"; data: { chunkLength: number } }
  | { event: "Finished" };
export interface PendingUpdate {
  version: string;
  body?: string;
  download(onEvent?: (event: UpdateProgress) => void, options?: { timeout: number }): Promise<void>;
  install(options?: { restartAfterInstall: boolean }): Promise<void>;
  close(): Promise<void>;
}

export const initialUpdateState = (): UpdateState => ({ stage: "idle", version: null, notes: "", downloaded: 0, total: null, error: "" });

/** The signed Tauri plugin is the only downloader/installer. Never execute a URL ourselves. */
export class UpdateController {
  state = initialUpdateState();
  private pending: PendingUpdate | null = null;
  private downloaded = false;
  private active = false;
  private disposed = false;
  private fetchUpdate: () => Promise<PendingUpdate | null>;
  private notify: (state: UpdateState) => void;

  constructor(fetchUpdate: () => Promise<PendingUpdate | null>, notify: (state: UpdateState) => void) {
    this.fetchUpdate = fetchUpdate;
    this.notify = notify;
  }

  private publish(patch: Partial<UpdateState>): void {
    this.state = { ...this.state, ...patch };
    if (!this.disposed) this.notify(this.state);
  }

  async check(): Promise<void> {
    if (this.active || this.disposed || this.downloaded) return;
    this.active = true;
    this.publish({ stage: "checking", error: "" });
    try {
      const update = await this.fetchUpdate();
      if (this.disposed) { await update?.close(); return; }
      await this.pending?.close();
      this.pending = update;
      this.publish({ stage: update ? "available" : "current", version: update?.version ?? null, notes: update?.body ?? "", downloaded: 0, total: null });
    } catch {
      // A 404/private repository/offline response is NOT proof that the app is current.
      this.publish({ stage: "error", error: "Vérification indisponible. Vérifie ta connexion ou réessaie plus tard." });
    } finally { this.active = false; }
  }

  async download(): Promise<void> {
    if (this.active || this.disposed || !this.pending || this.downloaded) return;
    this.active = true;
    this.publish({ stage: "downloading", downloaded: 0, total: null, error: "" });
    try {
      await this.pending.download((event) => {
        if (event.event === "Started") this.publish({ total: event.data.contentLength ?? null });
        if (event.event === "Progress") this.publish({ downloaded: this.state.downloaded + event.data.chunkLength });
        // Finished means transport finished; signature verification may still fail.
      }, { timeout: 300_000 });
      this.downloaded = true;
      this.publish({ stage: "ready" });
    } catch {
      this.publish({ stage: "error", error: "Téléchargement ou vérification de signature impossible. Rien n’a été installé ; réessaie plus tard." });
    } finally { this.active = false; }
  }

  async install(isBusy: () => boolean, confirm: () => Promise<boolean>, lock: (locked: boolean) => Promise<void>): Promise<void> {
    if (this.active || this.disposed || !this.pending || !this.downloaded || isBusy()) return;
    this.active = true;
    let locked = false;
    try {
      if (!(await confirm()) || this.disposed) return;
      // An analysis may have started while the confirmation dialog was open.
      if (isBusy()) { this.publish({ error: "Attends la fin des opérations en cours avant d’installer." }); return; }
      locked = true;
      await lock(true);
      if (isBusy()) { this.publish({ error: "Une opération est encore en cours. Installation différée." }); return; }
      this.publish({ stage: "installing", error: "" });
      await this.pending.install({ restartAfterInstall: true });
      this.publish({ stage: "installed" });
    } catch {
      this.publish({ stage: "ready", error: "L’installation a échoué. Tu peux réessayer ; aucun résultat d’analyse n’a été supprimé." });
    } finally {
      if (locked) await lock(false);
      this.active = false;
    }
  }

  async dispose(): Promise<void> {
    this.disposed = true;
    if (!this.active) await this.pending?.close();
  }
}

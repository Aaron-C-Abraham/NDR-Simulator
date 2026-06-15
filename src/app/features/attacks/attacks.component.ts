import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../shared/services/api.service';
import { ToastrService } from 'ngx-toastr';

@Component({
  selector: 'app-attacks',
  standalone: true,
  imports: [CommonModule, FormsModule],
  styles: [`
    /* ── Category filter tabs ── */
    .cat-tabs { display:flex; gap:0.5rem; flex-wrap:wrap; margin-bottom:1.25rem; }
    .cat-tab { padding:0.35rem 0.9rem; border-radius:9999px; font-size:0.78rem; font-weight:600;
               border:1.5px solid var(--border-color); background:#fff; cursor:pointer;
               transition:all 0.15s; color:var(--medium-gray); }
    .cat-tab:hover { border-color:var(--accent-color); color:var(--accent-color); }
    .cat-tab.active { background:var(--accent-color); color:#fff; border-color:var(--accent-color); }

    /* ── Table wrapper ── */
    .table-card { background:#fff; border-radius:12px; box-shadow:0 2px 8px rgba(0,0,0,0.06); overflow:hidden; }
    .table-toolbar { display:flex; align-items:center; justify-content:space-between;
                     padding:1rem 1.25rem; border-bottom:1px solid var(--border-color); }
    .table-title { font-size:0.95rem; font-weight:700; color:var(--primary-color); }
    .attack-count { font-size:0.8rem; color:var(--medium-gray); }

    table { width:100%; border-collapse:collapse; }
    thead th { background:#f8f9fa; padding:0.7rem 1rem; font-size:0.72rem; font-weight:600;
               text-transform:uppercase; letter-spacing:0.5px; color:var(--medium-gray);
               border-bottom:2px solid var(--border-color); white-space:nowrap; }
    tbody td { padding:0.8rem 1rem; border-bottom:1px solid var(--border-color);
               vertical-align:middle; font-size:0.85rem; }
    tbody tr:last-child td { border-bottom:none; }
    tbody tr:hover { background:linear-gradient(90deg,rgba(44,168,199,0.04),transparent); }
    .col-num { width:48px; color:var(--medium-gray); font-size:0.78rem; text-align:center; }
    .col-name { font-weight:600; color:var(--primary-color); }
    .col-desc { color:var(--medium-gray); font-size:0.8rem; max-width:300px; }
    .col-mitre { font-size:0.72rem; font-family:'Courier New',monospace; }
    .col-action { width:90px; text-align:center; }
    .mitre-tag { display:inline-block; background:rgba(139,92,246,0.1); color:#8b5cf6;
                 border-radius:4px; padding:0.15rem 0.4rem; font-size:0.7rem; margin:0.1rem; white-space:nowrap; }

    /* ── Category badge ── */
    .cat-badge { display:inline-flex; align-items:center; gap:5px;
                 padding:0.25rem 0.6rem; border-radius:9999px; font-size:0.7rem; font-weight:600; white-space:nowrap; }
    .cat-Reconnaissance  { background:rgba(139,92,246,0.12); color:#8b5cf6; }
    .cat-DoS-DDoS        { background:rgba(231,76,60,0.12);  color:#E74C3C; }
    .cat-Spoofing        { background:rgba(243,156,18,0.12); color:#d68910; }
    .cat-Injection       { background:rgba(155,35,53,0.12);  color:#9B2335; }
    .cat-Authentication  { background:rgba(52,152,219,0.12); color:#2980b9; }
    .cat-C2              { background:rgba(99,102,241,0.12); color:#6366f1; }
    .cat-Lateral-Movement{ background:rgba(16,185,129,0.12); color:#059669; }
    .cat-Wireless        { background:rgba(6,182,212,0.12);  color:#0891b2; }

    /* ── Launch button ── */
    .btn-launch { display:inline-flex; align-items:center; gap:5px;
                  padding:0.3rem 0.75rem; border-radius:6px; font-size:0.78rem; font-weight:600;
                  background:var(--accent-color); color:#fff; border:none; cursor:pointer;
                  transition:all 0.15s; }
    .btn-launch:hover { background:var(--accent-hover); transform:translateY(-1px); }

    /* ── Modal overlay ── */
    .modal-backdrop { position:fixed; inset:0; background:rgba(0,0,0,0.5);
                      display:flex; align-items:center; justify-content:center;
                      z-index:2000; padding:1rem; animation:fadeIn 0.15s ease; }
    @keyframes fadeIn { from { opacity:0; } to { opacity:1; } }
    .modal-box { background:#fff; border-radius:12px; width:100%; max-width:620px;
                 max-height:90vh; overflow:hidden; display:flex; flex-direction:column;
                 box-shadow:0 20px 60px rgba(0,0,0,0.25); animation:scaleIn 0.18s ease; }
    @keyframes scaleIn { from { opacity:0; transform:scale(0.95); } to { opacity:1; transform:scale(1); } }

    .modal-header { background:var(--primary-color); color:#fff; padding:1.1rem 1.5rem;
                    display:flex; align-items:center; justify-content:space-between; flex-shrink:0; }
    .modal-header-left { display:flex; flex-direction:column; gap:0.25rem; }
    .modal-title { font-size:1rem; font-weight:700; }
    .modal-subtitle { font-size:0.75rem; opacity:0.75; }
    .modal-close { background:rgba(255,255,255,0.15); border:none; color:#fff; cursor:pointer;
                   width:30px; height:30px; border-radius:6px; font-size:1.1rem;
                   display:flex; align-items:center; justify-content:center; transition:background 0.15s; }
    .modal-close:hover { background:rgba(255,255,255,0.28); }

    .modal-body { padding:1.5rem; overflow-y:auto; flex:1; }
    .modal-footer { padding:1rem 1.5rem; border-top:1px solid var(--border-color);
                    display:flex; justify-content:flex-end; gap:0.75rem; flex-shrink:0; }

    /* ── Form inside modal ── */
    .section-label { font-size:0.72rem; font-weight:600; text-transform:uppercase;
                     letter-spacing:0.5px; color:var(--medium-gray); margin-bottom:0.6rem; }
    .attack-desc-box { background:#f8f9fa; border-radius:8px; padding:0.75rem 1rem;
                       font-size:0.82rem; color:var(--medium-gray); line-height:1.5;
                       margin-bottom:1.25rem; }
    .param-grid { display:grid; grid-template-columns:1fr 1fr; gap:0.75rem; }
    .param-grid.full { grid-template-columns:1fr; }
    .form-label { font-size:0.8rem; font-weight:500; color:var(--primary-color); margin-bottom:0.3rem; }
    .form-control { width:100%; padding:0.45rem 0.7rem; font-size:0.85rem;
                    border:1px solid var(--border-color); border-radius:6px; outline:none;
                    transition:border-color 0.15s, box-shadow 0.15s; }
    .form-control:focus { border-color:var(--accent-color); box-shadow:0 0 0 3px rgba(44,168,199,0.15); }
    .form-hint { font-size:0.7rem; color:var(--medium-gray); margin-top:0.2rem; }
    .param-section { margin-top:1.25rem; }
    .param-section:first-child { margin-top:0; }

    /* ── Result box ── */
    .result-wrap { margin-top:1rem; }
    .result-box { background:#f8f9fa; border-radius:8px; padding:1rem;
                  font-size:0.77rem; font-family:'Courier New',monospace; max-height:200px;
                  overflow-y:auto; white-space:pre-wrap; border:1px solid var(--border-color); }
    .result-success { border-left:4px solid var(--success-color); }
    .result-error   { border-left:4px solid var(--danger-color); }
    .result-label { font-size:0.75rem; font-weight:600; margin-bottom:0.4rem; }
    .result-label.success { color:var(--success-color); }
    .result-label.error   { color:var(--danger-color); }

    /* ── Buttons ── */
    .btn-cancel { padding:0.45rem 1.1rem; border-radius:6px; font-size:0.85rem; font-weight:500;
                  background:#f8f9fa; color:var(--primary-color); border:1px solid var(--border-color);
                  cursor:pointer; transition:background 0.15s; }
    .btn-cancel:hover { background:#e9ecef; }
    .btn-execute { padding:0.45rem 1.25rem; border-radius:6px; font-size:0.85rem; font-weight:600;
                   background:var(--accent-color); color:#fff; border:none; cursor:pointer;
                   display:inline-flex; align-items:center; gap:6px; transition:all 0.15s; }
    .btn-execute:hover:not(:disabled) { background:var(--accent-hover); transform:translateY(-1px); }
    .btn-execute:disabled { opacity:0.65; cursor:not-allowed; }

    /* ── Search input ── */
    .search-wrap { position:relative; }
    .search-wrap i { position:absolute; left:0.6rem; top:50%; transform:translateY(-50%);
                     color:var(--medium-gray); font-size:0.85rem; pointer-events:none; }
    .search-input { padding:0.4rem 0.75rem 0.4rem 2rem; border:1px solid var(--border-color);
                    border-radius:8px; font-size:0.83rem; outline:none; width:200px; transition:all 0.15s; }
    .search-input:focus { border-color:var(--accent-color); box-shadow:0 0 0 3px rgba(44,168,199,0.12); }

    .empty-state { text-align:center; padding:3rem 1rem; color:var(--medium-gray); }
    .empty-state i { font-size:2.5rem; display:block; margin-bottom:0.75rem; opacity:0.4; }

    .spin { animation:spin 1s linear infinite; }
    @keyframes spin { from { transform:rotate(0deg); } to { transform:rotate(360deg); } }

    /* ── View tabs ── */
    .view-tabs { display:flex; gap:0; margin-bottom:1.25rem; background:#fff;
                 border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,0.06);
                 overflow:hidden; width:fit-content; border:1px solid var(--border-color); }
    .view-tab { padding:0.5rem 1.4rem; font-size:0.85rem; font-weight:600; cursor:pointer;
                border:none; background:transparent; color:var(--medium-gray);
                display:inline-flex; align-items:center; gap:6px; transition:all 0.15s; }
    .view-tab:hover { color:var(--primary-color); background:#f8f9fa; }
    .view-tab.active { background:var(--accent-color); color:#fff; }

    /* ── History table ── */
    .history-toolbar { display:flex; align-items:center; justify-content:space-between;
                       padding:1rem 1.25rem; border-bottom:1px solid var(--border-color); }
    .history-title { font-size:0.95rem; font-weight:700; color:var(--primary-color); }
    .btn-refresh { display:inline-flex; align-items:center; gap:5px; padding:0.35rem 0.9rem;
                   border-radius:6px; font-size:0.8rem; font-weight:600; border:1px solid var(--border-color);
                   background:#fff; color:var(--primary-color); cursor:pointer; transition:all 0.15s; }
    .btn-refresh:hover { background:#f8f9fa; border-color:var(--accent-color); color:var(--accent-color); }
    .status-success { display:inline-flex; align-items:center; gap:5px; padding:0.2rem 0.55rem;
                      border-radius:9999px; font-size:0.72rem; font-weight:600;
                      background:rgba(39,174,96,0.1); color:var(--success-color); }
    .status-error   { display:inline-flex; align-items:center; gap:5px; padding:0.2rem 0.55rem;
                      border-radius:9999px; font-size:0.72rem; font-weight:600;
                      background:rgba(231,76,60,0.1); color:var(--danger-color); }
    .target-chip { display:inline-block; background:#f0f4f8; border-radius:4px;
                   padding:0.1rem 0.4rem; font-size:0.7rem; font-family:'Courier New',monospace;
                   margin:0.1rem; color:var(--primary-color); }
    .col-time { width:140px; white-space:nowrap; font-size:0.78rem; color:var(--medium-gray); }
    .col-dur  { width:80px; text-align:right; font-size:0.78rem; color:var(--medium-gray); }
    .col-cnt  { width:70px; text-align:center; font-size:0.82rem; }
  `],
  template: `
    <div class="animate-in">
      <div class="page-header">
        <h1 class="page-title">
          <i class="bi bi-lightning-charge-fill me-2" style="color:var(--accent-color)"></i>Attack Modules
        </h1>
        <p class="page-subtitle">{{ attacks.length }} simulations across {{ categoryCount }} categories — select an attack to configure and launch</p>
      </div>

      <!-- View tab switcher -->
      <div class="view-tabs">
        <button class="view-tab" [class.active]="activeView==='catalog'" (click)="switchView('catalog')">
          <i class="bi bi-grid-3x3-gap-fill"></i> Catalog
        </button>
        <button class="view-tab" [class.active]="activeView==='history'" (click)="switchView('history')">
          <i class="bi bi-clock-history"></i> History
          <span *ngIf="history.length" style="background:rgba(255,255,255,0.25);border-radius:9999px;padding:0.05rem 0.45rem;font-size:0.7rem;margin-left:2px">{{ history.length }}</span>
        </button>
      </div>

      <!-- ═══════════ CATALOG VIEW ═══════════ -->
      <ng-container *ngIf="activeView==='catalog'">

      <!-- Category filter tabs -->
      <div class="cat-tabs">
        <button class="cat-tab" [class.active]="catFilter===''" (click)="catFilter='';searchQ=''">
          All ({{ attacks.length }})
        </button>
        <button *ngFor="let cat of categories" class="cat-tab" [class.active]="catFilter===cat"
                (click)="catFilter=cat;searchQ=''">
          <i class="bi" [class]="categoryIcon(cat)" style="font-size:0.75rem"></i>
          {{ cat }} ({{ countByCategory(cat) }})
        </button>
      </div>

      <!-- Table card -->
      <div class="table-card">
        <div class="table-toolbar">
          <div>
            <span class="table-title">Attack Simulations</span>
            <span class="attack-count ms-2">{{ filteredAttacks.length }} shown</span>
          </div>
          <div class="search-wrap">
            <i class="bi bi-search"></i>
            <input class="search-input" [(ngModel)]="searchQ" placeholder="Search attacks..." />
          </div>
        </div>

        <div *ngIf="loading" class="empty-state">
          <i class="bi bi-arrow-clockwise spin"></i>
          <div>Loading attacks…</div>
        </div>

        <div *ngIf="!loading && filteredAttacks.length===0" class="empty-state">
          <i class="bi bi-search"></i>
          <div>No attacks match your filter</div>
        </div>

        <table *ngIf="!loading && filteredAttacks.length>0">
          <thead>
            <tr>
              <th class="col-num">#</th>
              <th>Attack Name</th>
              <th>Category</th>
              <th>MITRE IDs</th>
              <th>Description</th>
              <th class="col-action">Launch</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let atk of filteredAttacks; let i=index">
              <td class="col-num">{{ i + 1 }}</td>
              <td class="col-name">{{ atk.name }}</td>
              <td>
                <span class="cat-badge" [class]="'cat-'+categoryKey(atk.category)">
                  <i class="bi" [class]="categoryIcon(atk.category)"></i>
                  {{ atk.category }}
                </span>
              </td>
              <td>
                <span *ngFor="let id of (atk.mitre_ids || [])" class="mitre-tag">{{ id }}</span>
                <span *ngIf="!atk.mitre_ids?.length" class="text-muted" style="font-size:0.75rem">—</span>
              </td>
              <td class="col-desc">{{ truncate(atk.description, 80) }}</td>
              <td class="col-action">
                <button class="btn-launch" (click)="openModal(atk)">
                  <i class="bi bi-play-fill"></i> Run
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      </ng-container>
      <!-- ═══════════ END CATALOG VIEW ═══════════ -->

      <!-- ═══════════ HISTORY VIEW ═══════════ -->
      <ng-container *ngIf="activeView==='history'">
        <div class="table-card">
          <div class="history-toolbar">
            <div>
              <span class="history-title"><i class="bi bi-clock-history me-2" style="color:var(--accent-color)"></i>Attack Execution History</span>
              <span class="attack-count ms-2">{{ history.length }} executions</span>
            </div>
            <button class="btn-refresh" (click)="loadHistory()" [disabled]="historyLoading">
              <i class="bi" [class]="historyLoading ? 'bi-arrow-clockwise spin' : 'bi-arrow-clockwise'"></i>
              Refresh
            </button>
          </div>

          <div *ngIf="historyLoading" class="empty-state">
            <i class="bi bi-arrow-clockwise spin"></i>
            <div>Loading history…</div>
          </div>

          <div *ngIf="!historyLoading && history.length===0" class="empty-state">
            <i class="bi bi-clock-history"></i>
            <div>No attack executions yet — run an attack from the Catalog tab</div>
          </div>

          <table *ngIf="!historyLoading && history.length>0">
            <thead>
              <tr>
                <th class="col-time">Time</th>
                <th>Attack</th>
                <th>Category</th>
                <th>Attacker IP</th>
                <th>Target(s)</th>
                <th style="text-align:center">Status</th>
                <th class="col-cnt">Syslog</th>
                <th class="col-cnt">Flows</th>
                <th class="col-dur">Duration</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let ex of history">
                <td class="col-time">{{ formatTime(ex.started_at) }}</td>
                <td class="col-name">{{ ex.attack_name }}</td>
                <td>
                  <span class="cat-badge" [class]="'cat-'+categoryKey(ex.category)">
                    <i class="bi" [class]="categoryIcon(ex.category)"></i>
                    {{ ex.category }}
                  </span>
                </td>
                <td style="font-family:'Courier New',monospace;font-size:0.8rem">{{ ex.attacker_ip }}</td>
                <td>
                  <span *ngFor="let ip of (ex.target_ips || [])" class="target-chip">{{ ip }}</span>
                </td>
                <td style="text-align:center">
                  <span *ngIf="ex.status==='success'" class="status-success">
                    <i class="bi bi-check-circle-fill"></i> Success
                  </span>
                  <span *ngIf="ex.status!=='success'" class="status-error" [title]="ex.error_msg">
                    <i class="bi bi-x-circle-fill"></i> Error
                  </span>
                </td>
                <td class="col-cnt">{{ ex.syslog_count }}</td>
                <td class="col-cnt">{{ ex.flow_count }}</td>
                <td class="col-dur">{{ formatDuration(ex.duration_ms) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </ng-container>
      <!-- ═══════════ END HISTORY VIEW ═══════════ -->

    </div>

    <!-- Configuration Modal -->
    <div class="modal-backdrop" *ngIf="showModal && selected" (click)="onBackdropClick($event)">
      <div class="modal-box" (click)="$event.stopPropagation()">

        <!-- Header -->
        <div class="modal-header">
          <div class="modal-header-left">
            <div class="modal-title">
              <i class="bi" [class]="categoryIcon(selected.category)" style="margin-right:6px"></i>
              {{ selected.name }}
            </div>
            <div class="modal-subtitle">
              <span class="cat-badge" [class]="'cat-'+categoryKey(selected.category)" style="background:rgba(255,255,255,0.15);color:rgba(255,255,255,0.9)">
                {{ selected.category }}
              </span>
              <span *ngFor="let id of (selected.mitre_ids || [])" style="margin-left:6px;font-family:monospace;font-size:0.72rem;opacity:0.8">{{ id }}</span>
            </div>
          </div>
          <button class="modal-close" (click)="closeModal()">
            <i class="bi bi-x-lg"></i>
          </button>
        </div>

        <!-- Body -->
        <div class="modal-body">

          <!-- Description -->
          <div class="attack-desc-box">
            <i class="bi bi-info-circle me-1"></i>{{ selected.description }}
          </div>

          <!-- Network targets -->
          <div class="param-section">
            <div class="section-label"><i class="bi bi-hdd-network me-1"></i>Network Configuration</div>
            <div class="param-grid">
              <div>
                <label class="form-label">Attacker IP <span style="color:var(--danger-color)">*</span></label>
                <input class="form-control" [(ngModel)]="execReq.attacker_ip" placeholder="198.51.100.100" />
                <div class="form-hint">Source IP of the simulated attacker</div>
              </div>
              <div>
                <label class="form-label">Target IPs <span style="color:var(--danger-color)">*</span></label>
                <input class="form-control" [(ngModel)]="targetIPsStr" placeholder="10.0.2.10, 10.0.3.101" />
                <div class="form-hint">Comma-separated list of target IPs</div>
              </div>
            </div>
          </div>

          <!-- Attack-specific parameters -->
          <div class="param-section" *ngIf="selected.parameters?.length">
            <div class="section-label"><i class="bi bi-sliders me-1"></i>Attack Parameters</div>
            <div class="param-grid">
              <div *ngFor="let param of selected.parameters">
                <label class="form-label">
                  {{ formatParamLabel(param.name) }}
                  <span style="color:var(--danger-color)" *ngIf="param.required">*</span>
                  <span style="font-weight:400;color:var(--medium-gray);font-size:0.72rem"> ({{ param.type }})</span>
                </label>
                <input class="form-control" [(ngModel)]="execParams[param.name]"
                       [placeholder]="param.default || param.description" />
                <div class="form-hint" *ngIf="param.description">{{ param.description }}</div>
              </div>
            </div>
          </div>

          <!-- Result -->
          <div class="result-wrap" *ngIf="result !== null">
            <div class="result-label" [class.success]="!resultError" [class.error]="resultError">
              <i class="bi" [class]="resultError ? 'bi-x-circle-fill' : 'bi-check-circle-fill'"></i>
              {{ resultError ? 'Attack Error' : 'Execution Result' }}
            </div>
            <div class="result-box" [class.result-success]="!resultError" [class.result-error]="resultError">{{ result | json }}</div>
          </div>
        </div>

        <!-- Footer -->
        <div class="modal-footer">
          <button class="btn-cancel" (click)="closeModal()">Close</button>
          <button class="btn-execute" (click)="executeAttack()" [disabled]="running">
            <i class="bi" [class]="running ? 'bi-arrow-clockwise spin' : 'bi-lightning-charge-fill'"></i>
            {{ running ? 'Executing…' : 'Execute Attack' }}
          </button>
        </div>

      </div>
    </div>
  `
})
export class AttacksComponent implements OnInit {
  private api = inject(ApiService);
  private toastr = inject(ToastrService);

  attacks: any[] = [];
  catFilter = '';
  searchQ = '';
  selected: any = null;
  showModal = false;
  execReq: any = { attacker_ip: '198.51.100.100' };
  execParams: Record<string, string> = {};
  targetIPsStr = '10.0.2.10';
  running = false;
  result: any = null;
  resultError = false;
  loading = true;

  activeView: 'catalog' | 'history' = 'catalog';
  history: any[] = [];
  historyLoading = false;

  get categories(): string[] {
    return [...new Set(this.attacks.map((a: any) => a.category))];
  }

  get categoryCount(): number {
    return this.categories.length;
  }

  get filteredAttacks(): any[] {
    let list = this.attacks;
    if (this.catFilter) list = list.filter((a: any) => a.category === this.catFilter);
    if (this.searchQ.trim()) {
      const q = this.searchQ.toLowerCase();
      list = list.filter((a: any) =>
        a.name.toLowerCase().includes(q) ||
        a.description.toLowerCase().includes(q) ||
        (a.mitre_ids || []).some((id: string) => id.toLowerCase().includes(q)) ||
        a.category.toLowerCase().includes(q)
      );
    }
    return list;
  }

  ngOnInit(): void {
    this.api.getAttacks().subscribe({
      next: d => { this.attacks = d.attacks || []; this.loading = false; },
      error: () => { this.toastr.error('Failed to load attacks'); this.loading = false; }
    });
    this.loadHistory();
  }

  switchView(view: 'catalog' | 'history'): void {
    this.activeView = view;
    if (view === 'history') this.loadHistory();
  }

  loadHistory(): void {
    this.historyLoading = true;
    this.api.getAttackHistory(200).subscribe({
      next: d => { this.history = d.history || []; this.historyLoading = false; },
      error: () => { this.historyLoading = false; }
    });
  }

  formatTime(iso: string): string {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleString(undefined, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  formatDuration(ms: number): string {
    if (!ms) return '< 1s';
    if (ms < 1000) return ms + 'ms';
    return (ms / 1000).toFixed(1) + 's';
  }

  countByCategory(cat: string): number {
    return this.attacks.filter((a: any) => a.category === cat).length;
  }

  openModal(atk: any): void {
    this.selected = atk;
    this.execParams = {};
    this.result = null;
    this.resultError = false;
    atk.parameters?.forEach((p: any) => { if (p.default) this.execParams[p.name] = p.default; });
    this.showModal = true;
  }

  closeModal(): void {
    this.showModal = false;
    this.selected = null;
    this.result = null;
    this.running = false;
  }

  onBackdropClick(event: MouseEvent): void {
    if ((event.target as HTMLElement).classList.contains('modal-backdrop')) {
      this.closeModal();
    }
  }

  executeAttack(): void {
    if (!this.selected || this.running) return;
    this.running = true;
    this.result = null;
    const req = {
      attack_id: this.selected.id,
      attacker_ip: this.execReq.attacker_ip,
      target_ips: this.targetIPsStr.split(',').map((s: string) => s.trim()).filter(Boolean),
      params: this.execParams
    };
    this.api.executeAttack(req).subscribe({
      next: r => {
        this.result = r;
        this.resultError = false;
        this.running = false;
        this.toastr.success(`${this.selected.name} executed`);
        this.loadHistory();
      },
      error: e => {
        this.result = e.error ?? { error: 'Request failed' };
        this.resultError = true;
        this.running = false;
        this.toastr.error('Attack execution failed');
        this.loadHistory();
      }
    });
  }

  truncate(text: string, len: number): string {
    if (!text) return '';
    return text.length > len ? text.slice(0, len) + '…' : text;
  }

  formatParamLabel(name: string): string {
    return name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  }

  categoryKey(cat: string): string {
    return cat.replace(/[^a-zA-Z]/g, '-');
  }

  categoryIcon(cat: string): string {
    const map: Record<string, string> = {
      'Reconnaissance': 'bi-search',
      'DoS/DDoS': 'bi-tsunami',
      'Spoofing': 'bi-mask',
      'Injection': 'bi-code-slash',
      'Authentication': 'bi-key-fill',
      'C2': 'bi-broadcast',
      'Lateral Movement': 'bi-arrow-left-right',
      'Wireless': 'bi-wifi-off'
    };
    return map[cat] ?? 'bi-lightning-charge';
  }
}

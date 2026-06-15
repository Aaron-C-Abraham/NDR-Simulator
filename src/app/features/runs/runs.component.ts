import { Component, OnInit, OnDestroy, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { ApiService } from '../../shared/services/api.service';
import { ToastrService } from 'ngx-toastr';

@Component({
  selector: 'app-runs',
  standalone: true,
  imports: [CommonModule],
  styles: [`
    .runs-table-wrap { background:#fff; border-radius:12px; box-shadow:0 2px 8px rgba(0,0,0,0.06); overflow:hidden; }
    .badge { padding:0.25rem 0.55rem; border-radius:4px; font-size:0.7rem; font-weight:600; }
    .badge-running { background:rgba(44,168,199,0.12); color:#2ca8c7; border:1px solid #2ca8c7; border-radius:9999px; }
    .badge-completed { background:rgba(39,174,96,0.12); color:#27AE60; border:1px solid #27AE60; border-radius:9999px; }
    .badge-pending { background:rgba(243,156,18,0.12); color:#F39C12; border:1px solid #F39C12; border-radius:9999px; }
    .badge-failed, .badge-aborted { background:rgba(231,76,60,0.12); color:#E74C3C; border:1px solid #E74C3C; border-radius:9999px; }
    .run-id { font-family:monospace; font-size:0.78rem; color:#6c757d; }
    .events-panel { background:#f8f9fa; border-radius:8px; padding:1rem; margin-top:1rem; max-height:400px; overflow-y:auto; }
    .event-row { display:flex; gap:0.75rem; padding:0.4rem 0; border-bottom:1px solid #eee; font-size:0.78rem; }
    .event-type { font-weight:600; min-width:60px; }
    .event-type-syslog { color:#2ca8c7; }
    .event-type-netflow { color:#6366f1; }
    .event-type-sflow { color:#8b5cf6; }
    .event-type-pcap { color:#10b981; }
    .live-pill { background:rgba(39,174,96,0.12); color:#27AE60; border:1px solid #27AE60; border-radius:9999px; padding:0.2rem 0.65rem; font-size:0.72rem; font-weight:600; display:inline-flex; align-items:center; gap:5px; }
    .live-dot { width:6px; height:6px; border-radius:50%; background:#27AE60; animation:pulse-dot 1.5s infinite; }
    @keyframes pulse-dot { 0%,100%{opacity:1;}50%{opacity:0.4;} }
  `],
  template: `
    <div class="animate-in">
      <div class="page-header d-flex justify-content-between align-items-center">
        <div>
          <h1 class="page-title"><i class="bi bi-play-circle-fill me-2" style="color:var(--accent-color)"></i>Test Runs</h1>
          <p class="page-subtitle">Live and historical scenario executions</p>
        </div>
        <div *ngIf="activeRunCount > 0" class="live-pill">
          <span class="live-dot"></span>{{ activeRunCount }} running
        </div>
      </div>

      <div class="runs-table-wrap">
        <table class="table mb-0">
          <thead>
            <tr>
              <th>Run ID</th><th>Scenario</th><th>Status</th><th>Attacker</th>
              <th>Started</th><th>Duration</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let run of runs" (click)="selectRun(run)" style="cursor:pointer" [style.background]="selectedRun?.id===run.id?'rgba(44,168,199,0.04)':''">
              <td><span class="run-id">{{ run.id?.slice(0,8) }}</span></td>
              <td style="font-size:0.85rem;font-weight:600">{{ run.scenario_name }}</td>
              <td><span class="badge" [class]="'badge-'+run.status">{{ run.status }}</span></td>
              <td style="font-family:monospace;font-size:0.78rem">{{ run.attacker_ip }}</td>
              <td style="font-size:0.78rem">{{ run.started_at | date:'shortTime' }}</td>
              <td style="font-size:0.78rem">{{ run.duration_secs ? run.duration_secs + 's' : '—' }}</td>
              <td>
                <button *ngIf="run.status==='running'" class="btn btn-danger btn-sm" (click)="abortRun(run,$event)">
                  <i class="bi bi-stop-fill"></i>
                </button>
              </td>
            </tr>
          </tbody>
        </table>
        <div *ngIf="runs.length===0" style="text-align:center;padding:2rem;color:#6c757d;font-size:0.85rem">
          No test runs. Go to Scenarios to start one.
        </div>
      </div>

      <!-- Events Panel -->
      <div class="mt-3" *ngIf="selectedRun">
        <div class="d-flex justify-content-between align-items-center mb-2">
          <h6 class="mb-0">Events — {{ selectedRun.scenario_name }}</h6>
          <button class="btn btn-outline btn-sm" (click)="loadEvents(selectedRun.id)"><i class="bi bi-arrow-clockwise"></i> Refresh</button>
        </div>
        <div class="events-panel">
          <div *ngFor="let ev of events" class="event-row">
            <span class="event-type" [class]="'event-type-'+ev.event_type">{{ ev.event_type?.toUpperCase() }}</span>
            <span style="color:#6c757d">{{ ev.event_time | date:'HH:mm:ss.SSS' }}</span>
            <span>{{ ev.source_ip }} → {{ ev.dest_ip }}</span>
            <span style="color:#6c757d">{{ ev.protocol }}</span>
          </div>
          <div *ngIf="events.length===0" style="text-align:center;padding:1rem;color:#6c757d;font-size:0.8rem">No events recorded</div>
        </div>
      </div>
    </div>
  `
})
export class RunsComponent implements OnInit, OnDestroy {
  private api = inject(ApiService);
  private toastr = inject(ToastrService);
  private wsSub?: Subscription;

  runs: any[] = [];
  selectedRun: any = null;
  events: any[] = [];

  get activeRunCount(): number { return this.runs.filter(r => r.status === 'running').length; }

  ngOnInit(): void {
    this.loadRuns();
    this.wsSub = this.api.events$.subscribe(ev => {
      if (['run_started','run_aborted','attack_completed'].includes(ev.type)) this.loadRuns();
    });
  }

  ngOnDestroy(): void { this.wsSub?.unsubscribe(); }

  loadRuns(): void {
    this.api.getRuns().subscribe({ next: d => this.runs = d.runs || [], error: () => {} });
  }

  selectRun(run: any): void {
    this.selectedRun = run;
    this.loadEvents(run.id);
  }

  loadEvents(runId: string): void {
    this.api.getRunEvents(runId).subscribe({ next: d => this.events = d.events || [], error: () => {} });
  }

  abortRun(run: any, event: Event): void {
    event.stopPropagation();
    this.api.abortRun(run.id).subscribe({
      next: () => { this.toastr.info('Run aborted'); this.loadRuns(); },
      error: () => this.toastr.error('Failed to abort run')
    });
  }
}

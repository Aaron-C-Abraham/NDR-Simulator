import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { ApiService } from '../../shared/services/api.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, RouterLink],
  styles: [`
    .metrics-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 1.25rem; margin-bottom: 1.5rem; }
    .metric-card { background:#fff; border-radius:12px; padding:1.25rem; box-shadow:0 2px 8px rgba(0,0,0,0.06); display:flex; align-items:center; gap:1rem; }
    .metric-icon { width:44px; height:44px; border-radius:8px; display:flex; align-items:center; justify-content:center; font-size:1.2rem; color:#fff; flex-shrink:0; }
    .metric-value { font-size:1.9rem; font-weight:800; line-height:1; }
    .metric-label { font-size:0.76rem; color:#6c757d; margin-top:0.2rem; }
    .section-row { display:grid; grid-template-columns:2fr 1fr; gap:1.25rem; }
    .card { background:#fff; border-radius:12px; box-shadow:0 2px 8px rgba(0,0,0,0.06); }
    .card-hdr { padding:1rem 1.25rem; border-bottom:1px solid #dee2e6; font-weight:600; font-size:0.9rem; display:flex; justify-content:space-between; align-items:center; }
    .card-body { padding:1.25rem; }
    .run-row { display:flex; align-items:center; gap:0.75rem; padding:0.65rem 0; border-bottom:1px solid #f1f3f5; }
    .run-row:last-child { border-bottom:none; }
    .run-name { font-size:0.85rem; font-weight:600; flex:1; }
    .run-ts { font-size:0.72rem; color:#6c757d; }
    .badge { padding:0.25rem 0.55rem; border-radius:4px; font-size:0.7rem; font-weight:600; }
    .bg-success { background:#27AE60; color:#fff; }
    .bg-warning { background:#F39C12; color:#fff; }
    .bg-info { background:#2ca8c7; color:#fff; }
    .bg-danger { background:#E74C3C; color:#fff; }
    .stat-item { display:flex; justify-content:space-between; padding:0.6rem 0; border-bottom:1px solid #f1f3f5; font-size:0.85rem; }
    .stat-item:last-child { border-bottom:none; }
    .stat-val { font-weight:700; color:#2c3e50; }
    @media (max-width:1200px) { .metrics-grid { grid-template-columns:repeat(2,1fr); } }
    @media (max-width:768px)  { .metrics-grid,.section-row { grid-template-columns:1fr; } }
  `],
  template: `
    <div class="animate-in">
      <div class="page-header">
        <h1 class="page-title"><i class="bi bi-grid-1x2-fill me-2" style="color:var(--accent-color)"></i>Dashboard</h1>
        <p class="page-subtitle">NDR detection performance at a glance</p>
      </div>

      <!-- Metric Cards -->
      <div class="metrics-grid mb-4">
        <div class="metric-card">
          <div class="metric-icon" style="background:linear-gradient(135deg,#2ca8c7,#186f98)"><i class="bi bi-play-circle-fill"></i></div>
          <div>
            <div class="metric-value">{{ stats?.total_runs ?? '—' }}</div>
            <div class="metric-label">Total Test Runs</div>
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-icon" style="background:linear-gradient(135deg,#27AE60,#1e8449)"><i class="bi bi-shield-check"></i></div>
          <div>
            <div class="metric-value">{{ detectionPct }}</div>
            <div class="metric-label">Avg Detection Rate</div>
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-icon" style="background:linear-gradient(135deg,#F39C12,#d68910)"><i class="bi bi-bell-fill"></i></div>
          <div>
            <div class="metric-value">{{ stats?.total_alerts ?? '—' }}</div>
            <div class="metric-label">Total NDR Alerts</div>
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-icon" style="background:linear-gradient(135deg,#8b5cf6,#6366f1)"><i class="bi bi-diagram-3-fill"></i></div>
          <div>
            <div class="metric-value">{{ stats?.device_count ?? '—' }}</div>
            <div class="metric-label">Simulated Devices</div>
          </div>
        </div>
      </div>

      <!-- Recent runs + Quick stats -->
      <div class="section-row">
        <div class="card">
          <div class="card-hdr">
            <span><i class="bi bi-clock-history me-2"></i>Recent Test Runs</span>
            <a routerLink="/runs" class="btn btn-outline btn-sm">View All</a>
          </div>
          <div class="card-body" style="padding:0">
            <div *ngFor="let run of recentRuns" class="run-row" style="padding:0.75rem 1.25rem">
              <div>
                <div class="run-name">{{ run.scenario_name }}</div>
                <div class="run-ts">{{ run.created_at | date:'medium' }}</div>
              </div>
              <span class="badge" [class]="statusClass(run.status)">{{ run.status }}</span>
            </div>
            <div *ngIf="recentRuns.length === 0" style="padding:2rem; text-align:center; color:#6c757d; font-size:0.85rem">
              No test runs yet. <a routerLink="/scenarios">Start a scenario</a>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-hdr"><span><i class="bi bi-info-circle me-2"></i>System Status</span></div>
          <div class="card-body">
            <div class="stat-item"><span>Active Runs</span><span class="stat-val">{{ stats?.active_runs ?? 0 }}</span></div>
            <div class="stat-item"><span>Runs Today</span><span class="stat-val">{{ stats?.runs_today ?? 0 }}</span></div>
            <div class="stat-item"><span>Top Scenario</span><span class="stat-val" style="font-size:0.78rem;text-align:right;max-width:140px">{{ stats?.top_scenario || '—' }}</span></div>
            <div class="stat-item"><span>Attack Modules</span><span class="stat-val">34</span></div>
            <div class="stat-item"><span>Syslog Devices</span><span class="stat-val">{{ topoSummary?.syslog_enabled ?? '—' }}</span></div>
            <div class="stat-item"><span>NetFlow Devices</span><span class="stat-val">{{ topoSummary?.netflow_enabled ?? '—' }}</span></div>
          </div>
        </div>
      </div>
    </div>
  `
})
export class DashboardComponent implements OnInit {
  private api = inject(ApiService);
  stats: any = null;
  recentRuns: any[] = [];
  topoSummary: any = null;

  get detectionPct(): string {
    if (!this.stats?.avg_detection_rate) return '—';
    return Math.round(this.stats.avg_detection_rate * 100) + '%';
  }

  ngOnInit(): void {
    this.api.getDashboard().subscribe({ next: d => this.stats = d, error: () => {} });
    this.api.getRuns().subscribe({ next: d => this.recentRuns = (d.runs || []).slice(0, 8), error: () => {} });
    this.api.getTopologySummary().subscribe({ next: d => this.topoSummary = d, error: () => {} });
  }

  statusClass(status: string): string {
    const map: Record<string, string> = { running: 'bg-info', completed: 'bg-success', pending: 'bg-warning', failed: 'bg-danger', aborted: 'bg-danger' };
    return map[status] ?? 'bg-secondary';
  }
}

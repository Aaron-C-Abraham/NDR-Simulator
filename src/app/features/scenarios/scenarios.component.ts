import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService } from '../../shared/services/api.service';
import { ToastrService } from 'ngx-toastr';

@Component({
  selector: 'app-scenarios',
  standalone: true,
  imports: [CommonModule],
  styles: [`
    .scenarios-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(340px,1fr)); gap:1.25rem; }
    .scenario-card { background:#fff; border-radius:12px; box-shadow:0 2px 8px rgba(0,0,0,0.06); overflow:hidden; transition:all 0.2s; }
    .scenario-card:hover { box-shadow:0 6px 20px rgba(0,0,0,0.1); }
    .scenario-card-hdr { padding:1rem 1.25rem; border-bottom:1px solid #f0f0f0; display:flex; align-items:center; gap:0.75rem; }
    .scenario-icon { width:36px; height:36px; border-radius:8px; display:flex; align-items:center; justify-content:center; color:#fff; font-size:1rem; flex-shrink:0; }
    .scenario-name { font-weight:700; font-size:0.9rem; }
    .scenario-body { padding:1rem 1.25rem; }
    .scenario-desc { font-size:0.8rem; color:#6c757d; margin-bottom:0.75rem; line-height:1.5; }
    .step-badge { display:inline-block; background:#f1f3f5; border-radius:6px; padding:0.2rem 0.5rem; font-size:0.72rem; font-weight:600; margin-right:0.3rem; margin-bottom:0.3rem; }
    .mitre-tag { display:inline-block; font-size:0.65rem; font-family:monospace; background:rgba(139,92,246,0.1); color:#8b5cf6; padding:0.15rem 0.4rem; border-radius:4px; margin-right:0.25rem; }
    .expected-tag { display:inline-block; font-size:0.65rem; background:rgba(39,174,96,0.1); color:#27AE60; padding:0.15rem 0.4rem; border-radius:4px; margin-right:0.2rem; margin-bottom:0.2rem; }
    .scenario-footer { padding:0.75rem 1.25rem; background:#fafafa; border-top:1px solid #f0f0f0; display:flex; justify-content:space-between; align-items:center; }
    .duration-pill { font-size:0.72rem; color:#6c757d; }
  `],
  template: `
    <div class="animate-in">
      <div class="page-header d-flex justify-content-between align-items-start">
        <div>
          <h1 class="page-title"><i class="bi bi-journal-code me-2" style="color:var(--accent-color)"></i>Attack Scenarios</h1>
          <p class="page-subtitle">Pre-built TTL scenarios — complete adversary kill chains</p>
        </div>
      </div>

      <div class="scenarios-grid">
        <div *ngFor="let sc of scenarios" class="scenario-card">
          <div class="scenario-card-hdr">
            <div class="scenario-icon" [style.background]="categoryGradient(sc.category)">
              <i class="bi" [class]="categoryIcon(sc.category)"></i>
            </div>
            <div>
              <div class="scenario-name">{{ sc.name }}</div>
              <small class="text-muted" style="font-size:0.72rem">{{ sc.steps?.length ?? 0 }} steps · {{ sc.category }}</small>
            </div>
          </div>
          <div class="scenario-body">
            <p class="scenario-desc">{{ sc.description }}</p>

            <div class="mb-2">
              <small class="text-muted fw-semibold" style="font-size:0.7rem">MITRE ATT&CK</small><br>
              <span *ngFor="let mid of sc.mitre_techniques" class="mitre-tag">{{ mid }}</span>
            </div>

            <div class="mb-2">
              <small class="text-muted fw-semibold" style="font-size:0.7rem">EXPECTED DETECTIONS</small><br>
              <span *ngFor="let exp of sc.expected_alerts" class="expected-tag">{{ exp }}</span>
            </div>

            <div>
              <small class="text-muted fw-semibold" style="font-size:0.7rem">STEPS</small><br>
              <span *ngFor="let step of sc.steps" class="step-badge">{{ step.name || step.attack_id }}</span>
            </div>
          </div>
          <div class="scenario-footer">
            <span class="duration-pill"><i class="bi bi-clock me-1"></i>{{ sc.duration_secs }}s</span>
            <button class="btn btn-primary btn-sm" (click)="runScenario(sc)">
              <i class="bi bi-play-fill"></i> Run
            </button>
          </div>
        </div>
      </div>

      <div *ngIf="scenarios.length === 0" style="text-align:center; padding:3rem; color:#6c757d">
        <i class="bi bi-journal-x" style="font-size:2rem"></i><br>No scenarios loaded
      </div>
    </div>
  `
})
export class ScenariosComponent implements OnInit {
  private api = inject(ApiService);
  private toastr = inject(ToastrService);
  scenarios: any[] = [];

  ngOnInit(): void {
    this.api.getScenarios().subscribe({ next: d => this.scenarios = d.scenarios || [], error: () => this.toastr.error('Failed to load scenarios') });
  }

  runScenario(sc: any): void {
    const req = { scenario_id: sc.id };
    this.api.startRun(req).subscribe({
      next: run => this.toastr.success(`Run started: ${run.id?.slice(0,8)}`),
      error: () => this.toastr.error('Failed to start run')
    });
  }

  categoryGradient(cat: string): string {
    const map: Record<string,string> = {
      beaconing: 'linear-gradient(135deg,#2ca8c7,#186f98)',
      dga: 'linear-gradient(135deg,#8b5cf6,#6366f1)',
      lateral_movement: 'linear-gradient(135deg,#10b981,#059669)',
      exfiltration: 'linear-gradient(135deg,#E74C3C,#c0392b)',
      ransomware: 'linear-gradient(135deg,#9B2335,#7a1c2a)',
      dns_tunnel: 'linear-gradient(135deg,#F39C12,#d68910)'
    };
    return map[cat] ?? 'linear-gradient(135deg,#2c3e50,#1a252f)';
  }

  categoryIcon(cat: string): string {
    const map: Record<string,string> = {
      beaconing:'bi-broadcast', dga:'bi-shuffle', lateral_movement:'bi-arrow-left-right',
      exfiltration:'bi-box-arrow-up-right', ransomware:'bi-lock-fill', dns_tunnel:'bi-ethernet'
    };
    return map[cat] ?? 'bi-shield-exclamation';
  }
}

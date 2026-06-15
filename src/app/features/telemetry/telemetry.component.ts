import { Component, OnInit, OnDestroy, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../shared/services/api.service';
import { Subscription, interval } from 'rxjs';

@Component({
  selector: 'app-telemetry',
  standalone: true,
  imports: [CommonModule, FormsModule],
  styles: [`
    .tab-nav { display:flex; gap:0; border-bottom:2px solid #dee2e6; margin-bottom:1.25rem; }
    .tab-btn { padding:0.6rem 1.25rem; font-size:0.85rem; font-weight:600; color:#6c757d; border:none; background:none; border-bottom:3px solid transparent; cursor:pointer; margin-bottom:-2px; transition:all 0.15s; }
    .tab-btn.active { color:#2ca8c7; border-bottom-color:#2ca8c7; }
    .tab-btn:hover:not(.active) { color:#2c3e50; }
    .filter-row { display:flex; gap:0.75rem; align-items:center; margin-bottom:1rem; flex-wrap:wrap; }
    .filter-input { padding:0.4rem 0.75rem; font-size:0.82rem; border:1px solid #dee2e6; border-radius:6px; min-width:160px; }
    .filter-select { padding:0.4rem 0.75rem; font-size:0.82rem; border:1px solid #dee2e6; border-radius:6px; }
    .table-wrap { overflow-x:auto; }
    table { width:100%; border-collapse:collapse; font-size:0.82rem; }
    th { background:#f8f9fa; padding:0.6rem 0.75rem; font-size:0.72rem; font-weight:600; text-transform:uppercase; letter-spacing:0.5px; color:#6c757d; border-bottom:2px solid #dee2e6; white-space:nowrap; }
    td { padding:0.55rem 0.75rem; border-bottom:1px solid #f1f3f5; vertical-align:middle; }
    tr:hover td { background:#f8f9fa; }
    .badge { padding:0.2rem 0.5rem; border-radius:4px; font-size:0.7rem; font-weight:600; }
    .sev-0,.sev-1,.sev-2 { background:#9B2335; color:#fff; }
    .sev-3 { background:#E74C3C; color:#fff; }
    .sev-4 { background:#F39C12; color:#fff; }
    .sev-5,.sev-6 { background:#2ca8c7; color:#fff; }
    .sev-7 { background:#6c757d; color:#fff; }
    .proto-tcp { background:rgba(44,168,199,0.12); color:#186f98; border-radius:4px; padding:0.15rem 0.4rem; font-size:0.72rem; font-weight:600; }
    .proto-udp { background:rgba(139,92,246,0.12); color:#6d28d9; border-radius:4px; padding:0.15rem 0.4rem; font-size:0.72rem; font-weight:600; }
    .proto-icmp { background:rgba(39,174,96,0.12); color:#1e8449; border-radius:4px; padding:0.15rem 0.4rem; font-size:0.72rem; font-weight:600; }
    .flow-type { background:#e8f4f8; color:#186f98; border-radius:4px; padding:0.15rem 0.4rem; font-size:0.7rem; font-weight:600; text-transform:uppercase; }
    .pcap-card { background:#fff; border:1px solid #dee2e6; border-radius:8px; padding:1rem 1.25rem; display:flex; align-items:center; gap:1rem; margin-bottom:0.75rem; }
    .pcap-icon { width:40px; height:40px; background:linear-gradient(135deg,#2ca8c7,#186f98); border-radius:8px; display:flex; align-items:center; justify-content:center; color:#fff; font-size:1rem; flex-shrink:0; }
    .pcap-name { font-weight:600; font-size:0.85rem; }
    .pcap-meta { font-size:0.75rem; color:#6c757d; }
    .metric-row { display:grid; grid-template-columns:repeat(3,1fr); gap:1rem; margin-bottom:1.25rem; }
    .metric-card { background:#fff; border-radius:10px; padding:1rem 1.25rem; box-shadow:0 2px 8px rgba(0,0,0,0.06); display:flex; align-items:center; gap:0.75rem; }
    .metric-icon { width:40px; height:40px; border-radius:8px; display:flex; align-items:center; justify-content:center; font-size:1rem; color:#fff; flex-shrink:0; }
    .metric-val { font-size:1.6rem; font-weight:800; line-height:1; }
    .metric-lbl { font-size:0.75rem; color:#6c757d; }
    .auto-refresh-chip { display:flex; align-items:center; gap:0.4rem; font-size:0.78rem; font-weight:500; }
    .live-dot { width:6px; height:6px; border-radius:50%; background:#27AE60; animation:pulse-dot 1.5s infinite; flex-shrink:0; }
    @keyframes pulse-dot { 0%,100%{opacity:1}50%{opacity:0.3} }
    .empty-state { text-align:center; padding:3rem 1rem; color:#6c757d; font-size:0.85rem; }
    .mono { font-family:'Courier New',monospace; font-size:0.75rem; }
    @media(max-width:768px){ .metric-row{ grid-template-columns:1fr; } }
  `],
  template: `
    <div class="animate-in">
      <div class="page-header">
        <h1 class="page-title"><i class="bi bi-reception-4 me-2" style="color:var(--accent-color)"></i>Live Telemetry</h1>
        <p class="page-subtitle">Real-time syslog, network flows and PCAP captures</p>
      </div>

      <!-- Metric cards -->
      <div class="metric-row">
        <div class="metric-card">
          <div class="metric-icon" style="background:linear-gradient(135deg,#2ca8c7,#186f98)"><i class="bi bi-terminal-fill"></i></div>
          <div><div class="metric-val">{{ stats?.total_syslog ?? 0 | number }}</div><div class="metric-lbl">Syslog Messages</div></div>
        </div>
        <div class="metric-card">
          <div class="metric-icon" style="background:linear-gradient(135deg,#8b5cf6,#6366f1)"><i class="bi bi-arrow-left-right"></i></div>
          <div><div class="metric-val">{{ stats?.total_flows ?? 0 | number }}</div><div class="metric-lbl">Flow Records</div></div>
        </div>
        <div class="metric-card">
          <div class="metric-icon" style="background:linear-gradient(135deg,#27AE60,#1e8449)"><i class="bi bi-file-earmark-binary-fill"></i></div>
          <div><div class="metric-val">{{ stats?.total_pcap ?? 0 }}</div><div class="metric-lbl">PCAP Files ({{ pcapSizeKB }} KB)</div></div>
        </div>
      </div>

      <!-- Controls -->
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
        <div class="tab-nav" style="border:none; margin:0;">
          <button class="tab-btn" [class.active]="activeTab==='syslog'" (click)="setTab('syslog')"><i class="bi bi-terminal me-1"></i>Syslog</button>
          <button class="tab-btn" [class.active]="activeTab==='flows'" (click)="setTab('flows')"><i class="bi bi-arrow-left-right me-1"></i>NetFlow / IPFIX / sFlow</button>
          <button class="tab-btn" [class.active]="activeTab==='pcap'" (click)="setTab('pcap')"><i class="bi bi-file-earmark-binary me-1"></i>PCAP Files</button>
        </div>
        <div style="display:flex; gap:0.75rem; align-items:center;">
          <label class="auto-refresh-chip">
            <input type="checkbox" [(ngModel)]="autoRefresh" (change)="toggleAutoRefresh()" style="margin-right:4px;">
            <span class="live-dot" *ngIf="autoRefresh"></span>
            Auto-refresh
          </label>
          <button class="btn btn-sm btn-outline" (click)="refresh()"><i class="bi bi-arrow-clockwise me-1"></i>Refresh</button>
        </div>
      </div>

      <!-- Syslog Tab -->
      <div *ngIf="activeTab==='syslog'" class="card">
        <div class="card-hdr" style="padding:0.75rem 1.25rem; border-bottom:1px solid #dee2e6;">
          <div class="filter-row" style="margin:0;">
            <input class="filter-input" placeholder="Filter by device IP..." [(ngModel)]="syslogDeviceFilter" (ngModelChange)="loadSyslog()">
            <select class="filter-select" [(ngModel)]="syslogFormatFilter" (ngModelChange)="loadSyslog()">
              <option value="">All formats</option>
              <option value="rfc3164">RFC 3164</option>
              <option value="rfc5424">RFC 5424</option>
              <option value="cef">CEF (Fortinet)</option>
              <option value="leef">LEEF (Microsoft)</option>
            </select>
            <select class="filter-select" [(ngModel)]="syslogLimit" (ngModelChange)="loadSyslog()">
              <option value="50">50 rows</option>
              <option value="200">200 rows</option>
              <option value="500">500 rows</option>
            </select>
            <span style="font-size:0.78rem; color:#6c757d; margin-left:auto;">{{ syslogMessages.length }} messages</span>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th><th>Device</th><th>IP</th><th>Format</th><th>Sev</th><th>Message</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let msg of syslogMessages">
                <td class="mono" style="white-space:nowrap; color:#6c757d;">{{ msg.created_at | date:'HH:mm:ss' }}</td>
                <td>{{ msg.device_name }}</td>
                <td class="mono">{{ msg.device_ip }}</td>
                <td><span class="badge" style="background:#e8f4f8;color:#186f98;">{{ msg.format }}</span></td>
                <td><span class="badge" [class]="'sev-' + msg.severity">{{ severityName(msg.severity) }}</span></td>
                <td class="mono" style="max-width:500px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" [title]="msg.message">{{ msg.message }}</td>
              </tr>
              <tr *ngIf="syslogMessages.length === 0">
                <td colspan="6" class="empty-state">No syslog messages yet. Run an attack scenario to generate telemetry.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Flows Tab -->
      <div *ngIf="activeTab==='flows'" class="card">
        <div class="card-hdr" style="padding:0.75rem 1.25rem; border-bottom:1px solid #dee2e6;">
          <div class="filter-row" style="margin:0;">
            <input class="filter-input" placeholder="Source IP filter..." [(ngModel)]="flowSrcFilter" (ngModelChange)="loadFlows()">
            <input class="filter-input" placeholder="Dest IP filter..." [(ngModel)]="flowDstFilter" (ngModelChange)="loadFlows()">
            <select class="filter-select" [(ngModel)]="flowTypeFilter" (ngModelChange)="loadFlows()">
              <option value="">All types</option>
              <option value="netflow9">NetFlow v9</option>
              <option value="ipfix">IPFIX</option>
              <option value="sflow">sFlow</option>
            </select>
            <select class="filter-select" [(ngModel)]="flowLimit" (ngModelChange)="loadFlows()">
              <option value="50">50 rows</option>
              <option value="200">200 rows</option>
              <option value="500">500 rows</option>
            </select>
            <span style="font-size:0.78rem; color:#6c757d; margin-left:auto;">{{ flowRecords.length }} flows</span>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th><th>Src IP</th><th>Src Port</th><th>Dst IP</th><th>Dst Port</th><th>Proto</th><th>Bytes</th><th>Pkts</th><th>Type</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let flow of flowRecords">
                <td class="mono" style="white-space:nowrap; color:#6c757d;">{{ flow.created_at | date:'HH:mm:ss' }}</td>
                <td class="mono">{{ flow.src_ip }}</td>
                <td class="mono">{{ flow.src_port }}</td>
                <td class="mono">{{ flow.dst_ip }}</td>
                <td class="mono">{{ flow.dst_port }}</td>
                <td><span [class]="protoClass(flow.protocol)">{{ protoName(flow.protocol) }}</span></td>
                <td class="mono">{{ formatBytes(flow.bytes) }}</td>
                <td class="mono">{{ flow.packets }}</td>
                <td><span class="flow-type">{{ flow.flow_type }}</span></td>
              </tr>
              <tr *ngIf="flowRecords.length === 0">
                <td colspan="9" class="empty-state">No flow records yet. Run an attack scenario to generate flow telemetry.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- PCAP Tab -->
      <div *ngIf="activeTab==='pcap'">
        <div *ngIf="pcapFiles.length === 0" class="card">
          <div class="empty-state"><i class="bi bi-file-earmark-binary" style="font-size:2rem; display:block; margin-bottom:0.5rem; color:#dee2e6;"></i>No PCAP files yet.<br><small>PCAP captures are generated when attack scenarios run.</small></div>
        </div>
        <div *ngFor="let file of pcapFiles" class="pcap-card">
          <div class="pcap-icon"><i class="bi bi-file-earmark-binary-fill"></i></div>
          <div style="flex:1;">
            <div class="pcap-name">{{ file.filename }}</div>
            <div class="pcap-meta">{{ (file.size_bytes / 1024).toFixed(1) }} KB &nbsp;·&nbsp; {{ file.created_at | date:'medium' }}</div>
          </div>
          <a [href]="file.url" class="btn btn-sm btn-outline" download><i class="bi bi-download me-1"></i>Download</a>
        </div>
      </div>
    </div>
  `
})
export class TelemetryComponent implements OnInit, OnDestroy {
  private api = inject(ApiService);
  private subs = new Subscription();
  private refreshTimer: any;

  activeTab = 'syslog';
  autoRefresh = true;

  stats: any = null;
  syslogMessages: any[] = [];
  flowRecords: any[] = [];
  pcapFiles: any[] = [];

  syslogDeviceFilter = '';
  syslogFormatFilter = '';
  syslogLimit = '200';

  flowSrcFilter = '';
  flowDstFilter = '';
  flowTypeFilter = '';
  flowLimit = '200';

  get pcapSizeKB(): string {
    const total = (this.stats?.pcap_size_bytes ?? 0) / 1024;
    return total.toFixed(1);
  }

  ngOnInit(): void {
    this.refresh();
    this.subs.add(this.api.events$.subscribe(evt => {
      if (!evt) return;
      if (evt.type === 'syslog_received') {
        const msg = { ...evt.payload, created_at: evt.payload.created_at ?? new Date().toISOString() };
        this.syslogMessages = [msg, ...this.syslogMessages].slice(0, +this.syslogLimit);
        if (this.stats) this.stats = { ...this.stats, total_syslog: (this.stats.total_syslog ?? 0) + 1 };
      } else if (evt.type === 'flow_received') {
        const flow = { ...evt.payload, created_at: evt.payload.created_at ?? new Date().toISOString() };
        this.flowRecords = [flow, ...this.flowRecords].slice(0, +this.flowLimit);
        if (this.stats) this.stats = { ...this.stats, total_flows: (this.stats.total_flows ?? 0) + 1 };
      } else if (evt.type === 'attack_completed') {
        this.loadStats();
      } else if (['run_started', 'run_completed'].includes(evt.type)) {
        setTimeout(() => this.refresh(), 800);
      }
    }));
    if (this.autoRefresh) this.startTimer();
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
    clearInterval(this.refreshTimer);
  }

  setTab(tab: string): void {
    this.activeTab = tab;
    this.refresh();
  }

  refresh(): void {
    this.loadStats();
    if (this.activeTab === 'syslog') this.loadSyslog();
    else if (this.activeTab === 'flows') this.loadFlows();
    else this.loadPCAP();
  }

  loadStats(): void {
    this.api.getTelemetryStats().subscribe({ next: d => this.stats = d, error: () => {} });
  }

  loadSyslog(): void {
    const params: any = { limit: this.syslogLimit };
    if (this.syslogDeviceFilter) params['device'] = this.syslogDeviceFilter;
    if (this.syslogFormatFilter) params['format'] = this.syslogFormatFilter;
    this.api.getSyslogTelemetry(params).subscribe({ next: d => this.syslogMessages = d.messages ?? [], error: () => {} });
  }

  loadFlows(): void {
    const params: any = { limit: this.flowLimit };
    if (this.flowSrcFilter) params['src'] = this.flowSrcFilter;
    if (this.flowDstFilter) params['dst'] = this.flowDstFilter;
    if (this.flowTypeFilter) params['type'] = this.flowTypeFilter;
    this.api.getFlowTelemetry(params).subscribe({ next: d => this.flowRecords = d.flows ?? [], error: () => {} });
  }

  loadPCAP(): void {
    this.api.getPCAPFiles().subscribe({ next: d => this.pcapFiles = d.files ?? [], error: () => {} });
  }

  toggleAutoRefresh(): void {
    if (this.autoRefresh) this.startTimer();
    else clearInterval(this.refreshTimer);
  }

  private startTimer(): void {
    clearInterval(this.refreshTimer);
    this.refreshTimer = setInterval(() => this.refresh(), 5000);
  }

  severityName(sev: number): string {
    const names: Record<number, string> = { 0:'emerg', 1:'alert', 2:'crit', 3:'err', 4:'warn', 5:'notice', 6:'info', 7:'debug' };
    return names[sev] ?? String(sev);
  }

  protoName(proto: number): string {
    const names: Record<number, string> = { 6: 'TCP', 17: 'UDP', 1: 'ICMP' };
    return names[proto] ?? String(proto);
  }

  protoClass(proto: number): string {
    if (proto === 6) return 'proto-tcp';
    if (proto === 17) return 'proto-udp';
    return 'proto-icmp';
  }

  formatBytes(bytes: number): string {
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return bytes + ' B';
  }
}

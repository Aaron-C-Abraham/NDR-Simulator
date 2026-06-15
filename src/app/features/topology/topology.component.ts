import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService } from '../../shared/services/api.service';

const ZONE_ORDER = ['external', 'dmz', 'management', 'internal'];

const ZONE_META: Record<string, { label: string; fill: string; stroke: string; labelColor: string }> = {
  external:   { label: 'EXTERNAL', fill: '#fef2f2', stroke: '#fca5a5', labelColor: '#dc2626' },
  dmz:        { label: 'DMZ',      fill: '#fffbeb', stroke: '#fcd34d', labelColor: '#d97706' },
  management: { label: 'MANAGEMENT', fill: '#eff6ff', stroke: '#93c5fd', labelColor: '#2563eb' },
  internal:   { label: 'INTERNAL', fill: '#f0fdf4', stroke: '#86efac', labelColor: '#16a34a' },
};

const TYPE_ORDER: Record<string, number> = {
  router: 0, firewall: 1, switch: 2, server: 3, workstation: 4, wireless_ap: 5, iot: 6,
};

const TYPE_COLORS: Record<string, { fill: string; dark: string }> = {
  router:      { fill: '#334155', dark: '#1e293b' },
  firewall:    { fill: '#ef4444', dark: '#b91c1c' },
  switch:      { fill: '#6366f1', dark: '#4338ca' },
  server:      { fill: '#8b5cf6', dark: '#6d28d9' },
  workstation: { fill: '#10b981', dark: '#059669' },
  wireless_ap: { fill: '#f59e0b', dark: '#d97706' },
  iot:         { fill: '#6b7280', dark: '#4b5563' },
};

const TYPE_ABBREV: Record<string, string> = {
  router: 'RT', firewall: 'FW', switch: 'SW', server: 'SV',
  workstation: 'WS', wireless_ap: 'AP', iot: 'IoT',
};

const LINK_COLORS: Record<string, string> = {
  'WAN':           '#ef4444',
  'DMZ trunk':     '#f59e0b',
  'Internal trunk':'#6366f1',
  'VPN':           '#10b981',
  'eth':           '#94a3b8',
};

const NODE_R        = 26;
const H_SPACING     = 150;
const V_SPACING     = 120;
const ZONE_TOP_PAD  = 44;
const ZONE_BOT_PAD  = 36;
const MAX_PER_ROW   = 7;
const ZONE_GAP      = 24;
const CANVAS_W      = 1300;

@Component({
  selector: 'app-topology',
  standalone: true,
  imports: [CommonModule],
  styles: [`
    :host { display:block; }
    .topo-page { display:flex; flex-direction:column; height:100%; }
    .topo-controls { display:flex; align-items:center; gap:0.75rem; flex-wrap:wrap; margin-bottom:1rem; }
    .filter-btn { padding:0.3rem 0.85rem; border-radius:9999px; font-size:0.78rem; font-weight:600; border:1.5px solid #dee2e6; background:#fff; cursor:pointer; transition:all 0.15s; }
    .filter-btn.active { border-color:#2ca8c7; color:#2ca8c7; background:rgba(44,168,199,0.07); }
    .summary-pills { display:flex; gap:0.75rem; flex-wrap:wrap; }
    .sum-pill { background:#fff; border-radius:8px; padding:0.4rem 0.85rem; box-shadow:0 2px 6px rgba(0,0,0,0.06); font-size:0.78rem; display:flex; align-items:center; gap:0.4rem; }
    .sum-val { font-weight:800; font-size:1rem; color:#2c3e50; }

    .topo-wrap { display:flex; gap:1.25rem; align-items:flex-start; }
    .svg-container { flex:1; background:#fff; border-radius:12px; box-shadow:0 2px 8px rgba(0,0,0,0.06); overflow-x:auto; overflow-y:auto; position:relative; min-height:500px; max-height:calc(100vh - 240px); cursor:default; }
    svg { display:block; }

    /* Node hover/selected */
    .node-group { cursor:pointer; }
    .node-group:hover .node-circle { filter:brightness(1.1); }
    .node-circle { transition:all 0.15s; }

    /* Detail panel */
    .detail-panel { width:290px; flex-shrink:0; background:#fff; border-radius:12px; box-shadow:0 2px 8px rgba(0,0,0,0.06); overflow:hidden; }
    .dp-header { padding:1rem 1.25rem; color:#fff; }
    .dp-title { font-weight:700; font-size:0.95rem; }
    .dp-ip { font-family:monospace; font-size:0.82rem; opacity:0.85; margin-top:0.2rem; }
    .dp-body { padding:1rem 1.25rem; }
    .dp-row { display:flex; justify-content:space-between; padding:0.45rem 0; border-bottom:1px solid #f1f3f5; font-size:0.82rem; }
    .dp-row:last-child { border-bottom:none; }
    .dp-label { color:#6c757d; }
    .dp-val { font-weight:600; color:#2c3e50; text-align:right; }
    .tpill { font-size:0.65rem; font-weight:600; padding:0.15rem 0.45rem; border-radius:4px; margin-left:3px; }
    .empty-panel { display:flex; flex-direction:column; align-items:center; justify-content:center; height:220px; color:#94a3b8; font-size:0.82rem; text-align:center; padding:1rem; }

    /* Tooltip */
    .topo-tooltip { position:absolute; background:rgba(30,41,59,0.95); color:#fff; border-radius:8px; padding:0.6rem 0.9rem; font-size:0.76rem; pointer-events:none; white-space:nowrap; z-index:100; box-shadow:0 4px 16px rgba(0,0,0,0.25); }
    .tt-name { font-weight:700; font-size:0.82rem; margin-bottom:0.3rem; }
    .tt-row { display:flex; gap:0.5rem; opacity:0.85; }

    /* Legend */
    .legend { display:flex; gap:1.5rem; flex-wrap:wrap; margin-top:0.75rem; font-size:0.75rem; }
    .legend-item { display:flex; align-items:center; gap:0.4rem; }
    .legend-dot { width:10px; height:10px; border-radius:50%; }
    .legend-line { width:24px; height:3px; border-radius:2px; }
  `],
  template: `
    <div class="animate-in topo-page">
      <div class="page-header d-flex justify-content-between align-items-start">
        <div>
          <h1 class="page-title"><i class="bi bi-diagram-3-fill me-2" style="color:var(--accent-color)"></i>Network Topology</h1>
          <p class="page-subtitle">{{ nodes.length }} devices · click a node to inspect · scroll to explore</p>
        </div>
      </div>

      <!-- Controls row -->
      <div class="topo-controls mb-3">
        <div class="summary-pills">
          <div class="sum-pill"><span class="sum-val">{{ summary?.total_devices ?? nodes.length }}</span> Devices</div>
          <div class="sum-pill"><span class="sum-val" style="color:#2ca8c7">{{ summary?.syslog_enabled ?? 0 }}</span> Syslog</div>
          <div class="sum-pill"><span class="sum-val" style="color:#6366f1">{{ summary?.netflow_enabled ?? 0 }}</span> NetFlow</div>
          <div class="sum-pill"><span class="sum-val" style="color:#8b5cf6">{{ summary?.sflow_enabled ?? 0 }}</span> sFlow</div>
        </div>
        <div style="flex:1"></div>
        <button class="filter-btn" [class.active]="zoneFilter===''" (click)="zoneFilter=''">All Zones</button>
        <button class="filter-btn" [class.active]="zoneFilter==='external'" (click)="zoneFilter='external'" style="border-color:#fca5a5; color:#dc2626" [class.active]="zoneFilter==='external'">External</button>
        <button class="filter-btn" [class.active]="zoneFilter==='dmz'" (click)="zoneFilter='dmz'" style="border-color:#fcd34d; color:#d97706" [class.active]="zoneFilter==='dmz'">DMZ</button>
        <button class="filter-btn" [class.active]="zoneFilter==='internal'" (click)="zoneFilter='internal'" style="border-color:#86efac; color:#16a34a" [class.active]="zoneFilter==='internal'">Internal</button>
      </div>

      <div class="topo-wrap">
        <!-- SVG Canvas -->
        <div class="svg-container" (mousemove)="onContainerMouseMove($event)" (mouseleave)="hoveredNode=null">
          <svg [attr.viewBox]="'0 0 ' + svgW + ' ' + svgH"
               [attr.width]="svgW" [attr.height]="svgH"
               xmlns="http://www.w3.org/2000/svg">
            <defs>
              <filter id="node-shadow" x="-30%" y="-30%" width="160%" height="160%">
                <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="rgba(0,0,0,0.25)"/>
              </filter>
              <filter id="node-selected" x="-40%" y="-40%" width="180%" height="180%">
                <feDropShadow dx="0" dy="0" stdDeviation="8" flood-color="rgba(44,168,199,0.7)"/>
              </filter>
              <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                <path d="M0,0 L0,6 L6,3 z" fill="#94a3b8" opacity="0.6"/>
              </marker>
            </defs>

            <!-- Zone bands -->
            <g *ngFor="let band of zoneBands" [attr.opacity]="zoneFilter && zoneFilter !== band.zone ? 0.35 : 1">
              <rect [attr.x]="12" [attr.y]="band.y" [attr.width]="svgW - 24" [attr.height]="band.height"
                    [attr.fill]="band.fill" [attr.stroke]="band.stroke" stroke-width="1.5" rx="12"/>
              <rect [attr.x]="20" [attr.y]="band.y + 10" width="4" [attr.height]="18"
                    [attr.fill]="band.stroke" rx="2"/>
              <text [attr.x]="32" [attr.y]="band.y + 23" font-size="9.5" font-weight="700"
                    [attr.fill]="band.labelColor" letter-spacing="1.2" font-family="Montserrat, sans-serif">{{ band.label }}</text>
            </g>

            <!-- Edges -->
            <g *ngFor="let edge of edgePaths">
              <path *ngIf="isEdgeVisible(edge)"
                    [attr.d]="edge.d"
                    [attr.stroke]="edge.color"
                    stroke-width="1.8"
                    fill="none"
                    stroke-linecap="round"
                    [attr.opacity]="zoneFilter ? 0.4 : 0.55"
                    [attr.stroke-dasharray]="edge.label === 'VPN' ? '6,4' : 'none'"/>
            </g>

            <!-- Edge labels (only for non-eth links) -->
            <g *ngFor="let edge of edgePaths">
              <text *ngIf="edge.label !== 'eth' && !zoneFilter && edge.midX"
                    [attr.x]="edge.midX" [attr.y]="edge.midY - 5"
                    text-anchor="middle" font-size="8.5" font-weight="600"
                    [attr.fill]="edge.color" opacity="0.85"
                    font-family="Montserrat, sans-serif">{{ edge.label }}</text>
            </g>

            <!-- Nodes -->
            <g *ngFor="let node of visibleNodes"
               class="node-group"
               [attr.transform]="nodeTransform(node.name)"
               [attr.opacity]="zoneFilter && zoneFilter !== node.network_zone ? 0.2 : 1"
               (mouseenter)="hoveredNode = node"
               (mouseleave)="hoveredNode = null"
               (click)="onClickNode(node)">

              <!-- Outer glow ring for selected -->
              <circle *ngIf="selectedNode?.id === node.id"
                      r="34" fill="none" stroke="#2ca8c7" stroke-width="2.5" opacity="0.6"
                      style="animation: pulse-ring 2s ease-in-out infinite"/>

              <!-- Node circle with gradient-like 2-tone fill -->
              <circle class="node-circle" [attr.r]="NODE_R"
                      [attr.fill]="nodeColor(node.device_type)"
                      [attr.filter]="selectedNode?.id === node.id ? 'url(#node-selected)' : 'url(#node-shadow)'"/>

              <!-- Inner highlight arc -->
              <circle [attr.r]="NODE_R - 8" fill="none" stroke="rgba(255,255,255,0.18)" stroke-width="6" [attr.cy]="-6"/>

              <!-- Type abbreviation -->
              <text x="0" y="5" text-anchor="middle" dominant-baseline="middle"
                    fill="white" font-size="10" font-weight="700"
                    font-family="Montserrat, sans-serif" letter-spacing="0.5">{{ typeAbbrev(node.device_type) }}</text>

              <!-- Device name -->
              <text x="0" [attr.y]="NODE_R + 16" text-anchor="middle"
                    fill="#1e293b" font-size="9" font-weight="600"
                    font-family="Montserrat, sans-serif">{{ node.name }}</text>

              <!-- IP address -->
              <text x="0" [attr.y]="NODE_R + 28" text-anchor="middle"
                    fill="#64748b" font-size="8" font-family="'Courier New', monospace">{{ node.ip_address }}</text>

              <!-- Telemetry indicator dots (bottom of circle) -->
              <g [attr.transform]="'translate(0,' + (NODE_R - 6) + ')'">
                <circle *ngIf="node.telemetry?.syslog"  cx="-9" cy="0" r="3.5" fill="#2ca8c7"/>
                <circle *ngIf="node.telemetry?.netflow" cx="-3" cy="0" r="3.5" fill="#6366f1"/>
                <circle *ngIf="node.telemetry?.sflow"   cx="3"  cy="0" r="3.5" fill="#8b5cf6"/>
                <circle *ngIf="node.telemetry?.pcap"    cx="9"  cy="0" r="3.5" fill="#10b981"/>
              </g>

              <!-- Attacker badge -->
              <text *ngIf="isAttacker(node)" x="0" y="-22" text-anchor="middle"
                    font-size="14">⚠</text>
            </g>
          </svg>

          <!-- Floating tooltip -->
          <div class="topo-tooltip" *ngIf="hoveredNode && !selectedNode"
               [style.left.px]="tooltipX + 12" [style.top.px]="tooltipY - 40">
            <div class="tt-name">{{ hoveredNode.name }}</div>
            <div class="tt-row"><span>{{ hoveredNode.ip_address }}</span><span>·</span><span>{{ hoveredNode.vendor }}</span></div>
            <div class="tt-row" style="margin-top:3px; opacity:0.7;">{{ hoveredNode.network_zone }} · {{ hoveredNode.device_type }}</div>
          </div>
        </div>

        <!-- Detail Panel -->
        <div class="detail-panel">
          <div *ngIf="!selectedNode" class="empty-panel">
            <i class="bi bi-cursor-fill" style="font-size:2rem; margin-bottom:0.75rem; color:#cbd5e1;"></i>
            Click a device node<br>to inspect its details
          </div>
          <div *ngIf="selectedNode">
            <div class="dp-header" [style.background]="nodeColor(selectedNode.device_type)">
              <div style="font-size:0.72rem; opacity:0.75; text-transform:uppercase; letter-spacing:1px; margin-bottom:0.25rem;">{{ selectedNode.device_type }}</div>
              <div class="dp-title">{{ selectedNode.name }}</div>
              <div class="dp-ip">{{ selectedNode.ip_address }}</div>
            </div>
            <div class="dp-body">
              <div class="dp-row"><span class="dp-label">Zone</span><span class="dp-val">{{ selectedNode.network_zone }}</span></div>
              <div class="dp-row"><span class="dp-label">Vendor</span><span class="dp-val">{{ selectedNode.vendor }}</span></div>
              <div class="dp-row"><span class="dp-label">OS</span><span class="dp-val">{{ selectedNode.os_type }}</span></div>
              <div class="dp-row"><span class="dp-label">MAC</span><span class="dp-val" style="font-family:monospace; font-size:0.75rem;">{{ selectedNode.mac_address }}</span></div>
              <div class="dp-row"><span class="dp-label">Status</span>
                <span class="dp-val" [style.color]="selectedNode.status === 'active' ? '#10b981' : '#ef4444'">{{ selectedNode.status }}</span>
              </div>
              <div class="dp-row">
                <span class="dp-label">Telemetry</span>
                <span>
                  <span *ngIf="selectedNode.telemetry?.syslog" class="tpill" style="background:rgba(44,168,199,0.12);color:#2ca8c7;">Syslog</span>
                  <span *ngIf="selectedNode.telemetry?.netflow" class="tpill" style="background:rgba(99,102,241,0.12);color:#6366f1;">NetFlow</span>
                  <span *ngIf="selectedNode.telemetry?.sflow" class="tpill" style="background:rgba(139,92,246,0.12);color:#8b5cf6;">sFlow</span>
                  <span *ngIf="selectedNode.telemetry?.pcap" class="tpill" style="background:rgba(16,185,129,0.12);color:#10b981;">PCAP</span>
                  <span *ngIf="!selectedNode.telemetry?.syslog && !selectedNode.telemetry?.netflow && !selectedNode.telemetry?.sflow && !selectedNode.telemetry?.pcap" style="color:#94a3b8; font-size:0.78rem;">none</span>
                </span>
              </div>
              <div class="dp-row" style="flex-direction:column; gap:0.4rem;">
                <span class="dp-label">Connections</span>
                <div style="margin-top:0.25rem;">
                  <div *ngFor="let peer of getPeers(selectedNode.name)" style="font-size:0.78rem; padding:0.2rem 0; color:#475569;">
                    <span style="color:#94a3b8; font-size:0.7rem; font-family:monospace;">→</span>
                    {{ peer.name }} <span style="color:#94a3b8; font-size:0.7rem;">({{ peer.link }})</span>
                  </div>
                  <span *ngIf="getPeers(selectedNode.name).length === 0" style="font-size:0.78rem; color:#94a3b8;">No connections</span>
                </div>
              </div>
              <button class="btn btn-sm btn-outline mt-2 w-100" (click)="selectedNode = null">
                <i class="bi bi-x me-1"></i>Close
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Legend -->
      <div class="legend mt-3">
        <span style="font-size:0.72rem; font-weight:600; color:#94a3b8; text-transform:uppercase; letter-spacing:0.5px;">Node types:</span>
        <div *ngFor="let lt of legendTypes" class="legend-item">
          <div class="legend-dot" [style.background]="lt.color"></div>
          <span style="color:#475569;">{{ lt.label }}</span>
        </div>
        <span style="font-size:0.72rem; font-weight:600; color:#94a3b8; text-transform:uppercase; letter-spacing:0.5px; margin-left:1rem;">Links:</span>
        <div *ngFor="let ll of legendLinks" class="legend-item">
          <div class="legend-line" [style.background]="ll.color"></div>
          <span style="color:#475569;">{{ ll.label }}</span>
        </div>
        <div class="legend-item">
          <div class="legend-dot" style="background:#2ca8c7"></div><span style="color:#475569;">Syslog</span>
          <div class="legend-dot" style="background:#6366f1; margin-left:4px"></div><span style="color:#475569;">NetFlow</span>
          <div class="legend-dot" style="background:#8b5cf6; margin-left:4px"></div><span style="color:#475569;">sFlow</span>
          <div class="legend-dot" style="background:#10b981; margin-left:4px"></div><span style="color:#475569;">PCAP</span>
          <span style="color:#94a3b8; font-size:0.7rem;">(telemetry dots)</span>
        </div>
      </div>
    </div>
  `
})
export class TopologyComponent implements OnInit {
  private api = inject(ApiService);

  nodes: any[] = [];
  edges: any[] = [];
  summary: any = null;
  zoneFilter = '';

  zoneBands: { zone: string; y: number; height: number; label: string; fill: string; stroke: string; labelColor: string }[] = [];
  positions = new Map<string, { x: number; y: number }>();
  edgePaths: { d: string; label: string; color: string; sourceName: string; targetName: string; midX: number; midY: number }[] = [];

  svgW = CANVAS_W;
  svgH = 600;
  NODE_R = NODE_R;

  hoveredNode: any = null;
  selectedNode: any = null;
  tooltipX = 0;
  tooltipY = 0;

  readonly legendTypes = [
    { label: 'Router',      color: '#334155' },
    { label: 'Firewall',    color: '#ef4444' },
    { label: 'Switch',      color: '#6366f1' },
    { label: 'Server',      color: '#8b5cf6' },
    { label: 'Workstation', color: '#10b981' },
    { label: 'Wireless AP', color: '#f59e0b' },
    { label: 'IoT',         color: '#6b7280' },
  ];
  readonly legendLinks = [
    { label: 'WAN',      color: '#ef4444' },
    { label: 'DMZ trunk',color: '#f59e0b' },
    { label: 'Int trunk', color: '#6366f1' },
    { label: 'VPN',      color: '#10b981' },
    { label: 'Ethernet', color: '#94a3b8' },
  ];

  ngOnInit(): void {
    Promise.all([
      this.api.getTopologyGraph().toPromise(),
      this.api.getTopologySummary().toPromise(),
    ]).then(([graph, summary]: any[]) => {
      this.nodes = graph?.nodes ?? [];
      this.edges = graph?.edges ?? [];
      this.summary = summary;
      this.computeLayout();
    });
  }

  computeLayout(): void {
    const zoneMap = new Map<string, any[]>();
    for (const node of this.nodes) {
      const zone = node.network_zone || 'internal';
      if (!zoneMap.has(zone)) zoneMap.set(zone, []);
      zoneMap.get(zone)!.push(node);
    }

    for (const devs of zoneMap.values()) {
      devs.sort((a: any, b: any) =>
        (TYPE_ORDER[a.device_type] ?? 9) - (TYPE_ORDER[b.device_type] ?? 9)
      );
    }

    let currentY = 18;
    this.zoneBands = [];
    this.positions.clear();

    for (const zone of ZONE_ORDER) {
      const devs = zoneMap.get(zone);
      if (!devs || devs.length === 0) continue;

      const meta = ZONE_META[zone] ?? ZONE_META['internal'];
      const rows: any[][] = [];
      for (let i = 0; i < devs.length; i += MAX_PER_ROW) {
        rows.push(devs.slice(i, i + MAX_PER_ROW));
      }

      const zoneHeight = ZONE_TOP_PAD + rows.length * V_SPACING + ZONE_BOT_PAD;
      this.zoneBands.push({ zone, y: currentY, height: zoneHeight, ...meta });

      rows.forEach((row, rowIdx) => {
        const rowY = currentY + ZONE_TOP_PAD + rowIdx * V_SPACING + 30;
        const totalRowW = (row.length - 1) * H_SPACING;
        const startX = (CANVAS_W - totalRowW) / 2;
        row.forEach((dev: any, colIdx: number) => {
          this.positions.set(dev.name, { x: startX + colIdx * H_SPACING, y: rowY });
        });
      });

      currentY += zoneHeight + ZONE_GAP;
    }

    this.svgH = currentY + 20;

    // Build edge paths
    this.edgePaths = [];
    for (const edge of this.edges) {
      const src = this.positions.get(edge.source);
      const tgt = this.positions.get(edge.target);
      if (!src || !tgt) continue;

      const dx = tgt.x - src.x;
      const dy = tgt.y - src.y;
      const absDy = Math.abs(dy);

      // Bezier control points — curve outward in Y direction
      const cp1x = src.x + dx * 0.15;
      const cp1y = src.y + absDy * 0.45 * Math.sign(dy);
      const cp2x = tgt.x - dx * 0.15;
      const cp2y = tgt.y - absDy * 0.45 * Math.sign(dy);

      const d = `M ${src.x} ${src.y + NODE_R} C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${tgt.x} ${tgt.y - NODE_R}`;
      const midX = (src.x + tgt.x) / 2;
      const midY = (src.y + tgt.y) / 2;
      const color = LINK_COLORS[edge.link] ?? '#94a3b8';

      this.edgePaths.push({ d, label: edge.link, color, sourceName: edge.source, targetName: edge.target, midX, midY });
    }
  }

  get visibleNodes(): any[] {
    return this.nodes;
  }

  nodeTransform(name: string): string {
    const pos = this.positions.get(name);
    if (!pos) return 'translate(0,0)';
    return `translate(${pos.x},${pos.y})`;
  }

  isEdgeVisible(edge: { sourceName: string; targetName: string }): boolean {
    if (!this.zoneFilter) return true;
    const src = this.nodes.find((n: any) => n.name === edge.sourceName);
    const tgt = this.nodes.find((n: any) => n.name === edge.targetName);
    return src?.network_zone === this.zoneFilter || tgt?.network_zone === this.zoneFilter;
  }

  nodeColor(deviceType: string): string {
    return TYPE_COLORS[deviceType]?.fill ?? '#6b7280';
  }

  typeAbbrev(deviceType: string): string {
    return TYPE_ABBREV[deviceType] ?? '??';
  }

  isAttacker(node: any): boolean {
    return node.name?.includes('attacker') || node.network_zone === 'external';
  }

  onClickNode(node: any): void {
    this.selectedNode = this.selectedNode?.id === node.id ? null : node;
    this.hoveredNode = null;
  }

  onContainerMouseMove(event: MouseEvent): void {
    const container = (event.currentTarget as HTMLElement);
    const rect = container.getBoundingClientRect();
    this.tooltipX = event.clientX - rect.left;
    this.tooltipY = event.clientY - rect.top;
  }

  getPeers(nodeName: string): { name: string; link: string }[] {
    const peers: { name: string; link: string }[] = [];
    for (const edge of this.edges) {
      if (edge.source === nodeName) peers.push({ name: edge.target, link: edge.link });
      else if (edge.target === nodeName) peers.push({ name: edge.source, link: edge.link });
    }
    return peers;
  }
}

import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, Subject } from 'rxjs';

const API = '/api/v1';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private http = inject(HttpClient);
  private wsEvents$ = new Subject<any>();
  private ws: WebSocket | null = null;

  constructor() { this.connectWebSocket(); }

  private connectWebSocket(): void {
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProto}//${window.location.host}/ws`;
    try {
      this.ws = new WebSocket(wsUrl);
      this.ws.onmessage = ev => {
        try { this.wsEvents$.next(JSON.parse(ev.data)); } catch {}
      };
      this.ws.onclose = () => setTimeout(() => this.connectWebSocket(), 3000);
    } catch {}
  }

  get events$(): Observable<any> { return this.wsEvents$.asObservable(); }

  // Dashboard
  getDashboard(): Observable<any> { return this.http.get(`${API}/dashboard`); }

  // Topology
  getDevices(): Observable<any> { return this.http.get(`${API}/topology/devices`); }
  getDevice(id: string): Observable<any> { return this.http.get(`${API}/topology/devices/${id}`); }
  createDevice(dev: any): Observable<any> { return this.http.post(`${API}/topology/devices`, dev); }
  updateDevice(id: string, dev: any): Observable<any> { return this.http.put(`${API}/topology/devices/${id}`, dev); }
  deleteDevice(id: string): Observable<any> { return this.http.delete(`${API}/topology/devices/${id}`); }
  getTopologyGraph(): Observable<any> { return this.http.get(`${API}/topology/graph`); }
  getTopologySummary(): Observable<any> { return this.http.get(`${API}/topology/summary`); }

  // Attacks
  getAttacks(category?: string): Observable<any> {
    const params = category ? `?category=${category}` : '';
    return this.http.get(`${API}/attacks${params}`);
  }
  executeAttack(req: any): Observable<any> { return this.http.post(`${API}/attacks/execute`, req); }
  getAttackHistory(limit = 100): Observable<any> { return this.http.get(`${API}/attacks/history?limit=${limit}`); }

  // Scenarios
  getScenarios(): Observable<any> { return this.http.get(`${API}/scenarios`); }
  getScenario(id: string): Observable<any> { return this.http.get(`${API}/scenarios/${id}`); }
  createScenario(def: any): Observable<any> { return this.http.post(`${API}/scenarios`, def); }
  deleteScenario(id: string): Observable<any> { return this.http.delete(`${API}/scenarios/${id}`); }

  // Runs
  getRuns(status?: string): Observable<any> {
    const params = status ? `?status=${status}` : '';
    return this.http.get(`${API}/runs${params}`);
  }
  getRun(id: string): Observable<any> { return this.http.get(`${API}/runs/${id}`); }
  startRun(req: any): Observable<any> { return this.http.post(`${API}/runs`, req); }
  abortRun(id: string): Observable<any> { return this.http.post(`${API}/runs/${id}/abort`, {}); }
  getRunEvents(id: string): Observable<any> { return this.http.get(`${API}/runs/${id}/events`); }

  // Telemetry
  getTelemetryStats(): Observable<any> { return this.http.get(`${API}/telemetry/stats`); }
  getSyslogTelemetry(params?: any): Observable<any> { return this.http.get(`${API}/telemetry/syslog`, { params }); }
  getFlowTelemetry(params?: any): Observable<any> { return this.http.get(`${API}/telemetry/flows`, { params }); }
  getPCAPFiles(): Observable<any> { return this.http.get(`${API}/telemetry/pcap`); }

  // Audit
  getAuditLog(limit?: number): Observable<any> { return this.http.get(`${API}/audit`, { params: limit ? { limit } : {} }); }
}

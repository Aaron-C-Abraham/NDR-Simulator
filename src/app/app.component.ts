import { Component } from '@angular/core';
import { RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, RouterLink, RouterLinkActive, CommonModule],
  styles: [`
    .app-container { display: flex; flex-direction: column; min-height: 100vh; }

    .topbar {
      position: fixed; top: 0; left: 0; right: 0; height: 56px;
      background: linear-gradient(135deg, #2c3e50 0%, #3a4e63 100%);
      z-index: 1000; box-shadow: 0 2px 10px rgba(0,0,0,0.15);
      display: flex; align-items: center; padding: 0 1.5rem; gap: 1rem;
    }
    .brand { display: flex; flex-direction: column; text-decoration: none; }
    .brand-main { color: #fff; font-weight: 700; font-size: 0.95rem; letter-spacing: 0.5px; }
    .brand-sub  { color: rgba(255,255,255,0.6); font-size: 0.6rem; }
    .brand-divider { width: 1px; height: 28px; background: rgba(255,255,255,0.2); margin: 0 0.25rem; }
    .brand-app { color: var(--accent-color); font-weight: 700; font-size: 0.95rem; }
    .topbar-spacer { flex: 1; }
    .live-pill { display: flex; align-items: center; gap: 6px; background: rgba(39,174,96,0.15); color: #27AE60; border: 1px solid rgba(39,174,96,0.3); border-radius: 9999px; padding: 0.25rem 0.65rem; font-size: 0.72rem; font-weight: 600; }
    .live-dot { width: 7px; height: 7px; border-radius: 50%; background: #27AE60; animation: pulse-dot 1.5s infinite; }
    @keyframes pulse-dot { 0%,100% { opacity:1; } 50% { opacity:0.4; } }

    .sidebar {
      position: fixed; top: 56px; left: 0; bottom: 0; width: 240px;
      background: linear-gradient(180deg, #2c3e50 0%, #1a252f 100%);
      z-index: 900; display: flex; flex-direction: column; overflow: hidden;
    }
    .sidebar-nav { flex: 1; overflow-y: auto; padding: 0.5rem 0; }
    .nav-section { font-size: 0.62rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.8px; color: rgba(255,255,255,0.3); padding: 0.75rem 1rem 0.2rem; }
    .nav-link { display: flex; align-items: center; gap: 0.65rem; padding: 0.6rem 1rem; color: rgba(255,255,255,0.65); text-decoration: none; font-size: 0.85rem; font-weight: 500; border-left: 3px solid transparent; transition: all 0.15s ease; cursor: pointer; }
    .nav-link:hover { color: #fff; background: rgba(255,255,255,0.07); }
    .nav-link.active { color: #fff; background: rgba(44,168,199,0.15); border-left-color: #2ca8c7; }
    .nav-link i { width: 20px; text-align: center; font-size: 0.95rem; }

    .app-main { margin-left: 240px; padding-top: 56px; min-height: 100vh; }
    .app-content { padding: 1.5rem; }

    @media (max-width: 992px) {
      .sidebar { width: 60px; }
      .app-main { margin-left: 60px; }
      .nav-link span { display: none; }
      .nav-section { display: none; }
      .sidebar-logo { display: none; }
    }
  `],
  template: `
    <div class="app-container">
      <!-- Topbar -->
      <nav class="topbar">
        <a class="brand" routerLink="/attacks">
          <span class="brand-main">Algomox</span>
          <span class="brand-sub">CyberMox CDR</span>
        </a>
        <div class="brand-divider"></div>
        <span class="brand-app">NDR Simulator</span>
        <div class="topbar-spacer"></div>
        <div class="live-pill">
          <span class="live-dot"></span>
          Simulator Active
        </div>
      </nav>

      <!-- Sidebar -->
      <nav class="sidebar">
        <div class="sidebar-nav">
          <div class="nav-section">Network</div>
          <a class="nav-link" routerLink="/topology" routerLinkActive="active">
            <i class="bi bi-diagram-3-fill"></i><span>Topology</span>
          </a>

          <div class="nav-section">Testing</div>
          <a class="nav-link" routerLink="/attacks" routerLinkActive="active">
            <i class="bi bi-lightning-charge-fill"></i><span>Attacks</span>
          </a>
          <a class="nav-link" routerLink="/scenarios" routerLinkActive="active">
            <i class="bi bi-journal-code"></i><span>Scenarios</span>
          </a>
          <a class="nav-link" routerLink="/runs" routerLinkActive="active">
            <i class="bi bi-play-circle-fill"></i><span>Test Runs</span>
          </a>

          <div class="nav-section">Telemetry</div>
          <a class="nav-link" routerLink="/telemetry" routerLinkActive="active">
            <i class="bi bi-reception-4"></i><span>Live Telemetry</span>
          </a>
        </div>
      </nav>

      <!-- Main Content -->
      <main class="app-main">
        <div class="app-content">
          <router-outlet></router-outlet>
        </div>
      </main>
    </div>
  `
})
export class AppComponent {}

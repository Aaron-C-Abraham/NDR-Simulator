import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', redirectTo: 'attacks', pathMatch: 'full' },
  { path: 'topology', loadComponent: () => import('./features/topology/topology.component').then(m => m.TopologyComponent) },
  { path: 'attacks', loadComponent: () => import('./features/attacks/attacks.component').then(m => m.AttacksComponent) },
  { path: 'scenarios', loadComponent: () => import('./features/scenarios/scenarios.component').then(m => m.ScenariosComponent) },
  { path: 'runs', loadComponent: () => import('./features/runs/runs.component').then(m => m.RunsComponent) },
  { path: 'telemetry', loadComponent: () => import('./features/telemetry/telemetry.component').then(m => m.TelemetryComponent) },
  { path: '**', redirectTo: 'attacks' }
];

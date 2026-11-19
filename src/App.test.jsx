import { fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, expect, test, vi } from 'vitest';
import App from './App';

vi.mock('./supabase/client', () => ({
  supabaseConfigured: false,
  supabase: null,
}));

beforeEach(() => {
  window.sessionStorage.removeItem('forensiai.navigation.v1');
});

function enterClueBoxOdyssey() {
  fireEvent.click(screen.getByRole('button', { name: /enter cluebox odyssey/i }));
}

test('shows the welcome page by default and enters the local vault explicitly when team auth is unconfigured', () => {
  render(<App />);
  expect(screen.getByRole('heading', { name: /explore the\s*digital unknown\./i })).toBeDefined();
  expect(screen.getAllByRole('link', { name: /cluebox odyssey home/i }).length).toBeGreaterThan(0);
  expect(screen.getByText('Explore the Digital Unknown.')).toBeDefined();
  expect(screen.getByRole('navigation', { name: /welcome navigation/i })).toBeDefined();
  expect(screen.getByRole('button', { name: /enter cluebox odyssey/i })).toBeDefined();
  expect(screen.getByRole('link', { name: /explore features/i }).getAttribute('href')).toBe('#features');
  expect(screen.getByRole('heading', { name: /a clear view of every part of the case/i })).toBeDefined();
  fireEvent.click(screen.getByRole('button', { name: /sign in/i }));
  expect(screen.getByRole('alert').textContent).toMatch(/team sign-in is not configured/i);
  expect(screen.queryByRole('heading', { name: /command center/i })).toBeNull();

  enterClueBoxOdyssey();
  expect(screen.getByRole('heading', { name: /command center/i })).toBeDefined();
  expect(screen.getAllByRole('img', { name: /cluebox odyssey mystery box and digital fingerprint logo/i }).length).toBeGreaterThan(0);
  expect(screen.getByLabelText(/cluebox odyssey — explore the digital unknown/i)).toBeDefined();
  expect(screen.getByRole('navigation', { name: /forensic workspace navigation/i })).toBeDefined();
  expect(screen.getByLabelText(/active evidence/i)).toBeDefined();
  expect(screen.getByLabelText(/selected evidence/i)).toBeDefined();
  const sidebar = document.querySelector('[data-scroll-region="sidebar"]');
  const workspace = document.querySelector('[data-scroll-region="main-workspace"]');
  expect(sidebar).toBeDefined();
  expect(workspace).toBeDefined();
  expect(screen.getByRole('navigation', { name: /forensic workspace navigation/i }).querySelectorAll('a')).toHaveLength(0);
  expect(screen.getByLabelText(/case id/i)).toBeDefined();
  expect(screen.getByLabelText(/custodian name/i)).toBeDefined();
});

test('navigation switches between dedicated workspaces instead of scrolling to page anchors', () => {
  render(<App />);
  enterClueBoxOdyssey();
  const root = document.querySelector('.locker-app');
  const navigation = screen.getByRole('navigation', { name: /forensic workspace navigation/i });
  const workspaces = [
    ['Evidence Locker', 'evidence', 'Evidence Locker'],
    ['EXIF Analysis', 'exif', 'EXIF Analysis'],
    ['Windows Registry', 'registry', 'Windows Registry'],
    ['PCAP Analysis', 'pcap', 'PCAP Analysis'],
    ['SQLite Analysis', 'sqlite', 'SQLite Analysis'],
    ['Timeline', 'timeline', 'Investigation Timeline'],
    ['Reports', 'reports', 'Investigation Reports'],
  ];

  for (const [label, workspace, heading] of workspaces) {
    fireEvent.click(within(navigation).getByRole('button', { name: new RegExp(label, 'i') }));
    expect(root.dataset.activeWorkspace).toBe(workspace);
    expect(screen.getByRole('heading', { level: 1, name: heading })).toBeDefined();
    expect(within(navigation).getByRole('button', { name: new RegExp(label, 'i') }).getAttribute('aria-current')).toBe('page');
  }

  fireEvent.click(within(navigation).getByRole('button', { name: /timeline/i }));
  expect(screen.getByLabelText(/timeline case/i)).toBeDefined();
  fireEvent.click(within(navigation).getByRole('button', { name: /^reports$/i }));
  expect(screen.getByRole('heading', { name: /final investigation report/i })).toBeDefined();
  expect(screen.getByRole('button', { name: /download pdf/i })).toBeDefined();
  expect(screen.getByRole('button', { name: /download json/i })).toBeDefined();
});

test('registry workspace does not display the synthetic fixture banner or download link', () => {
  render(<App />);
  enterClueBoxOdyssey();
  fireEvent.click(within(screen.getByRole('navigation', { name: /forensic workspace navigation/i })).getByRole('button', { name: /windows registry/i }));

  expect(screen.queryByRole('link', { name: /download the software\.hive fixture/i })).toBeNull();
  expect(screen.queryByText(/synthetic test fixture \(not evidence\)/i)).toBeNull();
  expect(screen.queryByText(/will not replace existing evidence/i)).toBeNull();
});

test('overview module cards provide distinct destinations for case, analysis, and Copilot workflows', () => {
  render(<App />);
  enterClueBoxOdyssey();
  const moduleCards = screen.getByRole('region', { name: /forensic modules/i });
  const modules = [
    ['cases', 'Case Management'],
    ['evidence', 'Evidence Locker'],
    ['exif', 'EXIF Analysis'],
    ['registry', 'Registry Analysis'],
    ['pcap', 'PCAP Analysis'],
    ['sqlite', 'SQLite Analysis'],
    ['timeline', 'Timeline'],
    ['reports', 'Reports'],
    ['copilot', 'AI Copilot'],
  ];

  for (const [id, title] of modules) {
    expect(moduleCards.querySelector(`[data-module="${id}"]`)).not.toBeNull();
    expect(within(moduleCards).getByRole('button', { name: title })).toBeDefined();
  }
  expect(moduleCards.querySelectorAll('.module-card-icon svg')).toHaveLength(9);

  fireEvent.click(within(moduleCards).getByRole('button', { name: 'Case Management' }));
  expect(document.querySelector('.locker-app').dataset.activeWorkspace).toBe('cases');
  expect(screen.getByRole('heading', { name: /case details/i })).toBeDefined();

  fireEvent.click(within(screen.getByRole('navigation', { name: /forensic workspace navigation/i })).getByRole('button', { name: /overview/i }));
  fireEvent.click(within(screen.getByRole('region', { name: /forensic modules/i })).getByRole('button', { name: 'EXIF Analysis' }));
  expect(document.querySelector('.locker-app').dataset.activeWorkspace).toBe('exif');

  fireEvent.click(within(screen.getByRole('navigation', { name: /forensic workspace navigation/i })).getByRole('button', { name: /overview/i }));
  fireEvent.click(within(screen.getByRole('region', { name: /forensic modules/i })).getByRole('button', { name: 'AI Copilot' }));
  expect(screen.getByRole('dialog', { name: /ai forensic copilot/i })).toBeDefined();
});

test('opens, toggles, and closes the Copilot chat from its floating launcher', () => {
  render(<App />);
  enterClueBoxOdyssey();
  const launcher = screen.getByRole('button', { name: /open ai copilot chat/i });
  expect(launcher.className).toContain('copilot-floating-launcher');
  expect(launcher.querySelector('svg')).not.toBeNull();
  expect(document.querySelectorAll('.copilot-floating-launcher')).toHaveLength(1);
  expect(document.querySelector('.sidebar-copilot-launcher')).toBeNull();
  expect(launcher.getAttribute('aria-expanded')).toBe('false');
  fireEvent.click(launcher);

  const panel = screen.getByRole('dialog', { name: /ai forensic copilot/i });
  expect(launcher.getAttribute('aria-expanded')).toBe('true');
  expect(panel.getAttribute('aria-modal')).toBe('false');
  expect(panel.className).toContain('copilot-chat-panel');
  expect(screen.getByLabelText(/investigation question/i)).toBeDefined();
  expect(document.activeElement).toBe(screen.getByLabelText(/investigation question/i));
  expect(screen.getByRole('button', { name: /^send$/i })).toBeDefined();
  expect(screen.getByText('AI Copilot unavailable — secure AI provider configuration required.')).toBeDefined();
  fireEvent.click(launcher);
  expect(screen.queryByRole('dialog', { name: /ai forensic copilot/i })).toBeNull();
  fireEvent.click(launcher);

  fireEvent.click(screen.getByRole('button', { name: /minimize ai copilot chat/i }));
  expect(screen.queryByLabelText(/investigation question/i)).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: /restore ai copilot chat/i }));
  expect(screen.getByLabelText(/investigation question/i)).toBeDefined();

  fireEvent.click(screen.getByRole('button', { name: /expand ai copilot chat/i }));
  expect(screen.getByRole('button', { name: /restore ai copilot chat size/i }).getAttribute('aria-expanded')).toBe('true');
  fireEvent.keyDown(window, { key: 'Escape' });
  expect(screen.queryByRole('dialog', { name: /ai forensic copilot/i })).toBeNull();
  expect(document.activeElement).toBe(launcher);
  fireEvent.click(launcher);
  fireEvent.click(within(screen.getByRole('dialog', { name: /ai forensic copilot/i })).getByRole('button', { name: /close ai copilot chat/i }));
  expect(screen.queryByRole('dialog', { name: /ai forensic copilot/i })).toBeNull();
});

test('sidebar navigation uses the matching module SVG icons and accent identities', () => {
  render(<App />);
  enterClueBoxOdyssey();
  const navigation = screen.getByRole('navigation', { name: /forensic workspace navigation/i });
  const matchingIcons = [
    ['overview', 'folderSearch'],
    ['evidence', 'folder'],
    ['exif', 'camera'],
    ['registry', 'database'],
    ['pcap', 'network'],
    ['sqlite', 'database'],
    ['timeline', 'activity'],
    ['reports', 'fileText'],
  ];

  for (const [workspace, icon] of matchingIcons) {
    const link = navigation.querySelector(`[data-workspace="${workspace}"]`);
    expect(link.getAttribute('aria-label')).not.toBe('');
    expect(link.querySelector('.sidebar-link-icon').dataset.icon).toBe(icon);
    expect(link.querySelector('.sidebar-link-icon svg')).not.toBeNull();
    expect(link.querySelector('.sidebar-link-icon').textContent).toBe('');
  }
});

test('collapses and expands the left navigation', () => {
  render(<App />);
  enterClueBoxOdyssey();
  const collapseButton = screen.getByRole('button', { name: /collapse navigation/i });

  fireEvent.click(collapseButton);
  expect(screen.getByRole('button', { name: /expand navigation/i })).toBeDefined();

  fireEvent.click(screen.getByRole('button', { name: /expand navigation/i }));
  expect(screen.getByRole('button', { name: /collapse navigation/i })).toBeDefined();
});

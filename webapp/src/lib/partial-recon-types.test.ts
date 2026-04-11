import { describe, test, expect } from 'vitest'
import {
  PARTIAL_RECON_SUPPORTED_TOOLS,
  PARTIAL_RECON_PHASES,
} from './recon-types'
import type {
  PartialReconStatus,
  PartialReconState,
  GraphInputs,
  PartialReconParams,
} from './recon-types'

// === PARTIAL_RECON_SUPPORTED_TOOLS ===
describe('PARTIAL_RECON_SUPPORTED_TOOLS', () => {
  test('contains SubdomainDiscovery', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('SubdomainDiscovery')).toBe(true)
  })

  test('does not contain unsupported tools', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Naabu')).toBe(false)
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Nuclei')).toBe(false)
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('Httpx')).toBe(false)
  })
})

// === PARTIAL_RECON_PHASES ===
describe('PARTIAL_RECON_PHASES', () => {
  test('has exactly 1 phase for subdomain discovery', () => {
    expect(PARTIAL_RECON_PHASES).toHaveLength(1)
    expect(PARTIAL_RECON_PHASES[0]).toBe('Subdomain Discovery')
  })

  test('is typed as readonly (as const)', () => {
    // `as const` creates a readonly tuple at the type level, not frozen at runtime
    expect(Array.isArray(PARTIAL_RECON_PHASES)).toBe(true)
  })
})

// === Type Shape Validation ===
describe('PartialReconState type shape', () => {
  test('default idle state has required fields', () => {
    const state: PartialReconState = {
      project_id: 'proj-123',
      tool_id: 'SubdomainDiscovery',
      status: 'idle',
      container_id: null,
      started_at: null,
      completed_at: null,
      error: null,
      stats: null,
    }
    expect(state.project_id).toBe('proj-123')
    expect(state.status).toBe('idle')
    expect(state.stats).toBeNull()
  })

  test('completed state with stats', () => {
    const state: PartialReconState = {
      project_id: 'proj-123',
      tool_id: 'SubdomainDiscovery',
      status: 'completed',
      container_id: 'abc123',
      started_at: '2026-04-11T10:00:00Z',
      completed_at: '2026-04-11T10:05:00Z',
      error: null,
      stats: { subdomains_total: 15, subdomains_new: 8, subdomains_existing: 7, ips_total: 12 },
    }
    expect(state.stats?.subdomains_new).toBe(8)
    expect(state.stats?.subdomains_existing).toBe(7)
  })

  test('error state with error message', () => {
    const state: PartialReconState = {
      project_id: 'proj-123',
      tool_id: 'SubdomainDiscovery',
      status: 'error',
      container_id: null,
      started_at: '2026-04-11T10:00:00Z',
      completed_at: '2026-04-11T10:01:00Z',
      error: 'Container exited with code 1',
      stats: null,
    }
    expect(state.error).toBeTruthy()
  })
})

describe('PartialReconStatus values', () => {
  test.each<PartialReconStatus>([
    'idle', 'starting', 'running', 'completed', 'error', 'stopping',
  ])('accepts valid status: %s', (status) => {
    const state: PartialReconState = {
      project_id: 'p', tool_id: 't', status,
      container_id: null, started_at: null, completed_at: null, error: null, stats: null,
    }
    expect(state.status).toBe(status)
  })
})

describe('GraphInputs type shape', () => {
  test('from graph source', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 42,
      source: 'graph',
    }
    expect(inputs.source).toBe('graph')
    expect(inputs.existing_subdomains_count).toBe(42)
  })

  test('from settings fallback', () => {
    const inputs: GraphInputs = {
      domain: 'example.com',
      existing_subdomains_count: 0,
      source: 'settings',
    }
    expect(inputs.source).toBe('settings')
    expect(inputs.existing_subdomains_count).toBe(0)
  })

  test('null domain when no data', () => {
    const inputs: GraphInputs = {
      domain: null,
      existing_subdomains_count: 0,
      source: 'settings',
    }
    expect(inputs.domain).toBeNull()
  })
})

describe('PartialReconParams type shape', () => {
  test('minimal params', () => {
    const params: PartialReconParams = {
      tool_id: 'SubdomainDiscovery',
      graph_inputs: { domain: 'example.com' },
      user_inputs: [],
      dedup_enabled: true,
    }
    expect(params.tool_id).toBe('SubdomainDiscovery')
    expect(params.user_inputs).toHaveLength(0)
    expect(params.dedup_enabled).toBe(true)
    expect(params.settings_overrides).toBeUndefined()
  })

  test('full params with user inputs and overrides', () => {
    const params: PartialReconParams = {
      tool_id: 'SubdomainDiscovery',
      graph_inputs: { domain: 'example.com' },
      user_inputs: ['api.example.com', 'admin.example.com'],
      dedup_enabled: false,
      settings_overrides: { SUBFINDER_ENABLED: false },
    }
    expect(params.user_inputs).toHaveLength(2)
    expect(params.dedup_enabled).toBe(false)
    expect(params.settings_overrides).toBeDefined()
  })
})

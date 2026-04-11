'use client'

import { useState, useEffect, useCallback } from 'react'
import { Play, Loader2, ArrowRight } from 'lucide-react'
import { Modal } from '@/components/ui'
import type { GraphInputs, PartialReconParams } from '@/lib/recon-types'
import { SECTION_INPUT_MAP, SECTION_NODE_MAP } from '../nodeMapping'
import { WORKFLOW_TOOLS } from './workflowDefinition'

interface PartialReconModalProps {
  isOpen: boolean
  toolId: string | null
  onClose: () => void
  onConfirm: (params: PartialReconParams) => void
  projectId?: string
  targetDomain?: string
  subdomainPrefixes?: string[]
  isStarting?: boolean
}

export function PartialReconModal({
  isOpen,
  toolId,
  onClose,
  onConfirm,
  projectId,
  targetDomain = '',
  subdomainPrefixes = [],
  isStarting = false,
}: PartialReconModalProps) {
  const [graphInputs, setGraphInputs] = useState<GraphInputs | null>(null)
  const [loadingInputs, setLoadingInputs] = useState(false)

  useEffect(() => {
    if (!isOpen || !toolId || !projectId) return
    setLoadingInputs(true)
    fetch(`/api/recon/${projectId}/graph-inputs/${toolId}`)
      .then(res => res.ok ? res.json() : null)
      .then((data: GraphInputs | null) => {
        setGraphInputs(data || { domain: targetDomain || null, existing_subdomains_count: 0, source: 'settings' })
        setLoadingInputs(false)
      })
      .catch(() => {
        setGraphInputs({ domain: targetDomain || null, existing_subdomains_count: 0, source: 'settings' })
        setLoadingInputs(false)
      })
  }, [isOpen, toolId, projectId, targetDomain])

  const handleRun = useCallback(() => {
    const domain = graphInputs?.domain || targetDomain || ''
    if (!domain) return

    onConfirm({
      tool_id: toolId || '',
      graph_inputs: { domain },
      user_inputs: [],
      dedup_enabled: true,
    })
  }, [graphInputs, targetDomain, toolId, onConfirm])

  if (!isOpen || !toolId) return null

  const domain = graphInputs?.domain || targetDomain || ''
  const inputNodeTypes = SECTION_INPUT_MAP[toolId] || []
  const outputNodeTypes = SECTION_NODE_MAP[toolId] || []

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`Partial Recon: ${WORKFLOW_TOOLS.find(t => t.id === toolId)?.label || toolId}`}
      size="default"
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {/* Input / Output flow */}
        <div style={{ display: 'flex', alignItems: 'stretch', gap: '12px' }}>
          {/* Input */}
          <div style={{
            flex: 1,
            padding: '12px 14px',
            borderRadius: '8px',
            backgroundColor: 'var(--bg-secondary, #1e293b)',
            border: '1px solid var(--border-color, #334155)',
          }}>
            <div style={{ fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#3b82f6', marginBottom: '8px' }}>
              Input
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap', marginBottom: '6px' }}>
              {inputNodeTypes.map(nt => (
                <span key={nt} style={{
                  fontSize: '10px', padding: '2px 6px', borderRadius: '4px',
                  backgroundColor: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa', fontWeight: 600,
                }}>{nt}</span>
              ))}
              <span style={{
                fontSize: '9px', padding: '1px 5px', borderRadius: '3px',
                backgroundColor: graphInputs?.source === 'graph' ? 'rgba(59, 130, 246, 0.1)' : 'rgba(234, 179, 8, 0.1)',
                color: graphInputs?.source === 'graph' ? '#60a5fa' : '#facc15',
              }}>
                {loadingInputs ? '...' : graphInputs?.source === 'graph' ? 'graph' : 'settings'}
              </span>
            </div>
            <div style={{ fontSize: '13px', fontFamily: 'monospace', color: 'var(--text-primary, #e2e8f0)' }}>
              {loadingInputs ? 'Loading...' : domain || 'No domain configured'}
            </div>
          </div>

          {/* Arrow */}
          <div style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>
            <ArrowRight size={18} style={{ color: 'var(--text-muted, #64748b)' }} />
          </div>

          {/* Output */}
          <div style={{
            flex: 1,
            padding: '12px 14px',
            borderRadius: '8px',
            backgroundColor: 'var(--bg-secondary, #1e293b)',
            border: '1px solid var(--border-color, #334155)',
          }}>
            <div style={{ fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#22c55e', marginBottom: '8px' }}>
              Output
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
              {outputNodeTypes.map(nt => (
                <span key={nt} style={{
                  fontSize: '10px', padding: '2px 6px', borderRadius: '4px',
                  backgroundColor: 'rgba(34, 197, 94, 0.15)', color: '#4ade80', fontWeight: 600,
                }}>{nt}</span>
              ))}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary, #94a3b8)', marginTop: '6px' }}>
              New nodes merged into graph
            </div>
          </div>
        </div>

        {/* Tools info */}
        <div style={{ fontSize: '11px', color: 'var(--text-secondary, #94a3b8)', lineHeight: '1.6' }}>
          Discovers subdomains using 5 tools in parallel (crt.sh, HackerTarget, Subfinder, Amass, Knockpy),
          filters wildcards with Puredns, then resolves full DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME) for each.
          Results are merged into the existing graph -- duplicates are updated, not recreated.
        </div>

        {/* Subdomain prefix warning */}
        {subdomainPrefixes.length > 0 && (
          <div style={{
            fontSize: '11px',
            color: '#f87171',
            lineHeight: '1.5',
            padding: '8px 12px',
            borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.08)',
            border: '1px solid rgba(239, 68, 68, 0.2)',
          }}>
            This project has subdomain prefixes locked to <strong>{subdomainPrefixes.join(', ')}</strong>.
            Partial recon ignores this filter and runs full discovery to find all subdomains.
            New subdomains found outside the prefix list will still be added to the graph.
          </div>
        )}

        {/* Actions */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', paddingTop: '8px', borderTop: '1px solid var(--border-color, #334155)' }}>
          <button
            type="button"
            onClick={onClose}
            disabled={isStarting}
            style={{
              padding: '8px 16px',
              borderRadius: '6px',
              border: '1px solid var(--border-color, #334155)',
              backgroundColor: 'transparent',
              color: 'var(--text-primary, #e2e8f0)',
              cursor: isStarting ? 'not-allowed' : 'pointer',
              fontSize: '13px',
              opacity: isStarting ? 0.5 : 1,
            }}
          >
            Cancel
          </button>

          <button
            type="button"
            onClick={handleRun}
            disabled={!domain || isStarting}
            style={{
              padding: '8px 16px',
              borderRadius: '6px',
              border: 'none',
              backgroundColor: '#3b82f6',
              color: '#fff',
              cursor: !domain || isStarting ? 'not-allowed' : 'pointer',
              fontSize: '13px',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              opacity: !domain || isStarting ? 0.5 : 1,
            }}
          >
            {isStarting ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Play size={14} />}
            {isStarting ? 'Starting...' : 'Run Partial Recon'}
          </button>
        </div>
      </div>
    </Modal>
  )
}

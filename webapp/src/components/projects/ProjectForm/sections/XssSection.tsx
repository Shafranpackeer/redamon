'use client'

import type { Project } from '@prisma/client'
import { Toggle } from '@/components/ui/Toggle/Toggle'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface XssSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function XssSection({ data, updateField }: XssSectionProps) {
  return (
    <div style={{ padding: 'var(--space-3) var(--space-4)' }}>
      <p className={styles.sectionDescription}>
        Configure Dalfox XSS scanner settings and WAF bypass options.
      </p>

      {/* Workers + Timeout */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Dalfox Workers</label>
          <input
            type="number"
            className="textInput"
            value={data.xssWorkers ?? 10}
            onChange={(e) => updateField('xssWorkers', parseInt(e.target.value) || 10)}
            min={1}
            max={50}
          />
          <span className={styles.fieldHint}>
            Concurrent scan threads. Higher = faster but more noisy. Default: 10.
          </span>
        </div>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Scan Timeout (seconds)</label>
          <input
            type="number"
            className="textInput"
            value={data.xssTimeout ?? 30}
            onChange={(e) => updateField('xssTimeout', parseInt(e.target.value) || 30)}
            min={5}
            max={300}
          />
          <span className={styles.fieldHint}>
            Timeout per parameter scan. Default: 30s.
          </span>
        </div>
      </div>

      {/* Max Attempts */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Max Attempts</label>
          <input
            type="number"
            className="textInput"
            value={data.xssMaxAttempts ?? 3}
            onChange={(e) => updateField('xssMaxAttempts', parseInt(e.target.value) || 3)}
            min={1}
            max={10}
          />
          <span className={styles.fieldHint}>
            Max retry attempts per parameter. Default: 3.
          </span>
        </div>
      </div>

      {/* Toggles */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Toggle
              checked={data.xssWafBypass ?? false}
              onChange={(v) => updateField('xssWafBypass', v)}
              size="large"
            />
            <label className={styles.fieldLabel} style={{ marginBottom: 0 }}>
              WAF Bypass Mode
            </label>
          </div>
          <span className={styles.fieldHint}>
            Enable WAF evasion techniques (encoding, case mixing, obfuscation).
          </span>
        </div>
        <div className={styles.fieldGroup}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Toggle
              checked={data.xssDeepDom ?? false}
              onChange={(v) => updateField('xssDeepDom', v)}
              size="large"
            />
            <label className={styles.fieldLabel} style={{ marginBottom: 0 }}>
              Deep DOM Analysis
            </label>
          </div>
          <span className={styles.fieldHint}>
            Enable deep DOM-based XSS analysis (slower but more thorough).
          </span>
        </div>
      </div>
    </div>
  )
}

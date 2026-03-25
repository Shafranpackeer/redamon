'use client'

import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface SqliSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

const TAMPER_SCRIPTS = [
  { value: 'space2comment', label: 'space2comment - Replace spaces with comments' },
  { value: 'randomcase', label: 'randomcase - Random case for keywords' },
  { value: 'charencode', label: 'charencode - URL encode all characters' },
  { value: 'between', label: 'between - Replace > with NOT BETWEEN' },
  { value: 'equaltolike', label: 'equaltolike - Replace = with LIKE' },
  { value: 'modsecurityversioned', label: 'modsecurityversioned - ModSecurity bypass' },
  { value: 'space2mssqlblank', label: 'space2mssqlblank - MSSQL space bypass' },
  { value: 'versionedkeywords', label: 'versionedkeywords - MySQL versioned keywords' },
]

export function SqliSection({ data, updateField }: SqliSectionProps) {
  // Handle tamper scripts as comma-separated string
  const tamperValue = (data as Record<string, unknown>).sqliTamper as string ?? 'space2comment'

  return (
    <div style={{ padding: 'var(--space-3) var(--space-4)' }}>
      <p className={styles.sectionDescription}>
        Configure SQL injection testing settings. These control SQLMap behavior including
        risk level, test thoroughness, and WAF bypass techniques.
      </p>

      {/* Risk Level + Test Level */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Risk Level (1-3)</label>
          <select
            className="textInput"
            value={(data as Record<string, unknown>).sqliRisk as number ?? 2}
            onChange={(e) => updateField('sqliRisk' as keyof FormData, parseInt(e.target.value) as FormData[keyof FormData])}
          >
            <option value={1}>1 - Safe (innocuous tests only)</option>
            <option value={2}>2 - Medium (OR-based, time-based)</option>
            <option value={3}>3 - Aggressive (stacked queries, heavy payloads)</option>
          </select>
          <span className={styles.fieldHint}>
            Higher risk increases chance of detection but tests more dangerous payloads.
          </span>
        </div>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Test Level (1-5)</label>
          <select
            className="textInput"
            value={(data as Record<string, unknown>).sqliLevel as number ?? 3}
            onChange={(e) => updateField('sqliLevel' as keyof FormData, parseInt(e.target.value) as FormData[keyof FormData])}
          >
            <option value={1}>1 - Basic (GET/POST params only)</option>
            <option value={2}>2 - Cookie injection</option>
            <option value={3}>3 - User-Agent/Referer headers</option>
            <option value={4}>4 - Additional HTTP headers</option>
            <option value={5}>5 - All HTTP headers + Host</option>
          </select>
          <span className={styles.fieldHint}>
            Higher level tests more injection points but takes longer.
          </span>
        </div>
      </div>

      {/* Max Attempts + Threads */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Max Attempts</label>
          <input
            type="number"
            className="textInput"
            value={(data as Record<string, unknown>).sqliMaxAttempts as number ?? 3}
            onChange={(e) => updateField('sqliMaxAttempts' as keyof FormData, (parseInt(e.target.value) || 3) as FormData[keyof FormData])}
            min={1}
            max={10}
          />
          <span className={styles.fieldHint}>
            Max different injection techniques to try before reporting no vulnerability.
          </span>
        </div>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Threads</label>
          <input
            type="number"
            className="textInput"
            value={(data as Record<string, unknown>).sqliThreads as number ?? 5}
            onChange={(e) => updateField('sqliThreads' as keyof FormData, (parseInt(e.target.value) || 5) as FormData[keyof FormData])}
            min={1}
            max={20}
          />
          <span className={styles.fieldHint}>
            Concurrent SQLMap threads. Higher = faster but more detectable.
          </span>
        </div>
      </div>

      {/* Timeout */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Connection Timeout (seconds)</label>
          <input
            type="number"
            className="textInput"
            value={(data as Record<string, unknown>).sqliTimeout as number ?? 30}
            onChange={(e) => updateField('sqliTimeout' as keyof FormData, (parseInt(e.target.value) || 30) as FormData[keyof FormData])}
            min={5}
            max={120}
          />
          <span className={styles.fieldHint}>
            SQLMap connection timeout per request.
          </span>
        </div>
      </div>

      {/* Tamper Scripts */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup} style={{ flex: 1 }}>
          <label className={styles.fieldLabel}>Default Tamper Script</label>
          <select
            className="textInput"
            value={tamperValue}
            onChange={(e) => updateField('sqliTamper' as keyof FormData, e.target.value as FormData[keyof FormData])}
          >
            {TAMPER_SCRIPTS.map(script => (
              <option key={script.value} value={script.value}>
                {script.label}
              </option>
            ))}
          </select>
          <span className={styles.fieldHint}>
            WAF bypass technique. Agent may use additional tamper scripts based on target.
          </span>
        </div>
      </div>
    </div>
  )
}

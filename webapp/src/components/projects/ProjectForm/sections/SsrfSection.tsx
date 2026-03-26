'use client'

import type { Project } from '@prisma/client'
import { Toggle } from '@/components/ui/Toggle/Toggle'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface SsrfSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function SsrfSection({ data, updateField }: SsrfSectionProps) {
  return (
    <div style={{ padding: 'var(--space-3) var(--space-4)' }}>
      <p className={styles.sectionDescription}>
        Configure SSRF testing settings for cloud metadata extraction and internal network scanning.
      </p>

      {/* Timeout */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Request Timeout (seconds)</label>
          <input
            type="number"
            className="textInput"
            value={data.ssrfTimeout ?? 10}
            onChange={(e) => updateField('ssrfTimeout', parseInt(e.target.value) || 10)}
            min={1}
            max={60}
          />
          <span className={styles.fieldHint}>
            Timeout for SSRF request attempts. Default: 10s.
          </span>
        </div>
      </div>

      {/* Toggles Row 1 */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Toggle
              checked={data.ssrfFollowRedirects ?? true}
              onChange={(v) => updateField('ssrfFollowRedirects', v)}
              size="large"
            />
            <label className={styles.fieldLabel} style={{ marginBottom: 0 }}>
              Follow Redirects
            </label>
          </div>
          <span className={styles.fieldHint}>
            Follow HTTP redirects during SSRF testing.
          </span>
        </div>
        <div className={styles.fieldGroup}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Toggle
              checked={data.ssrfCloudMetadata ?? true}
              onChange={(v) => updateField('ssrfCloudMetadata', v)}
              size="large"
            />
            <label className={styles.fieldLabel} style={{ marginBottom: 0 }}>
              Cloud Metadata Testing
            </label>
          </div>
          <span className={styles.fieldHint}>
            Test cloud metadata endpoints (AWS/GCP/Azure 169.254.169.254).
          </span>
        </div>
      </div>

      {/* Toggles Row 2 */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Toggle
              checked={data.ssrfProtocolSmuggle ?? false}
              onChange={(v) => updateField('ssrfProtocolSmuggle', v)}
              size="large"
            />
            <label className={styles.fieldLabel} style={{ marginBottom: 0 }}>
              Protocol Smuggling
            </label>
          </div>
          <span className={styles.fieldHint}>
            Test gopher://, dict://, file:// protocols for advanced exploitation.
          </span>
        </div>
        <div className={styles.fieldGroup}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Toggle
              checked={data.ssrfInternalScan ?? false}
              onChange={(v) => updateField('ssrfInternalScan', v)}
              size="large"
            />
            <label className={styles.fieldLabel} style={{ marginBottom: 0 }}>
              Internal Network Scan
            </label>
          </div>
          <span className={styles.fieldHint}>
            Scan internal IP ranges (10.x, 172.16.x, 192.168.x) via SSRF.
          </span>
        </div>
      </div>
    </div>
  )
}

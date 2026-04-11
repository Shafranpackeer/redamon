import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession } from '@/app/api/graph/neo4j'

interface RouteParams {
  params: Promise<{ projectId: string; toolId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId, toolId } = await params

    // Get project to know user_id and fallback domain
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { userId: true, targetDomain: true }
    })

    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    // Query Neo4j directly for graph inputs
    if (toolId === 'SubdomainDiscovery') {
      try {
        const session = getSession()
        try {
          const result = await session.run(
            `OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
             RETURN d.name AS domain, count(s) AS subdomainCount`,
            { uid: project.userId, pid: projectId }
          )
          const record = result.records[0]
          const domain = record?.get('domain') || null
          const subdomainCount = record?.get('subdomainCount')?.toNumber?.() ?? record?.get('subdomainCount') ?? 0

          if (domain) {
            return NextResponse.json({
              domain,
              existing_subdomains_count: subdomainCount,
              source: 'graph',
            })
          }
        } finally {
          await session.close()
        }
      } catch (err) {
        console.warn('Neo4j query failed for graph-inputs, falling back to settings:', err)
      }
    }

    // Fallback: return domain from project settings
    return NextResponse.json({
      domain: project.targetDomain || null,
      existing_subdomains_count: 0,
      source: 'settings',
    })

  } catch (error) {
    console.error('Error getting graph inputs:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}

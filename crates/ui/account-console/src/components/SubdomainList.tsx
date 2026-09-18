import { useEffect, useState } from 'react'

export interface Subdomain {
  id: string
  name: string
  description: string
  status: 'active' | 'inactive'
  usersCount: number
}

interface SubdomainListProps {
  onSubdomainSelect?: (subdomain: Subdomain) => void
  authToken?: string
}

export default function SubdomainList({ onSubdomainSelect, authToken }: SubdomainListProps) {
  const [subdomains, setSubdomains] = useState<Subdomain[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchSubdomains()
  }, [])

  const fetchSubdomains = async () => {
    try {
      setLoading(true)
      const headers: Record<string, string> = {}
      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`
      }

      const response = await fetch('http://localhost:9000/api/subdomains', { headers })
      if (!response.ok) {
        throw new Error('Failed to load subdomains')
      }
      const data = await response.json()
      setSubdomains(Array.isArray(data) ? data : [])
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load subdomains')
      setSubdomains([])
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return <div className="subdomain-list loading">Loading subdomains...</div>
  }

  if (error) {
    return <div className="subdomain-list error">Error: {error}</div>
  }

  return (
    <div className="subdomain-list">
      <div className="subdomains-grid">
        {subdomains.length === 0 ? (
          <div className="empty-state">No subdomains available</div>
        ) : (
          subdomains.map(subdomain => (
            <div
              key={subdomain.id}
              className={`subdomain-card ${subdomain.status}`}
              onClick={() => onSubdomainSelect?.(subdomain)}
            >
              <div className="subdomain-header">
                <h3>{subdomain.name}</h3>
                <span className={`status-badge ${subdomain.status}`}>
                  {subdomain.status}
                </span>
              </div>
              <p className="subdomain-description">{subdomain.description}</p>
              <div className="subdomain-meta">
                <span className="users-count">{subdomain.usersCount} users</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

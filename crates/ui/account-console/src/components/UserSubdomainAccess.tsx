import { useEffect, useState } from 'react'

export interface SubdomainAccess {
  id: string
  subdomainId: string
  subdomainName: string
  accessLevel: 'full_access' | 'restricted' | 'read_only'
  grantedAt: string
  expiresAt?: string
  isExpired: boolean
}

interface UserSubdomainAccessProps {
  userId?: string
  userName?: string
  onRevoke?: (subdomainAccessId: string) => void
  authToken?: string
}

export default function UserSubdomainAccess({
  userId,
  userName = 'User',
  onRevoke,
  authToken
}: UserSubdomainAccessProps) {
  const [accesses, setAccesses] = useState<SubdomainAccess[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    if (userId) {
      fetchUserAccess()
    }
  }, [userId])

  const fetchUserAccess = async () => {
    if (!userId) return

    try {
      setLoading(true)
      const headers: Record<string, string> = {}
      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`
      }

      const response = await fetch(
        `http://localhost:9000/api/users/${userId}/subdomains`,
        { headers }
      )

      if (!response.ok) {
        throw new Error('Failed to load subdomain access')
      }

      const data = await response.json()
      setAccesses(Array.isArray(data) ? data : [])
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load subdomain access')
      setAccesses([])
    } finally {
      setLoading(false)
    }
  }

  const handleRevoke = async (accessId: string) => {
    if (!userId || !window.confirm('Are you sure you want to revoke this access?')) {
      return
    }

    try {
      const response = await fetch(
        `http://localhost:9000/api/users/${userId}/subdomains/${accessId}`,
        {
          method: 'DELETE',
          headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
        }
      )

      if (!response.ok) {
        throw new Error('Failed to revoke access')
      }

      setAccesses(prev => prev.filter(a => a.id !== accessId))
      onRevoke?.(accessId)
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to revoke access')
    }
  }

  if (loading) {
    return <div className="user-subdomain-access loading">Loading access information...</div>
  }

  if (error) {
    return <div className="user-subdomain-access error">Error: {error}</div>
  }

  const activeAccesses = accesses.filter(a => !a.isExpired)
  const expiredAccesses = accesses.filter(a => a.isExpired)

  return (
    <div className="user-subdomain-access">
      <div className="access-header">
        <h3>{userName}'s Subdomain Access</h3>
        <span className="access-count">{activeAccesses.length} active</span>
      </div>

      {activeAccesses.length === 0 && expiredAccesses.length === 0 ? (
        <div className="empty-state">No subdomain access grants</div>
      ) : (
        <>
          {activeAccesses.length > 0 && (
            <div className="access-section">
              <h4 className="section-title">Active Access</h4>
              <div className="access-list">
                {activeAccesses.map(access => (
                  <div key={access.id} className="access-item active">
                    <div className="access-info">
                      <div className="access-name">{access.subdomainName}</div>
                      <div className="access-details">
                        <span className={`access-level level-${access.accessLevel}`}>
                          {access.accessLevel.replace('_', ' ')}
                        </span>
                        <span className="granted-date">
                          Granted: {new Date(access.grantedAt).toLocaleDateString()}
                        </span>
                        {access.expiresAt && (
                          <span className="expiry-date">
                            Expires: {new Date(access.expiresAt).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                    </div>
                    <button
                      onClick={() => handleRevoke(access.id)}
                      className="revoke-button"
                    >
                      Revoke
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {expiredAccesses.length > 0 && (
            <div className="access-section">
              <h4 className="section-title">Expired Access</h4>
              <div className="access-list">
                {expiredAccesses.map(access => (
                  <div key={access.id} className="access-item expired">
                    <div className="access-info">
                      <div className="access-name">{access.subdomainName}</div>
                      <div className="access-details">
                        <span className={`access-level level-${access.accessLevel}`}>
                          {access.accessLevel.replace('_', ' ')}
                        </span>
                        <span className="granted-date">
                          Granted: {new Date(access.grantedAt).toLocaleDateString()}
                        </span>
                        {access.expiresAt && (
                          <span className="expiry-date expired-badge">
                            Expired: {new Date(access.expiresAt).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}

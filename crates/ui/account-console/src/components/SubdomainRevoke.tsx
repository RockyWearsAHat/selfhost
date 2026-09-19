import { useState } from 'react'

export interface AccessGrant {
  id: string
  userId: string
  userEmail: string
  subdomainId: string
  subdomainName: string
  accessLevel: string
  grantedAt: string
  expiresAt?: string
}

interface SubdomainRevokeProps {
  subdomainId?: string
  subdomainName?: string
  grants?: AccessGrant[]
  onRevoke?: (grantId: string, userEmail: string) => void
  authToken?: string
  isLoading?: boolean
}

export default function SubdomainRevoke({
  subdomainId,
  subdomainName = 'Subdomain',
  grants = [],
  onRevoke,
  authToken,
  isLoading = false
}: SubdomainRevokeProps) {
  const [revoking, setRevoking] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [localGrants, setLocalGrants] = useState(grants)

  const handleRevoke = async (grantId: string, userEmail: string) => {
    if (!subdomainId) {
      setError('Subdomain ID is required')
      return
    }

    if (!window.confirm(`Revoke access to ${subdomainName} for ${userEmail}?`)) {
      return
    }

    try {
      setRevoking(grantId)
      setError('')

      const response = await fetch(
        `http://localhost:9000/api/subdomains/${subdomainId}/access/${grantId}`,
        {
          method: 'DELETE',
          headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
        }
      )

      if (!response.ok) {
        throw new Error('Failed to revoke access')
      }

      setLocalGrants(prev => prev.filter(g => g.id !== grantId))
      setSuccess(`Access revoked for ${userEmail}`)
      onRevoke?.(grantId, userEmail)

      setTimeout(() => setSuccess(''), 3000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke access')
    } finally {
      setRevoking(null)
    }
  }

  const handleRevokeAll = async () => {
    if (localGrants.length === 0) {
      setError('No access grants to revoke')
      return
    }

    if (!window.confirm(`Revoke access to ${subdomainName} for all ${localGrants.length} user(s)?`)) {
      return
    }

    try {
      setError('')
      let successCount = 0

      for (const grant of localGrants) {
        try {
          const response = await fetch(
            `http://localhost:9000/api/subdomains/${subdomainId}/access/${grant.id}`,
            {
              method: 'DELETE',
              headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
            }
          )

          if (response.ok) {
            successCount++
          }
        } catch (err) {
          console.error(`Failed to revoke access for ${grant.userEmail}:`, err)
        }
      }

      setLocalGrants([])
      setSuccess(`Revoked access for ${successCount} user(s)`)

      setTimeout(() => setSuccess(''), 3000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke access')
    }
  }

  return (
    <div className="subdomain-revoke">
      <div className="revoke-header">
        <h3>Manage Access: {subdomainName}</h3>
        {localGrants.length > 0 && (
          <span className="grant-count">{localGrants.length} grant(s)</span>
        )}
      </div>

      {error && <div className="error-message">{error}</div>}
      {success && <div className="success-message">{success}</div>}

      {localGrants.length === 0 ? (
        <div className="empty-state">
          <p>No users have access to this subdomain</p>
        </div>
      ) : (
        <>
          <div className="grants-table">
            <div className="table-header">
              <div className="col-email">User Email</div>
              <div className="col-level">Access Level</div>
              <div className="col-granted">Granted</div>
              <div className="col-expires">Expires</div>
              <div className="col-action">Action</div>
            </div>

            <div className="table-body">
              {localGrants.map(grant => (
                <div key={grant.id} className="table-row">
                  <div className="col-email">{grant.userEmail}</div>
                  <div className="col-level">
                    <span className={`level-badge level-${grant.accessLevel}`}>
                      {grant.accessLevel.replace('_', ' ')}
                    </span>
                  </div>
                  <div className="col-granted">
                    {new Date(grant.grantedAt).toLocaleDateString()}
                  </div>
                  <div className="col-expires">
                    {grant.expiresAt
                      ? new Date(grant.expiresAt).toLocaleDateString()
                      : 'Never'}
                  </div>
                  <div className="col-action">
                    <button
                      onClick={() => handleRevoke(grant.id, grant.userEmail)}
                      disabled={revoking === grant.id || isLoading}
                      className="revoke-item-button"
                    >
                      {revoking === grant.id ? 'Revoking...' : 'Revoke'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {localGrants.length > 1 && (
            <div className="bulk-actions">
              <button
                onClick={handleRevokeAll}
                disabled={revoking !== null || isLoading}
                className="revoke-all-button"
              >
                Revoke All Access
              </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}

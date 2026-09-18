import { useEffect, useState } from 'react'

export interface User {
  id: string
  email: string
  status: 'pending' | 'active' | 'inactive'
}

export interface Subdomain {
  id: string
  name: string
  description: string
}

interface GrantSubdomainAccessProps {
  users: User[]
  subdomains: Subdomain[]
  onGrant?: (userId: string, subdomainId: string, accessLevel: string, expiresAt?: string) => void
  authToken?: string
  isLoading?: boolean
}

export default function GrantSubdomainAccess({
  users,
  subdomains,
  onGrant,
  authToken,
  isLoading = false
}: GrantSubdomainAccessProps) {
  const [selectedUser, setSelectedUser] = useState('')
  const [selectedSubdomains, setSelectedSubdomains] = useState<string[]>([])
  const [accessLevel, setAccessLevel] = useState('full_access')
  const [expiresAt, setExpiresAt] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const handleSubdomainToggle = (subdomainId: string) => {
    setSelectedSubdomains(prev =>
      prev.includes(subdomainId)
        ? prev.filter(id => id !== subdomainId)
        : [...prev, subdomainId]
    )
  }

  const handleGrant = async () => {
    setError('')
    setSuccess('')

    if (!selectedUser || selectedSubdomains.length === 0) {
      setError('Please select a user and at least one subdomain')
      return
    }

    try {
      setSubmitting(true)

      const payload = {
        subdomain_ids: selectedSubdomains,
        access_level: accessLevel,
        ...(expiresAt && { expires_in: Math.floor((new Date(expiresAt).getTime() - Date.now()) / 1000) })
      }

      const response = await fetch(
        `http://localhost:9000/api/users/${selectedUser}/subdomains`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(authToken && { 'Authorization': `Bearer ${authToken}` })
          },
          body: JSON.stringify(payload)
        }
      )

      if (!response.ok) {
        throw new Error(`Failed to grant access to subdomains`)
      }

      for (const subdomainId of selectedSubdomains) {
        onGrant?.(selectedUser, subdomainId, accessLevel, expiresAt)
      }

      setSuccess(`Access granted to ${selectedSubdomains.length} subdomain(s)`)
      setSelectedUser('')
      setSelectedSubdomains([])
      setAccessLevel('full_access')
      setExpiresAt('')

      setTimeout(() => setSuccess(''), 3000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to grant access')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="grant-subdomain-access">
      <div className="form-group">
        <label htmlFor="user-select">Select User</label>
        <select
          id="user-select"
          value={selectedUser}
          onChange={(e) => setSelectedUser(e.target.value)}
          disabled={submitting}
        >
          <option value="">Choose a user...</option>
          {users.map(user => (
            <option key={user.id} value={user.id}>
              {user.email} ({user.status})
            </option>
          ))}
        </select>
      </div>

      <div className="form-group">
        <label>Select Subdomains</label>
        <div className="checkboxes-group">
          {subdomains.length === 0 ? (
            <p className="no-items">No subdomains available</p>
          ) : (
            subdomains.map(subdomain => (
              <div key={subdomain.id} className="checkbox-item">
                <input
                  type="checkbox"
                  id={`subdomain-${subdomain.id}`}
                  checked={selectedSubdomains.includes(subdomain.id)}
                  onChange={() => handleSubdomainToggle(subdomain.id)}
                  disabled={submitting}
                />
                <label htmlFor={`subdomain-${subdomain.id}`}>
                  <strong>{subdomain.name}</strong>
                  <span className="description">{subdomain.description}</span>
                </label>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="form-row">
        <div className="form-group">
          <label htmlFor="access-level">Access Level</label>
          <select
            id="access-level"
            value={accessLevel}
            onChange={(e) => setAccessLevel(e.target.value)}
            disabled={submitting}
          >
            <option value="full_access">Full Access</option>
            <option value="restricted">Restricted</option>
            <option value="read_only">Read Only</option>
          </select>
        </div>

        <div className="form-group">
          <label htmlFor="expires-at">Expiration Date (Optional)</label>
          <input
            id="expires-at"
            type="datetime-local"
            value={expiresAt}
            onChange={(e) => setExpiresAt(e.target.value)}
            disabled={submitting}
          />
        </div>
      </div>

      {error && <div className="error-message">{error}</div>}
      {success && <div className="success-message">{success}</div>}

      <button
        onClick={handleGrant}
        disabled={submitting || isLoading}
        className="grant-button"
      >
        {submitting ? 'Granting...' : 'Grant Access'}
      </button>
    </div>
  )
}

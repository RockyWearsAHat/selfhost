import { useEffect, useState } from 'react'
import '../styles/common.css'
import SubdomainList from '../components/SubdomainList'
import GrantSubdomainAccess from '../components/GrantSubdomainAccess'
import UserSubdomainAccess from '../components/UserSubdomainAccess'
import SubdomainRevoke from '../components/SubdomainRevoke'

export default function AdminDashboard({ auth, onLogout }: any) {
  const [users, setUsers] = useState<any[]>([])
  const [locations, setLocations] = useState<any[]>([])
  const [subdomains, setSubdomains] = useState<any[]>([])
  const [selectedUser, setSelectedUser] = useState<string>('')
  const [selectedSubdomain, setSelectedSubdomain] = useState<string>('')
  const [perm, setPerm] = useState({ location: '', action: 'read' })
  const [activeTab, setActiveTab] = useState<'users' | 'permissions' | 'subdomains'>('users')

  useEffect(() => {
    fetch('http://localhost:9000/api/users', {
      headers: { 'Authorization': `Bearer ${auth.token}` }
    })
    .then(r => r.json())
    .then(data => Array.isArray(data) ? setUsers(data) : alert('Error: ' + (data.error || 'Failed to load users')))
    .catch(err => alert('Error: ' + err.message))

    fetch('http://localhost:9000/api/vpn/locations')
      .then(r => r.json())
      .then(data => Array.isArray(data) ? setLocations(data) : console.error(data))
      .catch(err => console.error(err))

    fetch('http://localhost:9000/api/subdomains', {
      headers: { 'Authorization': `Bearer ${auth.token}` }
    })
      .then(r => r.json())
      .then(data => Array.isArray(data) ? setSubdomains(data) : console.error(data))
      .catch(err => console.error(err))
  }, [])

  const approveUser = async (userId: string) => {
    await fetch(`http://localhost:9000/api/users/${userId}/approve`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${auth.token}` }
    })
    setUsers(users.map(u => u.id === userId ? {...u, status: 'active'} : u))
  }

  const grantPermission = async () => {
    if (!selectedUser || !perm.location) return
    await fetch(`http://localhost:9000/api/users/${selectedUser}/permissions`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${auth.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ resource_type: 'vpn_location', resource_id: perm.location, action: perm.action })
    })
    alert('Permission granted!')
  }

  return (
    <div className="dashboard">
      <nav className="navbar">
        <h1>Admin Console</h1>
        <div><span>{auth.email}</span> <button onClick={onLogout}>Logout</button></div>
      </nav>

      <div className="tabs-navigation">
        <button
          className={`tab-button ${activeTab === 'users' ? 'active' : ''}`}
          onClick={() => setActiveTab('users')}
        >
          Users & Permissions
        </button>
        <button
          className={`tab-button ${activeTab === 'subdomains' ? 'active' : ''}`}
          onClick={() => setActiveTab('subdomains')}
        >
          Subdomain Access
        </button>
      </div>

      <div className="container">
        {activeTab === 'users' && (
          <div className="admin-grid">
            <div className="section">
              <h2>Pending Users</h2>
              <div className="users-list">
                {users.filter(u => u.status === 'pending').map(u => (
                  <div key={u.id} className="user-item">
                    <div><strong>{u.email}</strong> <span className="status">{u.status}</span></div>
                    <button onClick={() => approveUser(u.id)}>Approve</button>
                  </div>
                ))}
              </div>
            </div>

            <div className="section">
              <h2>Grant Permissions</h2>
              <select value={selectedUser} onChange={(e) => setSelectedUser(e.target.value)}>
                <option value="">Select User</option>
                {users.map(u => (
                  <option key={u.id} value={u.id}>{u.email}</option>
                ))}
              </select>
              <select value={perm.location} onChange={(e) => setPerm({...perm, location: e.target.value})}>
                <option value="">Select Location</option>
                {locations.map(loc => (
                  <option key={loc.id} value={loc.id}>{loc.name}</option>
                ))}
              </select>
              <button onClick={grantPermission}>Grant Access</button>
            </div>

            <div className="section">
              <h2>Active Users</h2>
              <div className="users-list">
                {users.filter(u => u.status === 'active').map(u => (
                  <div key={u.id} className="user-item">
                    <div><strong>{u.email}</strong></div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'subdomains' && (
          <div className="subdomains-section">
            <div className="subdomains-container">
              <div className="subdomain-section-split">
                <div className="subdomain-panel">
                  <div className="section">
                    <h2>Available Subdomains</h2>
                    <SubdomainList
                      authToken={auth.token}
                      onSubdomainSelect={(subdomain) => setSelectedSubdomain(subdomain.id)}
                    />
                  </div>
                </div>

                <div className="subdomain-panel">
                  <div className="section">
                    <h2>Grant Subdomain Access</h2>
                    <GrantSubdomainAccess
                      users={users}
                      subdomains={subdomains}
                      authToken={auth.token}
                      onGrant={() => {
                        setSelectedUser('')
                        setSelectedSubdomain('')
                      }}
                    />
                  </div>
                </div>
              </div>

              <div className="subdomain-section-full">
                <div className="section">
                  <h2>Access Management</h2>
                  {selectedUser ? (
                    <UserSubdomainAccess
                      userId={selectedUser}
                      userName={users.find(u => u.id === selectedUser)?.email || 'User'}
                      authToken={auth.token}
                    />
                  ) : selectedSubdomain ? (
                    <SubdomainRevoke
                      subdomainId={selectedSubdomain}
                      subdomainName={subdomains.find(s => s.id === selectedSubdomain)?.name || 'Subdomain'}
                      authToken={auth.token}
                    />
                  ) : (
                    <div className="empty-selection">
                      <p>Select a user or subdomain to manage access</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

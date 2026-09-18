import { useEffect, useState } from 'react'
import '../styles/common.css'

export default function AdminDashboard({ auth, onLogout }: any) {
  const [users, setUsers] = useState<any[]>([])
  const [locations, setLocations] = useState<any[]>([])
  const [selectedUser, setSelectedUser] = useState<string>('')
  const [perm, setPerm] = useState({ location: '', action: 'read' })

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
      <div className="container">
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
      </div>
    </div>
  )
}

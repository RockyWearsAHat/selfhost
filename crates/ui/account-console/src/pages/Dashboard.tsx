import { useEffect, useState } from 'react'
import '../styles/common.css'

export default function Dashboard({ auth, onLogout }: any) {
  const [locations, setLocations] = useState<any[]>([])

  useEffect(() => {
    fetch('http://localhost:9000/api/vpn/locations')
      .then(r => r.json())
      .then(setLocations)
  }, [])

  return (
    <div className="dashboard">
      <nav className="navbar">
        <h1>Account Console</h1>
        <div><span>{auth.email}</span> <button onClick={onLogout}>Logout</button></div>
      </nav>
      <div className="container">
        <h2>Available VPN Locations</h2>
        <div className="locations">
          {locations.map((loc: any) => (
            <div key={loc.id} className="location-card">
              <h3>{loc.name}</h3>
              <p>{loc.region}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

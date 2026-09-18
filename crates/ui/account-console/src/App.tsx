import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import './App.css'
import Register from './pages/Register'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import AdminDashboard from './pages/AdminDashboard'

export default function App() {
  const [auth, setAuth] = useState<{token: string, email: string, is_admin: boolean} | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (token) {
      fetch('http://localhost:9000/api/whoami', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      .then(r => r.json())
      .then(data => {
        setAuth({ token, email: data.email, is_admin: data.is_admin })
      })
      .catch(() => localStorage.removeItem('token'))
      .finally(() => setLoading(false))
    } else {
      setLoading(false)
    }
  }, [])

  if (loading) return <div className="loading">Loading...</div>

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={auth ? (auth.is_admin ? <Navigate to="/admin" /> : <Navigate to="/dashboard" />) : <Navigate to="/login" />} />
        <Route path="/register" element={<Register onSuccess={(token, email, is_admin) => { setAuth({token, email, is_admin}); localStorage.setItem('token', token) }} />} />
        <Route path="/login" element={<Login onSuccess={(token, email, is_admin) => { setAuth({token, email, is_admin}); localStorage.setItem('token', token) }} />} />
        <Route path="/dashboard" element={auth ? <Dashboard auth={auth} onLogout={() => { setAuth(null); localStorage.removeItem('token') }} /> : <Navigate to="/login" />} />
        <Route path="/admin" element={auth?.is_admin ? <AdminDashboard auth={auth} onLogout={() => { setAuth(null); localStorage.removeItem('token') }} /> : <Navigate to="/login" />} />
      </Routes>
    </BrowserRouter>
  )
}

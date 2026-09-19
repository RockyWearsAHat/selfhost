import axios from 'axios'
const API_URL = 'http://localhost:9000/api'
export const api = axios.create({ baseURL: API_URL })
export const auth = { login: (email: string) => api.post('/auth/authenticate', {email}), register: (email: string) => api.post('/auth/register', {email}) }

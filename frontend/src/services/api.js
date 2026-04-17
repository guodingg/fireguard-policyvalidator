/**
 * API 服务 - 连接后端
 */

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'

class APIService {
  constructor() {
    this.baseURL = API_BASE_URL
    this.token = localStorage.getItem('token')
  }

  setToken(token) {
    this.token = token
    if (token) {
      localStorage.setItem('token', token)
    } else {
      localStorage.removeItem('token')
    }
  }

  async request(path, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    }

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`
    }

    const response = await fetch(`${this.baseURL}${path}`, {
      ...options,
      headers
    })

    if (response.status === 401) {
      this.setToken(null)
      window.location.href = '/login'
      throw new Error('认证过期')
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: '请求失败' }))
      throw new Error(error.detail || '请求失败')
    }

    return response.json()
  }

  // Auth
  async login(username, password) {
    const formData = new URLSearchParams()
    formData.append('username', username)
    formData.append('password', password)

    const response = await fetch(`${this.baseURL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: formData
    })

    if (!response.ok) {
      throw new Error('用户名或密码错误')
    }

    const data = await response.json()
    this.setToken(data.access_token)
    return data
  }

  async getMe() {
    return this.request('/auth/me')
  }

  async logout() {
    this.setToken(null)
  }

  // Dashboard
  async getDashboardStats() {
    return this.request('/dashboard/stats')
  }

  async getScanTrend(days = 7) {
    return this.request(`/dashboard/trend?days=${days}`)
  }

  // Tasks
  async getTasks(params = {}) {
    const query = new URLSearchParams(params)
    return this.request(`/scan/tasks/?${query}`)
  }

  async getTask(id) {
    return this.request(`/scan/tasks/${id}`)
  }

  async createTask(data) {
    return this.request('/scan/tasks/', {
      method: 'POST',
      body: JSON.stringify(data)
    })
  }

  async startTask(id) {
    return this.request(`/scan/tasks/${id}/start`, { method: 'POST' })
  }

  async pauseTask(id) {
    return this.request(`/scan/tasks/${id}/pause`, { method: 'POST' })
  }

  async deleteTask(id) {
    return this.request(`/scan/tasks/${id}`, { method: 'DELETE' })
  }

  async getTaskProgress(id) {
    return this.request(`/scan/tasks/${id}/progress`)
  }

  // Assets
  async getAssets(params = {}) {
    const query = new URLSearchParams(params)
    return this.request(`/assets/?${query}`)
  }

  async getAssetStats() {
    return this.request('/assets/stats/summary')
  }

  // Vulns
  async getVulns(params = {}) {
    const query = new URLSearchParams(params)
    return this.request(`/vulns/?${query}`)
  }

  async verifyVuln(id) {
    return this.request(`/vulns/${id}/verify`, { method: 'PUT' })
  }

  async fixVuln(id) {
    return this.request(`/vulns/${id}/fix`, { method: 'PUT' })
  }

  async markFalsePositive(id) {
    return this.request(`/vulns/${id}/false-positive`, { method: 'PUT' })
  }

  // POC
  async getPOCs(params = {}) {
    const query = new URLSearchParams(params)
    return this.request(`/pocs/?${query}`)
  }

  // Reports
  async getReports(params = {}) {
    const query = new URLSearchParams(params)
    return this.request(`/reports/?${query}`)
  }

  async generateReport(taskId, type = 'markdown') {
    return this.request(`/reports/generate?task_id=${taskId}&report_type=${type}`, {
      method: 'POST'
    })
  }

  // Logs
  async getLogs(params = {}) {
    const query = new URLSearchParams(params)
    return this.request(`/logs/?${query}`)
  }

  // AI
  async analyzeVulnerability(vulnData) {
    return this.request('/ai/analyze/vulnerability', {
      method: 'POST',
      body: JSON.stringify(vulnData)
    })
  }

  async generatePOC(vulnDescription, target) {
    return this.request('/ai/generate/poc', {
      method: 'POST',
      body: JSON.stringify({ vuln_description: vulnDescription, target })
    })
  }

  // Users
  async getUsers() {
    return this.request('/users/')
  }

  async createUser(data) {
    return this.request('/users/', {
      method: 'POST',
      body: JSON.stringify(data)
    })
  }

  async updateUser(id, data) {
    return this.request(`/users/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    })
  }

  async deleteUser(id) {
    return this.request(`/users/${id}`, { method: 'DELETE' })
  }
}

export const api = new APIService()
export default api

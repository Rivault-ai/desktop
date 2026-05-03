export interface SearchResult {
  id: string
  available: boolean
  sensitivityLevel: number
}

export interface SearchResponse {
  results: SearchResult[]
}

export type GetSecretResponse =
  | { value: string; label: string }
  | { requires_auth: true; sensitivity_level: number; label: string }

export interface AuthRequestResponse {
  authRequestId: string
  authUrl: string
  expiresAt: string
  agentMessage: string
}

export interface AuthStatusResponse {
  status: 'pending' | 'approved' | 'denied' | 'expired'
  value?: string
}

export interface FormRequestResponse {
  formRequestId: string
  formUrl: string
  expiresAt: string
  agentMessage: string
}

export interface FormStatusResponse {
  status: 'pending' | 'submitted' | 'expired'
  itemId?: string
}

export interface HybridRequestResponse {
  hybridRequestId: string
  hybridUrl: string
  expiresAt: string
  agentMessage: string
}

export interface HybridStatusResponse {
  status: 'pending' | 'submitted' | 'expired'
  formValues?: Record<string, string>
  authorizedValues?: Record<string, string>
  createdItemIds?: string[]
}

export interface MeResponse {
  userId: string
  apiKeyId: string | null
}

export class RivaultClient {
  private baseUrl: string
  private apiKey: string
  private identity: Promise<MeResponse> | null = null

  constructor(apiKey: string, baseUrl = 'https://api.rivault.ai') {
    this.apiKey = apiKey
    this.baseUrl = baseUrl
  }

  getApiKey(): string { return this.apiKey }
  getBaseUrl(): string { return this.baseUrl }

  /** Cached identity for daemon release events. Best-effort: any failure swallowed. */
  async identityCached(): Promise<MeResponse | null> {
    if (!this.identity) {
      this.identity = this.me().catch(() => ({ userId: '', apiKeyId: null }) as MeResponse)
    }
    const r = await this.identity
    return r.userId ? r : null
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${path}`
    const res = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
        ...(options.headers ?? {}),
      },
      signal: AbortSignal.timeout(15_000),
    })
    if (!res.ok) {
      let message = `HTTP ${res.status}`
      try {
        const body = await res.json()
        message = body.error ?? message
      } catch {}
      throw new Error(`Rivault API error: ${message}`)
    }
    return res.json()
  }

  async search(query: string): Promise<SearchResponse> {
    const params = new URLSearchParams({ q: query })
    return this.request(`/agent/vault/search?${params}`)
  }

  async getSecret(itemId: string): Promise<GetSecretResponse> {
    return this.request(`/agent/vault/${itemId}`)
  }

  async requestAuth(itemId: string, reason?: string, callbackSessionId?: string): Promise<AuthRequestResponse> {
    return this.request('/agent/auth-request', {
      method: 'POST',
      body: JSON.stringify({ itemId, reason, callbackSessionId }),
    })
  }

  async pollAuth(authRequestId: string): Promise<AuthStatusResponse> {
    return this.request(`/agent/auth-request/${authRequestId}/status`)
  }

  async requestForm(
    requestedLabel: string,
    requestedCategory: string,
    reason?: string,
    callbackSessionId?: string,
  ): Promise<FormRequestResponse> {
    return this.request('/agent/form-request', {
      method: 'POST',
      body: JSON.stringify({ requestedLabel, requestedCategory, reason, callbackSessionId }),
    })
  }

  async pollForm(formRequestId: string): Promise<FormStatusResponse> {
    return this.request(`/agent/form-request/${formRequestId}/status`)
  }

  async requestHybrid(
    formFields: Array<{ key: string; label: string }>,
    authItemIds: string[],
    reason?: string,
    callbackSessionId?: string,
  ): Promise<HybridRequestResponse> {
    return this.request('/agent/hybrid-request', {
      method: 'POST',
      body: JSON.stringify({ formFields, authItemIds, reason, callbackSessionId }),
    })
  }

  async pollHybrid(hybridRequestId: string): Promise<HybridStatusResponse> {
    return this.request(`/agent/hybrid-request/${hybridRequestId}/status`)
  }

  async me(): Promise<MeResponse> {
    return this.request('/agent/me')
  }
}

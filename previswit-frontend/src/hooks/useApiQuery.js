/**
 * PreviSwit — Hook: useApiQuery
 * Wrapper de fetch para chamadas à API REST do servidor.
 */
import { useState, useCallback } from 'react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:10000/api/v1';

/**
 * Realiza uma chamada à API REST da PreviSwit.
 * @param {string} endpoint - Caminho relativo (ex: '/findings')
 * @param {object} options  - Opções do fetch (method, body, headers)
 * @returns {{ data, loading, error, execute }}
 */
export function useApiQuery(endpoint, options = {}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const execute = useCallback(async (overrideOptions = {}) => {
    setLoading(true);
    setError(null);

    try {
      const token = localStorage.getItem('previswit_token');
      const mergedOptions = {
        ...options,
        ...overrideOptions,
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...options.headers,
          ...overrideOptions.headers,
        },
      };

      if (mergedOptions.body && typeof mergedOptions.body !== 'string') {
        mergedOptions.body = JSON.stringify(mergedOptions.body);
      }

      const response = await fetch(`${API_BASE}${endpoint}`, mergedOptions);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: response.statusText }));
        throw new Error(errorData.detail || `HTTP ${response.status}`);
      }

      const result = await response.json();
      setData(result);
      return result;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [endpoint, JSON.stringify(options)]);

  return { data, loading, error, execute };
}

/**
 * Utilitário para chamadas REST diretas (sem hook React).
 */
export async function apiFetch(endpoint, options = {}) {
  const token = localStorage.getItem('previswit_token');
  const response = await fetch(`${API_BASE}${endpoint}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...options,
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }
  return response.json();
}

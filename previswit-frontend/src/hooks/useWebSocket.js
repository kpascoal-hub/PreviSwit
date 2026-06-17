/**
 * PreviSwit — Hook: useWebSocket
 * Gerencia conexão WebSocket com reconexão automática exponencial.
 */
import { useEffect, useRef, useState, useCallback } from 'react';

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:10000';

/**
 * @param {string} path - Caminho do WebSocket, ex: '/ws/web_dashboard'
 * @param {Function} onMessage - Callback chamado com cada mensagem JSON recebida
 * @returns {{ status, send, logs }}
 */
export function useWebSocket(path, onMessage) {
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const reconnectAttemptsRef = useRef(0);
  const MAX_RECONNECT_ATTEMPTS = 8;
  const BASE_DELAY_MS = 1000;

  const [status, setStatus] = useState('disconnected'); // connecting, connected, disconnected, error
  const [logs, setLogs] = useState([]);

  const addLog = useCallback((text, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString('pt-BR');
    setLogs(prev => [...prev.slice(-200), { text, type, timestamp, id: Date.now() }]);
  }, []);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    setStatus('connecting');
    const url = `${WS_URL}${path}`;

    try {
      wsRef.current = new WebSocket(url);

      wsRef.current.onopen = () => {
        setStatus('connected');
        reconnectAttemptsRef.current = 0;
        addLog('Conectado ao servidor PreviSwit.', 'system');
      };

      wsRef.current.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.action === 'LOG') addLog(msg.message, 'info');
          onMessage?.(msg);
        } catch {
          addLog(`Mensagem inválida: ${event.data}`, 'error');
        }
      };

      wsRef.current.onerror = () => {
        setStatus('error');
        addLog('Erro na conexão WebSocket.', 'error');
      };

      wsRef.current.onclose = (e) => {
        setStatus('disconnected');
        addLog(`Conexão encerrada (code: ${e.code}).`, 'system');

        // Reconexão exponencial
        if (reconnectAttemptsRef.current < MAX_RECONNECT_ATTEMPTS) {
          const delay = BASE_DELAY_MS * Math.pow(2, reconnectAttemptsRef.current);
          reconnectAttemptsRef.current += 1;
          addLog(`Reconectando em ${delay / 1000}s... (tentativa ${reconnectAttemptsRef.current})`, 'system');
          reconnectTimeoutRef.current = setTimeout(connect, delay);
        } else {
          addLog('Máximo de tentativas de reconexão atingido.', 'error');
        }
      };
    } catch (err) {
      setStatus('error');
      addLog(`Falha ao iniciar WebSocket: ${err.message}`, 'error');
    }
  }, [path, onMessage, addLog]);

  const send = useCallback((data) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
      return true;
    }
    addLog('Não conectado ao servidor.', 'error');
    return false;
  }, [addLog]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimeoutRef.current);
      wsRef.current?.close(1000, 'Component unmounted');
    };
  }, [connect]);

  return { status, send, logs, addLog };
}

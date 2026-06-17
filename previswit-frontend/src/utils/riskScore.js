/**
 * PreviSwit — Utils: riskScore.js
 * Cálculo e mapeamento do score de risco da organização.
 */

/**
 * Calcula o risk score (0-100) a partir de um objeto de contagens de findings.
 * @param {{ CRITICAL: number, HIGH: number, MEDIUM: number, LOW: number }} counts
 * @returns {number}
 */
export function calculateRiskScore({ CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0 } = {}) {
  const raw = CRITICAL * 25 + HIGH * 10 + MEDIUM * 3 + LOW * 1;
  return Math.min(100, parseFloat((raw * 0.5).toFixed(1)));
}

/**
 * Retorna a configuração visual de um score de risco.
 * @param {number} score
 * @returns {{ level: string, label: string, color: string, description: string }}
 */
export function getRiskConfig(score) {
  if (score >= 75) return {
    level: 'CRITICAL',
    label: 'Crítico',
    color: '#ef4444',
    gradientFrom: '#7f1d1d',
    gradientTo: '#ef4444',
    description: '🔴 Intervenção de emergência necessária.',
  };
  if (score >= 50) return {
    level: 'HIGH',
    label: 'Alto',
    color: '#f97316',
    gradientFrom: '#7c2d12',
    gradientTo: '#f97316',
    description: '🟠 Ação imediata recomendada.',
  };
  if (score >= 25) return {
    level: 'MEDIUM',
    label: 'Médio',
    color: '#eab308',
    gradientFrom: '#713f12',
    gradientTo: '#eab308',
    description: '🟡 Vulnerabilidades requerem atenção.',
  };
  return {
    level: 'LOW',
    label: 'Baixo',
    color: '#22c55e',
    gradientFrom: '#14532d',
    gradientTo: '#22c55e',
    description: '🟢 Postura de segurança satisfatória.',
  };
}

/**
 * Calcula a tendência (improving / stable / worsening) entre dois scores.
 * @param {number} currentScore
 * @param {number} previousScore
 * @returns {'improving' | 'stable' | 'worsening'}
 */
export function calculateTrend(currentScore, previousScore) {
  const delta = currentScore - previousScore;
  if (delta > 5) return 'worsening';
  if (delta < -5) return 'improving';
  return 'stable';
}

export const TREND_CONFIG = {
  improving: { label: 'Melhorando', icon: '↓', textClass: 'text-green-400' },
  stable:    { label: 'Estável',    icon: '→', textClass: 'text-blue-400' },
  worsening: { label: 'Piorando',   icon: '↑', textClass: 'text-red-400' },
};

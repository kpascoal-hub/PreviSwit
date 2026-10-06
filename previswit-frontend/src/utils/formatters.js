/*
 * PreviSwit AI-ASPM
 * Copyright (C) 2026 PreviSwit Team
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
/**
 * PreviSwit — Utils: formatters.js
 * Formatadores de datas, números, CVSS e duração.
 */

/**
 * Formata uma data ISO 8601 para exibição em pt-BR.
 * @param {string} isoString
 * @param {boolean} includeTime
 */
export function formatDate(isoString, includeTime = false) {
  if (!isoString) return '—';
  try {
    const date = new Date(isoString);
    if (isNaN(date)) return isoString;
    const opts = {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      ...(includeTime ? { hour: '2-digit', minute: '2-digit' } : {}),
    };
    return date.toLocaleDateString('pt-BR', opts);
  } catch {
    return isoString;
  }
}

/**
 * Formata uma duração em segundos para string legível.
 * @param {number} seconds
 */
export function formatDuration(seconds) {
  if (!seconds || seconds < 0) return '—';
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

/**
 * Formata um score CVSS com cor semântica.
 * @param {number} score
 * @returns {{ label: string, color: string }}
 */
export function formatCvss(score) {
  if (!score && score !== 0) return { label: 'N/A', color: '#6b7280' };
  const s = parseFloat(score);
  if (s >= 9.0) return { label: s.toFixed(1), color: '#ef4444' };
  if (s >= 7.0) return { label: s.toFixed(1), color: '#f97316' };
  if (s >= 4.0) return { label: s.toFixed(1), color: '#eab308' };
  return { label: s.toFixed(1), color: '#22c55e' };
}

/**
 * Formata um número grande com sufixo (1K, 1M).
 * @param {number} num
 */
export function formatNumber(num) {
  if (num === null || num === undefined) return '0';
  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(1)}M`;
  if (num >= 1_000) return `${(num / 1_000).toFixed(1)}K`;
  return String(num);
}

/**
 * Formata dias restantes de SLA.
 * @param {number} daysRemaining
 * @returns {{ label: string, textClass: string }}
 */
export function formatSla(daysRemaining) {
  if (daysRemaining === null || daysRemaining === undefined) {
    return { label: 'N/A', textClass: 'text-gray-400' };
  }
  if (daysRemaining < 0) {
    return { label: `Vencido há ${Math.abs(daysRemaining)}d`, textClass: 'text-red-400' };
  }
  if (daysRemaining === 0) {
    return { label: 'Vence hoje', textClass: 'text-orange-400' };
  }
  if (daysRemaining <= 7) {
    return { label: `${daysRemaining}d restantes`, textClass: 'text-yellow-400' };
  }
  return { label: `${daysRemaining}d restantes`, textClass: 'text-green-400' };
}

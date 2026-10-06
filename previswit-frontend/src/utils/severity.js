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
 * PreviSwit — Utils: severity.js
 * Mapeamento de cores, labels e pesos para severidades de findings.
 */

export const SEVERITY_CONFIG = {
  CRITICAL: {
    label: 'Crítico',
    color: '#ef4444',
    bgClass: 'bg-red-500/20',
    textClass: 'text-red-400',
    borderClass: 'border-red-500/40',
    glow: 'drop-shadow-[0_0_12px_rgba(239,68,68,0.6)]',
    weight: 25,
    order: 0,
  },
  HIGH: {
    label: 'Alto',
    color: '#f97316',
    bgClass: 'bg-orange-500/20',
    textClass: 'text-orange-400',
    borderClass: 'border-orange-500/40',
    glow: 'drop-shadow-[0_0_12px_rgba(249,115,22,0.5)]',
    weight: 10,
    order: 1,
  },
  MEDIUM: {
    label: 'Médio',
    color: '#eab308',
    bgClass: 'bg-yellow-500/20',
    textClass: 'text-yellow-400',
    borderClass: 'border-yellow-500/40',
    glow: 'drop-shadow-[0_0_12px_rgba(234,179,8,0.4)]',
    weight: 3,
    order: 2,
  },
  LOW: {
    label: 'Baixo',
    color: '#22c55e',
    bgClass: 'bg-green-500/20',
    textClass: 'text-green-400',
    borderClass: 'border-green-500/40',
    glow: '',
    weight: 1,
    order: 3,
  },
  INFO: {
    label: 'Info',
    color: '#3b82f6',
    bgClass: 'bg-blue-500/20',
    textClass: 'text-blue-400',
    borderClass: 'border-blue-500/40',
    glow: '',
    weight: 0,
    order: 4,
  },
};

export function getSeverityConfig(severity) {
  return SEVERITY_CONFIG[severity?.toUpperCase()] || SEVERITY_CONFIG.INFO;
}

export const STATUS_CONFIG = {
  open: { label: 'Aberto', textClass: 'text-red-400', dotClass: 'bg-red-500' },
  in_remediation: { label: 'Em Remediação', textClass: 'text-yellow-400', dotClass: 'bg-yellow-500' },
  verified: { label: 'Verificado', textClass: 'text-blue-400', dotClass: 'bg-blue-500' },
  closed: { label: 'Fechado', textClass: 'text-green-400', dotClass: 'bg-green-500' },
  false_positive: { label: 'Falso Positivo', textClass: 'text-gray-400', dotClass: 'bg-gray-500' },
};

export function getStatusConfig(status) {
  return STATUS_CONFIG[status] || STATUS_CONFIG.open;
}

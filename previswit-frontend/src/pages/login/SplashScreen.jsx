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
import React from 'react';
import { BrainCircuit } from 'lucide-react';

export default function SplashScreen() {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ animation: 'splashBg 1.5s ease-in-out forwards', background: '#060b13' }}
    >
      {/* Radial glow */}
      <div
        className="absolute rounded-full pointer-events-none"
        style={{
          width: 360,
          height: 360,
          animation: 'splashGlow 1.5s ease-in-out forwards',
          background: 'radial-gradient(circle, rgba(59,130,246,0.18) 0%, rgba(139,92,246,0.1) 45%, transparent 70%)',
        }}
      />

      {/* Icon */}
      <div style={{ animation: 'splashBot 1.5s ease-in-out forwards' }}>
        <BrainCircuit style={{ width: 96, height: 96, color: '#60a5fa' }} />
      </div>

      <style>{`
        @keyframes splashBot {
          0%   { opacity: 0; transform: scale(0.3); }
          22%  { opacity: 1; transform: scale(1.1);  filter: drop-shadow(0 0 10px #3b82f6); }
          45%  { opacity: 1; transform: scale(1);    filter: drop-shadow(0 0 24px #3b82f6); }
          68%  { opacity: 1; transform: scale(1.06); filter: drop-shadow(0 0 40px #3b82f6) drop-shadow(0 0 60px #8b5cf6); }
          85%  { opacity: 1; transform: scale(1);    filter: drop-shadow(0 0 18px #3b82f6); }
          100% { opacity: 0; transform: scale(1.3);  filter: none; }
        }
        @keyframes splashGlow {
          0%   { opacity: 0; transform: scale(0.4); }
          40%  { opacity: 1; transform: scale(1); }
          75%  { opacity: 0.6; transform: scale(1.6); }
          100% { opacity: 0; transform: scale(2.2); }
        }
        @keyframes splashBg {
          0%, 83% { opacity: 1; }
          100%    { opacity: 0; }
        }
      `}</style>
    </div>
  );
}

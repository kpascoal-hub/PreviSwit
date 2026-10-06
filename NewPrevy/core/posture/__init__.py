# PreviSwit AI-ASPM
# Copyright (C) 2026 PreviSwit Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""
PreviSwit AI-ASPM — core.posture
=================================
Engine de postura de risco, conformidade e simulação de investimento.

Todos os módulos deste pacote são FUNÇÕES PURAS de `list[finding]`.
Nenhum importa FastAPI. Isso torna o engine testável sem HTTP e garante
que o "depois" do simulador seja calculado exatamente pelo mesmo caminho
que o "agora" do snapshot — sem bookkeeping de delta que pode divergir.

Camadas:
    normalize   canonicalização/dedup + multiplicadores de idade e exploit
    taxonomy    12 famílias de controle + classificador determinístico
    frameworks  catálogos dos 7 frameworks + cálculo de conformidade
    scoring     exposição R, curva de score, saúde de controle
    packages    agrupamento de remediação + modelo de custo
    simulator   knapsack 0/1 + montagem antes/depois
    feeds       CISA/NVD/KEV + cache + timeline regulatória
    store       CRUD flat-JSON atômico
    prompts     construtor de prompt aterrado para a IA
"""

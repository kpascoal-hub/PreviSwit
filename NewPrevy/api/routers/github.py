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
# GitHub integration router

from fastapi import APIRouter, HTTPException, Header
import httpx
import os
from datetime import datetime
from typing import Optional

router = APIRouter(prefix="/github", tags=["GitHub"])

@router.get("/repos", summary="List GitHub repositories for the authenticated user")
async def list_github_repos(x_github_token: Optional[str] = Header(None)):
    """Fetch the authenticated user's repositories from GitHub.
    Returns a list of objects with fields: name, language, updated_at.
    """
    token = x_github_token or os.getenv("GITHUB_TOKEN")
    if not token:
        raise HTTPException(status_code=401, detail="GitHub token not provided. Please connect your GitHub account.")
    headers = {"Authorization": f"Bearer {token}"}
    url = "https://api.github.com/user/repos?sort=updated&per_page=100"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="Failed to fetch GitHub repositories")
        data = resp.json()
        result = []
        for repo in data:
            result.append({
                "name": repo.get("name"),
                "owner": repo.get("owner", {}).get("login"),
                "language": repo.get("language"),
                "updated_at": repo.get("updated_at"),
            })
        return {"repos": result}

@router.get("/repos/{owner}/{repo}/commits", summary="List commits for a specific repository")
async def list_github_commits(owner: str, repo: str, x_github_token: Optional[str] = Header(None)):
    """Fetch the commits for a repository to build the Deep Dive risk graph.
    Returns a simplified list of commits: sha, message, author, date.
    """
    token = x_github_token or os.getenv("GITHUB_TOKEN")
    if not token:
        raise HTTPException(status_code=401, detail="GitHub token not provided. Please connect your GitHub account.")
    headers = {"Authorization": f"Bearer {token}"}
    url_commits = f"https://api.github.com/repos/{owner}/{repo}/commits?per_page=30"
    url_pulls = f"https://api.github.com/repos/{owner}/{repo}/pulls?state=open"
    
    async with httpx.AsyncClient() as client:
        # Fetch commits
        resp = await client.get(url_commits, headers=headers)
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="Failed to fetch GitHub commits")
        commits_data = resp.json()
        
        result = []
        for commit_obj in commits_data:
            commit_data = commit_obj.get("commit", {})
            author_data = commit_data.get("author", {})
            result.append({
                "sha": commit_obj.get("sha"),
                "message": commit_data.get("message", "").split("\n")[0], # first line
                "author": author_data.get("name"),
                "date": author_data.get("date"),
                "branch_name": "main",
                "is_pending_auth": False
            })
            
        # Fetch PRs
        pulls_resp = await client.get(url_pulls, headers=headers)
        if pulls_resp.status_code == 200:
            pulls_data = pulls_resp.json()
            for pr in pulls_data:
                head = pr.get("head", {})
                head_sha = head.get("sha")
                head_ref = head.get("ref", "unknown")
                if head_sha:
                    result.append({
                        "sha": head_sha,
                        "message": f"PR: {pr.get('title', 'Unknown PR')}",
                        "author": pr.get("user", {}).get("login", "Unknown"),
                        "date": pr.get("updated_at") or pr.get("created_at"),
                        "branch_name": head_ref,
                        "is_pending_auth": True,
                        "base_sha": pr.get("base", {}).get("sha")
                    })
                    
        return {"commits": result}

@router.get("/repos/{owner}/{repo}/commits/{sha}", summary="Get detailed information about a single commit")
async def get_github_commit(owner: str, repo: str, sha: str, x_github_token: Optional[str] = Header(None)):
    """Fetch details of a specific commit, including files changed and patch."""
    token = x_github_token or os.getenv("GITHUB_TOKEN")
    if not token:
        raise HTTPException(status_code=401, detail="GitHub token not provided.")
    headers = {"Authorization": f"Bearer {token}"}
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="Failed to fetch commit details")
        return resp.json()

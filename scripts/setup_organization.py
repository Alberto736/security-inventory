import requests
import base64
import os

TOKEN = os.environ.get("PAT_TOKEN")
ORG = os.environ.get("ORG_NAME")

headers = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

dependabot_content = """version: 2

updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"

  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"

  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "daily"

  - package-ecosystem: "maven"
    directory: "/"
    schedule:
      interval: "daily"

  - package-ecosystem: "gradle"
    directory: "/"
    schedule:
      interval: "daily"

  - package-ecosystem: "composer"
    directory: "/"
    schedule:
      interval: "daily"

  - package-ecosystem: "nuget"
    directory: "/"
    schedule:
      interval: "daily"

  - package-ecosystem: "rubygems"
    directory: "/"
    schedule:
      interval: "daily"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "daily"

  - package-ecosystem: "terraform"
    directory: "/"
    schedule:
      interval: "daily"
"""

workflow_content = """name: Report Dependencies to Security Inventory

on:
  push:
    branches:
      - main
      - develop

jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Send dependencies to security-inventory
        uses: actions/github-script@v7
        with:
          github-token: ${{ secrets.PAT_TOKEN }}
          script: |
            const fs = require('fs');
            
            const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
            const deps = pkg.dependencies || {};
            
            const lines = [
              `repo: ${context.repo.repo}`,
              `rama: ${context.ref.replace('refs/heads/', '')}`,
              `ultima_actualizacion: "${new Date().toISOString().split('T')[0]}"`,
              `dependencias:`,
              ...Object.entries(deps).map(([name, version]) => 
                `  - name: ${name}\\n    version: "${version.replace(/[\\^~]/g, '')}"`)
            ];
            const content = lines.join('\\n');
            
            const path = `inventario/${context.repo.repo}.yaml`;
            
            let sha;
            try {
              const { data } = await github.rest.repos.getContent({
                owner: context.repo.owner,
                repo: 'security-inventory',
                path
              });
              sha = data.sha;
            } catch (e) {
              sha = undefined;
            }
            
            await github.rest.repos.createOrUpdateFileContents({
              owner: context.repo.owner,
              repo: 'security-inventory',
              path,
              message: `Update inventory for ${context.repo.repo}`,
              content: Buffer.from(content).toString('base64'),
              sha
            });
"""

repos_response = requests.get(
    f"https://api.github.com/orgs/{ORG}/repos?per_page=100",
    headers=headers
)
repos = repos_response.json()

for repo in repos:
    repo_name = repo["name"]
    print(f"Procesando {repo_name}...")

    for path, content in [
        (".github/dependabot.yml", dependabot_content),
        (".github/workflows/report-dependencies.yml", workflow_content)
    ]:
        response = requests.get(
            f"https://api.github.com/repos/{ORG}/{repo_name}/contents/{path}",
            headers=headers
        )
        sha = response.json().get("sha") if response.status_code == 200 else None

        requests.put(
            f"https://api.github.com/repos/{ORG}/{repo_name}/contents/{path}",
            headers=headers,
            json={
                "message": "Add security workflow",
                "content": base64.b64encode(content.encode()).decode(),
                "sha": sha
            }
        )

    print(f"✅ {repo_name} listo")

print("\n✅ Todos los repositorios configurados")

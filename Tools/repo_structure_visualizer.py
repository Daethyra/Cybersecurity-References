"""
Filename: repo_structure_visualizer.py
Author: Daethyra Carino <109057945+Daethyra@users.noreply.github.com>
Date: 2025-01-27
Version: v0.1.0
License: MIT (c) 2025 Daethyra Carino
Description: A Python script that automatically generates an interactive HTML navigation interface for a GitHub repository's directory structure. Adaptable for any repository.

Features:
- Recursive directory structure fetching via GitHub API
- Interactive collapsible folder navigation
- Dual file links (local preview + GitHub view)
- Responsive Bootstrap design with Font Awesome icons
- First-level directory auto-expansion
- Pagination support for large repositories

Dependencies:
- Python 3.6+
- requests library
- Regular expressions (re)
- Bootstrap CSS (CDN)
- Font Awesome Icons (CDN)

Environment Variables:
Set the following variables in the script:
- GITHUB_OWNER: Repository owner username
- GITHUB_REPO: Repository name 
- GITHUB_TOKEN: Personal access token (optional for public repos and higher request limit)

Usage:
1. Configure the script with repository details
2. Execute script: python repo_structure_visualizer.py
3. Open generated Index.html in a web browser or assign it as your repository's Page

Security Note:
- Never commit scripts with hardcoded tokens
- For public use, implement environment variables
- Token requires 'repo' scope for private repositories

Output:
Generates Index.html with interactive directory visualization
"""

import os
import re

import requests

# ======== CONFIGURATION ========
GITHUB_OWNER = "daethyra"
GITHUB_REPO = "Cybersecurity-References"
os.environ["GITHUB_TOKEN"] = os.environ.get("GITHUB_TOKEN", "REPLACE_ME_WITH_TOKEN")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
# ===============================

def fetch_repo_contents(path=''):
    """
    Fetches the contents of a GitHub repository path.

    Args:
        path (str): The path in the repository to fetch. Defaults to the root of the repository.

    Returns:
        list: A list of dictionaries representing the contents of the repository path.
            Each dictionary must have the following keys:
                - name (str): The name of the item.
                - path (str): The path of the item in the repository.
                - type (str): The type of the item, either 'file' or 'dir'.
                - download_url (str): The URL to download the file from. Only present for files.
                - html_url (str): The URL to view the item on GitHub.
    """
    headers = {'Authorization': f'token {GITHUB_TOKEN}'} if GITHUB_TOKEN else {}
    url = f'https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{path}'
    items = []
    while url:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        items.extend(response.json())
        link_header = response.headers.get('Link', '')
        if 'rel="next"' in link_header:
            next_url = re.search(r'<(.+?)>; rel="next"', link_header).group(1)
            url = next_url
        else:
            url = None
    return items

def build_directory_structure(path=''):
    """
    Recursively builds a nested list of dictionaries representing the directory structure of a GitHub repository.

    Args:
        path (str): The path to the directory in the repository.

    Returns:
        list: A nested list of dictionaries representing the directory structure.
            Each dictionary must have the following keys:
                - name (str): The name of the item.
                - path (str): The path of the item in the repository.
                - type (str): The type of the item, either 'file' or 'dir'.
                - children (list): A list of dictionaries representing the children of a directory.
                - download_url (str): The URL to download the file from. Only present for files.
                - html_url (str): The URL to view the item on GitHub.
    """
    items = fetch_repo_contents(path)
    structure = []
    for item in items:
        if item['type'] == 'dir':
            children = build_directory_structure(item['path'])
            structure.append({
                'name': item['name'],
                'path': item['path'],
                'type': 'dir',
                'children': children,
                'html_url': item['html_url']
            })
        else:
            structure.append({
                'name': item['name'],
                'path': item['path'],
                'type': 'file',
                'download_url': item.get('download_url', ''),
                'html_url': item['html_url']
            })
    return structure

def generate_html(structure):
    """
    Generates an HTML page representing the directory structure of the given repo.

    Args:
        structure (list): A nested list of dictionaries representing the directory structure.
            Each dictionary must have the following keys:
                - name (str): The name of the item.
                - path (str): The path of the item in the repository.
                - type (str): The type of the item, either 'file' or 'dir'.
                - children (list): A list of dictionaries representing the children of a directory.
                - download_url (str): The URL to download the file from. Only present for files.
                - html_url (str): The URL to view the item on GitHub.

    Returns:
        str: The generated HTML page.
    """
    html = []
    html.append(f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{GITHUB_REPO} Structure</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <style>
        .nested {{ display: none; margin-left: 20px; }}
        .dir-item {{ cursor: pointer; padding: 5px 0; }}
        .dir-item:hover {{ background-color: #f8f9fa; }}
        .file-item {{ padding: 5px 0; }}
        .filename-link {{ color: #24292e; text-decoration: none; margin-left: 5px; }}
        .filename-link:hover {{ text-decoration: underline; color: #0366d6; }}
        .link-icons {{ margin-left: 10px; display: inline-block; }}
        .container {{ margin-top: 20px; max-width: 800px; }}
        h1 {{ margin-bottom: 20px; }}
        i.fas {{ margin-right: 5px; }}
        a {{ color: #6c757d; }}
        a:hover {{ color: #0d6efd; }}
    </style>
</head>
<body>
    <div class="container">
        <h1 class="mb-4">📁 {GITHUB_REPO} Structure</h1>
        <ul class="list-unstyled">
    ''')

    def generate_list(items):
        """
        Recursively generates HTML for a list of items.

        Args:
            items (list): A list of dictionaries representing the items.
                Each dictionary must have the following keys:
                    - name (str): The name of the item.
                    - path (str): The path of the item in the repository.
                    - type (str): The type of the item, either 'file' or 'dir'.
                    - children (list): A list of dictionaries representing the children of a directory.
                    - download_url (str): The URL to download the file from. Only present for files.
                    - html_url (str): The URL to view the item on GitHub.

        Returns:
            None
        """
        for item in items:
            if item['type'] == 'dir':
                html.append(f'<li class="dir-item">')
                html.append(f'<i class="fas fa-folder"></i>{item["name"]}')
                html.append('<ul class="nested">')
                generate_list(item['children'])
                html.append('</ul>')
                html.append('</li>')
            else:
                html.append('<li class="file-item">')
                html.append(f'''<i class="fas fa-file"></i>
                    <a href="{item['html_url']}" 
                       target="_blank" 
                       class="filename-link"
                       title="View on GitHub">
                        {item['name']}
                    </a>''')
                html.append('<span class="link-icons">')
                html.append(f'''<a href="./{item['path']}" 
                    target="_blank" 
                    title="Open local file"
                    class="local-link">
                    <i class="fas fa-file-alt"></i>
                </a>''')
                html.append(f'''<a href="{item['html_url']}" 
                    target="_blank" 
                    title="View on GitHub"
                    class="github-link">
                    <i class="fab fa-github"></i>
                </a>''')
                html.append('</span>')
                html.append('</li>')

    generate_list(structure)

    html.append('''
        </ul>
    </div>
    <script>
        function toggleDirectory(event) {
            event.stopPropagation();
            const element = event.currentTarget;
            const nested = element.querySelector('.nested');
            
            if (nested) {
                // Get actual computed display value
                const currentDisplay = window.getComputedStyle(nested).display;
                const newDisplay = currentDisplay === 'none' ? 'block' : 'none';
                nested.style.display = newDisplay;
                
                // Update folder icon based on new state
                const folderIcon = element.querySelector('.fa-folder');
                folderIcon.classList.toggle('fa-folder-open', newDisplay === 'block');
            }
        }

        // Initialize event listeners
        document.querySelectorAll('.dir-item').forEach(item => {
            item.addEventListener('click', toggleDirectory);
        });

        // Set initial state correctly for first-level directories
        document.querySelectorAll('ul.list-unstyled > .dir-item > .nested').forEach(nested => {
            nested.style.display = 'block';
            nested.parentElement.querySelector('.fa-folder').classList.add('fa-folder-open');
        });
    </script>
</body>
</html>
    ''')

    return '\n'.join(html)

if __name__ == '__main__':
    structure = build_directory_structure()
    html_content = generate_html(structure)
    with open('Index.html', 'w') as f:
        f.write(html_content)
    print("Index.html generated successfully!")
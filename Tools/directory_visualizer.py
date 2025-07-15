import os
from pathlib import Path
from collections import defaultdict

def read_directory_structure(root_path: str) -> dict:
    """
    Recursively reads directory structure into a nested dictionary.
    
    Args:
        root_path: Starting directory path (absolute or relative)
    
    Returns:
        Nested dictionary representing the directory structure
    """
    def _build_tree(path: Path) -> dict:
        tree = defaultdict(dict)
        for entry in path.iterdir():
            if entry.is_dir():
                tree[entry.name] = _build_tree(entry)
            else:
                tree[entry.name] = None
        return dict(tree)
    
    return _build_tree(Path(root_path).resolve())

def visualize_directory_structure(structure: dict, indent: int = 0) -> None:
    """
    Prints directory structure in hierarchical format.
    
    Args:
        structure: Dictionary from read_directory_structure
        indent: Current indentation level (used recursively)
    """
    prefix = '│   ' * (indent - 1) + '├── ' if indent > 0 else ''
    for name, contents in structure.items():
        print(f"{prefix}{name}")
        if contents:  # Directory has children
            visualize_directory_structure(contents, indent + 1)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Visualize directory structure')
    parser.add_argument('path', nargs='?', default='.', help='Directory path (default: current)')
    args = parser.parse_args()
    
    try:
        structure = read_directory_structure(args.path)
        visualize_directory_structure(structure)
    except FileNotFoundError:
        print(f"Error: Directory not found - {args.path}")
    except NotADirectoryError:
        print(f"Error: Path is not a directory - {args.path}")
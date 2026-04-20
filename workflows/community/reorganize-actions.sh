#!/bin/bash
# reorganize-actions.sh
# Run this from workflows/community/  (or adjust paths)
# Purpose: For each vendor folder, turn loose *.json files into matching named subfolders

set -euo pipefail

echo "=== Starting Hyperautomation workflow reorganization ==="

# Find all vendor directories (skip template and hidden)
for vendor_dir in */; do
    # Skip if not a directory or special folders
    [[ -d "$vendor_dir" ]] || continue
    [[ "$vendor_dir" == "workflow-template-folder/" ]] && continue
    [[ "$vendor_dir" == "undefind vendor/" ]] && continue  # fix typo later if needed

    echo "Processing vendor: ${vendor_dir%/}"

    cd "$vendor_dir" || continue

    # Process every .json file
    for json_file in *.json; do
        [[ -f "$json_file" ]] || continue

        # Derive folder name: remove .json extension
        folder_name="${json_file%.json}"

        echo "  → Creating folder: $folder_name/ and moving $json_file"

        # Create folder (handles special chars like [] safely)
        mkdir -p "$folder_name"

        # Move the JSON inside
        mv "$json_file" "$folder_name/"
    done

    cd - > /dev/null
done

echo "=== Reorganization complete! ==="
echo "Next steps:"
echo "1. Review changes with: git status"
echo "2. Add metadata.yaml + README.md + Mermaid to each new subfolder"
echo "3. Commit with: git commit -m 'feat(workflows): reorganize M365/Okta JSON actions into matching named subfolders'"

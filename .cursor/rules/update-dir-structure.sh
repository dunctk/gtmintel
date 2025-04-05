#!/bin/bash

# Define the output file
output_file="directory-structure.mdc"

# Write the header to the file (overwrite)
echo "# For context, the current project structure is:" > "$output_file"
echo "" >> "$output_file" # Add a blank line after the header

# Append the tree output (level 3, colorized, ignoring target/node_modules)
# Note: -C adds color codes, which might not render correctly everywhere.
# Consider removing -C if the output looks strange in your markdown viewer.
tree -L 3 >> "$output_file"

echo "Updated $output_file"

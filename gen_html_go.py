
import os

public_dir = r"e:\ck\tools-standalone\file-manager-project\go-version\public"
output_file = r"e:\ck\tools-standalone\file-manager-project\go-version\html.go"

def read_file(filename):
    with open(os.path.join(public_dir, filename), 'r', encoding='utf-8') as f:
        return f.read()

index_html = read_file("index.html")
styles_css = read_file("styles.css")
tools_js = read_file("tools.js")
app_js = read_file("app.js")

# Inline CSS
index_html = index_html.replace('<link rel="stylesheet" href="styles.css">', f'<style>\n{styles_css}\n</style>')

# Inline JS
index_html = index_html.replace('<script src="tools.js"></script>', f'<script>\n{tools_js}\n</script>')
index_html = index_html.replace('<script src="app.js"></script>', f'<script>\n{app_js}\n</script>')

# Escape backticks for Go string literal
index_html_escaped = index_html.replace("`", "` + \"`\" + `")

go_content = f"""package main

const indexHTML = `{index_html_escaped}`
"""

with open(output_file, 'w', encoding='utf-8') as f:
    f.write(go_content)

print(f"Successfully generated {output_file}")

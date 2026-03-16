from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

@app.route('/')
def index():
    # 1. SSTI & XSS (Scanner looks for "49" or "<script>")
    # Your scanner sends ?id={{7*7}} or ?name={{7*7}}
    name_payload = request.args.get('name') or request.args.get('id')
    if name_payload:
        return render_template_string(f"Result: {name_payload}")

    # 2. LFI (Scanner looks for "root:x:")
    # Your scanner sends ?file=../../../../etc/passwd
    file_payload = request.args.get('file')
    if file_payload:
        try:
            # On Kali, this will actually read the passwd file
            with open(file_payload, 'r') as f:
                return f.read()
        except:
            return "File not found", 404

    # 3. SSRF (Scanner looks for "User-agent:")
    # Your scanner sends ?url=http://google.com/robots.txt
    url_payload = request.args.get('url') or request.args.get('dest')
    if url_payload:
        import requests
        try:
            resp = requests.get(url_payload, timeout=5)
            return resp.text
        except:
            return "Error fetching URL", 500

    # Default Home Page with the forms the scanner needs to find
    return '''
        <h1>Test Lab</h1>
        <form action="/" method="GET">
            <input name="id" placeholder="SQLi/SSTI">
            <input name="name" placeholder="XSS/SSTI">
            <input name="file" placeholder="LFI">
            <input name="url" placeholder="SSRF">
            <input type="submit">
        </form>
    '''

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5003, debug=True)

TOOLS = [
    {"id":"metasploit","name":"Metasploit","availability":"ready","execution":True,"profiles":["authorized-http-title"]},
    {"id":"sqlmap","name":"sqlmap","availability":"ready","execution":True,"profiles":["authorized-low-impact-detection"]},
    {"id":"john","name":"John the Ripper","availability":"ready","execution":True,"profiles":["offline-wordlist-audit"]},
    {"id":"hashcat","name":"Hashcat","availability":"ready","execution":True,"profiles":["offline-wordlist-audit"]},
    {"id":"hydra","name":"Hydra","availability":"ready","execution":True,"profiles":["authorized-single-account-check"]},
    {"id":"strix","name":"Strix report review","availability":"ready","execution":False,"profiles":["vulnerabilities-json","sarif-2.1.0"]},
    {"id":"nodezero","name":"NodeZero","availability":"needs_configuration","execution":False,"profiles":[]},
    {"id":"nmap","name":"Nmap","availability":"ready","execution":True,"profiles":["authorized-port-inventory"]},
    {"id":"zap_baseline","name":"OWASP ZAP passive baseline","availability":"ready","execution":True,"profiles":["authorized-passive-baseline"]},
]

def get_tool(tool_id: str):
    return next((tool for tool in TOOLS if tool["id"] == tool_id), None)

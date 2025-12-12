#!/usr/bin/env python3
"""
RED SCANNER v3.1
"""

import os
import sys
import re
import json
import base64
import hashlib
import subprocess
import tempfile
import shutil
import socket
import ipaddress
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import zipfile
import tarfile
from typing import Dict, List, Optional, Tuple, Set, Any

# Color System
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

class AdvancedMalwareScanner:
    def __init__(self):
        self.results = []
        self.scan_stats = {
            'files_scanned': 0,
            'malicious_found': 0,
            'suspicious_found': 0,
            'exfiltrations_found': 0,
            'start_time': datetime.now()
        }
        
        # Load detection patterns
        self.patterns = self._load_detection_patterns()
        
        # Known malicious domains and IPs (updated regularly)
        self.malicious_indicators = self._load_malicious_indicators()
        
        # Crypto wallet patterns
        self.crypto_patterns = self._load_crypto_patterns()
        
        # System info
        self.is_termux = 'com.termux' in os.environ.get('PREFIX', '')
        self.system_type = os.name
        
    def _load_detection_patterns(self) -> Dict:
        return {
            'data_exfiltration': [
                # HTTP/HTTPS data sending
                r'(curl|wget|fetch|axios|requests?\.(get|post|put|delete))\([^)]*?((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(https?://[^\s/]*))[^)]*?(wallet|key|secret|token|password|private|seed|mnemonic|passphrase)',
                r'https?://[^\s]*\.[a-z]{2,6}/[^\s]*?(api|send|receive|upload|exfil|steal|data)',
                r'fetch\([^)]*?(\.(tk|ml|ga|cf|xyz|top|club|pw|gq|review|bid|racing|stream|download|loan|men|party|trade|webcam|accountants|bar|bike|blackfriday|boo|cab|center|click|community|company|cricket|date|download|faith|ga|gdn|gq|help|hosting|info|loan|lol|men|ml|online|ooo|party|pro|racing|review|science|site|space|stream|tk|top|trade|webcam|win|work|xyz)|ngrok\.io|localtunnel\.me|serveo\.net)[^)]*\)',
                
                # WebSocket data exfiltration
                r'new\s+WebSocket\([^)]*?(ws://|wss://)[^)]*\)',
                r'websocket\.send\([^)]*?(wallet|key|secret)',
                
                # DNS exfiltration patterns
                r'new\s+Image\(\)\.src\s*=\s*["\']http://[^"\']*?\.(tk|ml|ga|cf|xyz)/',
                r'document\.location\s*=\s*["\']http://[^"\']*?\?data=',
                
                # File upload patterns
                r'FormData\(\)\.append\([^)]*?(file|data)',
                r'FileReader\(\)\.readAsDataURL\([^)]*?\.(txt|json|env|pem)',
                
                # Stealthy exfiltration
                r'setTimeout\([^)]*?fetch[^)]*?,\s*[5-9][0-9]{3,}\)',  # Delayed fetch
                r'setInterval\([^)]*?XMLHttpRequest[^)]*?,\s*[0-9]{4,}\)',  # Periodic sending
                
                # Encoded exfiltration
                r'btoa\([^)]*?(localStorage|sessionStorage|document\.cookie)',
                r'encodeURIComponent\([^)]*?(wallet|privateKey|secret)',
                
                # Clipboard theft
                r'navigator\.clipboard\.readText\(\)',
                r'document\.execCommand\(["\']copy["\']\)',
                
                # Browser storage theft
                r'localStorage\.getItem\([^)]*?(wallet|key|secret)',
                r'sessionStorage\.getItem\([^)]*?(private|seed)',
            ],
            
            'crypto_stealing': [
                # Direct wallet stealing
                r'(ethereum|web3|ethers|bitcoin|bitcoinjs-lib|crypto|blockchain)\.([^)]*?(privateKey|mnemonic|seed|wallet|sign|transaction|send))',
                r'process\.env\.(ETHEREUM_PRIVATE_KEY|BITCOIN_WALLET|MNEMONIC|SEED_PHRASE)',
                r'window\.ethereum\.request\([^)]*?eth_accounts',
                r'web3\.eth\.accounts\.privateKeyToAccount\([^)]*\)',
                r'Keypair\.fromSecretKey\([^)]*\)',  # Solana
                r'Keypair\.fromSeed\([^)]*\)',
                
                # Key file access
                r'fs\.readFileSync\([^)]*?\.(pem|key|cer|crt|pfx|p12|jks|keystore)',
                r'require\([^)]*?fs[^)]*?\.readFile\([^)]*?(\.env|config|secret)',
                
                # Clipboard monitoring for crypto addresses
                r'addEventListener\(["\']paste["\'][^)]*?(0x[a-fA-F0-9]{40}|bc1|[13][a-km-zA-HJ-NP-Z1-9]{25,34})',
                r'clipboardData\.getData\([^)]*?text/plain[^)]*?(bitcoin:|ethereum:|0x)',
                
                # Crypto mining in background
                r'new\s+Worker\([^)]*?miner[^)]*\)',
                r'CoinHive\.Anonymous\([^)]*\)',
                r'cryptonight\.WASM',
            ],
            
            'malicious_download': [
                # APK/Executable downloads
                r'(curl|wget|fetch)\([^)]*?\.(apk|exe|dmg|deb|rpm|msi|bat|sh|ps1)[^)]*\)',
                r'https?://[^\s]*\.(apk|exe|dmg|deb)[^\s]*',
                r'child_process\.exec\([^)]*?(wget|curl).*\.(sh|py|js)',
                
                # Package manager hijacking
                r'npm\s+install\s+https?://[^\s]*',
                r'pip\s+install\s+.*--index-url.*http://',
                r'gem\s+install.*--source.*http://',
                
                # Auto-update malicious
                r'autoUpdate\.checkForUpdates\([^)]*?http://[^)]*\)',
                r'app\.getVersion\([^)]*?\.then\([^)]*?fetch[^)]*?http://',
            ],
            
            'obfuscated_exfiltration': [
                # Base64 encoded URLs
                r'atob\(["\'][A-Za-z0-9+/]+={0,2}["\']\)',
                r'decodeURIComponent\(["\'][%A-Fa-f0-9]+["\']\)',
                
                # XOR encoded strings
                r'String\.fromCharCode\([^)]*?\^[^)]*?\)',
                r'charCodeAt\([^)]*?\^[^)]*?\)',
                
                # Array join for URL construction
                r'\["http","://","evil",".com"\]\.join\(["\']{2}["\']\)',
                r'["\'][a-z]{2,4}["\']\+\+["\'][a-z]{2,}["\']\+\+["\']\.[a-z]{2,}["\']',
                
                # Eval-based obfuscation
                r'eval\(["\'](?:\\x[0-9a-f]{2}){10,}["\']\)',
                r'Function\(["\'][a-z]{3,}["\']\)\(["\'][A-Za-z0-9+/=]{20,}["\']\)',
            ],
            
            'suspicious_network': [
                # Raw IP addresses (excluding localhost)
                r'https?://(?!127\.0\.0\.1|localhost|192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
                
                # Suspicious ports
                r':(4444|5555|6666|7777|8888|9999|1337|31337|12345)',
                
                # Unencrypted HTTP (sensitive data)
                r'http://[^\s]*?(wallet|key|secret|token|login|auth|password)',
                
                # Long random subdomains (common in malware)
                r'https?://[a-z0-9]{16,32}\.[a-z]{2,6}/',
            ],
            
            'env_secrets': [
                # Crypto keys in environment
                r'(PRIVATE_KEY|SECRET_KEY|MNEMONIC|SEED_PHRASE|WALLET_KEY)=[A-Za-z0-9+/=]{20,}',
                r'(ETHEREUM|BITCOIN|SOLANA|MONERO)_(KEY|WALLET|SEED)=[^\s]{20,}',
                r'(API_KEY|ACCESS_TOKEN|SECRET_TOKEN)=[^\s]{20,}',
                
                # Database credentials
                r'(DATABASE_URL|MONGODB_URI|REDIS_URL)=[^\s]*@[^\s]*\.[^\s]*',
                
                # Cloud credentials
                r'(AWS_ACCESS_KEY|AWS_SECRET_KEY|AZURE_STORAGE_KEY|GCP_SERVICE_KEY)=[^\s]{20,}',
            ],
            
            'file_operations': [
                # Reading sensitive files
                r'fs\.readFile\([^)]*?(\.env|\.aws|\.ssh|id_rsa|\.pem|wallet\.dat)',
                r'require\(["\']fs["\'][^)]*?\.readFileSync\([^)]*?(config|secret)',
                
                # Writing stolen data
                r'fs\.writeFile\([^)]*?(stolen|data|keys|dump)\.(txt|json|csv)',
                r'appendFile\([^)]*?(log|output|result)\.txt[^)]*?(wallet|key)',
                
                # Directory scanning for wallets
                r'fs\.readdir\([^)]*?(\.ethereum|\.bitcoin|\.solana|AppData|Library)',
            ]
        }
    
    def _load_malicious_indicators(self) -> Dict:
        return {
            'malicious_domains': [
                'ngrok.io', 'localtunnel.me', 'serveo.net',
                'requestbin.com', 'webhook.site', 'pipedream.com',
                'github.io.malicious', 'gitlab.io.suspicious'
            ],
            'suspicious_tlds': [
                '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club',
                '.pw', '.gq', '.review', '.bid', '.racing', '.stream',
                '.download', '.loan', '.men', '.party', '.trade', '.webcam'
            ],
            'crypto_exfiltration_patterns': [
                'sendtoaddress', 'transfer', 'withdraw', 'exportwallet',
                'dumpprivkey', 'importprivkey', 'sweepwallet'
            ]
        }
    
    def _load_crypto_patterns(self) -> Dict:
        return {
            'wallet_formats': [
                r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$',  # Bitcoin Legacy
                r'^bc1[ac-hj-np-z02-9]{11,87}$',  # Bitcoin SegWit
                r'^0x[a-fA-F0-9]{40}$',  # Ethereum
                r'^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$',  # Litecoin
                r'^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$',  # Dogecoin
                r'^X[1-9A-HJ-NP-Za-km-z]{33}$',  # Dash
                r'^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$',  # Monero
            ],
            'private_key_formats': [
                r'^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$',  # WIF Bitcoin
                r'^[1-9A-HJ-NP-Za-km-z]{51,52}$',  # WIF Compressed
                r'^[0-9a-f]{64}$',  # Raw hex private key
                r'^[A-Za-z0-9+/=]{44}$',  # Base64 encoded key
            ],
            'mnemonic_patterns': [
                r'(\b[a-z]+\b\s+){11,23}\b[a-z]+\b',  # BIP39 mnemonic
                r'^[a-z]+( [a-z]+){11,23}$',
            ]
        }
    
    def display_banner(self):
        banner = f"""{Colors.RED}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════╗
║    ██████╗ ███████╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗    ║
║    ██╔══██╗██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║    ║
║    ██████╔╝█████╗  ██║  ██║    ███████╗██║     ███████║██╔██╗ ██║    ║
║    ██╔══██╗██╔══╝  ██║  ██║    ╚════██║██║     ██╔══██║██║╚██╗██║    ║
║    ██║  ██║███████╗██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║    ║
║    ╚═╝  ╚═╝╚══════╝╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ║
║                                                                      ║
║           ADVANCED SUPPLY CHAIN ATTACK & CRYPTOSTEALER DETECTOR      ║
║                         Version 3.1 - Professional                   ║
╚══════════════════════════════════════════════════════════════════════╝{Colors.RESET}
        
{Colors.YELLOW}[!] Specialized in detecting:{Colors.RESET}
{Colors.CYAN}  • Fake GitHub repositories with malicious code{Colors.RESET}
{Colors.CYAN}  • Cryptocurrency wallet stealers & keyloggers{Colors.RESET}
{Colors.CYAN}  • Data exfiltration to external servers{Colors.RESET}
{Colors.CYAN}  • Supply chain attacks via npm/pip/gem packages{Colors.RESET}
{Colors.CYAN}  • Obfuscated malware in open-source projects{Colors.RESET}
"""
        print(banner)
    
    def display_menu(self):
        menu = f"""
{Colors.CYAN}{Colors.BOLD}[ RED ADVANCED MALWARE SCANNER v3.1 ]{Colors.RESET}

{Colors.GREEN}[1]{Colors.RESET} Scan GitHub Repository for Supply Chain Attacks
{Colors.GREEN}[2]{Colors.RESET} Scan Local Project/Files for Data Exfiltration
{Colors.GREEN}[3]{Colors.RESET} Deep System Scan for Cryptostealers
{Colors.GREEN}[4]{Colors.RESET} Analyze NPM/PIP Dependencies
{Colors.GREEN}[5]{Colors.RESET} Scan for Crypto Wallet Stealers
{Colors.GREEN}[6]{Colors.RESET} Check for External Server Connections
{Colors.RED}[0]{Colors.RESET} Exit

{Colors.YELLOW}Select option: {Colors.RESET}"""
        
        print(menu, end='')
        return input().strip()
    
    def scan_file_content(self, file_path: Path, content: str) -> List[Dict]:
        findings = []
        self.scan_stats['files_scanned'] += 1
        
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                try:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        # Get context around the match
                        start = max(0, match.start() - 50)
                        end = min(len(content), match.end() + 50)
                        context = content[start:end].replace('\n', ' ')
                        
                        finding = {
                            'file': str(file_path),
                            'category': category,
                            'pattern': pattern[:100],
                            'match': match.group()[:200],
                            'context': context,
                            'line': content[:match.start()].count('\n') + 1,
                            'severity': self._get_severity(category, match.group())
                        }
                        findings.append(finding)
                        
                        if category in ['data_exfiltration', 'crypto_stealing']:
                            self.scan_stats['exfiltrations_found'] += 1
                except Exception as e:
                    continue
        
        # Additional crypto pattern checking
        crypto_findings = self._check_crypto_patterns(content, file_path)
        findings.extend(crypto_findings)
        
        # Check for encoded URLs
        encoded_findings = self._check_encoded_urls(content, file_path)
        findings.extend(encoded_findings)
        
        return findings
    
    def _get_severity(self, category: str, match: str) -> str:
        severity_map = {
            'data_exfiltration': 'CRITICAL',
            'crypto_stealing': 'CRITICAL',
            'malicious_download': 'HIGH',
            'obfuscated_exfiltration': 'HIGH',
            'suspicious_network': 'MEDIUM',
            'env_secrets': 'HIGH',
            'file_operations': 'MEDIUM'
        }
        
        severity = severity_map.get(category, 'MEDIUM')
        
        # Increase severity for certain patterns
        critical_indicators = [
            'wallet', 'privateKey', 'mnemonic', 'seed', '0x', 'bc1',
            'sendtoaddress', 'transfer', 'steal', 'exfil'
        ]
        
        if any(indicator.lower() in match.lower() for indicator in critical_indicators):
            severity = 'CRITICAL'
        
        return severity
    
    def _check_crypto_patterns(self, content: str, file_path: Path) -> List[Dict]:
        findings = []
        
        # Check for crypto wallet addresses
        for pattern_name, patterns in self.crypto_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Avoid false positives (comments, example addresses)
                    if self._is_false_positive(match.group(), content, match.start()):
                        continue
                    
                    finding = {
                        'file': str(file_path),
                        'category': 'crypto_wallet_detected',
                        'pattern': f'{pattern_name}: {pattern[:50]}',
                        'match': match.group(),
                        'context': self._get_context(content, match.start()),
                        'line': content[:match.start()].count('\n') + 1,
                        'severity': 'HIGH'
                    }
                    findings.append(finding)
        
        return findings
    
    def _check_encoded_urls(self, content: str, file_path: Path) -> List[Dict]:
        findings = []
        
        # Base64 encoded URLs
        base64_patterns = [
            r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']',
            r'atob\(["\']([A-Za-z0-9+/]{20,}={0,2})["\']\)'
        ]
        
        for pattern in base64_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                encoded_str = match.group(1)
                try:
                    decoded = base64.b64decode(encoded_str + '=' * (-len(encoded_str) % 4)).decode('utf-8', errors='ignore')
                    if self._looks_like_url(decoded):
                        finding = {
                            'file': str(file_path),
                            'category': 'encoded_url',
                            'pattern': 'Base64 encoded URL',
                            'match': encoded_str[:100],
                            'decoded': decoded[:200],
                            'context': self._get_context(content, match.start()),
                            'line': content[:match.start()].count('\n') + 1,
                            'severity': 'HIGH'
                        }
                        findings.append(finding)
                except:
                    continue
        
        # Hex encoded URLs
        hex_pattern = r'["\']((?:\\x[0-9a-f]{2}){10,})["\']'
        matches = re.finditer(hex_pattern, content, re.IGNORECASE)
        for match in matches:
            hex_str = match.group(1)
            try:
                decoded = bytes.fromhex(hex_str.replace('\\x', '')).decode('utf-8', errors='ignore')
                if self._looks_like_url(decoded):
                    finding = {
                        'file': str(file_path),
                        'category': 'encoded_url',
                        'pattern': 'Hex encoded URL',
                        'match': hex_str[:100],
                        'decoded': decoded[:200],
                        'context': self._get_context(content, match.start()),
                        'line': content[:match.start()].count('\n') + 1,
                        'severity': 'HIGH'
                    }
                    findings.append(finding)
            except:
                continue
        
        return findings
    
    def _looks_like_url(self, text: str) -> bool:
        url_indicators = [
            'http://', 'https://', 'ws://', 'wss://',
            '.com', '.org', '.net', '.io', '.ru',
            '/api/', '/send', '/receive', '/upload'
        ]
        
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in url_indicators)
    
    def _is_false_positive(self, match: str, content: str, position: int) -> bool:
        # Check if it's in a comment
        lines = content[:position].split('\n')
        current_line = lines[-1] if lines else ''
        
        # Common comment patterns
        comment_indicators = ['//', '#', '/*', '<!--']
        if any(indicator in current_line for indicator in comment_indicators):
            return True
        
        # Check if it's example/placeholder text
        example_indicators = ['example', 'placeholder', 'test', 'demo', 'sample']
        context = content[max(0, position-50):min(len(content), position+50)].lower()
        if any(indicator in context for indicator in example_indicators):
            return True
        
        return False
    
    def _get_context(self, content: str, position: int, chars: int = 100) -> str:
        start = max(0, position - chars)
        end = min(len(content), position + chars)
        return content[start:end].replace('\n', ' ')
    
    def scan_directory(self, directory: Path) -> Dict:
        all_findings = []
        
        code_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.vue',
            '.php', '.html', '.htm', '.xml', '.json',
            '.java', '.c', '.cpp', '.h', '.cs', '.go',
            '.rb', '.pl', '.sh', '.bash', '.ps1', '.bat',
            '.rs', '.swift', '.kt', '.m', '.lua',
            '.yml', '.yaml', '.toml', '.ini', '.cfg',
            '.env', '.config', '.properties'
        }
        
        for root, dirs, files in os.walk(directory):
            # Skip node_modules and other large directories
            if 'node_modules' in dirs:
                dirs.remove('node_modules')
            if '.git' in dirs:
                dirs.remove('.git')
            
            for file in files:
                file_path = Path(root) / file
                if file_path.suffix.lower() in code_extensions:
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        findings = self.scan_file_content(file_path, content)
                        if findings:
                            all_findings.extend(findings)
                    except Exception as e:
                        continue
        
        return {
            'scan_type': 'directory',
            'path': str(directory),
            'findings': all_findings,
            'total_findings': len(all_findings),
            'files_scanned': self.scan_stats['files_scanned']
        }
    
    def analyze_package_file(self, file_path: Path) -> Dict:
        findings = []
        
        if file_path.name == 'package.json':
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Check for suspicious dependencies
                deps = {}
                deps.update(data.get('dependencies', {}))
                deps.update(data.get('devDependencies', {}))
                
                suspicious_packages = [
                    'node-fetch', 'axios', 'request', 'got', 'superagent',
                    'web3', 'ethers', 'bitcoinjs-lib', 'solana-web3.js'
                ]
                
                for dep in deps:
                    dep_lower = dep.lower()
                    
                    # Check for typosquatting
                    for legit in ['react', 'vue', 'angular', 'express', 'lodash']:
                        if legit in dep_lower and dep_lower != legit:
                            if any(c in dep_lower for c in ['-', '_', '.']):
                                findings.append({
                                    'category': 'typosquatting',
                                    'package': dep,
                                    'version': deps[dep],
                                    'severity': 'HIGH',
                                    'details': f'Possible typosquatting of {legit}'
                                })
                    
                    # Check for malicious patterns
                    malicious_patterns = ['steal', 'wallet', 'key', 'exfil', 'malicious']
                    if any(pattern in dep_lower for pattern in malicious_patterns):
                        findings.append({
                            'category': 'suspicious_package',
                            'package': dep,
                            'version': deps[dep],
                            'severity': 'CRITICAL',
                            'details': 'Package name contains suspicious keywords'
                        })
                
                # Check scripts
                scripts = data.get('scripts', {})
                for script_name, script_content in scripts.items():
                    if isinstance(script_content, str):
                        if 'curl' in script_content or 'wget' in script_content:
                            if 'http://' in script_content:
                                findings.append({
                                    'category': 'insecure_script',
                                    'script': script_name,
                                    'severity': 'HIGH',
                                    'details': 'Script uses insecure HTTP with curl/wget'
                                })
            
            except Exception as e:
                pass
        
        elif file_path.name == 'requirements.txt':
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Check for suspicious packages
                            pkg = line.split('==')[0].split('>=')[0].split('<=')[0]
                            pkg_lower = pkg.lower()
                            
                            suspicious_patterns = ['steal', 'key', 'wallet', 'exfil']
                            if any(pattern in pkg_lower for pattern in suspicious_patterns):
                                findings.append({
                                    'category': 'suspicious_python_package',
                                    'package': pkg,
                                    'severity': 'HIGH',
                                    'details': 'Suspicious package name in requirements.txt'
                                })
            except Exception as e:
                pass
        
        return {
            'file': str(file_path),
            'findings': findings,
            'total_findings': len(findings)
        }
    
    def clone_and_scan_repo(self, repo_url: str) -> Dict:
        print(f"{Colors.YELLOW}[*] Cloning repository: {repo_url}{Colors.RESET}")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            repo_path = temp_path / 'repo'
            
            try:
                # Try to clone
                result = subprocess.run(
                    ['git', 'clone', '--depth', '1', repo_url, str(repo_path)],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                if result.returncode != 0:
                    return {
                        'status': 'error',
                        'message': f'Failed to clone repository: {result.stderr}'
                    }
                
                print(f"{Colors.GREEN}[+] Repository cloned successfully{Colors.RESET}")
                
                # Scan the repository
                scan_results = self.scan_directory(repo_path)
                
                # Check for package files
                package_files = list(repo_path.glob('package.json')) + \
                              list(repo_path.glob('requirements.txt')) + \
                              list(repo_path.glob('Pipfile')) + \
                              list(repo_path.glob('Gemfile'))
                
                package_findings = []
                for pkg_file in package_files:
                    pkg_result = self.analyze_package_file(pkg_file)
                    if pkg_result['findings']:
                        package_findings.extend(pkg_result['findings'])
                
                # Combine results
                all_findings = scan_results['findings']
                for finding in package_findings:
                    finding['file'] = 'Package dependencies'
                    all_findings.append(finding)
                
                return {
                    'status': 'success',
                    'repo_url': repo_url,
                    'total_findings': len(all_findings),
                    'findings': all_findings,
                    'files_scanned': self.scan_stats['files_scanned'],
                    'package_findings': len(package_findings)
                }
                
            except subprocess.TimeoutExpired:
                return {
                    'status': 'error',
                    'message': 'Clone operation timed out'
                }
            except Exception as e:
                return {
                    'status': 'error',
                    'message': str(e)
                }
    
    def scan_system_for_cryptostealers(self) -> Dict:
        print(f"{Colors.YELLOW}[*] Scanning system for cryptostealers...{Colors.RESET}")
        
        # Common paths where cryptostealers might hide
        scan_paths = []
        
        if self.system_type == 'posix':
            if self.is_termux:
                scan_paths = [
                    Path('/data/data/com.termux/files/home'),
                    Path('/data/data/com.termux/files/usr/bin'),
                    Path('/storage/emulated/0')
                ]
            else:
                scan_paths = [
                    Path.home(),
                    Path('/tmp'),
                    Path('/var/tmp'),
                    Path('/dev/shm')
                ]
        else:  # Windows
            scan_paths = [
                Path(os.environ.get('APPDATA', '')),
                Path(os.environ.get('LOCALAPPDATA', '')),
                Path('C:\\Windows\\Temp'),
                Path.home()
            ]
        
        all_findings = []
        
        for path in scan_paths:
            if path.exists():
                print(f"{Colors.CYAN}[*] Scanning: {path}{Colors.RESET}")
                results = self.scan_directory(path)
                all_findings.extend(results['findings'])
        
        # Check for suspicious processes
        process_findings = self._check_suspicious_processes()
        all_findings.extend(process_findings)
        
        return {
            'scan_type': 'system_cryptostealers',
            'total_findings': len(all_findings),
            'findings': all_findings,
            'paths_scanned': [str(p) for p in scan_paths]
        }
    
    def _check_suspicious_processes(self) -> List[Dict]:
        findings = []
        
        if self.system_type == 'posix':
            try:
                # Check for mining processes
                ps_output = subprocess.run(
                    ['ps', 'aux'],
                    capture_output=True,
                    text=True
                ).stdout
                
                mining_indicators = [
                    'xmrig', 'cpuminer', 'ccminer', 'minerd',
                    'nicehash', 'nanopool', 'ethminer'
                ]
                
                for line in ps_output.split('\n'):
                    for indicator in mining_indicators:
                        if indicator in line.lower():
                            findings.append({
                                'category': 'crypto_mining_process',
                                'process': line[:200],
                                'severity': 'HIGH',
                                'details': f'Cryptocurrency mining process detected: {indicator}'
                            })
            except:
                pass
        
        return findings
    
    def check_external_connections(self) -> Dict:
        print(f"{Colors.YELLOW}[*] Analyzing network patterns...{Colors.RESET}")
        
        findings = []
        
        # This would require running the code in a sandbox
        # For now, we'll just check for patterns in files
        print(f"{Colors.CYAN}[*] Checking for external server connections in code...{Colors.RESET}")
        
        # Check common directories for suspicious network code
        check_dirs = [Path.cwd()]
        if Path('src').exists():
            check_dirs.append(Path('src'))
        if Path('lib').exists():
            check_dirs.append(Path('lib'))
        
        for check_dir in check_dirs:
            if check_dir.exists():
                results = self.scan_directory(check_dir)
                for finding in results['findings']:
                    if finding['category'] in ['data_exfiltration', 'suspicious_network']:
                        findings.append(finding)
        
        return {
            'scan_type': 'external_connections',
            'total_findings': len(findings),
            'findings': findings
        }
    
    def display_results(self, results: Dict):
        if results.get('status') == 'error':
            print(f"\n{Colors.RED}[-] Error: {results['message']}{Colors.RESET}")
            return
        
        total_findings = results.get('total_findings', 0)
        
        print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.WHITE}SCAN RESULTS{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
        
        if total_findings == 0:
            print(f"{Colors.GREEN}[+] No malicious patterns detected!{Colors.RESET}")
            return
        
        # Group findings by severity
        critical = []
        high = []
        medium = []
        
        for finding in results.get('findings', []):
            severity = finding.get('severity', 'MEDIUM')
            if severity == 'CRITICAL':
                critical.append(finding)
            elif severity == 'HIGH':
                high.append(finding)
            else:
                medium.append(finding)
        
        # Display summary
        print(f"\n{Colors.BOLD}Summary:{Colors.RESET}")
        print(f"  {Colors.RED}CRITICAL: {len(critical)}{Colors.RESET}")
        print(f"  {Colors.YELLOW}HIGH: {len(high)}{Colors.RESET}")
        print(f"  {Colors.CYAN}MEDIUM: {len(medium)}{Colors.RESET}")
        print(f"  {Colors.GREEN}Total Files Scanned: {self.scan_stats['files_scanned']}{Colors.RESET}")
        
        # Display critical findings
        if critical:
            print(f"\n{Colors.RED}{Colors.BOLD}CRITICAL FINDINGS:{Colors.RESET}")
            for i, finding in enumerate(critical[:10], 1):  # Show first 10
                print(f"\n  {Colors.RED}[{i}] {finding.get('category', 'Unknown')}{Colors.RESET}")
                print(f"     File: {finding.get('file', 'Unknown')}")
                print(f"     Line: {finding.get('line', 'Unknown')}")
                print(f"     Pattern: {finding.get('pattern', 'Unknown')[:100]}")
                print(f"     Match: {finding.get('match', 'Unknown')[:150]}")
                if 'decoded' in finding:
                    print(f"     Decoded: {finding['decoded'][:150]}")
        
        # Display high findings
        if high:
            print(f"\n{Colors.YELLOW}{Colors.BOLD}HIGH RISK FINDINGS:{Colors.RESET}")
            for i, finding in enumerate(high[:5], 1):  # Show first 5
                print(f"\n  {Colors.YELLOW}[{i}] {finding.get('category', 'Unknown')}{Colors.RESET}")
                print(f"     File: {finding.get('file', 'Unknown')}")
                print(f"     Pattern: {finding.get('pattern', 'Unknown')[:80]}")
        
        # Recommendations
        if critical or high:
            print(f"\n{Colors.RED}{Colors.BOLD}RECOMMENDATIONS:{Colors.RESET}")
            print(f"  1. {Colors.YELLOW}Immediately review all CRITICAL findings{Colors.RESET}")
            print(f"  2. {Colors.YELLOW}Check for unauthorized external connections{Colors.RESET}")
            print(f"  3. {Colors.YELLOW}Scan for cryptocurrency wallet files{Colors.RESET}")
            print(f"  4. {Colors.YELLOW}Monitor network traffic for data exfiltration{Colors.RESET}")
            print(f"  5. {Colors.YELLOW}Change all exposed API keys and secrets{Colors.RESET}")
        
        # Save results to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"malware_scan_{timestamp}.json"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n{Colors.GREEN}[+] Detailed results saved to: {output_file}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
    
    def run(self):
        self.display_banner()
        
        while True:
            choice = self.display_menu()
            
            if choice == '1':
                repo_url = input(f"\n{Colors.CYAN}Enter GitHub/GitLab repository URL: {Colors.RESET}").strip()
                if repo_url:
                    print(f"\n{Colors.YELLOW}[*] Starting deep scan of repository...{Colors.RESET}")
                    results = self.clone_and_scan_repo(repo_url)
                    self.display_results(results)
            
            elif choice == '2':
                path = input(f"\n{Colors.CYAN}Enter path to scan (file or directory): {Colors.RESET}").strip()
                if path:
                    target = Path(path)
                    if target.exists():
                        if target.is_file():
                            try:
                                content = target.read_text(encoding='utf-8', errors='ignore')
                                findings = self.scan_file_content(target, content)
                                results = {
                                    'scan_type': 'single_file',
                                    'total_findings': len(findings),
                                    'findings': findings
                                }
                                self.display_results(results)
                            except Exception as e:
                                print(f"{Colors.RED}[-] Error reading file: {e}{Colors.RESET}")
                        else:
                            results = self.scan_directory(target)
                            self.display_results(results)
                    else:
                        print(f"{Colors.RED}[-] Path does not exist{Colors.RESET}")
            
            elif choice == '3':
                print(f"\n{Colors.YELLOW}[!] This will scan system directories for cryptostealers{Colors.RESET}")
                confirm = input(f"{Colors.YELLOW}Continue? (y/n): {Colors.RESET}").strip().lower()
                if confirm == 'y':
                    results = self.scan_system_for_cryptostealers()
                    self.display_results(results)
            
            elif choice == '4':
                print(f"\n{Colors.YELLOW}[*] Analyzing package dependencies...{Colors.RESET}")
                # Check for package files in current directory
                package_files = []
                for pattern in ['package.json', 'requirements.txt', 'Pipfile', 'Gemfile', 'Cargo.toml']:
                    package_files.extend(Path('.').glob(pattern))
                
                if package_files:
                    all_findings = []
                    for pkg_file in package_files:
                        results = self.analyze_package_file(pkg_file)
                        all_findings.extend(results['findings'])
                    
                    results = {
                        'scan_type': 'package_analysis',
                        'total_findings': len(all_findings),
                        'findings': all_findings,
                        'files_analyzed': [str(p) for p in package_files]
                    }
                    self.display_results(results)
                else:
                    print(f"{Colors.YELLOW}[*] No package files found in current directory{Colors.RESET}")
            
            elif choice == '5':
                print(f"\n{Colors.YELLOW}[*] Scanning for crypto wallet stealers...{Colors.RESET}")
                results = self.scan_directory(Path.cwd())
                # Filter for crypto-related findings
                crypto_findings = [f for f in results['findings'] 
                                 if 'crypto' in f.get('category', '').lower() 
                                 or 'wallet' in f.get('match', '').lower()]
                results['findings'] = crypto_findings
                results['total_findings'] = len(crypto_findings)
                results['scan_type'] = 'crypto_stealer_scan'
                self.display_results(results)
            
            elif choice == '6':
                results = self.check_external_connections()
                self.display_results(results)
            
            elif choice == '0':
                print(f"\n{Colors.GREEN}[+] Thank you for using RED Scanner v3.1{Colors.RESET}")
                print(f"{Colors.GREEN}[+] Stay safe!{Colors.RESET}")
                break
            
            else:
                print(f"{Colors.RED}[-] Invalid option{Colors.RESET}")
            
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")

def main():
    scanner = AdvancedMalwareScanner()
    scanner.run()

if __name__ == "__main__":
    main()

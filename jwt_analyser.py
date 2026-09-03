#!/usr/bin/env python3
"""
Minimal JWT/OAuth Token Analyzer
Parse, decode and analyze JWT tokens
"""

import json
import base64
import argparse
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional
import re

# ============================================
# CORE PARSER
# ============================================

class JWTToken:
    """Structure pour un token JWT"""
    
    def __init__(self, token: str):
        self.raw = token
        self.header = {}
        self.payload = {}
        self.signature = None
        self.parsed = False
        self.errors = []
        self.warnings = []
        
    def parse(self) -> bool:
        """Décode et parse le token"""
        parts = self.raw.split('.')
        
        # Vérification de base
        if len(parts) != 3:
            self.errors.append("Invalid JWT format: expected 3 parts (header.payload.signature)")
            return False
        
        try:
            # Header
            self.header = self._decode_part(parts[0])
            
            # Payload
            self.payload = self._decode_part(parts[1])
            
            # Signature (garder en brut)
            self.signature = parts[2]
            
            self.parsed = True
            self._validate()
            return True
            
        except Exception as e:
            self.errors.append(f"Decoding error: {str(e)}")
            return False
    
    def _decode_part(self, part: str) -> Dict:
        """Décode une partie en base64url"""
        # Ajouter padding si nécessaire
        padding = 4 - (len(part) % 4)
        if padding != 4:
            part += '=' * padding
        
        # Remplacer les caractères URL-safe
        part = part.replace('-', '+').replace('_', '/')
        
        decoded = base64.b64decode(part)
        return json.loads(decoded)
    
    def _validate(self) -> None:
        """Validations supplémentaires"""
        # Vérifier l'expiration
        if 'exp' in self.payload:
            exp = self.payload['exp']
            now = int(datetime.now(timezone.utc).timestamp())
            if exp < now:
                self.warnings.append("⚠️  Token EXPIRED")
            else:
                remaining = exp - now
                self.warnings.append(f"✅ Valid for {self._format_time(remaining)}")
        
        # Vérifier l'émetteur
        if 'iss' not in self.payload:
            self.warnings.append("⚠️  No issuer (iss) claim")
        
        # Vérifier l'audience
        if 'aud' not in self.payload:
            self.warnings.append("⚠️  No audience (aud) claim")
        
        # Vérifier l'algorythme
        if self.header.get('alg') == 'none':
            self.errors.append("❌ CRITICAL: 'none' algorithm detected (insecure!)")
    
    def _format_time(self, seconds: int) -> str:
        """Formatte le temps restant"""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds // 60}m"
        elif seconds < 86400:
            return f"{seconds // 3600}h"
        else:
            return f"{seconds // 86400}d"
    
    def get_summary(self) -> Dict:
        """Résumé des informations importantes"""
        return {
            'algorithm': self.header.get('alg', 'unknown'),
            'type': self.header.get('typ', 'JWT'),
            'subject': self.payload.get('sub', 'N/A'),
            'issuer': self.payload.get('iss', 'N/A'),
            'audience': self.payload.get('aud', 'N/A'),
            'issued_at': self._format_timestamp(self.payload.get('iat')),
            'expires_at': self._format_timestamp(self.payload.get('exp')),
            'user_id': self.payload.get('user_id', self.payload.get('uid', 'N/A')),
            'email': self.payload.get('email', 'N/A'),
            'roles': self.payload.get('roles', self.payload.get('role', [])),
            'scopes': self.payload.get('scope', self.payload.get('scopes', [])),
        }
    
    def _format_timestamp(self, timestamp: Optional[int]) -> str:
        """Convertit un timestamp en date lisible"""
        if not timestamp:
            return 'N/A'
        try:
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            return str(timestamp)

# ============================================
# ANALYSEUR
# ============================================

class Analyzer:
    """Analyse et affiche les tokens"""
    
    @staticmethod
    def analyze(token_str: str, show_all: bool = False) -> None:
        """Analyse un token JWT"""
        
        # Nettoyer le token (enlever les guillemets)
        token_str = token_str.strip().strip('"\'')
        
        print("=" * 60)
        print("🔐 JWT/OAuth Token Analyzer")
        print("=" * 60)
        
        # Parse
        token = JWTToken(token_str)
        
        if not token.parse():
            print("\n❌ PARSE ERROR:")
            for err in token.errors:
                print(f"  {err}")
            return
        
        # Afficher le résumé
        print(f"\n📋 TOKEN SUMMARY")
        print(f"{'─' * 60}")
        
        summary = token.get_summary()
        print(f"  Algorithm     : {summary['algorithm']}")
        print(f"  Type          : {summary['type']}")
        print(f"  Subject       : {summary['subject']}")
        print(f"  Issuer        : {summary['issuer']}")
        print(f"  Audience      : {summary['audience']}")
        print(f"  Issued at     : {summary['issued_at']}")
        print(f"  Expires at    : {summary['expires_at']}")
        print(f"  User ID       : {summary['user_id']}")
        print(f"  Email         : {summary['email']}")
        print(f"  Roles         : {', '.join(summary['roles']) if isinstance(summary['roles'], list) else summary['roles']}")
        print(f"  Scopes        : {', '.join(summary['scopes']) if isinstance(summary['scopes'], list) else summary['scopes']}")
        
        # Afficher les warnings
        if token.warnings:
            print(f"\n⚠️  WARNINGS:")
            for warn in token.warnings:
                print(f"  {warn}")
        
        # Afficher les erreurs
        if token.errors:
            print(f"\n❌ ERRORS:")
            for err in token.errors:
                print(f"  {err}")
        
        # Afficher tout
        if show_all:
            print(f"\n📦 HEADER (raw)")
            print(f"{'─' * 60}")
            print(json.dumps(token.header, indent=2))
            
            print(f"\n📦 PAYLOAD (raw)")
            print(f"{'─' * 60}")
            print(json.dumps(token.payload, indent=2))
            
            print(f"\n🔑 SIGNATURE")
            print(f"{'─' * 60}")
            print(f"  {token.signature[:20]}...")
        
        print("\n" + "=" * 60)

# ============================================
# CLI
# ============================================

def main():
    parser = argparse.ArgumentParser(
        description='Analyze JWT/OAuth tokens',
        epilog='Example: python jwt_analyzer.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."'
    )
    parser.add_argument('token', help='JWT token to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show full header, payload and signature')
    
    # Alternative: lire depuis stdin
    args = parser.parse_args()
    
    # Si pas de token en argument, lire depuis stdin
    token = args.token
    if token == '-' or not token:
        token = sys.stdin.read().strip()
    
    if not token:
        parser.print_help()
        sys.exit(1)
    
    # Analyser
    Analyzer.analyze(token, show_all=args.verbose)

if __name__ == "__main__":
    main()

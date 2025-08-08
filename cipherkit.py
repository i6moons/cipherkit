#!/usr/bin/env python3
"""
CipherKit - Advanced Cryptographic Analysis Tool
Comprehensive crypto/encoding toolkit for security professionals
Author: i6moons
"""

import argparse
import base64
import hashlib
import hmac
import secrets
import string
import urllib.parse
import html
import json
import binascii
import re
import codecs
from collections import Counter
from colorama import init, Fore, Style
import sys

# Initialisation colorama
init(autoreset=True)

class CipherKit:
    def __init__(self):
        self.banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║                        CipherKit v2.0                     ║
║              Advanced Cryptographic Analysis Tool         ║
║                      by i6moons                           ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

    def print_banner(self):
        print(self.banner)

    def output(self, message, color=Fore.WHITE):
        print(f"{color}{message}{Style.RESET_ALL}")

    def success(self, message):
        print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")

    def error(self, message):
        print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}")

    def info(self, message):
        print(f"{Fore.BLUE}[*] {message}{Style.RESET_ALL}")

    def warn(self, message):
        print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")

    # ============= CAESAR/ROT CIPHERS =============
    def caesar_cipher(self, text, shift):
        """Caesar cipher avec shift variable"""
        try:
            result = ""
            for char in text:
                if char.isalpha():
                    ascii_offset = 65 if char.isupper() else 97
                    result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
                else:
                    result += char
            return result
        except Exception as e:
            self.error(f"Erreur Caesar cipher: {e}")
            return None

    def rot13(self, text):
        """ROT13 encode/decode"""
        return self.caesar_cipher(text, 13)

    def brute_force_caesar(self, text):
        """Brute force tous les shifts Caesar possibles"""
        try:
            self.info("Brute force Caesar cipher (all shifts):")
            results = []
            for shift in range(26):
                result = self.caesar_cipher(text, shift)
                results.append((shift, result))
                print(f"Shift {shift:2d}: {result}")
            return results
        except Exception as e:
            self.error(f"Erreur brute force Caesar: {e}")

    # ============= ATBASH =============
    def atbash(self, text):
        """Atbash cipher (A=Z, B=Y, etc.)"""
        try:
            result = ""
            for char in text:
                if char.isalpha():
                    if char.isupper():
                        result += chr(ord('Z') - (ord(char) - ord('A')))
                    else:
                        result += chr(ord('z') - (ord(char) - ord('a')))
                else:
                    result += char
            return result
        except Exception as e:
            self.error(f"Erreur Atbash: {e}")
            return None

    # ============= VIGENERE =============
    def vigenere_encrypt(self, text, key):
        """Vigenère cipher encryption"""
        try:
            result = ""
            key = key.upper()
            key_index = 0
            
            for char in text:
                if char.isalpha():
                    shift = ord(key[key_index % len(key)]) - ord('A')
                    if char.isupper():
                        result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                    else:
                        result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                    key_index += 1
                else:
                    result += char
            return result
        except Exception as e:
            self.error(f"Erreur Vigenère encrypt: {e}")
            return None

    def vigenere_decrypt(self, text, key):
        """Vigenère cipher decryption"""
        try:
            result = ""
            key = key.upper()
            key_index = 0
            
            for char in text:
                if char.isalpha():
                    shift = ord(key[key_index % len(key)]) - ord('A')
                    if char.isupper():
                        result += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                    else:
                        result += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                    key_index += 1
                else:
                    result += char
            return result
        except Exception as e:
            self.error(f"Erreur Vigenère decrypt: {e}")
            return None

    # ============= MORSE CODE =============
    def morse_encode(self, text):
        """Encode en morse"""
        morse_dict = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
            'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
            '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
            '8': '---..', '9': '----.', ' ': '/'
        }
        
        try:
            result = []
            for char in text.upper():
                if char in morse_dict:
                    result.append(morse_dict[char])
                else:
                    result.append(char)
            return ' '.join(result)
        except Exception as e:
            self.error(f"Erreur morse encode: {e}")
            return None

    def morse_decode(self, morse):
        """Decode du morse"""
        morse_dict_reverse = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
            '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
            '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
            '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
            '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
            '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
            '---..': '8', '----.': '9', '/': ' '
        }
        
        try:
            words = morse.split(' / ')
            result = []
            for word in words:
                letters = word.split(' ')
                decoded_word = ''.join([morse_dict_reverse.get(letter, letter) for letter in letters])
                result.append(decoded_word)
            return ' '.join(result)
        except Exception as e:
            self.error(f"Erreur morse decode: {e}")
            return None

    # ============= BINARY =============
    def binary_encode(self, text):
        """Encode en binaire"""
        try:
            return ' '.join(format(ord(char), '08b') for char in text)
        except Exception as e:
            self.error(f"Erreur binary encode: {e}")
            return None

    def binary_decode(self, binary):
        """Decode du binaire"""
        try:
            binary = binary.replace(' ', '')
            if len(binary) % 8 != 0:
                raise ValueError("Longueur binaire invalide")
            
            result = ""
            for i in range(0, len(binary), 8):
                byte = binary[i:i+8]
                result += chr(int(byte, 2))
            return result
        except Exception as e:
            self.error(f"Erreur binary decode: {e}")
            return None

    # ============= ENCODAGES STANDARDS =============
    def base64_encode(self, data):
        """Encode en base64"""
        try:
            encoded = base64.b64encode(data.encode()).decode()
            return encoded
        except Exception as e:
            self.error(f"Erreur base64 encode: {e}")
            return None

    def base64_decode(self, data):
        """Decode base64"""
        try:
            # Essaie plusieurs méthodes
            methods = [
                lambda x: base64.b64decode(x).decode(),
                lambda x: base64.b64decode(x + '=').decode(),
                lambda x: base64.b64decode(x + '==').decode(),
                lambda x: base64.urlsafe_b64decode(x + '==').decode()
            ]
            
            for method in methods:
                try:
                    return method(data)
                except:
                    continue
            raise ValueError("Impossible de décoder en base64")
        except Exception as e:
            self.error(f"Erreur base64 decode: {e}")
            return None

    def url_encode(self, data):
        """URL encode"""
        try:
            return urllib.parse.quote(data)
        except Exception as e:
            self.error(f"Erreur URL encode: {e}")
            return None

    def url_decode(self, data):
        """URL decode"""
        try:
            return urllib.parse.unquote(data)
        except Exception as e:
            self.error(f"Erreur URL decode: {e}")
            return None

    def html_encode(self, data):
        """HTML encode"""
        try:
            return html.escape(data)
        except Exception as e:
            self.error(f"Erreur HTML encode: {e}")
            return None

    def html_decode(self, data):
        """HTML decode"""
        try:
            return html.unescape(data)
        except Exception as e:
            self.error(f"Erreur HTML decode: {e}")
            return None

    def hex_encode(self, data):
        """Hex encode"""
        try:
            return data.encode().hex()
        except Exception as e:
            self.error(f"Erreur hex encode: {e}")
            return None

    def hex_decode(self, data):
        """Hex decode"""
        try:
            return bytes.fromhex(data).decode()
        except Exception as e:
            self.error(f"Erreur hex decode: {e}")
            return None

    # ============= HASHING =============
    def hash_md5(self, data):
        """Hash MD5"""
        try:
            return hashlib.md5(data.encode()).hexdigest()
        except Exception as e:
            self.error(f"Erreur MD5: {e}")
            return None

    def hash_sha1(self, data):
        """Hash SHA1"""
        try:
            return hashlib.sha1(data.encode()).hexdigest()
        except Exception as e:
            self.error(f"Erreur SHA1: {e}")
            return None

    def hash_sha256(self, data):
        """Hash SHA256"""
        try:
            return hashlib.sha256(data.encode()).hexdigest()
        except Exception as e:
            self.error(f"Erreur SHA256: {e}")
            return None

    def hash_sha512(self, data):
        """Hash SHA512"""
        try:
            return hashlib.sha512(data.encode()).hexdigest()
        except Exception as e:
            self.error(f"Erreur SHA512: {e}")
            return None

    # ============= ANALYSE AVANCEE =============
    def analyze_text(self, text):
        """Analyse complète d'un texte"""
        try:
            results = []
            
            # Analyse de fréquence des caractères
            char_freq = Counter(text.lower())
            most_common = char_freq.most_common(3)
            
            # Tests de détection
            detections = []
            
            # Test Base64 strict
            if self._is_base64(text):
                try:
                    decoded = self.base64_decode(text)
                    if decoded:
                        detections.append(("Base64", 95, decoded))
                except:
                    pass
            
            # Test Hexadécimal strict
            if self._is_hex(text):
                try:
                    decoded = self.hex_decode(text)
                    if decoded:
                        detections.append(("Hexadécimal", 90, decoded))
                except:
                    pass
            
            # Test ROT13/Caesar
            if text.isalpha():
                rot13_result = self.rot13(text)
                if self._looks_like_english(rot13_result):
                    detections.append(("ROT13", 85, rot13_result))
            
            # Test Atbash
            if text.isalpha():
                atbash_result = self.atbash(text)
                if self._looks_like_english(atbash_result):
                    detections.append(("Atbash", 80, atbash_result))
            
            # Test Morse
            if self._is_morse(text):
                try:
                    morse_result = self.morse_decode(text)
                    if morse_result:
                        detections.append(("Morse", 90, morse_result))
                except:
                    pass
            
            # Test Binaire
            if self._is_binary(text):
                try:
                    binary_result = self.binary_decode(text)
                    if binary_result:
                        detections.append(("Binaire", 95, binary_result))
                except:
                    pass
            
            # Test URL encoding
            if '%' in text:
                try:
                    url_result = self.url_decode(text)
                    if url_result != text:
                        detections.append(("URL encoding", 85, url_result))
                except:
                    pass
            
            # Test HTML encoding
            if '&' in text and ';' in text:
                try:
                    html_result = self.html_decode(text)
                    if html_result != text:
                        detections.append(("HTML encoding", 80, html_result))
                except:
                    pass
            
            # Trier par confiance
            detections.sort(key=lambda x: x[1], reverse=True)
            
            return {
                'length': len(text),
                'char_frequency': most_common,
                'detections': detections
            }
            
        except Exception as e:
            self.error(f"Erreur analyse: {e}")
            return None

    def _is_base64(self, text):
        """Vérifie si le texte est vraiment du base64"""
        try:
            # Doit contenir seulement des caractères base64
            if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', text):
                return False
            
            # Longueur doit être multiple de 4
            if len(text) % 4 != 0:
                return False
            
            # Test de décodage
            base64.b64decode(text)
            return True
        except:
            return False

    def _is_hex(self, text):
        """Vérifie si le texte est vraiment hexadécimal"""
        try:
            # Doit contenir seulement des caractères hex
            if not re.match(r'^[0-9a-fA-F]+$', text):
                return False
            
            # Longueur doit être paire
            if len(text) % 2 != 0:
                return False
            
            # Test de décodage
            bytes.fromhex(text)
            return True
        except:
            return False

    def _is_morse(self, text):
        """Vérifie si le texte ressemble au morse"""
        morse_chars = set('.- /')
        return all(c in morse_chars for c in text)

    def _is_binary(self, text):
        """Vérifie si le texte est binaire"""
        cleaned = text.replace(' ', '')
        return all(c in '01' for c in cleaned) and len(cleaned) % 8 == 0

    def _looks_like_english(self, text):
        """Vérifie si le texte ressemble à de l'anglais"""
        if not text or len(text) < 3:
            return False
        
        # Fréquence des lettres en anglais
        english_freq = 'etaoinshrdlcumwfgypbvkjxqz'
        char_freq = Counter(text.lower())
        
        # Vérifier si les lettres les plus fréquentes correspondent
        most_common = [char for char, _ in char_freq.most_common(3)]
        return any(char in english_freq[:5] for char in most_common)

    # ============= MODE AUTO =============
    def auto_process(self, data):
        """Analyse automatique avec détection précise"""
        self.info(f"Analyse: {data[:50]}{'...' if len(data) > 50 else ''}")
        
        analysis = self.analyze_text(data)
        if not analysis:
            return
        
        print(f"\nLongueur: {analysis['length']}")
        print(f"Caractères fréquents: {analysis['char_frequency']}")
        
        if analysis['detections']:
            print(f"\n{Fore.CYAN}Détections possibles:{Style.RESET_ALL}")
            for encoding_type, confidence, result in analysis['detections']:
                confidence_color = Fore.GREEN if confidence >= 85 else Fore.YELLOW if confidence >= 70 else Fore.RED
                print(f"{encoding_type}: {confidence_color}{confidence}%{Style.RESET_ALL}")
                print(f"Résultat: {result[:100]}{'...' if len(result) > 100 else ''}")
                print()
        else:
            self.warn("Aucun encodage détecté")

    # ============= MODE INTERACTIF =============
    def interactive_mode(self):
        """Mode interactif professionnel"""
        self.info("Mode interactif activé. 'help' pour l'aide, 'quit' pour sortir.")
        
        while True:
            try:
                print(f"\n{Fore.CYAN}cipher>{Style.RESET_ALL} ", end="")
                user_input = input().strip()
                
                if not user_input:
                    continue
                
                if user_input.lower() in ['quit', 'exit']:
                    break
                
                elif user_input.lower() == 'help':
                    self._show_help()
                
                elif user_input.startswith('caesar '):
                    parts = user_input.split(' ', 2)
                    if len(parts) == 3 and parts[1].isdigit():
                        result = self.caesar_cipher(parts[2], int(parts[1]))
                        print(f"Résultat: {result}")
                    else:
                        print("Usage: caesar <shift> <text>")
                
                elif user_input.startswith('vigenere_enc '):
                    parts = user_input.split(' ', 2)
                    if len(parts) == 3:
                        result = self.vigenere_encrypt(parts[2], parts[1])
                        print(f"Résultat: {result}")
                    else:
                        print("Usage: vigenere_enc <key> <text>")
                
                elif user_input.startswith('vigenere_dec '):
                    parts = user_input.split(' ', 2)
                    if len(parts) == 3:
                        result = self.vigenere_decrypt(parts[2], parts[1])
                        print(f"Résultat: {result}")
                    else:
                        print("Usage: vigenere_dec <key> <text>")
                
                elif user_input == 'brute_caesar':
                    text = input("Texte à analyser: ")
                    self.brute_force_caesar(text)
                
                else:
                    # Analyse automatique
                    self.auto_process(user_input)
                    
            except KeyboardInterrupt:
                print("\nUtilisez 'quit' pour sortir")
            except Exception as e:
                self.error(f"Erreur: {e}")

    def _show_help(self):
        """Affiche l'aide"""
        help_text = f"""
{Fore.CYAN}COMMANDES DISPONIBLES:{Style.RESET_ALL}

Auto-analyse:
  <données>                     Analyse automatique
  
Chiffrements classiques:
  caesar <shift> <text>         Caesar cipher
  vigenere_enc <key> <text>     Vigenère encrypt
  vigenere_dec <key> <text>     Vigenère decrypt  
  brute_caesar                  Brute force Caesar
  
Utilitaires:
  help                          Affiche cette aide
  quit/exit                     Quitte le programme
        """
        print(help_text)

def main():
    parser = argparse.ArgumentParser(
        description="CipherKit - Advanced Cryptographic Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--interactive', '-i', action='store_true', help='Mode interactif')
    
    subparsers = parser.add_subparsers(dest='command', help='Commandes disponibles')
    
    # Commande auto
    auto_parser = subparsers.add_parser('auto', help='Analyse automatique')
    auto_parser.add_argument('data', help='Données à analyser')
    
    # Commandes de chiffrement
    caesar_parser = subparsers.add_parser('caesar', help='Caesar cipher')
    caesar_parser.add_argument('shift', type=int, help='Décalage')
    caesar_parser.add_argument('text', help='Texte')
    
    rot13_parser = subparsers.add_parser('rot13', help='ROT13')
    rot13_parser.add_argument('text', help='Texte')
    
    atbash_parser = subparsers.add_parser('atbash', help='Atbash cipher')
    atbash_parser.add_argument('text', help='Texte')
    
    morse_parser = subparsers.add_parser('morse', help='Morse code')
    morse_parser.add_argument('action', choices=['encode', 'decode'])
    morse_parser.add_argument('text', help='Texte')
    
    binary_parser = subparsers.add_parser('binary', help='Binary')
    binary_parser.add_argument('action', choices=['encode', 'decode'])
    binary_parser.add_argument('text', help='Texte')
    
    brute_parser = subparsers.add_parser('brute-caesar', help='Brute force Caesar')
    brute_parser.add_argument('text', help='Texte chiffré')
    
    args = parser.parse_args()
    
    kit = CipherKit()
    
    if args.interactive:
        kit.print_banner()
        kit.interactive_mode()
        return
    
    if not args.command:
        kit.print_banner()
        parser.print_help()
        return
    
    kit.print_banner()
    
    if args.command == 'auto':
        kit.auto_process(args.data)
    elif args.command == 'caesar':
        result = kit.caesar_cipher(args.text, args.shift)
        print(f"Résultat: {result}")
    elif args.command == 'rot13':
        result = kit.rot13(args.text)
        print(f"ROT13: {result}")
    elif args.command == 'atbash':
        result = kit.atbash(args.text)
        print(f"Atbash: {result}")
    elif args.command == 'morse':
        if args.action == 'encode':
            result = kit.morse_encode(args.text)
        else:
            result = kit.morse_decode(args.text)
        print(f"Résultat: {result}")
    elif args.command == 'binary':
        if args.action == 'encode':
            result = kit.binary_encode(args.text)
        else:
            result = kit.binary_decode(args.text)
        print(f"Résultat: {result}")
    elif args.command == 'brute-caesar':
        kit.brute_force_caesar(args.text)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Programme interrompu{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Erreur fatale: {e}{Style.RESET_ALL}")
        sys.exit(1)
"""

Filename: regex_generator.py
Author: Daethyra Carino <109057945+Daethyra@users.noreply.github.com>
Date: 2025-01-26
Version: v0.1.0
License: MIT (c) 2025 Daethyra Carino
Description: A configurable advanced regex pattern generator to help detect and match keyword variations in text, accounting for common evasion techniques such as character substitutions, Unicode homoglyphs, and optional separators. Designed to identify exact word matches while accommodating intentional obfuscation, making it ideal for threat hunting and intelligence, content moderation, OSINT, keyword filtering, and text analysis.

Usage:

- Interactive mode: python regex_generator.py
- Config file mode: python regex_generator.py -c config.json

Example config file:

{
  "words": ["test", "example"],
  "substitutions": {
    "e": "[eE3]"
  },
  "min_length": 4,
  "word_boundaries": true
}

"""

import json
import re
import argparse
import datetime
import unicodedata
from typing import List, Dict, Set

class RegexGenerator:
    DEFAULT_SUBSTITUTIONS = {
        'a': '[aA@4ÀÁÂÃÄÅàáâãäåĀāĂăĄąǍǎǞǟǠǡǻȀȁȂȃȦȧȺα]',
        'b': '[bB8Ββ]',
        'c': '[cC¢©ÇçĆćĈĉĊċČčƇƈСсς]',
        'd': '[dDÐĎďĐđðƉƊƋƌ]',
        'e': '[eE3€ÈÉÊËèéêëĒēĔĕĖėĘęĚěȄȅȆȇȨȩƎƏɛ]',
        'f': '[fFƑƒ]',
        'g': '[gG6ĜĝĞğĠġĢģƓǤǥǦǧǴ]',
        'h': '[hHĤĥĦħƕǶ]',
        'i': '[iI1!|ÎÏîïÌÍĮìíĨĩĪīĬĭİıȈȉȊȋƖƗɨ]',
        'j': '[jJĴĵȷ]',
        'k': '[kKĶķĸƘƙǨǩ]',
        'l': '[lL£ĹĺĻļĽľĿŀŁłƚǇǈǉ]',
        'm': '[mMµΜм]',
        'n': '[nNÑñŃńŅņŇňŉƝƞȠȵǊǋǌ]',
        'o': '[oO0ØøÖöÒÓÔÕŌōŎŏŐőƟƠơȌȍȎȏȪȫȬȭȮȯȰȱǾǿ]',
        'p': '[pPÞþƤƥΡρ]',
        'q': '[qQȹ]',
        'r': '[rRŔŕŖŗŘřƦȐȑȒȓɌɍ]',
        's': '[sS5$§ſſŚśŜŝŞşŠšȘșƧƨς]',
        't': '[tT7ŢţŤťŦŧƫƬƭƮȚțȶ]',
        'u': '[uUÙÚÛÜùúûüŨũŪūŬŭŮůŰűŲųȔȕȖȗƯưƱƲμ]',
        'v': '[vVƔƲν]',
        'w': '[wWŴŵƜƿ]',
        'x': '[xX×Χχ]',
        'y': '[yY¥ŶŷŸÿƳƴȲȳɎɏγ]',
        'z': '[zZŹźŻżŽžƵƶȤȥ]',
        ' ': '[\\s\\p{Zs}_-]*'
    }

    def __init__(self, config_path: str = None) -> None:
        self.config = self._load_config(config_path) if config_path else {}
        self.substitutions = {**self.DEFAULT_SUBSTITUTIONS, **self.config.get('substitutions', {})}
        self.separator = self.config.get('separator', '[\\W_]*')
        self.min_length = self.config.get('min_length', 3)
        self.enable_word_boundaries = self.config.get('word_boundaries', True)

    def _load_config(self, path: str) -> Dict:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            return {}

    def _normalize(self, text: str) -> str:
        return unicodedata.normalize('NFKC', text).lower()

    def _get_variations(self, char: str) -> Set[str]:
        norm_char = self._normalize(char)
        return {norm_char, char, self._normalize(norm_char)}

    def generate_patterns(self, words: List[str]) -> List[str]:
        patterns = []
        for word in words:
            if len(word) < self.min_length:
                continue
                
            base_word = self._normalize(word.strip())
            seen = set()
            
            for variant in self._permute_word(base_word):
                if variant in seen: 
                    continue
                seen.add(variant)
                
                pattern = []
                for c in variant:
                    sub = self.substitutions.get(c, re.escape(c))
                    pattern.append(f'({sub}){self.separator}')
                
                if pattern:
                    full_pattern = ''.join(pattern).rstrip(self.separator)
                    if self.enable_word_boundaries:
                        full_pattern = f'\\b{full_pattern}\\b'
                    patterns.append(full_pattern)
        
        return list(set(patterns))

    def _permute_word(self, word: str, index: int = 0) -> List[str]:
        if index >= len(word):
            return ['']
        return [
            v + suffix
            for v in self._get_variations(word[index])
            for suffix in self._permute_word(word, index + 1)
        ]

def main():
    parser = argparse.ArgumentParser(description="Generate anti-censorship regex patterns")
    parser.add_argument('-c', '--config', help="Path to config file")
    args = parser.parse_args()

    generator = RegexGenerator(args.config)
    
    if args.config:
        words = generator.config.get('words', [])
    else:
        words_input = input("Enter words to generate patterns for (comma-separated): ")
        words = [w.strip() for w in words_input.split(',') if w.strip()]

    patterns = generator.generate_patterns(words)
    
    if not patterns:
        print("No valid patterns generated (check word length)")
        return

    print("\nGenerated Patterns:")
    print('\n'.join(patterns))

    save = input("\nSave patterns? (y/n): ").lower()
    if save == 'y':
        fname = input(f"Enter filename [patterns_{datetime.datetime.now().strftime('%Y%m%d')}.txt]: ")
        fname = fname or f"patterns_{datetime.datetime.now().strftime('%Y%m%d')}.txt"
        with open(fname, 'w') as f:
            f.write('\n'.join(patterns))
        print(f"Saved {len(patterns)} patterns to {fname}")

if __name__ == "__main__":
    main()
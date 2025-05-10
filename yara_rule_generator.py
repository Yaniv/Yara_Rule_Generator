#!/usr/bin/env python3

import yara
import re
import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("yara_generator.log"), logging.StreamHandler()]
)

# Localization configuration
PROMPTS = {
    'en': {
        'title': "\n=== YARA Rule Generator ===",
        'rule_name': "Enter rule name (alphanumeric, no spaces): ",
        'author': "Enter author name: ",
        'description': "Enter rule description: ",
        'hash': "Enter sample hash (optional, press Enter to skip): ",
        'mitre_id': "Enter MITRE ATT&CK ID (optional, e.g., T1234): ",
        'malware_family': "Enter malware family (optional, e.g., Emotet): ",
        'trust_level': "\nSelect trust level:\n1. Zero Trust\n2. Medium Trust\n3. Basic\n4. Custom\nEnter choice (1-4): ",
        'invalid_trust': "Invalid trust level. Choose 1, 2, 3, or 4.",
        'strings': "\nEnter strings to match (one per line, press Enter twice to finish):\n",
        'min_strings': "At least one string is required.",
        'modifiers': "\nSelect string modifiers (comma-separated, e.g., nocase,wide,ascii): ",
        'advanced_conditions': "\nAdd advanced conditions? (y/n): ",
        'min_size': "Minimum file size (e.g., 100KB): ",
        'pe_sections': "Max PE sections (e.g., 5): ",
        'ext_var': "External variable (e.g., my_var == \"value\"): ",
        'custom_condition': "\nEnter custom condition: ",
        'output_format': "\nSelect output format (1: YARA file, 2: JSON, 3: Print only): ",
        'basic_method': "\nSelect matching method for Basic mode:\n1. Any String\n2. At Least N Strings\n3. Specific Strings\n4. Weighted Strings\nEnter choice (1-4): ",
        'basic_n_strings': "Enter minimum number of strings to match (1 to {}): ",
        'basic_specific_strings': "Enter indices of required strings (comma-separated, e.g., 1,3): ",
        'basic_weights': "Enter weight for string {} (1-10): ",
        'basic_weight_threshold': "Enter minimum total weight threshold: ",
        'test_rule': "\nTest rule? (1: Inline data, 2: File, 3: Auto-generate, 4: Skip): ",
        'test_data': "Enter test data to scan: ",
        'test_file': "Enter path to test file: ",
        'save_rule': "\nSave rule to file? (y/n): ",
        'invalid_file': "File {} does not exist.",
        'input_error': "Input error: {}",
        'error': "An error occurred: {}"
    }
    # Add Hebrew prompts in a similar structure if needed
}

USE_HEBREW = False
LANG = 'he' if USE_HEBREW else 'en'
ALLOWED_MODIFIERS = {'nocase', 'wide', 'ascii'}

class YaraRuleGenerator:
    """Class to generate and manage YARA rules."""
    
    def __init__(self, lang: str = 'en'):
        self.lang = lang
        self.prompts = PROMPTS[lang]
        self.hex_pattern = re.compile(r'^[0-9a-fA-F\s?{}|]*$')
        
    def validate_hex_string(self, s: str) -> bool:
        """Validate if a string is a valid hex string."""
        return bool(self.hex_pattern.match(s))
    
    def validate_regex(self, s: str) -> bool:
        """Validate if a string is a valid regex pattern."""
        try:
            re.compile(s)
            return True
        except re.error:
            return False
    
    def get_user_input(self) -> Dict:
        """Collect and validate user input for rule creation."""
        logging.info("Starting user input collection")
        print(self.prompts['title'])
        
        # Rule metadata
        rule_name = self._get_valid_rule_name()
        author = input(self.prompts['author']).strip() or "Anonymous"
        description = input(self.prompts['description']).strip() or "No description"
        hash_value = input(self.prompts['hash']).strip()
        mitre_id = input(self.prompts['mitre_id']).strip()
        malware_family = input(self.prompts['malware_family']).strip()
        
        # Trust level
        trust_level = self._get_valid_trust_level()
        
        # Strings
        strings, string_types = self._get_strings()
        
        # Modifiers and conditions
        modifiers = self._get_modifiers(trust_level)
        advanced_conditions = self._get_advanced_conditions(trust_level)
        custom_condition = self._get_custom_condition(trust_level)
        
        # Output format
        output_format = self._get_output_format()
        
        return {
            'rule_name': rule_name,
            'author': author,
            'description': description,
            'hash': hash_value,
            'mitre_id': mitre_id,
            'malware_family': malware_family,
            'trust_level': trust_level,
            'strings': strings,
            'string_types': string_types,
            'modifiers': modifiers,
            'advanced_conditions': advanced_conditions,
            'custom_condition': custom_condition,
            'output_format': output_format,
            'basic_method': None,  # Add basic mode logic if needed
            'basic_config': {}
        }
    
    def _get_valid_rule_name(self) -> str:
        """Get and validate rule name."""
        while True:
            rule_name = input(self.prompts['rule_name']).strip()
            if re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', rule_name):
                return rule_name
            logging.warning("Invalid rule name entered: %s", rule_name)
            print("Invalid rule name. Use alphanumeric characters, start with a letter.")
    
    def _get_valid_trust_level(self) -> str:
        """Get and validate trust level."""
        print(self.prompts['trust_level'])
        while True:
            trust_level = input().strip()
            if trust_level in ['1', '2', '3', '4']:
                return trust_level
            logging.warning("Invalid trust level entered: %s", trust_level)
            print(self.prompts['invalid_trust'])
    
    def _get_strings(self) -> Tuple[List[str], List[str]]:
        """Collect and validate strings."""
        strings = []
        string_types = []
        print(self.prompts['strings'])
        
        while True:
            s = input().strip()
            if s == "":
                if not strings:
                    print(self.prompts['min_strings'])
                    continue
                break
            if s.startswith("hex:"):
                hex_str = s[4:].strip()
                if not self.validate_hex_string(hex_str):
                    logging.warning("Invalid hex string: %s", hex_str)
                    print(f"Invalid hex string: {hex_str}. Skipping.")
                    continue
                strings.append(hex_str)
                string_types.append("hex")
            elif s.startswith("regex:"):
                regex_str = s[6:].strip()
                if not self.validate_regex(regex_str):
                    logging.warning("Invalid regex: %s", regex_str)
                    print(f"Invalid regex: {regex_str}. Skipping.")
                    continue
                strings.append(regex_str)
                string_types.append("regex")
            else:
                strings.append(s)
                string_types.append("text")
        
        logging.info("Collected %d strings", len(strings))
        return strings, string_types
    
    def _get_modifiers(self, trust_level: str) -> List[str]:
        """Get string modifiers for text strings."""
        if trust_level not in ['1', '2']:
            return []
        print(self.prompts['modifiers'])
        modifiers_input = input().strip().split(',')
        return [m.strip() for m in modifiers_input if m.strip() in ALLOWED_MODIFIERS]
    
    def _get_advanced_conditions(self, trust_level: str) -> Dict:
        """Get advanced conditions."""
        if trust_level not in ['1', '2', '4']:
            return {}
        print(self.prompts['advanced_conditions'])
        if input().lower() not in ['y', 'yes']:
            return {}
        
        conditions = {}
        min_size = input(self.prompts['min_size']).strip()
        if min_size:
            conditions['min_size'] = min_size
        pe_sections = input(self.prompts['pe_sections']).strip()
        if pe_sections.is        conditions['pe_sections'] = int(pe_sections)
        ext_var = input(self.prompts['ext_var']).strip()
        if ext_var:
            conditions['ext_var'] = ext_var
        return conditions
    
    def _get_custom_condition(self, trust_level: str) -> str:
        """Get custom condition for Custom Trust level."""
        if trust_level != '4':
            return ""
        print(self.prompts['custom_condition'])
        return input().strip()
    
    def _get_output_format(self) -> str:
        """Get output format."""
        print(self.prompts['output_format'])
        output_format = input().strip()
        return output_format if output_format in ['1', '2', '3'] else '3'
    
    def generate_yara_rule(self, user_input: Dict) -> str:
        """Generate YARA rule text."""
        logging.info("Generating YARA rule: %s", user_input['rule_name'])
        imports = ["pe", "math"] if user_input['trust_level'] in ['1', '2'] or user_input['advanced_conditions'] else []
        rule = "\n".join(f"import \"{mod}\"" for mod in imports) + "\n\n" if imports else ""
        
        rule += f"rule {user_input['rule_name']} {{\n"
        rule += "    meta:\n"
        rule += f"        author = \"{user_input['author']}\"\n"
        rule += f"        description = \"{user_input['description']}\"\n"
        if user_input['hash']:
            rule += f"        hash = \"{user_input['hash']}\"\n"
        if user_input['mitre_id']:
            rule += f"        mitre_id = \"{user_input['mitre_id']}\"\n"
        if user_input['malware_family']:
            rule += f"        malware_family = \"{user_input['malware_family']}\"\n"
        rule += f"        date = \"{datetime.now().strftime('%Y-%m-%d')}\"\n"
        
        rule += "\n    strings:\n"
        modifiers = " ".join(user_input['modifiers']) if user_input['modifiers'] else ""
        for i, (s, s_type) in enumerate(zip(user_input['strings'], user_input['string_types']), 1):
            if s_type == "hex":
                rule += f"        $s{i} = {{{s}}}\n"
            elif s_type == "regex":
                rule += f"        $s{i} = /{s}/ {modifiers}\n"
            else:
                s = s.replace('"', '\\"')
                rule += f"        $s{i} = \"{s}\" {modifiers}\n"
        
        rule += "\n    condition:\n"
        condition = self._build_conditions(user_input)
        rule += f"        {condition}\n"
        rule += "}"
        
        return rule
    
    def _build_conditions(self, user_input: Dict) -> str:
        """Build YARA rule conditions."""
        strings = user_input['strings']
        trust_level = user_input['trust_level']
        advanced_conditions = user_input['advanced_conditions']
        custom_condition = user_input['custom_condition']
        
        string_ids = [f"$s{i+1}" for i in range(len(strings))]
        condition_parts = []
        
        if trust_level == '1':
            condition_parts.append(f"all of ({','.join(string_ids)})")
            condition_parts.append("math.entropy(0, filesize) >= 7.0")
        elif trust_level == '2':
            majority = max(1, len(strings) - 1) if len(strings) > 2 else len(strings)
            condition_parts.append(f"uint16(0) == 0x5A4D and {majority} of ({','.join(string_ids)})")
        elif trust_level == '3':
            condition_parts.append(f"any of ({','.join(string_ids)})")
        elif trust_level == '4':
            if not custom_condition:
                raise ValueError("Custom condition cannot be empty for Custom Trust level.")
            return custom_condition
        
        if 'min_size' in advanced_conditions:
            condition_parts.append(f"filesize > {advanced_conditions['min_size']}")
        if 'pe_sections' in advanced_conditions:
            condition_parts.append(f"pe.number_of_sections <= {advanced_conditions['pe_sections']}")
        if 'ext_var' in advanced_conditions:
            condition_parts.append(advanced_conditions['ext_var'])
        
        return " and ".join(condition_parts)
    
    def compile_and_test_rule(self, rule_text: str, test_data: Optional[bytes] = None, test_file: Optional[str] = None) -> bool:
        """Compile and test the YARA rule."""
        try:
            rules = yara.compile(source=rule_text)
            logging.info("YARA rule compiled successfully")
            print("\nYARA rule compiled successfully!")
            
            matches = []
            if test_file and os.path.exists(test_file):
                matches = rules.match(test_file)
            elif test_data:
                matches = rules.match(data=test_data)
            
            if matches:
                print("Rule matched the test data/file!")
                for match in matches:
                    print(f"Matched rule: {match.rule}")
                    for string_match in match.strings:
                        print(f"  String: {string_match.identifier} at offset {string_match.instances[0].offset}")
            else:
                print("Rule did not match the test data/file.")
            
            return True
        except yara.SyntaxError as e:
            logging.error("YARA syntax error: %s", e)
            print(f"Error compiling YARA rule: {e}")
            return False
        except yara.Error as e:
            logging.error("YARA error: %s", e)
            print(f"YARA error: {e}")
            return False
        except Exception as e:
            logging.error("Unexpected error: %s", e)
            print(f"Unexpected error: {e}")
            return False
    
    def generate_test_data(self, strings: List[str]) -> bytes:
        """Generate sample test data based on strings."""
        return " ".join(strings).encode()
    
    def save_rule(self, rule_text: str, user_input: Dict) -> None:
        """Save the YARA rule based on output format."""
        filename = f"{user_input['rule_name']}"
        try:
            if user_input['output_format'] == '1':
                filename += ".yar"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(rule_text)
                logging.info("YARA rule saved to %s", filename)
                print(f"YARA rule saved to {filename}")
            elif user_input['output_format'] == '2':
                filename += ".json"
                rule_json = {
                    'rule_name': user_input['rule_name'],
                    'rule_text': rule_text,
                    'meta': {
                        'author': user_input['author'],
                        'description': user_input['description'],
                        'hash': user_input['hash'],
                        'mitre_id': user_input['mitre_id'],
                        'malware_family': user_input['malware_family'],
                        'date': datetime.now().strftime('%Y-%m-%d')
                    }
                }
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(rule_json, f, indent=4)
                logging.info("YARA rule saved as JSON to %s", filename)
                print(f"YARA rule saved as JSON to {filename}")
        except IOError as e:
            logging.error("Failed to save rule: %s", e)
            print(f"Error saving rule: {e}")
    
    def run(self) -> None:
        """Main execution logic."""
        try:
            user_input = self.get_user_input()
            rule_text = self.generate_yara_rule(user_input)
            
            print("\nGenerated YARA Rule:")
            print("-" * 50)
            print(rule_text)
            print("-" * 50)
            
            print(self.prompts['test_rule'])
            test_option = input().strip()
            test_data = None
            test_file = None
            
            if test_option == '1':
                test_data = input(self.prompts['test_data']).encode()
            elif test_option == '2':
                test_file = input(self.prompts['test_file']).strip()
                if not os.path.exists(test_file):
                    logging.warning("Test file does not exist: %s", test_file)
                    print(self.prompts['invalid_file'].format(test_file))
                    test_file = None
            elif test_option == '3':
                test_data = self.generate_test_data(user_input['strings'])
            
            if test_option in ['1', '2', '3']:
                self.compile_and_test_rule(rule_text, test_data, test_file)
            
            if user_input['output_format'] in ['1', '2']:
                self.save_rule(rule_text, user_input)
            elif user_input['output_format'] == '3':
                save_option = input(self.prompts['save_rule']).lower()
                if save_option in ['y', 'yes']:
                    user_input['output_format'] = '1'
                    self.save_rule(rule_text, user_input)
        
        except ValueError as e:
            logging.error("Input error: %s", e)
            print(self.prompts['input_error'].format(e))
        except KeyboardInterrupt:
            logging.info("User interrupted the program")
            print("\nOperation cancelled by user.")
        except Exception as e:
            logging.error("Unexpected error: %s", e)
            print(self.prompts['error'].format(e))

if __name__ == "__main__":
    generator = YaraRuleGenerator(lang=LANG)
    generator.run()

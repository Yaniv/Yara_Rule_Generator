import yara
import re
import os
import json
from datetime import datetime
import binascii

# Localization flag (set to True for Hebrew prompts)
USE_HEBREW = False

def validate_hex_string(s):
    """Validate if a string is a valid hex string."""
    try:
        if not re.match(r'^[0-9a-fA-F\s?{}|]*$', s):
            return False
        return True
    except Exception:
        return False

def validate_regex(s):
    """Validate if a string is a valid regex pattern."""
    try:
        re.compile(s)
        return True
    except re.error:
        return False

def get_user_input():
    """Collect user input for rule creation."""
    prompts = {
        'en': {
            'title': "\n=== YARA Rule Generator ===",
            'rule_name': "Enter rule name (alphanumeric, no spaces): ",
            'author': "Enter author name: ",
            'description': "Enter rule description: ",
            'hash': "Enter sample hash (optional, press Enter to skip): ",
            'mitre_id': "Enter MITRE ATT&CK ID (optional, e.g., T1234): ",
            'malware_family': "Enter malware family (optional, e.g., Emotet): ",
            'trust_level': "\nSelect trust level:\n1. Zero Trust (strict, all strings, high entropy)\n2. Medium Trust (balanced, majority of strings)\n3. Basic (simple, customizable matching)\n4. Custom (define your own condition)\nEnter choice (1-4): ",
            'invalid_trust': "Invalid trust level. Choose 1, 2, 3, or 4.",
            'strings': "\nEnter strings to match (one per line, press Enter twice to finish):\nPrefix with 'hex:' for hex strings, 'regex:' for regular expressions, or none for text.\n",
            'min_strings': "At least one string is required.",
            'modifiers': "\nSelect string modifiers for text strings (comma-separated, e.g., nocase,wide,ascii): ",
            'advanced_conditions': "\nAdd advanced conditions? (y/n): ",
            'min_size': "Minimum file size (e.g., 100KB, press Enter to skip): ",
            'pe_sections': "Max PE sections (e.g., 5, press Enter to skip): ",
            'ext_var': "External variable (e.g., my_var == \"value\", press Enter to skip): ",
            'custom_condition': "\nEnter custom condition (e.g., 'all of them or filesize > 100KB'): ",
            'output_format': "\nSelect output format (1: YARA file, 2: JSON, 3: Print only): ",
            'basic_method': "\nSelect matching method for Basic mode:\n1. Any String (match any single string)\n2. At Least N Strings (specify minimum number)\n3. Specific Strings (choose required strings)\n4. Weighted Strings (assign weights, meet threshold)\nEnter choice (1-4): ",
            'basic_n_strings': "Enter minimum number of strings to match (1 to {}): ",
            'basic_specific_strings': "Enter indices of required strings (comma-separated, e.g., 1,3): ",
            'basic_weights': "Enter weight for string {} (1-10): ",
            'basic_weight_threshold': "Enter minimum total weight threshold: ",
            'test_rule': "\nTest rule? (1: Inline data, 2: File, 3: Auto-generate, 4: Skip)\nEnter choice (1-4): ",
            'test_data': "Enter test data to scan: ",
            'test_file': "Enter path to test file: ",
            'save_rule': "\nSave rule to file? (y/n): "
        },
        'he': {
            'title': "\n=== מחולל כללי YARA ===",
            'rule_name': "הזן שם כלל (תווים אלפאנומריים, ללא רווחים): ",
            'author': "הזן שם המחבר: ",
            'description': "הזן תיאור הכלל: ",
            'hash': "הזן האש לדוגמה (אופציונלי, הקש Enter לדילוג): ",
            'mitre_id': "הזן מזהה MITRE ATT&CK (אופציונלי, לדוגמה, T1234): ",
            'malware_family': "הזן משפחת תוכנה זדונית (אופציונלי, לדוגמה, Emotet): ",
            'trust_level': "\nבחר רמת אמון:\n1. אפס אמון (קפדני, כל המחרוזות, אנטרופיה גבוהה)\n2. אמון בינוני (מאוזן, רוב המחרוזות)\n3. בסיסי (פשוט, התאמה מותאמת אישית)\n4. מותאם אישית (הגדר תנאי משלך)\nהזן בחירה (1-4): ",
            'invalid_trust': "רמת אמון לא חוקית. בחר 1, 2, 3 או 4.",
            'strings': "\nהזן מחרוזות להתאמה (אחת בשורה, הקש Enter פעמיים לסיום):\nהוסף קידומת 'hex:' למחרוזות הקסדצימליות, 'regex:' לביטויים רגולריים, או ללא קידומת לטקסט.\n",
            'min_strings': "נדרשת לפחות מחרוזת אחת.",
            'modifiers': "\nבחר מודיפיירים למחרוזות טקסט (מופרדים בפסיק, לדוגמה, nocase,wide,ascii): ",
            'advanced_conditions': "\nהוסף תנאים מתקדמים? (כן/לא): ",
            'min_size': "גודל קובץ מינימלי (לדוגמה, 100KB, הקש Enter לדילוג): ",
            'pe_sections': "מספר מקסימלי של סקציות PE (לדוגמה, 5, הקש Enter לדילוג): ",
            'ext_var': "משתנה חיצוני (לדוגמה, my_var == \"value\", הקש Enter לדילוג): ",
            'custom_condition': "\nהזן תנאי מותאם אישית (לדוגמה, 'all of them or filesize > 100KB'): ",
            'output_format': "\nבחר פורמט פלט (1: קובץ YARA, 2: JSON, 3: הדפסה בלבד): ",
            'basic_method': "\nבחר שיטת התאמה עבור מצב בסיסי:\n1. כל מחרוזת (התאם למחרוזת אחת כלשהי)\n2. לפחות N מחרוזות (ציין מספר מינימלי)\n3. מחרוזות ספציפיות (בחר מחרוזות נדרשות)\n4. מחרוזות משוקללות (הקצה משקלים, עמוד בסף)\nהזן בחירה (1-4): ",
            'basic_n_strings': "הזן מספר מינימלי של מחרוזות להתאמה (1 עד {}): ",
            'basic_specific_strings': "הזן אינדקסים של מחרוזות נדרשות (מופרדים בפסיק, לדוגמה, 1,3): ",
            'basic_weights': "הזן משקל עבור מחרוזת {} (1-10): ",
            'basic_weight_threshold': "הזן סף משקל כולל מינימלי: ",
            'test_rule': "\nבדוק כלל? (1: נתונים מוטבעים, 2: קובץ, 3: יצירה אוטומטית, 4: דלג)\nהזן בחירה (1-4): ",
            'test_data': "הזן נתונים לבדיקה: ",
            'test_file': "הזן נתיב לקובץ בדיקה: ",
            'save_rule': "\nשמור כלל לקובץ? (כן/לא): "
        }
    }
    lang = 'he' if USE_HEBREW else 'en'
    p = prompts[lang]

    print(p['title'])
    rule_name = input(p['rule_name']).strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', rule_name):
        raise ValueError("Invalid rule name. Use alphanumeric characters, start with a letter.")

    author = input(p['author']).strip()
    description = input(p['description']).strip()
    hash_value = input(p['hash']).strip()
    mitre_id = input(p['mitre_id']).strip()
    malware_family = input(p['malware_family']).strip()

    print(p['trust_level'])
    trust_level = input().strip()
    if trust_level not in ['1', '2', '3', '4']:
        raise ValueError(p['invalid_trust'])

    strings = []
    string_types = []
    print(p['strings'])
    while True:
        s = input().strip()
        if s == "":
            if len(strings) == 0:
                print(p['min_strings'])
                continue
            break
        if s.startswith("hex:"):
            hex_str = s[4:].strip()
            if not validate_hex_string(hex_str):
                print(f"Invalid hex string: {hex_str}. Skipping.")
                continue
            strings.append(hex_str)
            string_types.append("hex")
        elif s.startswith("regex:"):
            regex_str = s[6:].strip()
            if not validate_regex(regex_str):
                print(f"Invalid regex: {regex_str}. Skipping.")
                continue
            strings.append(regex_str)
            string_types.append("regex")
        else:
            strings.append(s)
            string_types.append("text")

    modifiers = []
    basic_method = None
    basic_config = {}
    if trust_level == '3':  # Basic mode
        print(p['basic_method'])
        basic_method = input().strip()
        if basic_method not in ['1', '2', '3', '4']:
            raise ValueError("Invalid matching method. Choose 1, 2, 3, or 4.")
        
        if basic_method == '2':  # At Least N Strings
            max_n = len(strings)
            n = input(p['basic_n_strings'].format(max_n)).strip()
            if not n.isdigit() or int(n) < 1 or int(n) > max_n:
                raise ValueError(f"Number must be between 1 and {max_n}.")
            basic_config['n_strings'] = int(n)
        elif basic_method == '3':  # Specific Strings
            indices = input(p['basic_specific_strings']).strip().split(',')
            indices = [int(i.strip()) for i in indices if i.strip().isdigit()]
            if not indices or max(indices) > len(strings) or min(indices) < 1:
                raise ValueError("Invalid indices. Use comma-separated numbers starting from 1.")
            basic_config['specific_strings'] = indices
        elif basic_method == '4':  # Weighted Strings
            weights = []
            for i, s in enumerate(strings, 1):
                w = input(p['basic_weights'].format(i)).strip()
                if not w.isdigit() or int(w) < 1 or int(w) > 10:
                    raise ValueError("Weight must be between 1 and 10.")
                weights.append(int(w))
            threshold = input(p['basic_weight_threshold']).strip()
            if not threshold.isdigit() or int(threshold) < 1:
                raise ValueError("Threshold must be a positive number.")
            basic_config['weights'] = weights
            basic_config['weight_threshold'] = int(threshold)

    if trust_level in ['1', '2']:  # Zero or Medium Trust
        print(p['modifiers'])
        modifiers_input = input().strip().split(',')
        modifiers = [m.strip() for m in modifiers_input if m.strip() in ['nocase', 'wide', 'ascii']]

    advanced_conditions = {}
    if trust_level in ['1', '2', '4']:
        print(p['advanced_conditions'])
        if input().lower() in ['y', 'כן']:
            min_size = input(p['min_size']).strip()
            if min_size:
                advanced_conditions['min_size'] = min_size
            pe_sections = input(p['pe_sections']).strip()
            if pe_sections and pe_sections.isdigit():
                advanced_conditions['pe_sections'] = int(pe_sections)
            ext_var = input(p['ext_var']).strip()
            if ext_var:
                advanced_conditions['ext_var'] = ext_var

    custom_condition = ""
    if trust_level == '4':
        print(p['custom_condition'])
        custom_condition = input().strip()

    output_format = input(p['output_format']).strip()
    if output_format not in ['1', '2', '3']:
        output_format = '3'

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
        'basic_method': basic_method,
        'basic_config': basic_config
    }

def build_conditions(trust_level, strings, advanced_conditions, custom_condition, basic_method, basic_config):
    """Build YARA rule conditions based on trust level and advanced options."""
    string_ids = [f"$s{i+1}" for i in range(len(strings))]
    condition_parts = []

    if trust_level == '1':  # Zero Trust
        condition_parts.append(f"all of ({','.join(string_ids)})")
        condition_parts.append("math.entropy(0, filesize) >= 7.0")
    elif trust_level == '2':  # Medium Trust
        majority = max(1, len(strings) - 1) if len(strings) > 2 else len(strings)
        condition_parts.append(f"uint16(0) == 0x5A4D and {majority} of ({','.join(string_ids)})")
    elif trust_level == '3':  # Basic
        if basic_method == '1' or not basic_method:  # Any String
            condition_parts.append(f"any of ({','.join(string_ids)})")
        elif basic_method == '2':  # At Least N Strings
            condition_parts.append(f"{basic_config['n_strings']} of ({','.join(string_ids)})")
        elif basic_method == '3':  # Specific Strings
            specific_ids = [f"$s{i}" for i in basic_config['specific_strings']]
            condition_parts.append(f"all of ({','.join(specific_ids)})")
        elif basic_method == '4':  # Weighted Strings
            weights = basic_config['weights']
            threshold = basic_config['weight_threshold']
            weighted_sum = " + ".join([f"{w} * ($s{i+1} matches)" for i, w in enumerate(weights)])
            condition_parts.append(f"({weighted_sum}) >= {threshold}")
    elif trust_level == '4':  # Custom
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

def generate_yara_rule(user_input):
    """Generate YARA rule text."""
    imports = ["pe", "math"] if user_input['trust_level'] in ['1', '2'] or user_input['advanced_conditions'] else []
    rule = ""
    if imports:
        rule += "\n".join(f"import \"{mod}\"" for mod in imports) + "\n\n"
    
    rule += f"rule {user_input['rule_name']} {{\n"
    
    # Meta section
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

    # Strings section
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

    # Condition section
    rule += "\n    condition:\n"
    rule += f"        {build_conditions(user_input['trust_level'], user_input['strings'], user_input['advanced_conditions'], user_input['custom_condition'], user_input['basic_method'], user_input['basic_config'])}\n"
    rule += "}"

    return rule

def compile_and_test_rule(rule_text, test_data=None, test_file=None):
    """Compile and test the YARA rule."""
    try:
        rules = yara.compile(source=rule_text)
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
        print(f"Error compiling YARA rule: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False

def generate_test_data(strings):
    """Generate sample test data based on strings."""
    return " ".join(strings).encode()

def save_rule(rule_text, user_input):
    """Save the YARA rule based on output format."""
    filename = f"{user_input['rule_name']}"
    if user_input['output_format'] == '1':
        filename += ".yar"
        with open(filename, 'w') as f:
            f.write(rule_text)
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
        with open(filename, 'w') as f:
            json.dump(rule_json, f, indent=4)
        print(f"YARA rule saved as JSON to {filename}")

def main():
    lang = 'he' if USE_HEBREW else 'en'
    prompts = {
        'en': {
            'invalid_file': "File {} does not exist.",
            'input_error': "Input error: {}",
            'error': "An error occurred: {}"
        },
        'he': {
            'invalid_file': "הקובץ {} אינו קיים.",
            'input_error': "שגיאת קלט: {}",
            'error': "אירעה שגיאה: {}"
        }
    }
    p = prompts[lang]

    try:
        user_input = get_user_input()
        rule_text = generate_yara_rule(user_input)
        
        print("\nGenerated YARA Rule:")
        print("-" * 50)
        print(rule_text)
        print("-" * 50)

        print(prompts[lang]['test_rule'])
        test_option = input().strip()
        test_data = None
        test_file = None
        if test_option == '1':
            test_data = input(prompts[lang]['test_data']).encode()
        elif test_option == '2':
            test_file = input(prompts[lang]['test_file']).strip()
            if not os.path.exists(test_file):
                print(p['invalid_file'].format(test_file))
                test_file = None
        elif test_option == '3':
            test_data = generate_test_data(user_input['strings'])

        if test_option in ['1', '2', '3']:
            compile_and_test_rule(rule_text, test_data, test_file)

        if user_input['output_format'] in ['1', '2']:
            save_rule(rule_text, user_input)
        elif user_input['output_format'] == '3':
            save_option = input(prompts[lang]['save_rule']).lower()
            if save_option in ['y', 'כן']:
                user_input['output_format'] = '1'
                save_rule(rule_text, user_input)

    except ValueError as e:
        print(p['input_error'].format(e))
    except Exception as e:
        print(p['error'].format(e))

if __name__ == "__main__":
    main()
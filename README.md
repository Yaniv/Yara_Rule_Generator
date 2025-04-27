# Yara_Rule_Generator
YARA Rule Generator

The YARA Rule Generator is a Python-based tool that simplifies the creation, compilation, and testing of YARA rules for malware detection, threat hunting, and file analysis. With an interactive command-line interface, it supports users of all skill levels, from beginners to advanced analysts, by offering customizable trust levels and matching methods.

Features





Multiple Trust Levels:





Zero Trust: Strict rules with all strings matching, high entropy checks, and advanced conditions.



Medium Trust: Balanced rules requiring a majority of strings and PE file checks.



Basic: Simple, customizable matching (any string, at least N strings, specific strings, or weighted strings).



Custom: User-defined conditions for maximum flexibility.



String Types:





Text strings (e.g., "malware.exe").



Hex strings (e.g., {4D 5A ?? 00}).



Regular expressions (e.g., /trojan\d+/).



Customizable Matching (Basic Mode):





Any single string match.



At least N strings match.



Specific strings required.



Weighted strings with a threshold (e.g., (3 * $s1 + 5 * $s2) >= 7).



Advanced Conditions:





File size constraints (e.g., filesize > 100KB).



PE module checks (e.g., pe.number_of_sections <= 5).



External variables (e.g., ext_var == "value").



Output Formats:





YARA files (.yar).



JSON for integration with other tools.



Console output for quick inspection.



Testing:





Test rules against inline data, files, or auto-generated data.



Detailed match reporting (strings and offsets).



Localization:





Supports English and Hebrew prompts (toggle via USE_HEBREW flag).



Robust Error Handling:





Validates inputs (hex, regex, weights, etc.) to prevent syntax errors.



Graceful handling of compilation and runtime errors.

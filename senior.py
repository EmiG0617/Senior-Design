import re
import pyverilog
from pyverilog.vparser.parser import parse
from pyverilog import *

import re
def correct_code(text, errorlist):
    corrected_code = text  # Start with the original code

    # Debugging the error list
    print(f"Initial code:\n{corrected_code}\n")
    for error in errorlist:
        print(f"Error in list: '{error}'")

    # Process errors one by one based on the failed checks
    for error in errorlist[1:]:  # Start from the second item since the first is "failed checks list:"
        print(f"current error: {error.strip()}")
        
        if error.strip() == 'extract_module_names':
            print("Fixing invalid module names...")
            corrected_code = fix_invalid_module_names(corrected_code)

        elif error.strip() == 'semicolon_placement':
            print("Fixing semicolon placement errors...")
            corrected_code = fix_missing_semicolons(corrected_code)

        elif error.strip() == 'check_unclosed_brackets':
            print("Fixing unclosed brackets...")
            corrected_code = fix_unclosed_brackets(corrected_code)

        elif error.strip() == 'check_variable_names':
            print("Fixing invalid variable names...")
            corrected_code = fix_invalid_variable_names(corrected_code)


        elif error.strip() == 'check_always_sensitivity_list':
            print(f"Handling 'check_always_sensitivity_list' error: {error.strip()}")
            corrected_code = fix_empty_sensitivity_lists(corrected_code)

        elif error.strip() == 'check_unclosed_brackets':
            print("Fixing unclosed brackets...")
            corrected_code = fix_unclosed_brackets(corrected_code)
    return corrected_code

def fix_missing_semicolons(text):
    # Example: add missing semicolons at the end of statements or declarations
    lines = text.splitlines()
    corrected_lines = []
    
    for i, line in enumerate(lines):
        # Preserve the indentation by not stripping leading whitespaces
        stripped_line = line.strip()
        # If it's not a comment or empty, ensure it ends with a semicolon
        if stripped_line and not stripped_line.startswith('//'):
            # Ensure semicolon at the end of declarations/assignments
            if not stripped_line.endswith(";") and not stripped_line.startswith(('begin', 'end', 'always', 'if', 'else')) and not (stripped_line.startswith('module') and stripped_line.endswith(('('))) and not stripped_line.startswith(('input', 'output', 'reg')):
                corrected_lines.append(line.rstrip() + ";")  # Append semicolon but preserve indentation and trailing spaces
            elif stripped_line.endswith(";") and stripped_line.startswith(('begin', 'end', 'always')):
                corrected_lines.append(line.replace(";", ""))
            elif stripped_line.startswith(('input', 'output', 'reg')) and not stripped_line.endswith(',') and not lines[i+1].lstrip().startswith(')'):
                corrected_lines.append(line.rstrip() + ";")
            else:
                corrected_lines.append(line)  # Leave the line as it is
        else:
            corrected_lines.append(line)  # Leave comments or empty lines as they are

    # Join the lines back with new line characters, preserving the original structure
    return "\n".join(corrected_lines)

import re

import re

def fix_invalid_variable_names(text):
    """
    Fixes invalid Verilog variable names by:
    - Removing leading digits
    - Removing special characters
    - Replacing invalid names in sensitivity list, declarations, and logic
    """
    corrected_lines = []

    # Patterns
    module_var_pattern = r'\b(input|output)\s+(wire|reg\s+)?(\[\s*\d+\s*:\s*\d+\s*\]\s*)?([a-zA-Z0-9_$%#,\s]+)\s*;'
    sens_list_pattern = r'(module\s+[^\s(]+?\s*)\((.*?)\)(\s*;)'

    modvarslist = []
    sensvarslist = []
    invalid_var_map = {}

    # Helper to fix a variable name
    def fix_var_name(name):
        fixed = re.sub(r'^\d+', '', name)           # remove leading digits
        fixed = re.sub(r'\W', '', fixed)            # remove special chars (non-alphanumeric, underscore)
        return fixed

    # Step 1: Fix input/output declarations in place
    def fix_module_declaration(match):
        direction = match.group(1)
        kind = match.group(2) or ''
        width = match.group(3) or ''
        var_list = match.group(4)

        vars_split = [v.strip() for v in var_list.split(',')]
        fixed_vars = []

        for var in vars_split:
            fixed = fix_var_name(var)
            if fixed != var:
                invalid_var_map[var] = fixed
            fixed_vars.append(fixed)
            modvarslist.append(var)

        return f"{direction} {kind or ''}{width or ''}{', '.join(fixed_vars)};"

    text = re.sub(module_var_pattern, fix_module_declaration, text)

    # Step 2: Fix sensitivity list
    def fix_sens_list(match):
        prefix, vars_group, suffix = match.groups()
        vars_split = [v.strip() for v in vars_group.split(',')]
        new_vars = []
        for v in vars_split:
            fixed = fix_var_name(v)
            if fixed != v:
                invalid_var_map[v] = fixed
            new_vars.append(fixed)
        return f"{prefix}({', '.join(new_vars)}){suffix}"

    text = re.sub(sens_list_pattern, fix_sens_list, text, flags=re.DOTALL)

    # Step 3: Replace all variable name references throughout the rest of the code
    for old_name, new_name in invalid_var_map.items():
        text = re.sub(rf'\b{re.escape(old_name)}\b', new_name, text)

    # Step 4: Consistency check
    cleaned_modvars = [invalid_var_map.get(var, var) for var in modvarslist]
    modvars_set = set(cleaned_modvars)

    sens_match = re.search(sens_list_pattern, text)
    if sens_match:
        sensvarslist = [v.strip() for v in sens_match.group(2).split(',')]
    sensvars_set = set(sensvarslist)

    missing_from_mod = list(sensvars_set - modvars_set)
    missing_from_sens = list(modvars_set - sensvars_set)

    if missing_from_mod:
        corrected_lines.append(
            f"Suggested correction: The following variable(s) are in the port list but missing declarations: {', '.join(missing_from_mod)}."
        )
    elif missing_from_sens:
        corrected_lines.append(
            f"Suggested correction: Module port sensitivity list should look like this: ({', '.join(sorted(modvars_set))});"
        )
    corrected_lines.extend(text.splitlines())
    return "\n".join(corrected_lines)



def fix_unclosed_brackets(text):
    fixed_code = []

    # Pattern to find 'always @( ...' with missing closing parenthesis
    always_end_pattern = r'(\balways\s+@\(.*?)(?=\s+begin)'  # matches always @( ... without a closing parenthesis
    always_begin_pattern = r'(\balways\s+@)\s*([^\(\s][^\n]*)' # for detecting missing opening paren.
    
    # Pattern for detecting module declaration with unclosed parentheses (missing closing parentheses before semicolon)
    module_pattern = r'(\bmodule\s+[^\n]*\([^)]*)\s*;'  # matches unclosed module sensitivity list before the semicolon
    module_missing_beginning_pattern = r'^\s*module\s+\w+\s+([^\(]*);'
    module_missing_closing_pattern = r'^\s*module\s+\w+\s*\([^\)]*;'
    # Pattern to detect 'if' statements with unbalanced parentheses
    pattern = r'^(\s*)if\s*\(?\s*([^\(\)]*?)\s*\)?\s+(begin)'
  # matches if with unclosed parentheses, followed by 'begin' or 'else'
    bracket_pattern = r'(\s*\S+)\s*(\d+:\d+)(\]|\[)?'

    # Process each line of the text
    for line in text.splitlines():
        # Check if the line contains 'always @( ...' with missing parentheses
        match = re.search(always_end_pattern, line)
        match2 = re.search(always_begin_pattern, line)
        module_match = re.search(module_pattern, line)
        module_mb_match = re.search(module_missing_beginning_pattern, line)
        module_mc_match = re.search(module_missing_closing_pattern, line)
        match3 = re.match(pattern, line)
        bracket_match = re.search(bracket_pattern, line)
        if match:
            # If there's a match for always @( ... without a closing parenthesis, add the missing ')'
            if (line[:match.end(1)][-1]) != ')':
                line = line[:match.end(1)] + ')' + line[match.end(1):]
        if match2:
            line = line[:match2.end(1)] + '(' + line[match2.end(1):]
            if (line[match2.end(1):][-7]) != ')':
                line = (line[:match2.end(1)] + line[match2.end(1):][:-6] + ')' + line[match2.end(1):][-6:])
                #print(line[match2.end(1):])
                
        if module_match: 
            # If there's a match for unclosed module parentheses, add the missing ')'
            print('here3')
            print(line[:module_match.end(1)])
            line = line[:module_match.end(1)] + ')' + line[module_match.end(1):]  # Insert closing parentheses before semicolon
        
        if module_mb_match:
            print('here')
            line = re.sub(r'(\bmodule\s+\w+)\s', r'\1(', line)
            module_mc_match = re.match(module_missing_closing_pattern, line)

            if module_mc_match: 
                print('here2')
                line = line[:module_mc_match.end(0)][:-1]  + ')' + line[:module_mc_match.end(0)][-1]

        if match3: 
            indent = match3.group(1)
            condition = match3.group(2).strip()
            keyword = match3.group(3)  # usually 'begin'
            line = re.sub(pattern, f'{indent}if ({condition}) {keyword}', line)
            
        if bracket_match:
            group = bracket_match.group(0)
            group1 = bracket_match.group(0)

            if group[-1] != ']' and group[-4] != '[': # Fix if missing opening and closing bracket
                group = group[-5] + ' '
                print(f'{group}')
                group += '['
                group2 = group1[0].rstrip()
                group2 += ']'
                line = line[:bracket_match.end(0)][:-5] + group + line[:bracket_match.end(0)][-3:] + group2 + line[bracket_match.end(0):]
            
            elif group[-1] != ']': # Fix if missing closing bracket
                group += ']'
                line = line[:bracket_match.start(0)] + group + line[bracket_match.end(0):]

            elif group[-1] == ']' and group[-5] != '[': # Fix if missing opening bracket
                group = group[-5]
                print(group)
                group += '['
                line = line[:bracket_match.end(0)][:-5] + group + line[:bracket_match.end(0)][-4:] + line[bracket_match.end(0):]

            
                
            
            # If no opening bracket, add it
            
        # Append the corrected line directly to the list without adding extra spaces
        fixed_code.append(line)

    return "\n".join(fixed_code)
    
def fix_empty_sensitivity_lists(text):
    # Pattern to match the module declaration (input/output variables)
    module_pattern = r'\b(input|output|reg)\s+(wire|reg)?\s*(\[\s*\d*\s*[:]\s*\d*\s*\]*\s*)?([a-zA-Z_][a-zA-Z0-9_]*)'
    always_pattern = r'\balways\s+@\(\s*\)\s*'
    print(text)
    corrected_code = text
    # Find all module port declarations (inputs, outputs)
    module_ports = re.findall(module_pattern, text)
    module_vars = []

    # Extract module variables (inputs, outputs)
    for x in module_ports:
        module_vars.append(x[-1])

    # Find all always blocks with empty sensitivity lists
    matches = re.findall(always_pattern, text)
    
    # Initialize the suggestion variable to ensure it's always defined
    print(matches)
    if matches: 
        for match in matches:
        
        # Construct the new sensitivity list based on input/output variables
            suggestion = (f"Suggested Correction: replace your empty always sensitivity list with an already declared variable, such as {module_vars[-1]}.\nNote: If using a clock variable, an always block can trigger on its positive or negative edge using posedge/negedge + (clock variable name).\n")
            z = corrected_code.replace(f"always @()", f"always @({module_vars[-1]})")
            suggestion += (z)
        
    return suggestion
    
def fix_invalid_module_names(text):
    # Ensure module names don't start with digits or contain invalid characters
    corrected_code = text
    module_pattern = r'\bmodule\s+([^\s\(\)]+)\s*(?=\()'
    module_names = re.findall(module_pattern, text)
    
    for name in module_names:
        print(name)
        if name[0].isdigit() or re.search(r'[^a-zA-Z0-9_]', name):
            # Change the module name to a valid one
            corrected_name = re.sub(r'[^a-zA-Z0-9_]', '', name)
            corrected_name = corrected_name.lstrip('0123456789')  # Ensure it doesn't start with a number
            corrected_code = corrected_code.replace(name, corrected_name)
    return (f"Suggested Correction: Replace module name {name} with {corrected_name}. \n {corrected_code}")

def semicolon_placement(text):
    """
    Function to check if the placement of semicolons in Verilog code is valid.
    It checks if a semicolon appears in valid places and warns about incorrect usage.
    """
    lines = text.splitlines()  # Split the text into lines
    errors = []  # List to hold error messages
    
    inside_module = False  # Flag to track if we're inside a module declaration
    
    for line_num, line in enumerate(lines, 1):
        # Remove comments from the line (everything after '//')
        line = re.sub(r'//.*', '', line).strip()
        
        # Ignore empty lines or lines that are just comments
        if not line:
            continue
        
        # Case 1: Check if 'module' declaration is multi-line and has a semicolon after ')'
        if line.startswith("module"):
            inside_module = True  # We are inside a module declaration
            if line.endswith("endmodule"): # check if the code is all in one line (module and endmodule are on the same line in this case.)
                continue
            elif ")" in line:  # If we find the closing parenthesis on the same line
                # Check if the next character after ')' is a semicolon
                if not line.strip().endswith(";"):
                    errors.append(f"Error: 'module' declaration should end with a semicolon on line {line_num}: {line}")
                inside_module = False  # No longer inside the module declaration
            else:
                # The module declaration is split across multiple lines, so continue
                continue

        # If we are inside a module and the line ends with ')', check for a semicolon
        if inside_module:
            if ")" in line:  # This line contains the closing parenthesis of the module portlist
                # Check if the next character after ')' is a semicolon
                if not line.strip().endswith(";"):
                    errors.append(f"Error: 'module' declaration should end with a semicolon on line {line_num}: {line}")
                inside_module = False  # No longer inside the module declaration
        
        # Case 2: Check if 'begin' or 'end' have semicolons (they should not)
        elif re.search(r'\b(begin|end)\b', line) and line.endswith(";"):
            errors.append(f"Error: Semicolon placed after '{line}' on line {line_num}. 'begin' and 'end' should not end with semicolons.")
        
        # Case 3: Check if the line contains a statement but does not end with a semicolon
        elif re.search(r'(input|output|reg|wire|assign|always|if|for|while)', line) and not line.endswith(";"):
            # Exclude lines that are 'always' or 'if' statements, they don't need semicolons
            if line.startswith("always") or line.startswith("if"):
                continue  # Skip this line, as 'always' and 'if' don't require a semicolon after them
            if not line.startswith("module") and not line.startswith("endmodule"):
                errors.append(f"Error: Missing semicolon at the end of statement on line {line_num}: {line}")

        # Case 4: Check if the line is an assignment statement and ends with a semicolon
        elif re.search(r'\b(assign|=)\b', line) and not line.endswith(";"):
            errors.append(f"Error: Missing semicolon at the end of assignment statement on line {line_num}: {line}")
        
    # Return all lines that don't end with a semicolon
    if errors:
        for error in errors:
            print(error)
        return False  # Return all the errors
    
    else:
        print("All semicolons are correctly placed.")
        return True


def check_unclosed_brackets(text):
    stack = []
    pairs = {'(': ')', '[': ']', '{': '}'}
    for char in text:
        if char in pairs.keys():
            stack.append(char)
        elif char in pairs.values():
            if not stack or pairs[stack.pop()] != char:
                return False  # Unmatched closing bracket found
    return len(stack) == 0  # Stack should be empty if all are closed
# If no errors, print a success message

def check_variable_names(text):
    """
    Function to check the validity of all variable names in the Verilog code.
    It looks for 'input', 'output', 'reg', and 'wire' declarations and checks the variable names.
    """
    # Regular expression to match 'input wire', 'output wire', 'input', 'output', 'reg' declarations
    pattern = r'\b(input|output)\s+(wire|reg)?\s*(\[\s*\d+\s*[:]\s*\d+\s*\]\s*)?([a-zA-Z_][a-zA-Z0-9_]*(?:\s*,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*)*)\s*'

    reserved_keywords = [
        "module", "always", "initial", "assign", "if", "else", "for", "while", 
        "case", "end", "parameter", "input", "output", "reg", "wire"
    ]
    
    pattern2 = r'module\s+[^\s(]+?\s*\((.*?)\)\s*;'
    matches2 = re.findall(pattern2, text, flags = re.DOTALL)
    port_names = []
    for x in matches2:
        # Split the port list into individual ports
        ports = [port.strip() for port in x.split(',')]
        port_names.extend(ports)
    print(f'port names: {port_names}')

    # Find all matches for the pattern
    matches = re.findall(pattern, text)
    
    invalid_names = []
    var_names = []

    for match in matches:
        # match[0] is the variable type and match[2] is the variable name
        var_type = match[0]
        variable_names = match[-1].split(',')  # Split multiple variables by commas
        variable_names = [var.strip() for var in variable_names]  # Strip extra spaces
        for variable_name in variable_names:
            starts_with_number = re.match(r'^\d', variable_name)
    
    # Check if it contains any special characters (not a letter, number, or underscore)
            has_special_char = re.search(r'[^\w\s]', variable_name)

            if bool(starts_with_number or has_special_char) == False:
                print("Variable names cannot begin with a number or contain special characters.")
                return False
            
            var_names.append((var_type, variable_name))  # Store both type and name

    print(f'var names: {var_names}')    
    undeclared_module_vars = [] # List for variables in sens list but not inside module
    undeclared_sens_vars = [] # List for variables in module but not inside sens list
    for var_type, variable_name in var_names:
        line_num = find_line_number(text, variable_name)

        # Check if the variable name is a reserved keyword
        if variable_name in reserved_keywords:
            print(f"Error: Variable name '{variable_name}' at line {line_num} cannot be a reserved keyword in Verilog.")
            invalid_names.append(variable_name)
        
        # Validate the variable name
        elif variable_name[0].isdigit():
            print(f"Error: Variable name '{variable_name}' at line {line_num} cannot start with a digit.")
            invalid_names.append(variable_name)
        
        # Check if the variable contains invalid characters (like @, $, %, etc.)
        elif re.search(r'[^a-zA-Z0-9_]', variable_name):
            print(f"Error: Variable name '{variable_name}' at line {line_num} contains invalid characters.")
            invalid_names.append(variable_name)
        
        # Check if the variable is a valid name
        elif re.match(r'^[a-zA-Z_][a-zA9-9_]*$', variable_name):
            continue  # This is a valid name, so we move to the next check

    # Check if any undeclared variables are in the sensitivity list but not declared in the module
    for x in port_names:  # Port names are variables declared in the sensitivity list
        if x not in [var[1] for var in var_names]:  # Variable names declared in the actual module
            undeclared_module_vars.append(x)

    # Check if any undeclared variables are in the module but not in the sensitivity list
    for var_type, x in var_names:
        # Skip 'wire' types for undeclared_vars1 check
        if var_type == 'wire':
            continue  # Move to the next variable if the type is 'wire'
        if x not in port_names:
            undeclared_sens_vars.append(x)

    # If any undeclared variables are found, print them and return False
    if undeclared_module_vars:
        for var in undeclared_module_vars:
            if any(reserved_keyword in var for reserved_keyword in reserved_keywords):
                break
            else:
                print(f'Variable {var} declared in sensitivity list but not declared within the module.')
                return False    

    if undeclared_sens_vars:
        for var in undeclared_sens_vars:
            print(f'Variable {var} declared in module but not declared within the sensitivity list.')
        return False        

    # If any invalid names are found, print them and return False
    if invalid_names:
        print(f"Invalid variable names: {', '.join(invalid_names)}")
        return False
    else:
        print("All variable names are valid.")
        return True



def find_line_number(text, target):
    lines = text.splitlines()  # Split the text into lines
    for index, line in enumerate(lines, 1):  # Enumerate with line numbers starting from 1
        if target in line:  # Check if the target string is in the line
            return index  # Return the line number
    return None  # Return None if the target isn't found

import re

def check_always_sensitivity_list(text):
    """
    Function to check the always blocks for empty sensitivity lists.
    This function works before the AST is generated.
    """
    # Pattern to match only 'always @()' with no content inside the parentheses
    always_pattern = r'\balways\s+@\(\s*\)\s*'  # Matches 'always @()' with empty parentheses
    
    always_blocks = re.finditer(always_pattern, text, re.MULTILINE)  # re.MULTILINE to check line-by-line
    
    found_empty_sensitivity_list = True  # Flag to track if any empty sensitivity list is found
    for match in always_blocks:
        line_number = text.count('\n', 0, match.start()) + 1  # Find line number of match
        print(f"Warning: Empty sensitivity list in 'always' block at line {line_number}.")
        found_empty_sensitivity_list = False
    
    # Return the result
    return found_empty_sensitivity_list

  
def extract_module_names(text):
    # Regular expression to match 'module' followed by a name with special characters, stopping before '('
    pattern = r'\bmodule\s+([^\s\(\)]+)\s*(?=\()'
    
    # Find all matches for the pattern
    module_names = re.findall(pattern, text)
    for x in module_names:
        res = find_line_number(text, x)
        if x[0].isdigit():
            print(f"Module name on line {res} cannot start with digit: {x}")
            return False
            break
        elif re.search(r'[^a-zA-Z0-9_]', x):
            print(f"Module name on line {res} cannot start with, contain, or end with a special character: {x}")
            return False
            break
    # Ensure the module name doesn't start or end with special characters
        elif not x[0].isalnum() or not x[-1].isalnum():
            return False
            break
        else:
            print(f"valid module name detected: {x}")
    return True
            
            
 
# Function to simulate the process of making the file
def make_file(text):
    filename = "makeFile.v"
    print(f"Running checks for input: \n{text}")
    functions = [extract_module_names, check_variable_names, semicolon_placement, check_unclosed_brackets, check_always_sensitivity_list]  # list of our checks
    passed = True  # Track if all checks pass
    passedlist = ["Passed checks list: "]
    failedlist = ["Failed checks list: "]
    for func in functions:  # iterate through each function
        result = func(text)  # get result for each function
        print(f"Running check: {func.__name__}")
        if result == False:  # if any function result is false, output which check failed
            failedlist.append(func.__name__)  # add to failed list
            print(f"Check failed.")
            passed = False  # Set passed to False and stop further checks
            
        elif result == True:  # if result is True, output which check passed
            passedlist.append(func.__name__)  # add to passed list
            print(f"Check passed.")
    
    if passed:  # Proceed to file creation only if all checks passed
        joined_passed_list = ' '.join(passedlist[1:])
        print(f"All checks passed: {joined_passed_list}")
        with open(filename, "w+") as file:
            file.write(text)  # Write the Verilog code to the file
        parse_file(filename)

    elif not passed:
        joined_failed_list = ' '.join(failedlist)
        print(joined_failed_list)
        if passedlist[1:]:
            joined_passed_list = ' '.join(passedlist)
            print(joined_passed_list)
        corrected_code = correct_code(text, failedlist)
        print("Corrected Code:")
        print(corrected_code)

# Function to parse the Verilog file and handle AST
def parse_file(filename):
    ast = None
    try:
        with open(filename, 'r') as f:
            #print("File content:")
            #print(f.read())
            print("Checks passed.")
            print("Parsing file...")
            ast, _ = parse([filename], debug=True)  # Ensure the file path is passed as a list
            print("Parsing successful.")
    except pyverilog.vparser.parser.ParseError as e:
        print(f"Verilog Parsing Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

    # Proceed with AST processing only if parsing is successful
    if ast is not None:  # Ensure AST is valid before proceeding
        if hasattr(ast, 'description'):
            if hasattr(ast.description, 'children'):
                print("Processing children...")
                children = ast.description.children()  # Call the method to get the children
                check_code(children)
            else:
                print("No children attribute found in description.")
        else:
            print("AST doesn't have a description attribute.")
    else:
        print()
        print("AST is None, skipping further processing.")


# Function to check the parsed module details
def check_code(children):
    global module_details
    module_details = []
    for item in children:
        if isinstance(item, pyverilog.vparser.ast.ModuleDef):  # Check if it's a ModuleDef object
            find_ports(item)

def find_ports(item):
    try:
        module_info = {
            'name': item.name,
            'ports': []
        }
        # Check if the module has an empty portlist
        if not item.portlist.ports:  # No ports declared
            print(f"Error: Module '{item.name}' does not have any ports declared but is using ports.")
            module_info['ports'].append("No ports declared")
            return
            
        # Iterate through ports in the portlist
        for port in item.portlist.ports:
            if isinstance(port, pyverilog.vparser.ast.Ioport): # Check if port is an Ioport object
                if isinstance(port.first, pyverilog.vparser.ast.Input):
                    if isinstance(port.second, pyverilog.vparser.ast.Wire):
                        port_name = "Input " + "wire " + port.first.name
                        module_info['ports'].append(port_name)
                        continue
                    elif isinstance(port.second, pyverilog.vparser.ast.Reg):
                        port_name = "Input " + "register " + port.first.name
                        module_info['ports'].append(port_name)
                        continue
                    port_name = "Input " + port.first.name
                    module_info['ports'].append(port_name)
                elif isinstance(port.first, pyverilog.vparser.ast.Output):
                    if isinstance(port.second, pyverilog.vparser.ast.Wire):
                        port_name = "Output " + "wire " + port.first.name
                        module_info['ports'].append(port_name)
                        continue
                    elif isinstance(port.second, pyverilog.vparser.ast.Reg):
                        port_name = "Output " + "register " + port.first.name
                        module_info['ports'].append(port_name)
                        continue
                    port_name = "Output " + port.first.name
                    module_info['ports'].append(port_name)
            elif isinstance(port, pyverilog.vparser.ast.Port): # check if current port is general declared port(a port that is only declared in the module sens list with a letter and no direction (in or output)
                continue    
            else:
                print(f"Port {port} has no 'first' attribute value.")
        else:
            if hasattr(item, 'items'):
                find_instances(item, module_info)  # Check instances if any

    except AttributeError as e:
        print(f"Error while accessing ports for module {item.name}: {e}")


def find_instances(item, module_info):
    module_info['instances'] = []
    for instance in item.items:
        # Handling Assign statements (Blocking and Non-blocking)
        if isinstance(instance, pyverilog.vparser.ast.Assign):  # Check for assignment statements
            
            if hasattr(instance.right.var, 'cond'): ## this will account for conditional statements. ex: assign out = sel ? in[1] : in[0];
                lhs = instance.left.var
                true_val = str(instance.right.var.true_value.var) + str(f'[{instance.right.var.true_value.ptr}]' if instance.right.var.false_value.ptr else None)
                false_val = str(instance.right.var.false_value.var) + str(f'[{instance.right.var.false_value.ptr}]' if instance.right.var.false_value.ptr else None)
                rhs = instance.right.var.cond.name 
                instance_info = {'Assign statement': f'{lhs} = {true_val} if {rhs} is true, otherwise {lhs} = {false_val}'}
                module_info['instances'].append(instance_info)
            else:
                lhs = instance.left.var 
                rhs = instance.right.var
                instance_info = {
                    'Assign statement': f'{lhs} = {rhs}',  # Left-hand side and Right-hand side of the assignment
                    
                }
                module_info['instances'].append(instance_info)
        
        # Handling Always block
        elif isinstance(instance, pyverilog.vparser.ast.Always):
            senslist = instance.sens_list.list  # Sensitivity list
            portlist = ""
            for x in senslist: # .type returns if the sig if pos/neg edge, .sig returns the variable name
                if x.type == 'all':
                    portlist += 'any variable used in this block'
                elif x.type: # if senslist uses edge triggered sigs like pos/negedge
                    portlist += f"{x.type} {x.sig} "
                else: # if senslist only uses var names such as 'always @(a)'
                    portlist += f"{x.sig} "
            instance_info = {
                'Always senslist': portlist
            }
            module_info['instances'].append(instance_info)
            # Print for debugging
            # Ensure statement is a Block before accessing its statements
            if isinstance(instance.statement, pyverilog.vparser.ast.Block):
                # This ensures we're working with a Block type statement                
                # If the block contains statements, process them
                if hasattr(instance.statement, 'statements'):
                    for stmt in instance.statement.statements:
                        #print("Processing statement:", stmt)

                        # Handling BlockingSubstitution statements
                        if isinstance(stmt, pyverilog.vparser.ast.BlockingSubstitution):
                            print("BlockingSubstitution statement found")
                            astatement = f"{stmt.left.var} = {stmt.right.var}"  # Blocking assignment
                            instance_info = {
                                'Always statement': astatement
                            }
                            module_info['instances'].append(instance_info)
                        
                        # Handling NonblockingSubstitution statements
                        elif isinstance(stmt, pyverilog.vparser.ast.NonblockingSubstitution):
                            print("NonblockingSubstitution statement found")
                            if hasattr(stmt.right.var, 'left'):
                                astatement = f"{stmt.left.var} <= {stmt.right.var.left} {type(stmt.right.var).__name__} {stmt.right.var.right}"
                            #print((stmt.right.var.left))
                            #print(stmt.right.var.right)
                            else:
                                astatement = f"{stmt.left.var} <= {stmt.right.var}"  # Non-blocking assignment
                            instance_info = {
                                'Always statement': astatement
                            }
                            module_info['instances'].append(instance_info)
                        
                        # Handling IfStatement (conditional statements)
                        elif isinstance(stmt, pyverilog.vparser.ast.IfStatement):
                            if hasattr(stmt.cond, 'left'):
                                # print((stmt.cond.left))
                                # print(type(stmt.cond).__name__)
                                # print((stmt.cond.right))
                                cond = f'{str(stmt.cond.left)} { type(stmt.cond).__name__} { str(stmt.cond.right)}'
                                # print(f'If {cond}')
                                # print(dir(stmt))
                                # print(dir(stmt.true_statement))
                                # print((stmt.true_statement.right.var.ptr))
                                # print((stmt.true_statement.right.var.var))
                                
                                tst = f'{stmt.true_statement.left.var} =' + f' {stmt.true_statement.right.var.var}' + f'[{stmt.true_statement.right.var.ptr}]' if stmt.true_statement.right.var.ptr else ''
                                fst = f'{stmt.false_statement.left.var} =' + f' {stmt.false_statement.right.var.var}' + f'[{stmt.false_statement.right.var.ptr}]' if stmt.false_statement.right.var.ptr else ''
                                ifstatement = f'If {cond}, then {tst}. Else {fst}'
                                instance_info = {
                                        'If statement': ifstatement
                                         }
                                module_info['instances'].append(instance_info)
                                break
                            if not hasattr(stmt.cond, 'left'):
                                if isinstance(stmt.true_statement, pyverilog.vparser.ast.Block):
                                    tstatement = ''
                                    for x in stmt.true_statement.statements:
                                        if isinstance(x, pyverilog.vparser.ast.NonblockingSubstitution):
                                            tstatement += f'{x.left.var} = {x.right.var} '
                                    if hasattr(stmt.false_statement, 'statements'):
                                        for x in stmt.false_statement.statements:
                                            if isinstance(x, pyverilog.vparser.ast.NonblockingSubstitution):
                                                fstatement = f'{x.left.var} = {x.right.var}'
                                            # This writes to module info if both T/F statements are present and it is a Block object
                                                ifstatement = f"if {stmt.cond}, then {tstatement}. Else, {fstatement}. "
                                                instance_info = {
                                        'If statement': ifstatement
                                         }
                                                module_info['instances'].append(instance_info)
                                                break
                                    elif not hasattr(stmt.false_statement, 'statements'):
                                    #executes when block object is found but there is no false statement
                                        ifstatement = f"if {stmt.cond}, then {tstatement}. No else statement found. "
                                        instance_info = {
                                        'If statement': ifstatement
                                         }
                                        module_info['instances'].append(instance_info)
                                        break
                                        
                                else: # executes when no block object is found
                                    if hasattr(stmt.false_statement, 'left'): # executes if there is an else statement (false statement)
                                        ifstatement = f'if {stmt.cond}, then {stmt.true_statement.left.var} = {stmt.true_statement.right.var}. Else, {stmt.false_statement.left.var} = {stmt.false_statement.right.var}'
                                        instance_info = {
                                        'If statement': ifstatement
                                         }
                                        module_info['instances'].append(instance_info)
                                        break
                                    elif not hasattr(stmt.false_statement, 'left'): # executes if there isn't a false statement
                                        ifstatement = f'if {stmt.cond}, then {stmt.true_statement.left.var} = {stmt.true_statement.right.var}. No else statement found.'
                                        instance_info = {
                                         'If statement': ifstatement
                                          }
                                        module_info['instances'].append(instance_info)
                                        break
                        elif isinstance(stmt, pyverilog.vparser.ast.CaseStatement):
                            x = stmt.comp.name # this is the variable we are checking for our case statements
                            cst2 = ''
                            for x in stmt.caselist: # iterate through case statements
                                # cond[0] holds the statement condition, statement.left/.right contain the variables used. 
                                cst = f'If {stmt.comp.name} is {x.cond[0]}, then {x.statement.left.var} = {x.statement.right.var.var}' + f'[{x.statement.right.var.ptr}]' if x.statement.right.var.ptr else '' 
                                cst = cst + '. '
                                cst2 = cst2 + (cst)
                            instance_info = {'Case Statement': cst2}
                            module_info['instances'].append(instance_info)
                        else:
                            print(f"always statement found is not a blking/nonblking/if statement ")
                else:
                    print("No statements found in this block")
            else:
                print("instance.statement is not a Block object")

        # Handling Initial block statements
        elif isinstance(instance, pyverilog.vparser.ast.Initial):
            initstatement1 = ""
            for x in instance.statement.statements:
                if isinstance(x, pyverilog.vparser.ast.NonblockingSubstitution):
                    initstatement = f"{x.left.var} <= {x.right.var} "
                    initstatement1 += initstatement
            instance_info = {
                'Variables initialized': initstatement1
            }
            module_info['instances'].append(instance_info)

        # Handling other declarations such as Input, Output, etc.
        elif isinstance(instance, pyverilog.vparser.ast.Decl):
            print(instance.list)
            for p in instance.list:
                if isinstance(p, pyverilog.vparser.ast.Input):
                    port_name = f'{int(str(p.width.msb)) - int(str(p.width.lsb)) + 1}-bit Input ' + p.name if p.width else "Input " + p.name # adds bit width for variable if it exists.
                    module_info['ports'].append(port_name)
                elif isinstance(p, pyverilog.vparser.ast.Output):
                    port_name = f'{int(str(p.width.msb)) - int(str(p.width.lsb)) + 1}-bit Output ' + p.name if p.width else "Output " + p.name
                    port_name = "Output " + p.name
                    module_info['ports'].append(port_name)
                elif isinstance(p, pyverilog.vparser.ast.Wire):
                    print(dir(p))
                    wire_name = f'{int(str(p.width.msb)) - int(str(p.width.lsb)) + 1}-bit Wire ' + p.name if p.width else "Wire " + p.name
                    module_info['ports'].append(wire_name)
                elif isinstance(p, pyverilog.vparser.ast.Reg):
                    reg_name = f'{int(str(p.width.msb)) - int(str(p.width.lsb)) + 1}-bit Reg ' + p.name if p.width else "Reg " + p.name
                    module_info['ports'].append(reg_name)
                elif isinstance(p, pyverilog.vparser.ast.Parameter):
                    param_name = f'{int(str(p.width.msb)) - int(str(p.width.lsb)) + 1}-bit Paramater ' + p.name if p.width else "Parameter " + p.name
                    if p.value.var:
                        param_name = param_name + f" (initialized to {(p.value.var)})"
                    module_info['ports'].append(param_name)
                else:
                    print(f"Error gathering info on Port {p.first.name}")
        elif isinstance(instance, pyverilog.vparser.ast.InstanceList):
            x = f'Module {instance.instances[0].module} instantiated as {instance.instances[0].name}'
            instance_info = {'Module Instantiations': x}
            module_info['instances'].append(instance_info)
            
        else:
            print("Not an assign, decl, if or always statement")
    
    # Append to the global module_details list
    module_details.append(module_info)
    output_module_details()

def output_module_details():
    result = []
    for module in module_details:
        module_info = {
            'module name': module['name'],
            'ports': module['ports'],
            'instances': []
        }

        # Iterate over the instances and add relevant statements
        for instance in module.get('instances', []):
            if 'Assign statement' in instance:
                statement = instance['Assign statement']  # Extract LHS name
                module_info['instances'].append({'Assign statement': statement})
            if 'Always senslist' in instance:
                senslist = instance['Always senslist']
                module_info['instances'].append({'Always senslist': senslist})
            if 'Always statement' in instance:
                astatement = instance['Always statement']
                module_info['instances'].append({'Always statement': astatement})
            if 'Variables initialized' in instance:
                statement = instance['Variables initialized']
                module_info['instances'].append({'Variables initialized': statement})
            if 'If statement' in instance:
                x = instance['If statement']
                module_info['instances'].append({'If statement': x})
            if 'Module Instantiations' in instance:
                x = instance['Module Instantiations']
                module_info['instances'].append({'Module Instantiation': x})
            if 'Case Statement' in instance:
                x = instance['Case Statement']
                module_info['instances'].append({'Case Statement': x})
        result.append(module_info)

    # Print the result to see the module details
    for module in result:
        # Print the module name with a newline after it
        print(f"Module name: {module['module name']}\n")
        
        # Print the module ports, joined by a comma and space
        ports = ', '.join(module['ports'])
        print(f"Module ports: {ports}\n")
        
        # Print the module instances, each on a new line
        print("Module instances:")
        for instance in module['instances']:
            for key, value in instance.items():
                print(f"    {key}: {value}")
        
        # Add a newline after the instances section
        print()

# make_file("""module slow_clock(Clk, Clk_Slow);
# parameter size = 100000000;  //added to be used by test bench 
# input x;
# output Clk_Slow;
# reg [31:0] counter_out;
# reg Clk_Slow;
# 	initial begin	//Note this will synthesize because we are using an FPGA and not making an IC
# 	counter_out<= 32'h00000000;
# 	Clk_Slow <=0;
# 	end
	
# //this always block runs on the fast 100MHz clock
# always @(*) begin
# 	counter_out<=    counter_out + 32'h00000001;
		
# 	if (counter_out  > size) 
# 		counter_out <= 32'h00000000;
# 		Clk_Slow <= !Clk_Slow;
# 	end

# endmodule

# """)

# make_file("""
# module MUX8to1(in, sel, out, clk);
#     input [7:0] sel;
#     output [2:0] out;
#     output reg in;
#     input wire clk;      

    
#     wire [5:0] MUX_output;
#     always@() begin
#     end
          
#     MUX2to1 M0(in[1:0], sel[0], MUX_output[0]);
#     MUX2to1 M1(in[3:2], sel[0], MUX_output[1]);
#     MUX2to1 M2(in[5:4], sel[0], MUX_output[2]);
#     MUX2to1 M3(in[7:6], sel[0], MUX_output[3]);
#     MUX2to1 M4(MUX_output[1:0], sel[1], MUX_output[4]);
#     MUX2to1 M5(MUX_output[3:2], sel[1], MUX_output[5]);
#     MUX2to1 M6(MUX_output[5:4], sel[2], out);

# endmodule



# """)

make_file("""module D_FF(#CLK, $D, %RST, Q, Q_NOT);
    input [3:0] CLK, D, RST
    output reg [5:0] Q, Q_NOT
    
    always @(Q) begin
        if (RST) begin
            Q <= 1'b0;
            Q_NOT <= 1'b1
            end
        else begin
            Q <= D;
            Q_NOT <= !D;
            end
            end
endmodule""")
make_file("""module counter(
    input clk,
    input reset,
    output reg [3:0] count
)
    assign clk = count
    always @() begin
        if (reset)
            count <= 4'b0000;
        else
            count <= 0;
    end
endmodule""")

# make_file("""module d_flip_flop (  
# input wire d,   
# input wire clk, 
# input wire reset, 
# output wire q);  
# always @() begin  
#  if (reset) begin // When 'reset' is active (1), asynchronously reset the flop.  
#   q <= 1'b0;  
#  end  
#  else begin // On the rising edge of the clock, store the value of 'd'. 
#   q <= d;  
#  end  
# end  
# endmodule""")
#make_file("module test(a, b, c, d); input a; output a, b;  assign a = b; endmodule")  
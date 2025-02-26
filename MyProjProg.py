import re
import pyverilog
from pyverilog.vparser.parser import parse
from pyverilog import *

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
        
    # If no errors, print a success message
    if not errors:
        print("All semicolons are correctly placed.")
        return True
    else:
        for error in errors:
            print(error)
        return False

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
    pattern = r'\b(input|output|reg|wire)\s+(\[\s*\d+\s*[:]\s*\d+\s*\]\s*)?([a-zA-Z_][a-zA-Z0-9_]*[^;\s,]*)\s*;'

    reserved_keywords = [
        "module", "always", "initial", "assign", "if", "else", "for", "while", 
        "case", "end", "parameter", "input", "output", "reg", "wire"
    ]
    
    pattern2 = r'\bmodule\s+\w+\s*\(\s*([\w\s,]+)\s*\)'
    matches2 = re.findall(pattern2, text)
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
        variable_name = match[2]
        var_names.append((var_type, variable_name))  # Store both type and name

    print(f'var names: {var_names}')    
    undeclared_vars = []
    undeclared_vars1 = []
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
            undeclared_vars.append(x)

    # Check if any undeclared variables are in the module but not in the sensitivity list
    for var_type, x in var_names:
        # Skip 'wire' types for undeclared_vars1 check
        if var_type == 'wire':
            continue  # Move to the next variable if the type is 'wire'
        if x not in port_names:
            undeclared_vars1.append(x)

    # If any undeclared variables are found, print them and return False
    if undeclared_vars:
        for var in undeclared_vars:
            print(f'Variable {var} declared in sensitivity list but not declared within the module.')
        return False    

    if undeclared_vars1:
        for var in undeclared_vars1:
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

def check_always_sensivity_list(text):
    """
    Function to check the always blocks for sensitivity lists containing ports.
    This function works before the AST is generated.
    """
    always_pattern = r'always\s+(@\((.*?)\))'  # Matches always block with sensitivity list
    always_blocks = re.findall(always_pattern, text)
    for always in always_blocks:
        sens_list = always[1].strip()  # Extract the content inside the sensitivity list
        if not sens_list:
            x = find_line_number(text, "always")
            print(f"Warning: Empty sensitivity list in 'always' block at line {x}.")
            return False
    else:
        return True
  
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
    functions = [extract_module_names, check_variable_names, semicolon_placement, check_unclosed_brackets, check_always_sensivity_list]  # list of our checks
    passed = True  # Track if all checks pass
    passedlist = ["Passed checks list: "]
    failedlist = ["Failed checks list: "]
    for func in functions:  # iterate through each function
        result = func(text)  # get result for each function

        if result == False:  # if any function result is false, output which check failed
            failedlist.append(func.__name__)  # add to failed list
            print(f"Check failed: {func.__name__}")
            passed = False  # Set passed to False and stop further checks
            
        elif result == True:  # if result is True, output which check passed
            passedlist.append(func.__name__)  # add to passed list
            print(f"Check passed: {func.__name__}")
    print(passedlist)
    print(failedlist)
    if passed:  # Proceed to file creation only if all checks passed
        with open(filename, "w+") as file:
            file.write(text)  # Write the Verilog code to the file
        parse_file(filename)

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
        
        #print(instance)
        # Handling Assign statements (Blocking and Non-blocking)
        if isinstance(instance, pyverilog.vparser.ast.Assign):  # Check for assignment statements
            if instance.right.var.cond: ## this will account for conditional statements. ex: assign out = sel ? in[1] : in[0];
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
            print(instance)
            for p in instance.list:
                if isinstance(p, pyverilog.vparser.ast.Input):
                    port_name = f'{int(str(p.width.msb)) - int(str(p.width.lsb)) + 1}-bit Input ' + p.name if p.width else "Input " + p.name # adds bit width for variable if it exists.
                    module_info['ports'].append(port_name)
                elif isinstance(p, pyverilog.vparser.ast.Output):
                    port_name = f'{int(str(p.width.msb)) - int(str(p.width.lsb)) + 1}-bit Output ' + p.name if p.width else "Output " + p.name
                    port_name = "Output " + p.name
                    module_info['ports'].append(port_name)
                elif isinstance(p, pyverilog.vparser.ast.Wire):
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

make_file("""
module MUX8to1(in, sel, out, clk);
    input clk;
    input [7:0] sel;
    input [2:0] out;
    output in;
    output x;
    
    wire [5:0] MUX_output;
   
    MUX2to1 M0(in[1:0], sel[0], MUX_output[0]);
    MUX2to1 M1(in[3:2], sel[0], MUX_output[1]);
    MUX2to1 M2(in[5:4], sel[0], MUX_output[2]);
    MUX2to1 M3(in[7:6], sel[0], MUX_output[3]);
    MUX2to1 M4(MUX_output[1:0], sel[1], MUX_output[4]);
    MUX2to1 M5(MUX_output[3:2], sel[1], MUX_output[5]);
    MUX2to1 M6(MUX_output[5:4], sel[2], out);

endmodule



""")
# make_file("""module counter(
#     input clk,
#     input reset,
#     output reg [3:0] count
# );
#     assign clk = count;
#     always @(posedge clk or posedge reset) begin
#         if (reset)
#             count <= 4'b0000;
#         else
#             count <= 0;
#     end
# endmodule""")


#make_file("module test(a, b, c, d); input a; output a, b;  assign a = b; endmodule")  
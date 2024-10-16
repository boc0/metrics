from functools import wraps
import json

import pandas
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser
from tree_sitter import Node
from tqdm import tqdm
from IPython import embed
import click

DATASET_NAME = "diversevul_20230702.json"

CPP_LANGUAGE = Language(tscpp.language())
parser = Parser(CPP_LANGUAGE)


def register(recursive=False):
    def decorator(metric):
        varnames = metric.__code__.co_varnames
        @wraps(metric)
        def wrapper(code, **kwargs):
            if not hasattr(wrapper, 'is_recursive'):
                wrapper.is_recursive = False

            if isinstance(code, str):
                root = parser.parse(bytes(code, "utf8")).root_node
            elif isinstance(code, Node):
                root = code

            if wrapper.is_recursive:
                return metric(root, **kwargs)

            wrapper.is_recursive = True
            try:
                args = []
                if "body" in varnames or 'node' in varnames:
                    body = get_body(root)
                    if body is None:
                        raise ValueError(f"No function body found for {code}")
                    args.append(body)
                if "params" in varnames:
                    params = get_parameters(root)
                    args.append(params)
                
                result = metric(*args, **kwargs)
            finally:
                wrapper.is_recursive = False

            return result
        return wrapper
    return decorator

def get_body(root):
    """Given a function, return its body node"""
    if root.type == "function_definition":
        return root.child_by_field_name("body")
    elif root.type == "compound_statement":
        return root
    # elif root.type == "translation_unit":
    for child in root.children:
        if (body := get_body(child)):
            return body
        

def get_parameters(root) -> set:
    """Given a function, return a list of its parameters"""
    if root.type == "function_definition":
        return get_parameters(root.child_by_field_name("declarator"))
    elif root.type == "function_declarator":
        param_list = root.child_by_field_name("parameters")
        return {c for c in param_list.children if c.type == "parameter_declaration"}
    elif root.type == "translation_unit":
        decl = root.child_by_field_name("declarator")
        if decl is not None:
            return get_parameters(decl)
        for child in root.children:
            if (params := get_parameters(child)):
                return params
    return set()


def param_names(params):
    """Given a function, return a set of its parameter names"""
    return {get_identifier(param.child_by_field_name("declarator")) for param in params}


def get_identifier(declarator: Node, decode=True):
    """Given a declaration node, return the name of the declared variable"""
    if declarator is None:
        return None
    if declarator.type in {"pointer_declarator", "init_declarator"}:
        identifier = declarator.child_by_field_name("declarator").text
        return identifier.decode() if decode else identifier
    elif declarator.type == "function_declarator":
        decl = declarator.child_by_field_name("declarator")
        try:
            pointer_decl = decl.child(1)
            decl_decl = pointer_decl.child_by_field_name("declarator")
        except IndexError:
            pass
        try:
            identifier = decl.text
        except AttributeError:
            print(declarator.text)
            print(declarator)
            raise
        return identifier.decode() if decode else identifier
    else:
        return (identifier := declarator.text).decode() if decode else identifier


LOOPS = {
    "for_statement",
    "while_statement",
    "do_statement"
}

judge_nodes = [
    "if_statement",
    "case_statement",
    "do_statement",
    "for_range_loop",
    "for_statement",
    "goto_statement",
    "function_declarator",
    "pointer_declarator",
    "class_specifier",
    "struct_specifier",
    "preproc_elif",
    "while_statement",
    "switch_statement",
    "&&",
    "||",
]

@register(recursive=True)
def cyclomatic_complexity(body):
    node = body
    count = 0
    if node.type in judge_nodes:
        count += 1
    for child in node.children:
        count += cyclomatic_complexity(child)
    return count


@register(recursive=True)
def n_loops(node): # C2
    increment = 1 if node.type in LOOPS else 0
    return increment + sum(n_loops(child) for child in node.children)


@register(recursive=True)
def n_nested_loops(node, inside_loop=False): # C3
    increment = 1 if node.type in LOOPS and inside_loop else 0
    inside_loop = inside_loop or node.type in LOOPS
    return increment + sum(n_nested_loops(child, inside_loop=inside_loop) for child in node.children)


@register(recursive=True)
def max_nesting_level_of_loops(node, level=0): # C4
    increment = 1 if node.type in LOOPS else 0
    return increment + max(
        (max_nesting_level_of_loops(child, level=level+increment) for child in node.children), default=0)


@register()
def n_param_variables(params): # V1
    """Given a function, its number of arguments, without arguments for any function calls inside the function code"""
    return len(params)


@register()
def n_variables_as_parameters(body, params): # V2
    """The number of variables prepared by the function as parameters of function calls.
    This excludes the function's own parameters."""
    variables = set()
    in_calls = set()

    def traverse(node, in_declaration=False, in_call=False):
        if (node.type == "identifier"):
            if in_declaration:
                variables.add(node.text)
            elif in_call and (txt := node.text) in variables:
                in_calls.add(txt)
        elif node.type == "declaration":
            declarator = node.child_by_field_name("declarator")
            traverse(declarator, in_declaration=True)
        elif "declarator" in node.type:
            identifier = node.child_by_field_name("identifier")
            if identifier is not None:
                variables.add(identifier.text)
            else:
                decl = node.child_by_field_name("declarator")
                if decl is not None:
                    traverse(decl, in_declaration=True)
        elif node.type == "call_expression":
            for arg in node.child_by_field_name("arguments").children:
                if arg.type == "identifier" and arg.text.decode() not in {'True', 'False'}:
                    in_calls.add(arg.text)
                else:
                    pass # traverse(arg, in_call=True)
                # traverse(arg, in_call=True)
        for child in node.children:
            traverse(child)
    traverse(body)
    return len(variables & in_calls - params)


def count_field_expressions(node) -> tuple[bytes, int]:
    count = 0
    while node.type == "field_expression":
        count += 1
        node = node.child_by_field_name("argument")
    return node.text, count


def get_pointer_variables(body, params) -> dict[bytes, int]:
    r"""
    Pointer metrics (V3-V5) capture the manipulation of pointers, i.e., the number of pointer arithmetic, 
    the number of variables used in pointer arithmetic, and the maximum number of pointer arithmetic a variable 
    is involved in. Member access operations (e.g., $\mathrm{ptr} \rightarrow \mathrm{m}$ ), 
    deference operations (e.g., *ptr), incrementing pointers (e.g., ptr++), 
    and decrementing pointers (e.g., prt--) are all pointer arithmetics.
    """
    '''
    variables = {decl.child_by_field_name("declarator").text: 0
                 for param in params 
                 if (decl := param.child_by_field_name("declarator")).type == "pointer_declarator"}
    '''
    variables = {}
    for param in params:
        decl = param.child_by_field_name("declarator")
        if decl is not None and decl.type == "pointer_declarator":
            var = decl.child_by_field_name("declarator")
            if var is not None:
                variables[var.text] = 0

    def visit(node, scope=set()):
        if node.type == "pointer_declarator":
            var = node.child_by_field_name("declarator").text
            if var is not None and var not in scope:
                scope[var] = 0
        elif node.type == "field_expression":
            var, count = count_field_expressions(node)
            scope[var] = count + scope.get(var, 0)
        elif node.type == "update_expression":
            arg = node.child_by_field_name("argument")
            var, count = count_field_expressions(arg)
            if (b'++' in node.text or b'--' in node.text) and count == 0:
                count = 1
            if var in scope:
                scope[var] += count
        else:
            for child in node.children:
                visit(child, scope)

    visit(body, scope=variables)
    variables = {k: v for k, v in variables.items() if v > 0}
    # return sum(variables.values()), len(variables), max(variables.values(), default=0)
    return variables

@register()
def n_pointer_arithmetic(body, params): # V3
    return sum(get_pointer_variables(body, params).values())

@register()
def n_vars_in_pointer_arithmetic(body, params): # V4
    return len(get_pointer_variables(body, params))

@register()
def max_pointer_arithmetic(body, params): # V5
    return max(get_pointer_variables(body, params).values(), default=0)



CONTROL_STRUCTURES = {
    "if_statement",
    "for_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "try_statement"
}

@register(recursive=True)
def n_nested_control_structures(node, inside_control_structure=False): # V6
    """Number of control structures that are nested inside at least one other control structure."""
    if node.type in CONTROL_STRUCTURES:
        return (1 if inside_control_structure else 0) + sum(n_nested_control_structures(child, inside_control_structure=True) for child in node.children)
    return sum(n_nested_control_structures(child, inside_control_structure=inside_control_structure) for child in node.children)


@register(recursive=True)
def max_nesting_level_of_control_structures(node): # V7
    if node.type in CONTROL_STRUCTURES:
        return 1 + max((max_nesting_level_of_control_structures(child) for child in node.children), default=0)
    return max((max_nesting_level_of_control_structures(child) for child in node.children), default=0)


def extract_variables(node):
    """Extract variables used in the predicate of the given control stucture node."""
    variables = set()
    if node.type == "identifier" and node.text not in {b'True', b'False'} and node.text:
        variables.add(node.text.decode())
    elif node.type == "declaration":
        declarators = node.children_by_field_name("declarator")
        for declarator in declarators:
            variables |= extract_variables(declarator)
    elif node.type == "condition_clause":
        variables |= extract_variables(node.child_by_field_name("value"))
    elif node.type in {"binary_expression", "assignment_expression"}:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        for child in (left, right):
            variables |= extract_variables(child)
    elif node.type == "call_expression":
        name = node.child_by_field_name("function")
        variables |= extract_variables(name) # in case the function itself is a variable
        arguments = node.child_by_field_name("arguments")
        for arg in arguments.children:
            variables |= extract_variables(arg)
    elif node.type in {"update_expression", "field_expression"}:
        variables |= extract_variables(node.child_by_field_name("argument"))
    elif node.type in {"if_statement", "while_statement", "do_statement"}:
        condition = node.child_by_field_name("condition")
        variables |= extract_variables(condition)
    elif node.type == "for_statement":
        init, condition, update = node.children[2:5]
        for each in (init, condition, update):
            variables |= extract_variables(each)
    elif node.type == "switch_statement":
        condition = node.child_by_field_name("condition")
        variables |= extract_variables(condition)
    elif node.type == "case_statement":
        value = node.child_by_field_name("value")
        if value:
            variables |= extract_variables(value)
    return variables

@register()
def control_dependent_control_structures(body): # V8
    after_return = False

    def visit(node, inside_control_structure=False):
        nonlocal after_return
        indicator = 1 if (inside_control_structure or after_return) and node.type in CONTROL_STRUCTURES else 0
        if node.type in CONTROL_STRUCTURES:
            inside_control_structure = True
        elif node.type == "return_statement":
            if inside_control_structure:
                after_return = True
        return indicator + sum(visit(child, inside_control_structure) for child in node.children)
    
    return visit(body)


def is_data_dependent(node, variables):
    if node.type in CONTROL_STRUCTURES:
        in_predicate = extract_variables(node)
        if len(in_predicate & variables) != 0:
            return True
    return False

@register()
def data_dependent_control_structures(body, params): # V9
    variables = param_names(params)

    def visit(node):
        nonlocal variables
        if node.type == "declaration":
            declarator = node.child_by_field_name("declarator")
            variables.add(get_identifier(declarator))
        indicator = 1 if is_data_dependent(node, variables) else 0
        return indicator + sum(visit(child) for child in node.children)
    
    return visit(body)


@register(recursive=True)
def n_if_without_else(node): # V10: number of if statements without an else clause
    '''
    if node.type == "if_statement":
        print(node.text)
        print(node.child_by_field_name("alternative"))
        if node.child_by_field_name("alternative") is None:
            return 1
    '''
    indicator = 1 if node.type == "if_statement" and node.child_by_field_name("alternative") is None else 0
    return indicator + sum(n_if_without_else(child) for child in node.children)
    
    return sum(n_if_without_else(child) for child in node.children)

def _vars_in_control_predicates(node):
    return (extract_variables(node) if node.type in CONTROL_STRUCTURES else set()) \
            .union(*(_vars_in_control_predicates(child) for child in node.children))

@register()
def vars_in_control_predicates(body): # V11
   return len(_vars_in_control_predicates(body))

        

        

@click.command()
@click.argument('dataset_name', type=str, default=DATASET_NAME)
def main(dataset_name):
    print(f'Processing {dataset_name}')
    metrics = [
        cyclomatic_complexity,
        n_loops,
        n_nested_loops,
        max_nesting_level_of_loops,
        n_param_variables,
        n_variables_as_parameters,
        n_pointer_arithmetic,
        n_vars_in_pointer_arithmetic,
        max_pointer_arithmetic,
        n_nested_control_structures,
        max_nesting_level_of_control_structures,
        control_dependent_control_structures,
        data_dependent_control_structures,
        vars_in_control_predicates,
        n_if_without_else,
    ]
    
    data = []
    try:
        counter = 0
        with open(dataset_name, "r") as f:
            for line in f:
                counter += 1
                if line[0] == '{':
                    data.append(json.loads(line))
    except FileNotFoundError:
        print(f'File {dataset_name} not found')
        return
    except json.JSONDecodeError:
        print(f'Each line in {dataset_name} must be a valid JSON, parsing error at line {counter}')
        return
    # data = data[100000:101000]
    for d in tqdm(data):
        d['metrics'] = {}
        for m in metrics:
            root = parser.parse(bytes(d['func'], "utf8")).root_node
            try:
                d['metrics'][m.__name__] = m(root)
            except Exception as e:
                d['metrics'][m.__name__] = -1

    results = pandas.DataFrame([d['metrics'] for d in data], columns=[m.__name__ for m in metrics])
    results.to_csv(f'{dataset_name}_results.csv')

    with open(f'{dataset_name}_metrics.json', 'w') as f:
        for d in data:
            f.write(json.dumps(d) + '\n')

if __name__ == '__main__':
    main()
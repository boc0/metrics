from functools import wraps
import json


import pandas
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser
from tree_sitter import Node
from tqdm import tqdm
from IPython import embed
import mccabe as mcc

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

        

        

if __name__ == "__main__":

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
    with open(DATASET_NAME, "r") as f:
        for line in f:
            if line[0] == '{':
                data.append(json.loads(line))
    # data = data[100000:101000]
    for d in tqdm(data):
        d['metrics'] = {}
        for m in metrics:
            root = parser.parse(bytes(d['func'], "utf8")).root_node
            try:
                d['metrics'][m.__name__] = m(root)
            except Exception as e:
                d['metrics'][m.__name__] = -1
    '''
    errors = [2269, 2271, 4198, 14528, 14734, 14777, 19559, 21501, 24726, 24738, 24741, 24747, 24753, 24809, 24818, 24825, 24830, 24857, 24883, 24895, 24902, 24908, 24924, 24949, 24956, 29348, 30074, 41875, 42120, 42122, 42535, 43300, 44250, 53122, 53148, 53153, 54438, 54734, 57602, 57605, 57607, 57613, 57621, 57624, 57644, 57694, 57708, 57742, 57744, 57748, 60408, 62932, 62949, 63098, 63142, 63204, 63234, 63506, 64768, 66338, 66345, 66384, 66403, 66410, 66422, 66423, 66435, 66454, 66456, 66480, 70984, 71348, 71351, 71370, 71403, 71407, 74742, 75512, 76526, 80459, 80585, 80786, 80796, 80800, 80949, 82716, 82740, 83561, 84035, 85035, 85055, 85057, 85082, 85114, 85156, 85161, 85163, 85260, 85282, 85289, 89067, 89071, 89103, 89107, 91178, 92145, 92245, 93948, 94368, 94443, 94468, 94982, 94999, 95441, 95448, 95461, 95462, 95491, 95494, 95496, 95501, 95506, 96060, 99347, 101734, 106798, 107252, 110161, 110165, 110171, 110192, 112528, 112529, 112549, 112550, 112555, 112559, 112619, 112659, 112674, 112701, 112759, 112788, 113551, 115475, 115483, 115494, 115498, 115508, 115510, 115514, 115522, 115524, 115528, 115543, 115544, 115549, 115555, 115558, 115560, 115568, 115569, 115575, 115580, 115581, 115582, 115589, 115590, 115593, 115594, 115599, 115609, 115610, 115619, 115621, 115636, 115646, 115647, 115648, 115670, 115671, 115675, 115684, 115686, 115710, 115723, 115726, 115728, 115729, 115737, 115739, 115741, 115754, 115757, 115764, 115777, 115780, 115805, 115807, 115809, 115815, 115832, 115833, 115837, 115841, 115849, 115859, 115864, 115872, 115875, 115877, 115885, 115886, 115887, 115896, 115897, 115898, 115899, 115904, 115905, 115909, 115913, 115922, 115939, 115942, 115944, 115950, 115951, 115956, 115961, 115964, 115966, 115979, 115982, 115985, 115999, 116000, 116004, 116014, 116023, 116031, 116033, 116045, 116050, 116053, 116054, 116058, 116059, 116072, 116074, 116082, 116088, 116090, 116097, 116099, 116101, 116105, 116109, 116120, 116127, 116132, 116139, 116140, 116143, 116152, 116157, 116166, 116173, 116178, 116186, 116201, 116211, 116215, 116217, 116221, 116222, 116227, 116228, 116231, 116252, 116264, 116266, 116267, 116268, 116272, 116288, 116293, 116300, 116311, 116314, 116317, 116322, 116335, 116341, 116354, 116356, 116361, 116366, 116367, 116391, 116398, 116401, 116406, 116408, 116409, 116410, 116415, 116421, 116427, 116429, 116433, 116435, 116436, 116455, 116461, 116466, 116468, 116477, 116483, 116486, 116488, 116494, 116501, 116507, 116508, 116511, 116519, 116525, 116537, 116546, 116561, 116567, 116569, 116575, 116585, 116588, 116591, 116599, 116601, 116619, 116629, 116631, 116645, 116649, 116661, 116663, 116668, 116669, 116680, 116688, 116696, 116709, 116710, 116713, 116724, 116731, 116732, 116740, 116748, 116753, 116755, 116759, 116766, 116768, 116771, 116774, 116782, 116783, 116796, 116798, 116810, 116813, 116828, 116830, 116835, 116843, 116853, 116858, 116860, 116867, 116868, 116879, 116897, 116907, 116923, 116931, 116950, 116953, 116954, 116955, 116961, 116967, 116969, 116975, 116981, 116983, 116988, 116991, 116996, 117004, 117009, 117023, 117029, 117053, 117057, 117058, 117059, 117060, 117065, 117068, 117077, 117082, 117085, 117101, 117105, 117114, 117117, 117122, 117127, 117129, 117137, 117138, 117139, 117145, 117151, 117161, 117173, 117184, 117189, 117195, 117197, 117213, 117219, 117233, 117235, 117252, 117266, 117278, 117291, 117293, 117298, 117303, 117309, 117338, 117344, 117355, 117368, 117387, 117388, 117391, 117398, 117407, 117416, 117418, 117419, 117426, 117433, 117434, 117437, 117438, 117445, 117455, 117460, 117462, 117472, 117475, 117478, 117479, 117485, 117492, 117512, 117525, 117542, 117549, 117557, 117563, 117569, 117577, 117580, 117583, 117585, 117596, 117604, 117605, 117609, 117616, 117629, 117636, 117639, 117651, 117656, 117659, 117664, 117666, 117667, 117676, 117680, 117689, 117691, 117692, 117695, 117701, 117711, 120603, 121189, 121234, 121308, 122728, 124247, 124250, 124269, 124453, 124463, 129224, 129945, 135011, 135026, 135039, 135892, 136577, 137809, 137851, 137991, 138061, 144529, 144673, 144758, 144819, 144848, 144850, 148494, 148614, 148618, 148634, 148644, 148671, 148677, 148696, 148712, 148713, 148714, 148719, 148722, 148732, 148735, 148747, 148755, 148760, 148763, 148767, 148776, 148777, 148784, 148786, 148795, 148813, 148821, 148836, 148847, 148850, 148854, 148858, 148875, 148877, 148880, 148882, 148943, 148953, 148960, 148970, 148972, 148993, 148995, 149000, 149010, 149017, 149021, 149038, 149042, 149072, 149077, 149079, 149083, 149094, 149096, 149115, 149124, 153109, 153110, 153131, 162246, 162252, 162266, 162273, 168711, 173046, 173077, 173098, 173105, 177752, 177815, 178432, 180345, 180358, 180363, 180376, 180382, 180394, 180399, 180401, 180405, 180409, 180411, 180413, 180425, 180426, 180434, 180436, 180453, 180472, 180473, 180479, 180481, 180485, 180493, 180503, 180507, 180509, 180510, 180511, 180529, 180530, 180536, 180539, 180544, 180549, 180553, 180558, 180823, 180897, 180899, 180921, 180929, 180932, 180938, 180941, 180942, 180946, 180948, 180949, 181505, 181632, 183024, 185111, 194755, 198482, 198485, 198492, 198495, 198509, 198513, 198527, 198539, 198566, 198567, 198582, 198591, 198605, 198613, 198637, 198644, 198664, 198674, 198677, 198682, 198685, 206602, 211613, 220036, 220080, 220098, 220107, 220165, 220184, 220195, 220205, 226540, 226573, 226579, 226600, 226651, 226817, 226907, 226913, 226952, 227033, 227212, 227241, 227341, 227385, 227447, 227471, 227503, 227524, 227538, 227550, 227578, 227651, 227726, 227734, 227754, 227763, 227923, 227934, 227977, 227994, 228011, 228072, 228107, 228130, 228156, 228241, 228300, 228308, 228356, 228378, 228380, 228421, 228437, 228496, 228501, 228566, 228609, 228611, 228667, 228711, 228729, 228733, 228743, 228758, 228794, 232548, 233494, 233501, 236174, 242437, 245199, 245318, 245489, 245736, 248752, 249784, 249786, 249791, 249793, 249838, 249856, 249871, 249880, 249895, 249936, 250011, 250358, 253135, 253198, 253373, 253387, 253405, 253518, 253605, 253613, 253667, 261993, 263135, 264042, 266165, 266464, 272099, 276625, 281180, 290997, 291113, 298523, 304639, 304651, 307424, 307691, 312655, 313897, 313903, 313954, 313991, 314016, 314051, 314082, 318002, 318065, 319529, 319698, 319733, 319892, 320032, 320378, 324524, 324689, 324723]
    for err in errors:
        this = []
        for m in metrics:
            print(m(data[err]), end=" ")
        print()
    '''

    results = pandas.DataFrame([d['metrics'] for d in data], columns=[m.__name__ for m in metrics])
    results.to_csv("results.csv")

    with open('diversevul_20230702_metrics.json', 'w') as f:
        for d in data:
            f.write(json.dumps(d) + '\n')

    embed()
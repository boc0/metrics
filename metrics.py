import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser
from tree_sitter import Node

CPP_LANGUAGE = Language(tscpp.language())
parser = Parser(CPP_LANGUAGE)

LOOPS = {
    "for_statement",
    "while_statement",
    "do_statement"
}

CONTROL_STRUCTURES = {
    "if_statement",
    "switch_statement"
}

def funcdef(root):
    while root.type != "function_definition":
        try:
            root = root.children[0]
        except IndexError:
            print("No function definition found.")
            return None
    return root

def find_funcdef(func):
    def wrapper(root):
        root = funcdef(root)
        return func(root)
    return wrapper

def callable(cls):
    def wrapper(code):
        instance = cls()
        return instance(code)
    return wrapper

class Metric:
    # @staticmethod
    def __call__(self, code: str | Node):
        if isinstance(code, Node):
            root = code
        else:
            root = parser.parse(
                bytes(
                    code,
                    "utf8"
                )
            ).root_node

        # instance = cls()
        root = self._get_funcdef(root)
        return self._visit(root)
    
    def _get_funcdef(self, root):
        return funcdef(root)

@callable
class n_loops(Metric):
    def __init__(self):
        self.count = 0

    def _visit(self, node):
        if node.type in LOOPS:
            self.count += 1
        for child in node.children:
            self._visit(child)
        return self.count
    
@callable
class n_nested_loops(Metric):
    """Number of loops that are nested inside at least one other loop."""

    def __init__(self):
        self.count = 0

    def _visit(self, node, inside_loop=False):
        if node.type in LOOPS:
            self.count += 1 if inside_loop else 0
            for child in node.children:
                self._visit(child, inside_loop=True)
        else:
            for child in node.children:
                self._visit(child, inside_loop)
        return self.count
"""
@callable
class max_nesting_level_of_loops(Metric):
    def __init__(self):
        self.max = 0

    def _visit(self, node, level=0):
        increment = 1 if node.type in LOOPS else 0
        return increment + max((self._visit(child, level + increment) for child in node.children), default=0)
"""

def n_loops(node): # C2
    increment = 1 if node.type in LOOPS else 0
    return increment + sum(n_loops(child) for child in node.children)
    
def n_nested_loops(node, inside_loop=False): # C3
    """
    # works
    if node.type in LOOPS:
        return (1 if inside_loop else 0) + sum(n_nested_loops(child, inside_loop=True) for child in node.children)
    return sum(n_nested_loops(child, inside_loop) for child in node.children)

    # doesn't work
    increment = 1 if node.type in LOOPS else 0
    inside_loop = inside_loop or node.type in LOOPS
    return increment + sum(n_nested_loops(child, inside_loop) for child in node.children)
    """

    increment = 1 if node.type in LOOPS and inside_loop else 0
    inside_loop = inside_loop or node.type in LOOPS
    return increment + sum(n_nested_loops(child, inside_loop) for child in node.children)

def max_nesting_level_of_loops(node, level=0): # C4
    increment = 1 if node.type in LOOPS else 0
    return increment + max(
        (max_nesting_level_of_loops(child, level + increment)
            for child in node.children),
        default=0)


def parameters(funcdef) -> list:
    """Given a function, return a list of its parameters"""
    declarator = funcdef.child_by_field_name("declarator")
    param_list = declarator.child_by_field_name("parameters")
    params = [c for c in param_list.children if c.type == "parameter_declaration"]
    # params = [c.child_by_field_name("declarator").child_by_field_name("identifier").text for c in param_list.children if c.type == "parameter_declaration"]
    return params

@find_funcdef
def n_param_variables(funcdef): # V1
    """Given a function, its number of arguments, without arguments for any function calls inside the function code"""
    params = parameters(funcdef)
    return len(params)

def get_body(funcdef):
    """Given a function, return its body node"""
    return funcdef.child_by_field_name("body")


def get_identifier(declarator: Node):
    """Given a declaration node, return the name of the declared variable"""
    if declarator is None:
        return None
    if declarator.type == "pointer_declarator":
        return declarator.child_by_field_name("declarator").text
    elif declarator.type == "function_declarator":
        parenthesized_decl = declarator.child_by_field_name("declarator")
        pointer_decl = parenthesized_decl.child(1)
        decl = pointer_decl.child_by_field_name("declarator")
        return decl.text
    else:
        return declarator.text


@find_funcdef
def n_variables_as_parameters(funcdef): # V2
    """The number of variables prepared by the function as parameters of function calls.
    This excludes the function's own parameters."""
    param_nodes = parameters(funcdef)
    params = set()
    for param in param_nodes:
        declarator = param.child_by_field_name("declarator")
        params += get_identifier(declarator)
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
                traverse(node.child_by_field_name("declarator"), in_declaration=True)
        elif node.type == "call_expression":
            for arg in node.child_by_field_name("arguments").children:
                if arg.type == "identifier" and arg.text.decode() not in {'True', 'False'}:
                    in_calls.add(arg.text)
                else:
                    pass # traverse(arg, in_call=True)
                # traverse(arg, in_call=True)
        for child in node.children:
            traverse(child)
    funcbody = get_body(funcdef)
    traverse(funcbody)
    return len(variables & in_calls - params)

@callable
class n_variables_as_parameters(Metric):
    def __init__(self):
        self.params = set()
        self.variables = set()
        self.in_calls = set()

    def _visit(self, node, in_declaration=False, in_call=False):
        if (node.type == "identifier"):
            if in_declaration:
                self.variables.add(node.text)
            elif in_call and (txt := node.text) in self.variables:
                self.in_calls.add(txt)
        elif node.type == "declaration":
            declarator = node.child_by_field_name("declarator")
            self._visit(declarator, in_declaration=True)
        elif "declarator" in node.type:
            identifier = node.child_by_field_name("identifier")
            if identifier is not None:
                self.variables.add(identifier.text)
            else:
                self._visit(node.child_by_field_name("declarator"), in_declaration=True)
        elif node.type == "call_expression":
            for arg in node.child_by_field_name("arguments").children:
                if arg.type == "identifier" and arg.text.decode() not in {'True', 'False'}:
                    self.in_calls.add(arg.text)
                else:
                    self._visit(arg, in_call=True)
        for child in node.children:
            self._visit(child)
        return len(self.variables & self.in_calls - self.params)

    def _get_funcdef(self, root):
        root = funcdef(root)
        self.params = {get_identifier(param.child_by_field_name("declarator")) for param in parameters(root)}
        return root


def count_field_expressions(node):
    if node.type != "field_expression":
        return 0
    argument_node = node.child_by_field_name("argument")
    return 1 + count_field_expressions(argument_node)

def find_base_variable_and_count_field_expressions(node):
    count = 0
    while node.type == "field_expression":
        count += 1
        node = node.child_by_field_name("argument")
    return node.text, count


def pointers(node): # V3, V4, V5
    r"""
    Pointer metrics (V3-V5) capture the manipulation of pointers, i.e., the number of pointer arithmetic, 
    the number of variables used in pointer arithmetic, and the maximum number of pointer arithmetic a variable 
    is involved in. Member access operations (e.g., $\mathrm{ptr} \rightarrow \mathrm{m}$ ), 
    deference operations (e.g., *ptr), incrementing pointers (e.g., ptr++), 
    and decrementing pointers (e.g., prt--) are all pointer arithmetics.
    """

    # define a dictionary that saves for each variable declared as an unsigned type, the number of pointer arithmetic
    # statements it is involved in
    variables = {}
    def increment(var_name, count=1):
        if var_name not in variables:
            variables[var_name] = 0
        variables[var_name] += count

    def find_pointers(node):
        if node.type == "pointer_declarator":
            declarator = node.child_by_field_name("declarator")
            var_name = declarator.child_by_field_name("identifier")
            if var_name not in variables:
                variables[var_name] = 0
        if node.type == "assignment_expression":
            left_node = node.child_by_field_name("left")
            if left_node.type == "field_expression":
                var_name, field_expression_count = find_base_variable_and_count_field_expressions(left_node)
                increment(var_name, field_expression_count)
            else:
                var_name = left_node.text
                increment(var_name)
        if node.type == "field_expression":
            argument_node = node.child_by_field_name("argument")
            if argument_node.type == "identifier":
                var_name = argument_node.text
                field_expression_count = count_field_expressions(node)
            else:
                # Handle cases where the argument is another field_expression
                while argument_node.type == "field_expression":
                    argument_node = argument_node.child_by_field_name("argument")
                var_name = argument_node.text
                field_expression_count = count_field_expressions(node)
            increment(var_name, field_expression_count)
        for child in node.children:
            find_pointers(child)
    
    find_pointers(node)
    n_pointer_arithmetic = sum(variables.values())
    n_variables = len(variables)
    max_pointer_arithmetic = max(variables.values(), default=0)
    return n_pointer_arithmetic, n_variables, max_pointer_arithmetic


CONTROL_STRUCTURES = {
    "if_statement",
    "for_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "try_statement"
}

def n_control_structures(node): # V6
    if node.type in CONTROL_STRUCTURES:
        return 1 + sum(n_control_structures(child) for child in node.children)
    return sum(n_control_structures(child) for child in node.children)


def n_nested_control_structures(node, inside_control_structure=False): # V7
    """Number of control structures that are nested inside at least one other control structure."""
    if node.type in CONTROL_STRUCTURES:
        return (1 if inside_control_structure else 0) + sum(n_nested_control_structures(child, inside_control_structure=True) for child in node.children)
    return sum(n_nested_control_structures(child, inside_control_structure) for child in node.children)

def max_nesting_level_of_control_structures(node): # V8
    if node.type in CONTROL_STRUCTURES:
        return 1 + max((max_nesting_level_of_control_structures(child) for child in node.children), default=0)
    return max((max_nesting_level_of_control_structures(child) for child in node.children), default=0)

    
r"""
\begin{verbatim}
void fibonacci(int *res, int n) {
    if (n <= 0) {
        return;
    }
    res[0] = 0;
    res[1] = 1;
    if (n > 1) {
        if (n == 3) {
            res[2] = 1;
            return;
        }
        for(int i = 2; i <= n; i++) {
            res[i] = res[i-1] + res[i-2];
        }
    }
}
\end{verbatim}

Figure 2: An example of calculating Fibonacci series.

Control structure metrics (V6-V11) capture the vulnerability due to highly coupled and dependent control structures 
(such as if and while), i.e., the number of nested control structures pairs, the maximum nesting level of control
structures, the maximum number of control structures that are control- or data-dependent, the number of if structures
without explicit else statement, and the number of variables that are involved in the data-dependent control structures.
We explain the above metrics with an example (Fig. 2) calculating Fibonacci series. There are two pairs of nested control
structures, if at Line 7 respectively with if at Line 8 and for at Line 12. Obviously, the maximum nesting level is two, 
with the outer structure as if at Line 7. The maximum of control-dependent control structures is 3, including if at Line 7 
and Line 8, and for at Line 12. The maximum of data-dependent control structures is four since conditions in all four control 
structures make checks on variable $n$. All three if statements are without else. There are two variables, i.e., 
$n$ and $i$ involved in the predicates of control structures. Actually, the more variables used in the predicates, the more 
likely to makes error on sanity checks. The higher these metrics, the harder for programmers to follow, and the more
difficult to reach the deeper part of the function during vulnerability hunting. Stand-alone if structures are suspicious 
for missing checks on the implicit else branches.
"""

def extract_variables(node):
    variables = set()
    '''
    if node.type == "function_definition":
        declarator = node.child_by_field_name("declarator")
        param_list = declarator.child_by_field_name("parameters")
        variables |= extract_variables(param_list)
    elif node.type == "function_declarator":
        param_list = node.child_by_field_name("parameters")
        variables |= extract_variables(param_list)
    '''
    if node.type == "identifier" and node.text not in {b'True', b'False'} and node.text:
        variables.add(node.text)
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
    else: pass
        # for child in node.children:
        #     variables |= extract_variables(child)
    
    if b'res' in variables:
        print(node.text)
        print(node.type)
        print()
    return variables



# needs to count all control structures that come after a return in an if as control dependent too
def find_control_structures(node, inside_control_structure=False, in_if=False, variables=set()):
    control_dependent = 0
    data_dependent = 0
    if node.type in CONTROL_STRUCTURES:
        if inside_control_structure:
            control_dependent += 1
        vars_involved = extract_variables(node)
        if vars_involved & variables:
            data_dependent += 1
        variables.update(vars_involved)

    inside_control_structure = inside_control_structure or node.type in CONTROL_STRUCTURES
    in_if = in_if or node.type == "if_statement"
    if node.type == "return_statement" and in_if:
        inside_control_structure = True
    for child in node.children:
        control_dependent_child, data_dependent_child, variables_child, in_cstr = find_control_structures(child, inside_control_structure=inside_control_structure, in_if=in_if, variables=variables)
        control_dependent += control_dependent_child
        data_dependent += data_dependent_child
        if b'res' in variables_child and child.type in CONTROL_STRUCTURES:
            print(child.text)
            print(child.type)
            print()
        if child.type in CONTROL_STRUCTURES:
            variables.update(variables_child)
        inside_control_structure = in_cstr
    return control_dependent, data_dependent, variables, inside_control_structure
    
@find_funcdef
def find_control_structures_outer(funcdef):
    param_nodes = parameters(funcdef)
    params = set()
    for param in param_nodes:
        declarator = param.child_by_field_name("declarator")
        params.add(get_identifier(declarator))
    
    body = get_body(funcdef)
    control_dependent, data_dependent, variables, _ = find_control_structures(body, variables=params)
    return control_dependent, data_dependent, len(variables)



if __name__ == "__main__":

    test_code = {"func": "int _gnutls_ciphertext2compressed(gnutls_session_t session,\n\t\t\t\t  opaque * compress_data,\n\t\t\t\t  int compress_size,\n\t\t\t\t  gnutls_datum_t ciphertext, uint8 type)\n{\n    uint8 MAC[MAX_HASH_SIZE];\n    uint16 c_length;\n    uint8 pad;\n    int length;\n    mac_hd_t td;\n    uint16 blocksize;\n    int ret, i, pad_failed = 0;\n    uint8 major, minor;\n    gnutls_protocol_t ver;\n    int hash_size =\n\t_gnutls_hash_get_algo_len(session->security_parameters.\n\t\t\t\t  read_mac_algorithm);\n\n    ver = gnutls_protocol_get_version(session);\n    minor = _gnutls_version_get_minor(ver);\n    major = _gnutls_version_get_major(ver);\n\n    blocksize = _gnutls_cipher_get_block_size(session->security_parameters.\n\t\t\t\t\t      read_bulk_cipher_algorithm);\n\n    /* initialize MAC \n     */\n    td = mac_init(session->security_parameters.read_mac_algorithm,\n\t\t  session->connection_state.read_mac_secret.data,\n\t\t  session->connection_state.read_mac_secret.size, ver);\n\n    if (td == GNUTLS_MAC_FAILED\n\t&& session->security_parameters.read_mac_algorithm !=\n\tGNUTLS_MAC_NULL) {\n\tgnutls_assert();\n\treturn GNUTLS_E_INTERNAL_ERROR;\n    }\n\n\n    /* actual decryption (inplace)\n     */\n    switch (_gnutls_cipher_is_block\n\t    (session->security_parameters.read_bulk_cipher_algorithm)) {\n    case CIPHER_STREAM:\n\tif ((ret = _gnutls_cipher_decrypt(session->connection_state.\n\t\t\t\t\t  read_cipher_state,\n\t\t\t\t\t  ciphertext.data,\n\t\t\t\t\t  ciphertext.size)) < 0) {\n\t    gnutls_assert();\n\t    return ret;\n\t}\n\n\tlength = ciphertext.size - hash_size;\n\n\tbreak;\n    case CIPHER_BLOCK:\n\tif ((ciphertext.size < blocksize)\n\t    || (ciphertext.size % blocksize != 0)) {\n\t    gnutls_assert();\n\t    return GNUTLS_E_DECRYPTION_FAILED;\n\t}\n\n\tif ((ret = _gnutls_cipher_decrypt(session->connection_state.\n\t\t\t\t\t  read_cipher_state,\n\t\t\t\t\t  ciphertext.data,\n\t\t\t\t\t  ciphertext.size)) < 0) {\n\t    gnutls_assert();\n\t    return ret;\n\t}\n\n\t/* ignore the IV in TLS 1.1.\n\t */\n\tif (session->security_parameters.version >= GNUTLS_TLS1_1) {\n\t    ciphertext.size -= blocksize;\n\t    ciphertext.data += blocksize;\n\n\t    if (ciphertext.size == 0) {\n\t\tgnutls_assert();\n\t\treturn GNUTLS_E_DECRYPTION_FAILED;\n\t    }\n\t}\n\n\tpad = ciphertext.data[ciphertext.size - 1] + 1;\t/* pad */\n\n\tlength = ciphertext.size - hash_size - pad;\n\n\tif (pad > ciphertext.size - hash_size) {\n\t    gnutls_assert();\n\t    /* We do not fail here. We check below for the\n\t     * the pad_failed. If zero means success.\n\t     */\n\t    pad_failed = GNUTLS_E_DECRYPTION_FAILED;\n\t}\n\n\t/* Check the pading bytes (TLS 1.x)\n\t */\n\tif (ver >= GNUTLS_TLS1)\n\t    for (i = 2; i < pad; i++) {\n\t\tif (ciphertext.data[ciphertext.size - i] !=\n\t\t    ciphertext.data[ciphertext.size - 1])\n\t\t    pad_failed = GNUTLS_E_DECRYPTION_FAILED;\n\t    }\n\n\tbreak;\n    default:\n\tgnutls_assert();\n\treturn GNUTLS_E_INTERNAL_ERROR;\n    }\n\n    if (length < 0)\n\tlength = 0;\n    c_length = _gnutls_conv_uint16((uint16) length);\n\n    /* Pass the type, version, length and compressed through\n     * MAC.\n     */\n    if (td != GNUTLS_MAC_FAILED) {\n\t_gnutls_hmac(td,\n\t\t     UINT64DATA(session->connection_state.\n\t\t\t\tread_sequence_number), 8);\n\n\t_gnutls_hmac(td, &type, 1);\n\tif (ver >= GNUTLS_TLS1) {\t/* TLS 1.x */\n\t    _gnutls_hmac(td, &major, 1);\n\t    _gnutls_hmac(td, &minor, 1);\n\t}\n\t_gnutls_hmac(td, &c_length, 2);\n\n\tif (length > 0)\n\t    _gnutls_hmac(td, ciphertext.data, length);\n\n\tmac_deinit(td, MAC, ver);\n    }\n\n    /* This one was introduced to avoid a timing attack against the TLS\n     * 1.0 protocol.\n     */\n    if (pad_failed != 0)\n\treturn pad_failed;\n\n    /* HMAC was not the same. \n     */\n    if (memcmp(MAC, &ciphertext.data[length], hash_size) != 0) {\n\tgnutls_assert();\n\treturn GNUTLS_E_DECRYPTION_FAILED;\n    }\n\n    /* copy the decrypted stuff to compress_data.\n     */\n    if (compress_size < length) {\n\tgnutls_assert();\n\treturn GNUTLS_E_INTERNAL_ERROR;\n    }\n    memcpy(compress_data, ciphertext.data, length);\n\n    return length;\n}", "target": 1, "cwe": [], "project": "gnutls", "commit_id": "7ad6162573ba79a4392c63b453ad0220ca6c5ace", "hash": 73008646937836648589283922871188272089, "size": 157, "message": "added an extra check while checking the padding."}
    # test_code = {"func": "void async_request(TALLOC_CTX *mem_ctx, struct winbindd_child *child,\n\t\t   struct winbindd_request *request,\n\t\t   struct winbindd_response *response,\n\t\t   void (*continuation)(void *private_data, BOOL success),\n\t\t   void *private_data)\n{\n\tstruct winbindd_async_request *state;\n\n\tSMB_ASSERT(continuation != NULL);\n\n\tstate = TALLOC_P(mem_ctx, struct winbindd_async_request);\n\n\tif (state == NULL) {\n\t\tDEBUG(0, (\"talloc failed\\n\"));\n\t\tcontinuation(private_data, False);\n\t\treturn;\n\t}\n\n\tstate->mem_ctx = mem_ctx;\n\tstate->child = child;\n\tstate->request = request;\n\tstate->response = response;\n\tstate->continuation = continuation;\n\tstate->private_data = private_data;\n\n\tDLIST_ADD_END(child->requests, state, struct winbindd_async_request *);\n\n\tschedule_async_request(child);\n\n\treturn;\n}", "target": 1, "cwe": [], "project": "samba", "commit_id": "c93d42969451949566327e7fdbf29bfcee2c8319", "hash": 13500245137413054717180286489878807064, "size": 31, "message": "Back-port of Volkers fix.\n\n    Fix a race condition in winbind leading to a crash\n\n    When SIGCHLD handling is delayed for some reason, sending a request to a child\n    can fail early because the child has died already. In this case\n    async_main_request_sent() directly called the continuation function without\n    properly removing the malfunctioning child process and the requests in the\n    queue. The next request would then crash in the DLIST_ADD_END() in\n    async_request() because the request pending for the child had been\n    talloc_free()'ed and yet still was referenced in the list.\n\n    This one is *old*...\n\n    Volker\n\nJeremy."}
    # test_code = {"func": "void async_request(TALLOC_CTX *mem_ctx, struct winbindd_child *child,\n\t\t   struct winbindd_request *request,\n\t\t   struct winbindd_response *response,\n\t\t   void (*continuation)(void *private_data, BOOL success),\n\t\t   void *private_data)\n{\n\tstruct winbindd_async_request *state = TALLOC_P(mem_ctx, struct winbindd_async_request);\n\n\tif (state == NULL) {\n\t\tDEBUG(0, (\"talloc failed\\n\"));\n\t\tcontinuation(private_data, False);\n\t\treturn;\n\t}\n\n\tstate->mem_ctx = mem_ctx;\n\tstate->child = child;\n\tstate->request = request;\n\tstate->response = response;\n\tstate->continuation = continuation;\n\tstate->private_data = private_data;\n\n\tDLIST_ADD_END(child->requests, state, struct winbindd_async_request *);\n\n\tschedule_async_request(child);\n\n\treturn;\n}", "target": 1, "cwe": [], "project": "samba", "commit_id": "c93d42969451949566327e7fdbf29bfcee2c8319", "hash": 13500245137413054717180286489878807064, "size": 31, "message": "Back-port of Volkers fix.\n\n    Fix a race condition in winbind leading to a crash\n\n    When SIGCHLD handling is delayed for some reason, sending a request to a child\n    can fail early because the child has died already. In this case\n    async_main_request_sent() directly called the continuation function without\n    properly removing the malfunctioning child process and the requests in the\n    queue. The next request would then crash in the DLIST_ADD_END() in\n    async_request() because the request pending for the child had been\n    talloc_free()'ed and yet still was referenced in the list.\n\n    This one is *old*...\n\n    Volker\n\nJeremy."}
    # test_code = {"func": "ProcShmCreatePixmap(client)\n    register ClientPtr client;\n{\n    PixmapPtr pMap;\n    DrawablePtr pDraw;\n    DepthPtr pDepth;\n    register int i, rc;\n    ShmDescPtr shmdesc;\n    REQUEST(xShmCreatePixmapReq);\n    unsigned int width, height, depth;\n    unsigned long size;\n\n    REQUEST_SIZE_MATCH(xShmCreatePixmapReq);\n    client->errorValue = stuff->pid;\n    if (!sharedPixmaps)\n\treturn BadImplementation;\n    LEGAL_NEW_RESOURCE(stuff->pid, client);\n    rc = dixLookupDrawable(&pDraw, stuff->drawable, client, M_ANY,\n\t\t\t   DixGetAttrAccess);\n    if (rc != Success)\n\treturn rc;\n\n    VERIFY_SHMPTR(stuff->shmseg, stuff->offset, TRUE, shmdesc, client);\n    \n    width = stuff->width;\n    height = stuff->height;\n    depth = stuff->depth;\n    if (!width || !height || !depth)\n    {\n\tclient->errorValue = 0;\n        return BadValue;\n    }\n    if (width > 32767 || height > 32767)\n\treturn BadAlloc;\n\n    if (stuff->depth != 1)\n    {\n        pDepth = pDraw->pScreen->allowedDepths;\n        for (i=0; i<pDraw->pScreen->numDepths; i++, pDepth++)\n\t   if (pDepth->depth == stuff->depth)\n               goto CreatePmap;\n\tclient->errorValue = stuff->depth;\n        return BadValue;\n    }\n\nCreatePmap:\n    size = PixmapBytePad(width, depth) * height;\n    if (sizeof(size) == 4 && BitsPerPixel(depth) > 8) {\n\tif (size < width * height)\n\t    return BadAlloc;\n\t/* thankfully, offset is unsigned */\n\tif (stuff->offset + size < size)\n\t    return BadAlloc;\n    }\n\n    VERIFY_SHMSIZE(shmdesc, stuff->offset, size, client);\n    pMap = (*shmFuncs[pDraw->pScreen->myNum]->CreatePixmap)(\n\t\t\t    pDraw->pScreen, stuff->width,\n\t\t\t    stuff->height, stuff->depth,\n\t\t\t    shmdesc->addr + stuff->offset);\n    if (pMap)\n    {\n\trc = XaceHook(XACE_RESOURCE_ACCESS, client, stuff->pid, RT_PIXMAP,\n\t\t      pMap, RT_NONE, NULL, DixCreateAccess);\n\tif (rc != Success) {\n\t    pDraw->pScreen->DestroyPixmap(pMap);\n\t    return rc;\n\t}\n\tdixSetPrivate(&pMap->devPrivates, shmPixmapPrivate, shmdesc);\n\tshmdesc->refcnt++;\n\tpMap->drawable.serialNumber = NEXT_SERIAL_NUMBER;\n\tpMap->drawable.id = stuff->pid;\n\tif (AddResource(stuff->pid, RT_PIXMAP, (pointer)pMap))\n\t{\n\t    return(client->noClientException);\n\t}\n\tpDraw->pScreen->DestroyPixmap(pMap);\n    }\n    return (BadAlloc);\n}", "target": 1, "cwe": ["CWE-189"], "project": "xserver", "commit_id": "be6c17fcf9efebc0bbcc3d9a25f8c5a2450c2161", "hash": 129275241199461482775430751894790125185, "size": 80, "message": "CVE-2007-6429: Always test for size+offset wrapping."}
    test_code = test_code["func"]
    # test_code = """
    """
    void fibonacci(int *res, int n) {
        if (n <= 0) {
            return;
        }
        res[0] = 0;
        res[1] = 1;
        if (n > 1) {
            if (n == 3) {
                res[2] = 1;
                return;
            }
            for(int i = 2; i <= n; i++) {
                res[i] = res[i-1] + res[i-2];
            }
        }
    }
    """
    test_code = """
    void fibonacci_with_do_while(int *res, int n) {
        if (False) {}
        if (n <= 0) {
            return;
        }
        res[0] = 0;
        res[1] = 1;
        if (n > 1) {
            if (n == 3) {
                res[2] = 1;
                return;
            }
            int i = 2;
            do {
                res[i] = res[i-1] + res[i-2];
                i++;
            } while(i <= n);
        }
    }
    """

    tree = parser.parse(bytes(test_code, "utf8"))
    root = tree.root_node

    def find_function_node(node):
        if node.type == 'translation_unit':
            pass
        elif node.type == "function_definition":
            return node
        for child in node.children:
            result = find_function_node(child)
            if result:
                return result
        return None

    root = find_function_node(root)

    control_dependent, data_dependent, variables = find_control_structures_outer(root)
    # variables = len(variables)
    print(control_dependent)
    print(data_dependent)
    print(variables)

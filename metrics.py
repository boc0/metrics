"""
\begin{center}
\begin{tabular}{|c|l|l|}
\hline
Dimension & ID & Metric Description \\
\hline
CD1: Function & C1 & Cyclomatic complexity \\
\hline
\multirow{3}{*}{CD2: Loop Structures} & C2 & \# of loops \\
\cline { 2 - 3 }
 & C3 & \# of nested loops \\
\cline { 2 - 3 }
 & C4 & Maximum nesting level of loops \\
\hline
\end{tabular}
\end{center}

TABLE II: Vulnerability Metrics of a Function

\begin{center}
\begin{tabular}{|c|c|l|}
\hline
Dimension & ID & Metric Description \\
\hline
VD1: & V1 & \# of parameter variables \\
\cline { 2 - 3 }
Dependency & V2 & \# of variables as parameters for callee function \\
\hline\hline
\multirow{3}{*}{VD2:} & V3 & \# of pointer arithmetic \\
\cline { 2 - 3 }
 & V4 & \# of variables involved in pointer arithmetic \\
\cline { 2 - 3 }
 & V5 & Max pointer arithmetic a variable is involved in \\
\hline
\multirow{3}{*}{}\begin{tabular}{c}
VD3: \\
Control \\
Structures \\
\end{tabular} & V6 & \# of nested control structures \\
\cline { 2 - 3 }
 & V7 & Maximum nesting level of control structures \\
\cline { 2 - 3 }
 & V8 & Maximum of control-dependent control structures \\
\cline { 2 - 3 }
 & V9 & Maximum of data-dependent control structures \\
\cline { 2 - 3 }
 & V10 & \# of if structures without else \\
\cline { 2 - 3 }
 & V11 & \# of variables involved in control predicates \\
\hline
\end{tabular}
\end{center}

\section{B. Function Binning}
Different vulnerabilities often have different levels of complexity. To identify vulnerabilities at all levels of complexity, in the first step, we categorize all functions in the target application into a set of bins based on complexity metrics. As a result, each bin represents a different level of complexity. Afterwards, the second step (§ II-C) plays the prediction role via ranking. Such a binning-and-ranking approach is designed to avoid missing low-complexity vulnerable functions.

Complexity Metrics. By "complexity", we refer to the approximate number of paths in a function, and derive the complexity metrics of a function from its structural complexity. A function often has loop and control structures, which are the main sources of structural complexity. Cyclomatic complexity [39] is a widely-used metric to measure the complexity, but without reflection of the loop structures. Based on such understanding, we introduce the complexity of a function with respect to these two complementary dimensions, as shown in Table I.

Function metric (C1) captures the standard cyclomatic complexity [39] of a function, i.e., the number of linearly independent paths through a function. A higher value of C 1 means that the function is likely more difficult to analyze or test

Loop structure metrics ( 2 - C 4 ) reflect the complexity resulting from loops, which can drastically increase the number of paths in the function. Metrics include the number of loops, the number of nested loops, and the maximum nesting level of loops. Loops are challenging in program analysis [68] and hinder vulnerability analysis. Basically, the higher these metrics the more (and possibly longer) paths need to be considered and the more difficult to analyze the function.

Binning Strategy. Given the values of these complexity metrics for functions in the target application, we compute a complexity score for each function by adding up all the complexity metric values, and then group the functions with the same score into the same bin. Here we do not use a range-based binning strategy (i.e., grouping the functions whose scores fall into the same range into the same bin) as it is hard to determine the suitable granularity of the range. Such a simple strategy not only makes our framework lightweight, but also works well, as evidenced by our experimental study in $\S$ IV-C.

\section{Function Ranking}
Different from the structural complexity metrics, in the second step, we derive a new set of vulnerability metrics according to the characteristics of general causes of vulnerabilities and then rank the functions and identify the top ones in each bin as potentially vulnerable based on the vulnerability metrics Existing metric-based techniques [44, 45] rarely employ any vulnerability-oriented metrics, and make no differentiation between complexity metrics and vulnerability metrics. Here,\\

we propose and incorporate vulnerability metrics to have a high potential of characterizing and identifying vulnerable functions. Vulnerability Metrics. Most critical types of vulnerabilities in $\mathrm{C} / \mathrm{C}++$ programs are directly or indirectly caused by memory management errors [61] and/or missing checks on some sensitive variables [74] (e.g., pointers). Resulting vulnerabilities include but are not limited to memory errors, access control errors (e.g., missing checks on user permission), and information leakage. Actually, the root causes of many denial of service and code execution vulnerabilities can also be traced back to these causes. The above mentioned types account for more than $70 \%$ of all vulnerabilities [11]. Hence, it is possible to define a set of vulnerability metrics that are compatible with major vulnerability types. Here we would not favor any specific types of vulnerabilities, e.g., to include metrics like division operation which is closely related to divide-by-zero, while the exploration of type-specific metrics is worth of investigation in the future. With either high or low complexity scores, vulnerable functions we focus on are mainly with complicated and compact computations, which are independent from the number of paths in the function. Based on these observations we introduce the vulnerability metrics of a function w.r.t. three dimensions, as summarized in Table II.

Dependency metrics (V1-V2) characterize the dependency relationship of a function with other functions, i.e., the number of parameter variables of the function and the number of variables prepared by the function as parameters of function calls. The more dependent with other functions, the more difficult to track the interaction.

Pointer metrics (V3-V5) capture the manipulation of pointers, i.e., the number of pointer arithmetic, the number of variables used in pointer arithmetic, and the maximum number of pointer arithmetic a variable is involved in. Member access operations (e.g., $\mathrm{ptr} \rightarrow \mathrm{m}$ ), deference operations (e.g., *ptr), incrementing pointers (e.g., ptr++), and decrementing pointers (e.g., prt--) are all pointer arithmetics. The number of pointer arithmetic can be obtained from the Abstract Syntax Tree (AST) of the function via simple counting. These operations are closely related to sensitive memory manipulations, which can increase the risk of memory management errors.

Alongside, we count how many unique variables are used in the pointer arithmetic operations. The more variables get involved, the more challenging for programmers to make correct decisions. For these variables, we also examine how many pointer arithmetic operations they are involved in and record the maximum value. Frequent operations on the same pointer
make it harder to track its value and guarantee the correctness. In a word, the higher these metrics, the higher chance to cause complicated memory management problems, and thus higher chance to dereference null or out-of-bound pointers.

Control structure metrics (V6-V11) capture the vulnerability due to highly coupled and dependent control structures (such as if and while), i.e., the number of nested control structures pairs, the maximum nesting level of control structures, the maximum number of control structures that are control- or data-dependent, the number of if structures without explicit else statement, and the number of variables that are involved in the data-dependent control structures. We explain the above metrics with an example (Fig. 2) calculating Fibonacci series. There are two pairs of nested control structures, if at Line 7 respectively with if at Line 8 and for at Line 12. Obviously, the maximum nesting level is two, with the outer structure as if at Line 7. The maximum of control-dependent control structures is 3, including if at Line 7 and Line 8, and for at Line 12. The maximum of data-dependent control structures is four since conditions in all four control structures make checks on variable $n$. All three if statements are without else. There are two variables, i.e., $n$ and $i$ involved in the predicates of control structures. Actually, the more variables used in the predicates, the more likely to makes error on sanity checks. The higher these metrics, the harder for programmers to follow, and the more difficult to reach the deeper part of the function during vulnerability hunting. Stand-alone if structures are suspicious for missing checks on the implicit else branches.
\begin{verbatim}
    void fibonacci(int *res, int n) {
    if (n<=0){
    if ( n<==
    }
    res[0] = 0
    res[1] = 1;
    if (n> 1) {
        res[2] = 1
        return
    }
        for(int i = 2; i <= n; i++) {
        res[i] = res[i-1]+ res[i-2]
    }
}}
\end{verbatim}

Fig. 2: A Function to Calculate Fibonacci Series

There usually exists a proportional relation between complexity and vulnerability metrics, because the more complex the (independent path and loop) structures of a function, the higher chance the variables, pointers and coupled control structures are involved. The complexity metrics are used to approximate the number of paths in the function, which are neutral to the vulnerable characteristics. Importantly, for the set of control structure metrics used as vulnerability indicators, they describe a different aspect of properties than complexity metrics. First, whether control structures are nested or dependent, or whether if are followed by else, are independent to cyclomatic complexity metrics. Second, intensively coupled control structures are good evidence of vulnerability. Instead of directly ranking functions with complexity and/or vulnerability metrics, we propose a binning-and-ranking approach to avoid missing less complicated but vulnerable functions, as will be evidenced in $\S$ IV-B. Ranking Strategy. Based on the values of these metrics for the functions, we compute a vulnerability score for each function by adding up all the metric values, rank the functions in each bin according to the scores, and cumulatively identify the top functions with highest scores in each bin as potential vulnerable functions. During the selection, we identify the top $k$ functions from each bin where $k$ is initially 1 , and increase by 1 in each selection iteration. Notice that we may take more than $k$ functions as we treat functions with the same score equally. This selection stops when an appropriate portion (i.e., $p$ ) of functions has been selected. Here $p$ can be set by users. Similar to the binning strategy, we adopt a simple ranking strategy to make our framework both lightweight and effective.

"""


import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser
from utils import pretty_print_node

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

def n_loops(node): # C2
    if node.type in LOOPS:
        return 1 + sum(n_loops(child) for child in node.children)
    return sum(n_loops(child) for child in node.children)

def n_nested_loops(node, inside_loop=False): # C3
    """Number of loops that are nested inside at least one other loop."""
    if node.type in LOOPS:
        return (1 if inside_loop else 0) + sum(n_nested_loops(child, inside_loop=True) for child in node.children)
    return sum(n_nested_loops(child, inside_loop) for child in node.children)

def max_nesting_level_of_loops(node): # C4
    if node.type in LOOPS:
        return 1 + max((max_nesting_level_of_loops(child) for child in node.children), default=0)
    return max((max_nesting_level_of_loops(child) for child in node.children), default=0)


def parameters(funcdef) -> list:
    """Given a function, return a list of its parameters"""
    declarator = funcdef.child_by_field_name("declarator")
    param_list = declarator.child_by_field_name("parameters")
    params = [c for c in param_list.children if c.type == "parameter_declaration"]
    # params = [c.child_by_field_name("declarator").child_by_field_name("identifier").text for c in param_list.children if c.type == "parameter_declaration"]
    return params

def n_param_variables(funcdef): # V1
    """Given a function, its number of arguments, without arguments for any function calls inside the function code"""
    params = parameters(funcdef)
    return len(params)

def n_variables_as_parameters(funcdef): # V2
    """The number of variables prepared by the function as parameters of function calls.
    This excludes the function's own parameters."""
    param_nodes = parameters(funcdef)
    params = set()
    for param in param_nodes:
        declarator = param.child_by_field_name("declarator")
        if declarator.type == "pointer_declarator":
            params.add(declarator.child_by_field_name("declarator").text)
        elif declarator.type == "function_declarator":
            parenthesized_decl = declarator.child_by_field_name("declarator")
            pointer_decl = parenthesized_decl.child(1)
            decl = pointer_decl.child_by_field_name("declarator")
            params.add(decl.text)
        else:
            params.add(declarator.child_by_field_name("identifier").text)
    print(params)
    variables = set()

    def traverse(node):
        if node.type == "call_expression":
            for arg in node.child_by_field_name("argument_list").children:
                print(arg, arg.text)
                if arg.type == "identifier" and arg.text not in params:
                    variables.add(arg.text)
                else:
                    traverse(arg)
        for child in node.children:
            traverse(child)
        
    traverse(funcdef)
    print(params)
    print(variables)
    return len(variables)

"""
Pointer metrics (V3-V5) capture the manipulation of pointers, i.e., the number of pointer arithmetic, 
the number of variables used in pointer arithmetic, and the maximum number of pointer arithmetic a variable 
is involved in. Member access operations (e.g., $\mathrm{ptr} \rightarrow \mathrm{m}$ ), 
deference operations (e.g., *ptr), incrementing pointers (e.g., ptr++), 
and decrementing pointers (e.g., prt--) are all pointer arithmetics.
"""

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
    """
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
            # variables[var_name] += 1
        if node.type == "assignment_expression":
            left_node = node.child_by_field_name("left")
            if left_node.type == "field_expression":
                var_name, field_expression_count = find_base_variable_and_count_field_expressions(left_node)
                # print(f"Variable '{var_name}' has {field_expression_count} field expressions in the assignment.")
                increment(var_name, field_expression_count)
            else:
                var_name = left_node.text
                # print(f"Variable '{var_name}' is assigned directly.")
                increment(var_name)
        if node.type == "field_expression":
            argument_node = node.child_by_field_name("argument")
            if argument_node.type == "identifier":
                var_name = argument_node.text
                field_expression_count = count_field_expressions(node)
                # print(f"Variable '{var_name}' has {field_expression_count} field expressions.")
            else:
                # Handle cases where the argument is another field_expression
                while argument_node.type == "field_expression":
                    argument_node = argument_node.child_by_field_name("argument")
                # print(argument_node.text)
                var_name = argument_node.text
                field_expression_count = count_field_expressions(node)
                # print(f"Variable '{var_name}' has {field_expression_count} field expressions.")
            increment(var_name, field_expression_count)
        for child in node.children:
            find_pointers(child)
    
    find_pointers(node)
    # print(variables)
    n_pointer_arithmetic = sum(variables.values())
    n_variables = len(variables)
    max_pointer_arithmetic = max(variables.values(), default=0)
    return n_pointer_arithmetic, n_variables, max_pointer_arithmetic


"""
Control structure metrics (V6-V11) capture the vulnerability due to highly coupled and dependent control structures 
(such as if and while), i.e., the number of nested control structures pairs, the maximum nesting level of control structures,
the maximum number of control structures that are control- or data-dependent,
the number of if structures without explicit else statement, and the number of variables that are involved
in the data-dependent control structures. We explain the above metrics with an example (Fig. 2) calculating Fibonacci series.
There are two pairs of nested control structures, if at Line 7 respectively with if at Line 8 and for at Line 12.
Obviously, the maximum nesting level is two, with the outer structure as if at Line 7.
The maximum of control-dependent control structures is 3, including if at Line 7 and Line 8, and for at Line 12.
The maximum of data-dependent control structures is four since conditions in all four control structures make checks on variable $n$.
All three if statements are without else. There are two variables, i.e., $n$ and $i$ involved in the predicates of control structures.
Actually, the more variables used in the predicates, the more likely to makes error on sanity checks.
The higher these metrics, the harder for programmers to follow,
and the more difficult to reach the deeper part of the function during vulnerability hunting.
Stand-alone if structures are suspicious for missing checks on the implicit else branches.

\begin{verbatim}
    void fibonacci(int *res, int n) {
    if (n<=0){
    if ( n<==
    }
    res[0] = 0
    res[1] = 1;
    if (n> 1) {
        res[2] = 1
        return
    }
        for(int i = 2; i <= n; i++) {
        res[i] = res[i-1]+ res[i-2]
    }
}}
\end{verbatim}
Fig. 2: A Function to Calculate Fibonacci Series
"""

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

# Function to extract variables from a condition node
def extract_variables(condition_node):
    variables = set()
    if condition_node:
        for child in condition_node.children:
            if child.type == "identifier":
                variables.add(child.text)
            else:
                variables.update(extract_variables(child))
    return variables

# Function to find control structures and count dependencies
def find_control_structures(node): # V8, V9, V11
    control_dependent_count = 0
    data_dependent_count = 0
    variables_in_conditions = set()

    if node.type in ["if_statement", "for_statement", "while_statement"]:
        # Extract variables from the condition
        condition_node = node.child_by_field_name("condition")
        variables_in_conditions.update(extract_variables(condition_node))

        # Check for control dependency (nested control structures)
        for child in node.children:
            if child.type in ["if_statement", "for_statement", "while_statement"]:
                control_dependent_count += 1
                nested_control_dependent, nested_data_dependent, nested_variables = find_control_structures(child)
                control_dependent_count += nested_control_dependent
                data_dependent_count += nested_data_dependent
                variables_in_conditions.update(nested_variables)

    # Recursively check all children
    for child in node.children:
        nested_control_dependent, nested_data_dependent, nested_variables = find_control_structures(child)
        control_dependent_count += nested_control_dependent
        data_dependent_count += nested_data_dependent
        variables_in_conditions.update(nested_variables)

    # Count data-dependent control structures
    if variables_in_conditions:
        data_dependent_count += 1

    return control_dependent_count, data_dependent_count, variables_in_conditions
    

# test_code = {"func": "int _gnutls_ciphertext2compressed(gnutls_session_t session,\n\t\t\t\t  opaque * compress_data,\n\t\t\t\t  int compress_size,\n\t\t\t\t  gnutls_datum_t ciphertext, uint8 type)\n{\n    uint8 MAC[MAX_HASH_SIZE];\n    uint16 c_length;\n    uint8 pad;\n    int length;\n    mac_hd_t td;\n    uint16 blocksize;\n    int ret, i, pad_failed = 0;\n    uint8 major, minor;\n    gnutls_protocol_t ver;\n    int hash_size =\n\t_gnutls_hash_get_algo_len(session->security_parameters.\n\t\t\t\t  read_mac_algorithm);\n\n    ver = gnutls_protocol_get_version(session);\n    minor = _gnutls_version_get_minor(ver);\n    major = _gnutls_version_get_major(ver);\n\n    blocksize = _gnutls_cipher_get_block_size(session->security_parameters.\n\t\t\t\t\t      read_bulk_cipher_algorithm);\n\n    /* initialize MAC \n     */\n    td = mac_init(session->security_parameters.read_mac_algorithm,\n\t\t  session->connection_state.read_mac_secret.data,\n\t\t  session->connection_state.read_mac_secret.size, ver);\n\n    if (td == GNUTLS_MAC_FAILED\n\t&& session->security_parameters.read_mac_algorithm !=\n\tGNUTLS_MAC_NULL) {\n\tgnutls_assert();\n\treturn GNUTLS_E_INTERNAL_ERROR;\n    }\n\n\n    /* actual decryption (inplace)\n     */\n    switch (_gnutls_cipher_is_block\n\t    (session->security_parameters.read_bulk_cipher_algorithm)) {\n    case CIPHER_STREAM:\n\tif ((ret = _gnutls_cipher_decrypt(session->connection_state.\n\t\t\t\t\t  read_cipher_state,\n\t\t\t\t\t  ciphertext.data,\n\t\t\t\t\t  ciphertext.size)) < 0) {\n\t    gnutls_assert();\n\t    return ret;\n\t}\n\n\tlength = ciphertext.size - hash_size;\n\n\tbreak;\n    case CIPHER_BLOCK:\n\tif ((ciphertext.size < blocksize)\n\t    || (ciphertext.size % blocksize != 0)) {\n\t    gnutls_assert();\n\t    return GNUTLS_E_DECRYPTION_FAILED;\n\t}\n\n\tif ((ret = _gnutls_cipher_decrypt(session->connection_state.\n\t\t\t\t\t  read_cipher_state,\n\t\t\t\t\t  ciphertext.data,\n\t\t\t\t\t  ciphertext.size)) < 0) {\n\t    gnutls_assert();\n\t    return ret;\n\t}\n\n\t/* ignore the IV in TLS 1.1.\n\t */\n\tif (session->security_parameters.version >= GNUTLS_TLS1_1) {\n\t    ciphertext.size -= blocksize;\n\t    ciphertext.data += blocksize;\n\n\t    if (ciphertext.size == 0) {\n\t\tgnutls_assert();\n\t\treturn GNUTLS_E_DECRYPTION_FAILED;\n\t    }\n\t}\n\n\tpad = ciphertext.data[ciphertext.size - 1] + 1;\t/* pad */\n\n\tlength = ciphertext.size - hash_size - pad;\n\n\tif (pad > ciphertext.size - hash_size) {\n\t    gnutls_assert();\n\t    /* We do not fail here. We check below for the\n\t     * the pad_failed. If zero means success.\n\t     */\n\t    pad_failed = GNUTLS_E_DECRYPTION_FAILED;\n\t}\n\n\t/* Check the pading bytes (TLS 1.x)\n\t */\n\tif (ver >= GNUTLS_TLS1)\n\t    for (i = 2; i < pad; i++) {\n\t\tif (ciphertext.data[ciphertext.size - i] !=\n\t\t    ciphertext.data[ciphertext.size - 1])\n\t\t    pad_failed = GNUTLS_E_DECRYPTION_FAILED;\n\t    }\n\n\tbreak;\n    default:\n\tgnutls_assert();\n\treturn GNUTLS_E_INTERNAL_ERROR;\n    }\n\n    if (length < 0)\n\tlength = 0;\n    c_length = _gnutls_conv_uint16((uint16) length);\n\n    /* Pass the type, version, length and compressed through\n     * MAC.\n     */\n    if (td != GNUTLS_MAC_FAILED) {\n\t_gnutls_hmac(td,\n\t\t     UINT64DATA(session->connection_state.\n\t\t\t\tread_sequence_number), 8);\n\n\t_gnutls_hmac(td, &type, 1);\n\tif (ver >= GNUTLS_TLS1) {\t/* TLS 1.x */\n\t    _gnutls_hmac(td, &major, 1);\n\t    _gnutls_hmac(td, &minor, 1);\n\t}\n\t_gnutls_hmac(td, &c_length, 2);\n\n\tif (length > 0)\n\t    _gnutls_hmac(td, ciphertext.data, length);\n\n\tmac_deinit(td, MAC, ver);\n    }\n\n    /* This one was introduced to avoid a timing attack against the TLS\n     * 1.0 protocol.\n     */\n    if (pad_failed != 0)\n\treturn pad_failed;\n\n    /* HMAC was not the same. \n     */\n    if (memcmp(MAC, &ciphertext.data[length], hash_size) != 0) {\n\tgnutls_assert();\n\treturn GNUTLS_E_DECRYPTION_FAILED;\n    }\n\n    /* copy the decrypted stuff to compress_data.\n     */\n    if (compress_size < length) {\n\tgnutls_assert();\n\treturn GNUTLS_E_INTERNAL_ERROR;\n    }\n    memcpy(compress_data, ciphertext.data, length);\n\n    return length;\n}", "target": 1, "cwe": [], "project": "gnutls", "commit_id": "7ad6162573ba79a4392c63b453ad0220ca6c5ace", "hash": 73008646937836648589283922871188272089, "size": 157, "message": "added an extra check while checking the padding."}
test_code = {"func": "void async_request(TALLOC_CTX *mem_ctx, struct winbindd_child *child,\n\t\t   struct winbindd_request *request,\n\t\t   struct winbindd_response *response,\n\t\t   void (*continuation)(void *private_data, BOOL success),\n\t\t   void *private_data)\n{\n\tstruct winbindd_async_request *state;\n\n\tSMB_ASSERT(continuation != NULL);\n\n\tstate = TALLOC_P(mem_ctx, struct winbindd_async_request);\n\n\tif (state == NULL) {\n\t\tDEBUG(0, (\"talloc failed\\n\"));\n\t\tcontinuation(private_data, False);\n\t\treturn;\n\t}\n\n\tstate->mem_ctx = mem_ctx;\n\tstate->child = child;\n\tstate->request = request;\n\tstate->response = response;\n\tstate->continuation = continuation;\n\tstate->private_data = private_data;\n\n\tDLIST_ADD_END(child->requests, state, struct winbindd_async_request *);\n\n\tschedule_async_request(child);\n\n\treturn;\n}", "target": 1, "cwe": [], "project": "samba", "commit_id": "c93d42969451949566327e7fdbf29bfcee2c8319", "hash": 13500245137413054717180286489878807064, "size": 31, "message": "Back-port of Volkers fix.\n\n    Fix a race condition in winbind leading to a crash\n\n    When SIGCHLD handling is delayed for some reason, sending a request to a child\n    can fail early because the child has died already. In this case\n    async_main_request_sent() directly called the continuation function without\n    properly removing the malfunctioning child process and the requests in the\n    queue. The next request would then crash in the DLIST_ADD_END() in\n    async_request() because the request pending for the child had been\n    talloc_free()'ed and yet still was referenced in the list.\n\n    This one is *old*...\n\n    Volker\n\nJeremy."}
# test_code = {"func": "ProcShmCreatePixmap(client)\n    register ClientPtr client;\n{\n    PixmapPtr pMap;\n    DrawablePtr pDraw;\n    DepthPtr pDepth;\n    register int i, rc;\n    ShmDescPtr shmdesc;\n    REQUEST(xShmCreatePixmapReq);\n    unsigned int width, height, depth;\n    unsigned long size;\n\n    REQUEST_SIZE_MATCH(xShmCreatePixmapReq);\n    client->errorValue = stuff->pid;\n    if (!sharedPixmaps)\n\treturn BadImplementation;\n    LEGAL_NEW_RESOURCE(stuff->pid, client);\n    rc = dixLookupDrawable(&pDraw, stuff->drawable, client, M_ANY,\n\t\t\t   DixGetAttrAccess);\n    if (rc != Success)\n\treturn rc;\n\n    VERIFY_SHMPTR(stuff->shmseg, stuff->offset, TRUE, shmdesc, client);\n    \n    width = stuff->width;\n    height = stuff->height;\n    depth = stuff->depth;\n    if (!width || !height || !depth)\n    {\n\tclient->errorValue = 0;\n        return BadValue;\n    }\n    if (width > 32767 || height > 32767)\n\treturn BadAlloc;\n\n    if (stuff->depth != 1)\n    {\n        pDepth = pDraw->pScreen->allowedDepths;\n        for (i=0; i<pDraw->pScreen->numDepths; i++, pDepth++)\n\t   if (pDepth->depth == stuff->depth)\n               goto CreatePmap;\n\tclient->errorValue = stuff->depth;\n        return BadValue;\n    }\n\nCreatePmap:\n    size = PixmapBytePad(width, depth) * height;\n    if (sizeof(size) == 4 && BitsPerPixel(depth) > 8) {\n\tif (size < width * height)\n\t    return BadAlloc;\n\t/* thankfully, offset is unsigned */\n\tif (stuff->offset + size < size)\n\t    return BadAlloc;\n    }\n\n    VERIFY_SHMSIZE(shmdesc, stuff->offset, size, client);\n    pMap = (*shmFuncs[pDraw->pScreen->myNum]->CreatePixmap)(\n\t\t\t    pDraw->pScreen, stuff->width,\n\t\t\t    stuff->height, stuff->depth,\n\t\t\t    shmdesc->addr + stuff->offset);\n    if (pMap)\n    {\n\trc = XaceHook(XACE_RESOURCE_ACCESS, client, stuff->pid, RT_PIXMAP,\n\t\t      pMap, RT_NONE, NULL, DixCreateAccess);\n\tif (rc != Success) {\n\t    pDraw->pScreen->DestroyPixmap(pMap);\n\t    return rc;\n\t}\n\tdixSetPrivate(&pMap->devPrivates, shmPixmapPrivate, shmdesc);\n\tshmdesc->refcnt++;\n\tpMap->drawable.serialNumber = NEXT_SERIAL_NUMBER;\n\tpMap->drawable.id = stuff->pid;\n\tif (AddResource(stuff->pid, RT_PIXMAP, (pointer)pMap))\n\t{\n\t    return(client->noClientException);\n\t}\n\tpDraw->pScreen->DestroyPixmap(pMap);\n    }\n    return (BadAlloc);\n}", "target": 1, "cwe": ["CWE-189"], "project": "xserver", "commit_id": "be6c17fcf9efebc0bbcc3d9a25f8c5a2450c2161", "hash": 129275241199461482775430751894790125185, "size": 80, "message": "CVE-2007-6429: Always test for size+offset wrapping."}
test_code = test_code["func"]
# print(test_code)
tree = parser.parse(bytes(test_code, "utf8"))
root = tree.root_node
# find root node of function definition, has node type "function_definition"
while root.type != "function_definition":
    try:
        root = root.children[0]
    except IndexError:
        print("No function definition found.")
        break

# print(pretty_print_node(root))


# print(test_code)
print(n_loops(root))
print(n_nested_loops(root))
print(max_nesting_level_of_loops(root))
print(n_param_variables(root))
# print(n_variables_as_parameters(root))
n_pointer_arithmetic, n_variables, max_pointer_arithmetic = pointers(root)
print(n_pointer_arithmetic, n_variables, max_pointer_arithmetic)
print(n_control_structures(root))
print(n_nested_control_structures(root))
print(max_nesting_level_of_control_structures(root))
control_dependent, data_dependent, variables = find_control_structures(root)
variables = len(variables)
print(control_dependent, data_dependent, variables)
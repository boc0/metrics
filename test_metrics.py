import pytest
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser, Node
# import the following:

from metrics import (
    n_loops,
    n_nested_loops,
    max_nesting_level_of_loops,
    n_param_variables,
    n_variables_as_parameters,
    pointers,
    n_control_structures,
    n_nested_control_structures,
    max_nesting_level_of_control_structures,
    control_dependent_control_structures,
    data_dependent_control_structures,
    vars_in_control_predicates,
    extract_variables,
    param_names,
    pointers,
)

CPP_LANGUAGE = Language(tscpp.language())
parser = Parser(CPP_LANGUAGE)

def parse(code):
    return parser.parse(
        bytes(
            code,
            "utf8"
        )
    ).root_node

@pytest.fixture
def root(request):
    try:
        code = request.param
    except AttributeError:
        code = request._parent_request.param
    return parse(code)

@pytest.fixture
def first_statement(root):
    funcdef = root.children[0]
    body = funcdef.child_by_field_name("body")
    return body.children[1]

def expect(*args, fixture='root'):
    """Wrapper for pytest.mark.parametrize which gives test functions
    the examples to test on and expected results"""
    expected = args[0]
    if isinstance(expected, list): # list of tuples in args
        arg = [expected]
    else:
        code, res = args
        arg = [(code, res)]
    return lambda func: pytest.mark.parametrize(f'{fixture}, expected', arg, indirect=[fixture])(func)

boilerplate = 'void foo() {{ {}; }}'

def expect_first_statement(code, result):
    return expect(boilerplate.format(code), result, fixture='first_statement')

loops = """
void foo() {
    for (int i = 0; i < 10; i++) {
        while (true) {}
    }
    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 10; j++) {
            for (int k = 0; k < 10; k++) {
                while (true) {}
            }
        }
        while (true) {
            for (int j = 0; j < 10; j++) {
                do {
                    for (int k = 0; k < 10; k++) {
                        while (true) {}
                } while (true);
            }
        }
    }
}
"""


@expect(loops, 11)
def test_n_loops(root, expected):
    assert n_loops(root) == expected


@expect(loops, 9)
def test_n_nested_loops(root, expected):
    assert n_nested_loops(root) == expected


@expect(loops, 5)
def test_max_nesting_level_of_loops(root, expected):
    assert max_nesting_level_of_loops(root) == expected

params = """
static void foo(int a, int b, int c) {
    int d = a + b + c;
    int e;
    e = a + b;
    int f = a + b;
    bar(d, a, c);
    baz(d, e);
    barz(c, f);
}
"""

# params = "int _gnutls_ciphertext2compressed(gnutls_session_t session,\n\t\t\t\t  opaque * compress_data,\n\t\t\t\t  int compress_size,\n\t\t\t\t  gnutls_datum_t ciphertext, uint8 type)\n{\n    uint8 MAC[MAX_HASH_SIZE];\n    uint16 c_length;\n    uint8 pad;\n    int length;\n    mac_hd_t td;\n    uint16 blocksize;\n    int ret, i, pad_failed = 0;\n    uint8 major, minor;\n    gnutls_protocol_t ver;\n    int hash_size =\n\t_gnutls_hash_get_algo_len(session->security_parameters.\n\t\t\t\t  read_mac_algorithm);\n\n    ver = gnutls_protocol_get_version(session);\n    minor = _gnutls_version_get_minor(ver);\n    major = _gnutls_version_get_major(ver);\n\n    blocksize = _gnutls_cipher_get_block_size(session->security_parameters.\n\t\t\t\t\t      read_bulk_cipher_algorithm);\n\n    /* initialize MAC \n     */\n    td = mac_init(session->security_parameters.read_mac_algorithm,\n\t\t  session->connection_state.read_mac_secret.data,\n\t\t  session->connection_state.read_mac_secret.size, ver);\n\n    if (td == GNUTLS_MAC_FAILED\n\t&& session->security_parameters.read_mac_algorithm !=\n\tGNUTLS_MAC_NULL) {\n\tgnutls_assert();\n\treturn GNUTLS_E_INTERNAL_ERROR;\n    }\n\n\n    /* actual decryption (inplace)\n     */\n    switch (_gnutls_cipher_is_block\n\t    (session->security_parameters.read_bulk_cipher_algorithm)) {\n    case CIPHER_STREAM:\n\tif ((ret = _gnutls_cipher_decrypt(session->connection_state.\n\t\t\t\t\t  read_cipher_state,\n\t\t\t\t\t  ciphertext.data,\n\t\t\t\t\t  ciphertext.size)) < 0) {\n\t    gnutls_assert();\n\t    return ret;\n\t}\n\n\tlength = ciphertext.size - hash_size;\n\n\tbreak;\n    case CIPHER_BLOCK:\n\tif ((ciphertext.size < blocksize)\n\t    || (ciphertext.size % blocksize != 0)) {\n\t    gnutls_assert();\n\t    return GNUTLS_E_DECRYPTION_FAILED;\n\t}\n\n\tif ((ret = _gnutls_cipher_decrypt(session->connection_state.\n\t\t\t\t\t  read_cipher_state,\n\t\t\t\t\t  ciphertext.data,\n\t\t\t\t\t  ciphertext.size)) < 0) {\n\t    gnutls_assert();\n\t    return ret;\n\t}\n\n\t/* ignore the IV in TLS 1.1.\n\t */\n\tif (session->security_parameters.version >= GNUTLS_TLS1_1) {\n\t    ciphertext.size -= blocksize;\n\t    ciphertext.data += blocksize;\n\n\t    if (ciphertext.size == 0) {\n\t\tgnutls_assert();\n\t\treturn GNUTLS_E_DECRYPTION_FAILED;\n\t    }\n\t}\n\n\tpad = ciphertext.data[ciphertext.size - 1] + 1;\t/* pad */\n\n\tlength = ciphertext.size - hash_size - pad;\n\n\tif (pad > ciphertext.size - hash_size) {\n\t    gnutls_assert();\n\t    /* We do not fail here. We check below for the\n\t     * the pad_failed. If zero means success.\n\t     */\n\t    pad_failed = GNUTLS_E_DECRYPTION_FAILED;\n\t}\n\n\t/* Check the pading bytes (TLS 1.x)\n\t */\n\tif (ver >= GNUTLS_TLS1)\n\t    for (i = 2; i < pad; i++) {\n\t\tif (ciphertext.data[ciphertext.size - i] !=\n\t\t    ciphertext.data[ciphertext.size - 1])\n\t\t    pad_failed = GNUTLS_E_DECRYPTION_FAILED;\n\t    }\n\n\tbreak;\n    default:\n\tgnutls_assert();\n\treturn GNUTLS_E_INTERNAL_ERROR;\n    }\n\n    if (length < 0)\n\tlength = 0;\n    c_length = _gnutls_conv_uint16((uint16) length);\n\n    /* Pass the type, version, length and compressed through\n     * MAC.\n     */\n    if (td != GNUTLS_MAC_FAILED) {\n\t_gnutls_hmac(td,\n\t\t     UINT64DATA(session->connection_state.\n\t\t\t\tread_sequence_number), 8);\n\n\t_gnutls_hmac(td, &type, 1);\n\tif (ver >= GNUTLS_TLS1) {\t/* TLS 1.x */\n\t    _gnutls_hmac(td, &major, 1);\n\t    _gnutls_hmac(td, &minor, 1);\n\t}\n\t_gnutls_hmac(td, &c_length, 2);\n\n\tif (length > 0)\n\t    _gnutls_hmac(td, ciphertext.data, length);\n\n\tmac_deinit(td, MAC, ver);\n    }\n\n    /* This one was introduced to avoid a timing attack against the TLS\n     * 1.0 protocol.\n     */\n    if (pad_failed != 0)\n\treturn pad_failed;\n\n    /* HMAC was not the same. \n     */\n    if (memcmp(MAC, &ciphertext.data[length], hash_size) != 0) {\n\tgnutls_assert();\n\treturn GNUTLS_E_DECRYPTION_FAILED;\n    }\n\n    /* copy the decrypted stuff to compress_data.\n     */\n    if (compress_size < length) {\n\tgnutls_assert();\n\treturn GNUTLS_E_INTERNAL_ERROR;\n    }\n    memcpy(compress_data, ciphertext.data, length);\n\n    return length;\n}"

@expect(params, 3)
def test_n_param_variables(root, expected):
    assert n_param_variables(root) == expected


@expect(params, 3)
def test_n_variables_as_parameters(root, expected):
    assert n_variables_as_parameters(root) == expected


fib = """
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

@expect(fib, 4)
def test_n_control_structures(root, expected):
    assert n_control_structures(root) == expected

@expect(fib, 2)
def test_n_nested_control_structures(root, expected):
    assert n_nested_control_structures(root) == expected

@expect(fib, 2)
def test_max_nesting_level_of_control_structures(root, expected):
    assert max_nesting_level_of_control_structures(root) == expected

@expect(fib, 3)
def test_control_dependent_control_structures(root, expected):
    assert control_dependent_control_structures(root) == expected

@expect(fib, 4)
def test_data_dependent_control_structures(root, expected):
    assert data_dependent_control_structures(root) == expected

@expect(fib, 2)
def test_vars_in_control_predicates(root, expected):
    assert vars_in_control_predicates(root) == expected

@expect_first_statement('for (int i = 0; i < 10; i++)', {"i"})
def test_extract_variables_for_loop(first_statement, expected):
    assert extract_variables(first_statement) == expected

@expect_first_statement('if (a > 0) {}', {"a"})
def test_extract_variables_if(first_statement, expected):
    assert extract_variables(first_statement) == expected

@expect_first_statement('while (e) {}', {"e"})
def test_extract_variables_while(first_statement, expected):
    assert extract_variables(first_statement) == expected

@expect_first_statement('switch (func(arg->field1.field2)) {}', {'func', 'arg'})
def test_extract_variables_switch(first_statement, expected):
    assert extract_variables(first_statement) == expected

test_func = "int _gnutls_ciphertext2compressed(gnutls_session_t session,\n\t\t\t\t  opaque * compress_data,\n\t\t\t\t  int compress_size,\n\t\t\t\t  gnutls_datum_t ciphertext, uint8 type)\n{\n    uint8 MAC[MAX_HASH_SIZE];\n    uint16 c_length;\n    uint8 pad;\n    int length;\n    mac_hd_t td;\n    uint16 blocksize;\n    int ret, i, pad_failed = 0;\n    uint8 major, minor;\n    gnutls_protocol_t ver;\n    int hash_size =\n\t_gnutls_hash_get_algo_len(session->security_parameters.\n\t\t\t\t  read_mac_algorithm);\n\n    ver = gnutls_protocol_get_version(session);\n    minor = _gnutls_version_get_minor(ver);\n    major = _gnutls_version_get_major(ver);\n\n    blocksize = _gnutls_cipher_get_block_size(session->security_parameters.\n\t\t\t\t\t      read_bulk_cipher_algorithm);\n\n    /* initialize MAC \n     */\n    td = mac_init(session->security_parameters.read_mac_algorithm,\n\t\t  session->connection_state.read_mac_secret.data,\n\t\t  session->connection_state.read_mac_secret.size, ver);\n\n    if (td == GNUTLS_MAC_FAILED\n\t&& session->security_parameters.read_mac_algorithm !=\n\tGNUTLS_MAC_NULL) {\n\tgnutls_assert();\n\treturn GNUTLS_E_INTERNAL_ERROR;\n    }\n\n\n    /* actual decryption (inplace)\n     */\n    switch (_gnutls_cipher_is_block\n\t    (session->security_parameters.read_bulk_cipher_algorithm)) {\n    case CIPHER_STREAM:\n\tif ((ret = _gnutls_cipher_decrypt(session->connection_state.\n\t\t\t\t\t  read_cipher_state,\n\t\t\t\t\t  ciphertext.data,\n\t\t\t\t\t  ciphertext.size)) < 0) {\n\t    gnutls_assert();\n\t    return ret;\n\t}\n\n\tlength = ciphertext.size - hash_size;\n\n\tbreak;\n    case CIPHER_BLOCK:\n\tif ((ciphertext.size < blocksize)\n\t    || (ciphertext.size % blocksize != 0)) {\n\t    gnutls_assert();\n\t    return GNUTLS_E_DECRYPTION_FAILED;\n\t}\n\n\tif ((ret = _gnutls_cipher_decrypt(session->connection_state.\n\t\t\t\t\t  read_cipher_state,\n\t\t\t\t\t  ciphertext.data,\n\t\t\t\t\t  ciphertext.size)) < 0) {\n\t    gnutls_assert();\n\t    return ret;\n\t}\n\n\t/* ignore the IV in TLS 1.1.\n\t */\n\tif (session->security_parameters.version >= GNUTLS_TLS1_1) {\n\t    ciphertext.size -= blocksize;\n\t    ciphertext.data += blocksize;\n\n\t    if (ciphertext.size == 0) {\n\t\tgnutls_assert();\n\t\treturn GNUTLS_E_DECRYPTION_FAILED;\n\t    }\n\t}\n\n\tpad = ciphertext.data[ciphertext.size - 1] + 1;\t/* pad */\n\n\tlength = ciphertext.size - hash_size - pad;\n\n\tif (pad > ciphertext.size - hash_size) {\n\t    gnutls_assert();\n\t    /* We do not fail here. We check below for the\n\t     * the pad_failed. If zero means success.\n\t     */\n\t    pad_failed = GNUTLS_E_DECRYPTION_FAILED;\n\t}\n\n\t/* Check the pading bytes (TLS 1.x)\n\t */\n\tif (ver >= GNUTLS_TLS1)\n\t    for (i = 2; i < pad; i++) {\n\t\tif (ciphertext.data[ciphertext.size - i] !=\n\t\t    ciphertext.data[ciphertext.size - 1])\n\t\t    pad_failed = GNUTLS_E_DECRYPTION_FAILED;\n\t    }\n\n\tbreak;\n    default:\n\tgnutls_assert();\n\treturn GNUTLS_E_INTERNAL_ERROR;\n    }\n\n    if (length < 0)\n\tlength = 0;\n    c_length = _gnutls_conv_uint16((uint16) length);\n\n    /* Pass the type, version, length and compressed through\n     * MAC.\n     */\n    if (td != GNUTLS_MAC_FAILED) {\n\t_gnutls_hmac(td,\n\t\t     UINT64DATA(session->connection_state.\n\t\t\t\tread_sequence_number), 8);\n\n\t_gnutls_hmac(td, &type, 1);\n\tif (ver >= GNUTLS_TLS1) {\t/* TLS 1.x */\n\t    _gnutls_hmac(td, &major, 1);\n\t    _gnutls_hmac(td, &minor, 1);\n\t}\n\t_gnutls_hmac(td, &c_length, 2);\n\n\tif (length > 0)\n\t    _gnutls_hmac(td, ciphertext.data, length);\n\n\tmac_deinit(td, MAC, ver);\n    }\n\n    /* This one was introduced to avoid a timing attack against the TLS\n     * 1.0 protocol.\n     */\n    if (pad_failed != 0)\n\treturn pad_failed;\n\n    /* HMAC was not the same. \n     */\n    if (memcmp(MAC, &ciphertext.data[length], hash_size) != 0) {\n\tgnutls_assert();\n\treturn GNUTLS_E_DECRYPTION_FAILED;\n    }\n\n    /* copy the decrypted stuff to compress_data.\n     */\n    if (compress_size < length) {\n\tgnutls_assert();\n\treturn GNUTLS_E_INTERNAL_ERROR;\n    }\n    memcpy(compress_data, ciphertext.data, length);\n\n    return length;\n}"
# test_func = "static void cirrus_mem_writeb_mode4and5_16bpp(CirrusVGAState * s,\n\t\t\t\t\t      unsigned mode,\n\t\t\t\t\t      unsigned offset,\n\t\t\t\t\t      uint32_t mem_value)\n{\n    int x;\n    unsigned val = mem_value;\n    uint8_t *dst;\n\n    dst = s->vram_ptr + offset;\n    for (x = 0; x < 8; x++) {\n\tif (val & 0x80) {\n\t    *dst = s->cirrus_shadow_gr1;\n\t    *(dst + 1) = s->gr[0x11];\n\t} else if (mode == 5) {\n\t    *dst = s->cirrus_shadow_gr0;\n\t    *(dst + 1) = s->gr[0x10];\n\t}\n\tval <<= 1;\n\tdst += 2;\n    }\n    cpu_physical_memory_set_dirty(s->vram_offset + offset);\n    cpu_physical_memory_set_dirty(s->vram_offset + offset + 15);\n}"


@expect(test_func, {'session', 'compress_data', 'compress_size', 'ciphertext', 'type'})
def test_param_names(root, expected):
    funcdef = root.children[0]
    assert param_names(funcdef) == expected

test_code_pointers = """
void foo() {
    _struct *a;
    int *b;
    int c;
    c++;
    b++;
    a->field1.field2++;
    a[10];
}
"""

@expect(test_code_pointers, (3, 2, 2))
def test_pointers(root, expected):
    n_pointer_arithmetic, n_variables, max_pointer_arithmetic = pointers(root)
    assert n_pointer_arithmetic == expected[0]
    assert n_variables == expected[1]
    assert max_pointer_arithmetic == expected[2]
    
@expect(test_func, (45, 2, 24))
def test_pointers_big(root, expected):
    n_pointer_arithmetic, n_variables, max_pointer_arithmetic = pointers(root)
    assert n_pointer_arithmetic == expected[0]
    assert n_variables == expected[1]
    assert max_pointer_arithmetic == expected[2]

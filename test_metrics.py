import pytest
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser
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
    find_control_structures,
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
    code = request.param
    return parse(code)

# def expect(expected: tuple[str, int] | list[tuple[str, int]]):
def expect(*args):
    """Wrapper for pytest.mark.parametrize which gives test functions
    the examples to test on and expected results"""
    expected = args[0]
    if isinstance(expected, list): # list of tuples in args
        arg = [expected]
    else:
        code, res = args
        arg = [(code, res)]
    return lambda func: pytest.mark.parametrize('root, expected', arg, indirect=['root'])(func)

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

# @pytest.mark.parametrize('root, expected', [(loops, 11)], indirect=['root'])
@expect(loops, 11)
def test_n_loops(root, expected):
    assert n_loops(root) == expected

# @pytest.mark.parametrize('root, expected', [(loops, 9)], indirect=['root'])
@expect(loops, 9)
def test_n_nested_loops(root, expected):
    assert n_nested_loops(root) == expected

# @pytest.mark.parametrize('root, expected', [(loops, 5)], indirect=['root'])
@expect(loops, 5)
def test_max_nesting_level_of_loops(root, expected):
    assert max_nesting_level_of_loops(root) == expected

params = """
static void foo(int a, int b, int c) {
    int j;
    int d = a + b + c;
    int e;
    bar(d, a, c);
    baz(d, e);
    barz(c, j);
}
"""

# params = "int _gnutls_ciphertext2compressed(gnutls_session_t session,\n\t\t\t\t  opaque * compress_data,\n\t\t\t\t  int compress_size,\n\t\t\t\t  gnutls_datum_t ciphertext, uint8 type)\n{\n    uint8 MAC[MAX_HASH_SIZE];\n    uint16 c_length;\n    uint8 pad;\n    int length;\n    mac_hd_t td;\n    uint16 blocksize;\n    int ret, i, pad_failed = 0;\n    uint8 major, minor;\n    gnutls_protocol_t ver;\n    int hash_size =\n\t_gnutls_hash_get_algo_len(session->security_parameters.\n\t\t\t\t  read_mac_algorithm);\n\n    ver = gnutls_protocol_get_version(session);\n    minor = _gnutls_version_get_minor(ver);\n    major = _gnutls_version_get_major(ver);\n\n    blocksize = _gnutls_cipher_get_block_size(session->security_parameters.\n\t\t\t\t\t      read_bulk_cipher_algorithm);\n\n    /* initialize MAC \n     */\n    td = mac_init(session->security_parameters.read_mac_algorithm,\n\t\t  session->connection_state.read_mac_secret.data,\n\t\t  session->connection_state.read_mac_secret.size, ver);\n\n    if (td == GNUTLS_MAC_FAILED\n\t&& session->security_parameters.read_mac_algorithm !=\n\tGNUTLS_MAC_NULL) {\n\tgnutls_assert();\n\treturn GNUTLS_E_INTERNAL_ERROR;\n    }\n\n\n    /* actual decryption (inplace)\n     */\n    switch (_gnutls_cipher_is_block\n\t    (session->security_parameters.read_bulk_cipher_algorithm)) {\n    case CIPHER_STREAM:\n\tif ((ret = _gnutls_cipher_decrypt(session->connection_state.\n\t\t\t\t\t  read_cipher_state,\n\t\t\t\t\t  ciphertext.data,\n\t\t\t\t\t  ciphertext.size)) < 0) {\n\t    gnutls_assert();\n\t    return ret;\n\t}\n\n\tlength = ciphertext.size - hash_size;\n\n\tbreak;\n    case CIPHER_BLOCK:\n\tif ((ciphertext.size < blocksize)\n\t    || (ciphertext.size % blocksize != 0)) {\n\t    gnutls_assert();\n\t    return GNUTLS_E_DECRYPTION_FAILED;\n\t}\n\n\tif ((ret = _gnutls_cipher_decrypt(session->connection_state.\n\t\t\t\t\t  read_cipher_state,\n\t\t\t\t\t  ciphertext.data,\n\t\t\t\t\t  ciphertext.size)) < 0) {\n\t    gnutls_assert();\n\t    return ret;\n\t}\n\n\t/* ignore the IV in TLS 1.1.\n\t */\n\tif (session->security_parameters.version >= GNUTLS_TLS1_1) {\n\t    ciphertext.size -= blocksize;\n\t    ciphertext.data += blocksize;\n\n\t    if (ciphertext.size == 0) {\n\t\tgnutls_assert();\n\t\treturn GNUTLS_E_DECRYPTION_FAILED;\n\t    }\n\t}\n\n\tpad = ciphertext.data[ciphertext.size - 1] + 1;\t/* pad */\n\n\tlength = ciphertext.size - hash_size - pad;\n\n\tif (pad > ciphertext.size - hash_size) {\n\t    gnutls_assert();\n\t    /* We do not fail here. We check below for the\n\t     * the pad_failed. If zero means success.\n\t     */\n\t    pad_failed = GNUTLS_E_DECRYPTION_FAILED;\n\t}\n\n\t/* Check the pading bytes (TLS 1.x)\n\t */\n\tif (ver >= GNUTLS_TLS1)\n\t    for (i = 2; i < pad; i++) {\n\t\tif (ciphertext.data[ciphertext.size - i] !=\n\t\t    ciphertext.data[ciphertext.size - 1])\n\t\t    pad_failed = GNUTLS_E_DECRYPTION_FAILED;\n\t    }\n\n\tbreak;\n    default:\n\tgnutls_assert();\n\treturn GNUTLS_E_INTERNAL_ERROR;\n    }\n\n    if (length < 0)\n\tlength = 0;\n    c_length = _gnutls_conv_uint16((uint16) length);\n\n    /* Pass the type, version, length and compressed through\n     * MAC.\n     */\n    if (td != GNUTLS_MAC_FAILED) {\n\t_gnutls_hmac(td,\n\t\t     UINT64DATA(session->connection_state.\n\t\t\t\tread_sequence_number), 8);\n\n\t_gnutls_hmac(td, &type, 1);\n\tif (ver >= GNUTLS_TLS1) {\t/* TLS 1.x */\n\t    _gnutls_hmac(td, &major, 1);\n\t    _gnutls_hmac(td, &minor, 1);\n\t}\n\t_gnutls_hmac(td, &c_length, 2);\n\n\tif (length > 0)\n\t    _gnutls_hmac(td, ciphertext.data, length);\n\n\tmac_deinit(td, MAC, ver);\n    }\n\n    /* This one was introduced to avoid a timing attack against the TLS\n     * 1.0 protocol.\n     */\n    if (pad_failed != 0)\n\treturn pad_failed;\n\n    /* HMAC was not the same. \n     */\n    if (memcmp(MAC, &ciphertext.data[length], hash_size) != 0) {\n\tgnutls_assert();\n\treturn GNUTLS_E_DECRYPTION_FAILED;\n    }\n\n    /* copy the decrypted stuff to compress_data.\n     */\n    if (compress_size < length) {\n\tgnutls_assert();\n\treturn GNUTLS_E_INTERNAL_ERROR;\n    }\n    memcpy(compress_data, ciphertext.data, length);\n\n    return length;\n}"

# @pytest.mark.parametrize('root, expected', [(params, 3)], indirect=['root'])
@expect(params, 3)
def test_n_param_variables(root, expected):
    assert n_param_variables(root) == expected


# @pytest.mark.parametrize('root, expected', [(params, 1)], indirect=['root'])
@expect(params, 1)
def test_n_variables_as_parameters(root, expected):
    assert n_variables_as_parameters(root) == expected
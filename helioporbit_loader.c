/*
 * helioporbit_loader.c
 * ====================
 * CPython C extension implementing encrypted bytecode with lazy decryption.
 *
 * Architecture:
 *   - Python side compiles .py -> code objects -> marshal -> encrypt (ChaCha20)
 *   - Each code object is stored as an encrypted blob with a per-object key
 *   - This C extension provides:
 *       hpb_load_encrypted(blob, key, nonce) -> code_object
 *       hpb_exec_encrypted(blob, key, nonce, globals, locals) -> result
 *       hpb_register(name, blob, key, nonce) -> None  (register lazy module)
 *       hpb_import(name) -> module                    (trigger lazy decrypt)
 *
 * Lazy decryption:
 *   - Encrypted blobs stored in a static registry (dict)
 *   - Code is decrypted ONLY when first called/imported
 *   - After decryption, plaintext bytecode is immediately discarded from C heap
 *   - Decrypted code objects live only in CPython's object allocator
 *   - Prevents full memory dump from recovering all bytecode at once
 *
 * ChaCha20 implementation is self-contained (no libsodium dependency).
 * For production, link against libsodium for AEAD authentication.
 *
 * Build:
 *   Windows: python setup_loader.py build_ext --inplace
 *   Linux:   python setup_loader.py build_ext --inplace
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <marshal.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* ── ChaCha20 (RFC 7539) ─────────────────────────────────────────────────── */

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d)          \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d,  8); \
    c += d; b ^= c; b = ROTL32(b,  7)

static void chacha20_block(
    const uint8_t  key[32],
    uint32_t       counter,
    const uint8_t  nonce[12],
    uint8_t        out[64])
{
    uint32_t state[16], working[16];
    int i;

    /* Constants "expand 32-byte k" */
    state[0]  = 0x61707865u;
    state[1]  = 0x3320646eu;
    state[2]  = 0x79622d32u;
    state[3]  = 0x6b206574u;

    /* Key (little-endian) */
    for (i = 0; i < 8; i++) {
        state[4 + i] = (uint32_t)key[4*i]
                     | ((uint32_t)key[4*i+1] << 8)
                     | ((uint32_t)key[4*i+2] << 16)
                     | ((uint32_t)key[4*i+3] << 24);
    }

    state[12] = counter;

    /* Nonce (little-endian) */
    for (i = 0; i < 3; i++) {
        state[13 + i] = (uint32_t)nonce[4*i]
                      | ((uint32_t)nonce[4*i+1] << 8)
                      | ((uint32_t)nonce[4*i+2] << 16)
                      | ((uint32_t)nonce[4*i+3] << 24);
    }

    memcpy(working, state, sizeof(state));

    /* 20 rounds = 10 double-rounds */
    for (i = 0; i < 10; i++) {
        /* Column rounds */
        QR(working[0], working[4], working[ 8], working[12]);
        QR(working[1], working[5], working[ 9], working[13]);
        QR(working[2], working[6], working[10], working[14]);
        QR(working[3], working[7], working[11], working[15]);
        /* Diagonal rounds */
        QR(working[0], working[5], working[10], working[15]);
        QR(working[1], working[6], working[11], working[12]);
        QR(working[2], working[7], working[ 8], working[13]);
        QR(working[3], working[4], working[ 9], working[14]);
    }

    /* Add working state to original, store as little-endian bytes */
    for (i = 0; i < 16; i++) {
        uint32_t v = working[i] + state[i];
        out[4*i]   = (uint8_t)(v);
        out[4*i+1] = (uint8_t)(v >> 8);
        out[4*i+2] = (uint8_t)(v >> 16);
        out[4*i+3] = (uint8_t)(v >> 24);
    }
}

/*
 * chacha20_xor: in-place XOR of buf with ChaCha20 keystream.
 * counter starts at 1 (block 0 is reserved for Poly1305 key in AEAD mode).
 */
static void chacha20_xor(
    const uint8_t  key[32],
    const uint8_t  nonce[12],
    uint8_t       *buf,
    size_t         len)
{
    uint8_t  block[64];
    uint32_t counter = 1;
    size_t   i, block_start;

    for (block_start = 0; block_start < len; block_start += 64, counter++) {
        size_t chunk = (len - block_start < 64) ? (len - block_start) : 64;
        chacha20_block(key, counter, nonce, block);
        for (i = 0; i < chunk; i++)
            buf[block_start + i] ^= block[i];
    }

    /* Scrub keystream block from stack */
    memset(block, 0, sizeof(block));
}

/* ── Registry for lazy-loaded encrypted blobs ────────────────────────────── */

/*
 * Registry entry: stores the encrypted blob + key material.
 * After first load, blob is freed and PyCodeObject* is cached.
 */
typedef struct HpbEntry {
    char     *name;          /* module/function name (owned) */
    uint8_t  *blob;          /* encrypted marshal bytes (owned, freed after load) */
    size_t    blob_len;
    uint8_t   key[32];       /* per-object ChaCha20 key */
    uint8_t   nonce[12];     /* per-object nonce */
    PyObject *code_cache;    /* NULL until first decrypt; Py_INCREF'd after */
    struct HpbEntry *next;
} HpbEntry;

static HpbEntry *g_registry = NULL;

static HpbEntry *find_entry(const char *name)
{
    HpbEntry *e = g_registry;
    while (e) {
        if (strcmp(e->name, name) == 0) return e;
        e = e->next;
    }
    return NULL;
}

/*
 * decrypt_entry: decrypt the blob of entry e, unmarshal to PyCodeObject,
 * cache it, and free the encrypted blob (preventing full memory dump).
 */
static PyObject *decrypt_entry(HpbEntry *e)
{
    uint8_t  *plain = NULL;
    PyObject *code  = NULL;

    if (e->code_cache) {
        Py_INCREF(e->code_cache);
        return e->code_cache;
    }

    /* Decrypt into a temporary heap buffer */
    plain = (uint8_t *)PyMem_Malloc(e->blob_len);
    if (!plain) {
        PyErr_NoMemory();
        return NULL;
    }
    memcpy(plain, e->blob, e->blob_len);
    chacha20_xor(e->key, e->nonce, plain, e->blob_len);

    /* Unmarshal bytes -> PyCodeObject */
    code = PyMarshal_ReadObjectFromString((const char *)plain, (Py_ssize_t)e->blob_len);

    /* Scrub plaintext immediately — lazy: only one object in memory at a time */
    memset(plain, 0, e->blob_len);
    PyMem_Free(plain);

    if (!code) {
        /* PyMarshal already set an exception */
        return NULL;
    }
    if (!PyCode_Check(code)) {
        PyErr_SetString(PyExc_TypeError, "hpb: decrypted object is not a code object");
        Py_DECREF(code);
        return NULL;
    }

    /* Cache and free encrypted blob — reduces attack surface */
    e->code_cache = code;  /* steal reference */
    PyMem_Free(e->blob);
    e->blob     = NULL;
    e->blob_len = 0;
    /* Scrub key material from memory after first use */
    memset(e->key,   0, sizeof(e->key));
    memset(e->nonce, 0, sizeof(e->nonce));

    Py_INCREF(code);
    return code;
}

/* ── Python-facing API ───────────────────────────────────────────────────── */

/*
 * hpb_load_encrypted(blob: bytes, key: bytes, nonce: bytes) -> code
 *
 * One-shot decrypt: decrypts a single blob and returns the code object.
 * Does not use the registry.
 */
static PyObject *py_hpb_load_encrypted(PyObject *self, PyObject *args)
{
    const uint8_t *blob;
    Py_ssize_t     blob_len;
    const uint8_t *key;
    Py_ssize_t     key_len;
    const uint8_t *nonce;
    Py_ssize_t     nonce_len;
    uint8_t       *plain;
    PyObject      *code;

    if (!PyArg_ParseTuple(args, "y#y#y#",
                          &blob, &blob_len,
                          &key,  &key_len,
                          &nonce, &nonce_len))
        return NULL;

    if (key_len < 32) {
        PyErr_SetString(PyExc_ValueError, "hpb: key must be >= 32 bytes");
        return NULL;
    }
    if (nonce_len < 12) {
        PyErr_SetString(PyExc_ValueError, "hpb: nonce must be >= 12 bytes");
        return NULL;
    }

    plain = (uint8_t *)PyMem_Malloc(blob_len);
    if (!plain) return PyErr_NoMemory();

    memcpy(plain, blob, blob_len);
    chacha20_xor(key, nonce, plain, blob_len);

    code = PyMarshal_ReadObjectFromString((const char *)plain, blob_len);
    memset(plain, 0, blob_len);
    PyMem_Free(plain);

    if (code && !PyCode_Check(code)) {
        PyErr_SetString(PyExc_TypeError, "hpb: not a code object");
        Py_DECREF(code);
        return NULL;
    }
    return code;  /* NULL if PyMarshal failed */
}

/*
 * hpb_exec_encrypted(blob, key, nonce, globals=None, locals=None) -> None
 *
 * Decrypt and immediately exec the code object.
 * The decrypted bytecode is never stored — minimum exposure window.
 */
static PyObject *py_hpb_exec_encrypted(PyObject *self, PyObject *args)
{
    const uint8_t *blob;
    Py_ssize_t     blob_len;
    const uint8_t *key;
    Py_ssize_t     key_len;
    const uint8_t *nonce;
    Py_ssize_t     nonce_len;
    PyObject      *globs   = Py_None;
    PyObject      *locs    = Py_None;
    uint8_t       *plain;
    PyObject      *code, *result;

    if (!PyArg_ParseTuple(args, "y#y#y#|OO",
                          &blob,  &blob_len,
                          &key,   &key_len,
                          &nonce, &nonce_len,
                          &globs, &locs))
        return NULL;

    if (key_len < 32 || nonce_len < 12) {
        PyErr_SetString(PyExc_ValueError, "hpb: invalid key/nonce length");
        return NULL;
    }

    plain = (uint8_t *)PyMem_Malloc(blob_len);
    if (!plain) return PyErr_NoMemory();

    memcpy(plain, blob, blob_len);
    chacha20_xor(key, nonce, plain, blob_len);

    code = PyMarshal_ReadObjectFromString((const char *)plain, blob_len);
    memset(plain, 0, blob_len);
    PyMem_Free(plain);

    if (!code) return NULL;

    if (globs == Py_None) globs = PyEval_GetGlobals();
    if (locs  == Py_None) locs  = globs;

    result = PyEval_EvalCode(code, globs, locs);
    Py_DECREF(code);  /* plaintext code object freed immediately after exec */

    if (!result) return NULL;
    Py_DECREF(result);
    Py_RETURN_NONE;
}

/*
 * hpb_register(name: str, blob: bytes, key: bytes, nonce: bytes) -> None
 *
 * Register an encrypted blob for lazy loading.
 */
static PyObject *py_hpb_register(PyObject *self, PyObject *args)
{
    const char    *name;
    const uint8_t *blob;
    Py_ssize_t     blob_len;
    const uint8_t *key;
    Py_ssize_t     key_len;
    const uint8_t *nonce;
    Py_ssize_t     nonce_len;
    HpbEntry      *entry;

    if (!PyArg_ParseTuple(args, "sy#y#y#",
                          &name,
                          &blob,  &blob_len,
                          &key,   &key_len,
                          &nonce, &nonce_len))
        return NULL;

    if (key_len < 32 || nonce_len < 12) {
        PyErr_SetString(PyExc_ValueError, "hpb: invalid key/nonce length");
        return NULL;
    }

    /* Check for duplicate registration */
    if (find_entry(name)) {
        PyErr_Format(PyExc_ValueError, "hpb: '%s' already registered", name);
        return NULL;
    }

    entry = (HpbEntry *)PyMem_Malloc(sizeof(HpbEntry));
    if (!entry) return PyErr_NoMemory();

    entry->name = (char *)PyMem_Malloc(strlen(name) + 1);
    if (!entry->name) { PyMem_Free(entry); return PyErr_NoMemory(); }
    strcpy(entry->name, name);

    entry->blob = (uint8_t *)PyMem_Malloc(blob_len);
    if (!entry->blob) {
        PyMem_Free(entry->name);
        PyMem_Free(entry);
        return PyErr_NoMemory();
    }
    memcpy(entry->blob, blob, blob_len);
    entry->blob_len = (size_t)blob_len;

    memcpy(entry->key,   key,   32);
    memcpy(entry->nonce, nonce, 12);
    entry->code_cache = NULL;
    entry->next       = g_registry;
    g_registry        = entry;

    Py_RETURN_NONE;
}

/*
 * hpb_get(name: str) -> code_object
 *
 * Retrieve (and lazily decrypt) a registered code object.
 */
static PyObject *py_hpb_get(PyObject *self, PyObject *args)
{
    const char *name;
    HpbEntry   *entry;

    if (!PyArg_ParseTuple(args, "s", &name)) return NULL;

    entry = find_entry(name);
    if (!entry) {
        PyErr_Format(PyExc_KeyError, "hpb: '%s' not registered", name);
        return NULL;
    }
    return decrypt_entry(entry);
}

/*
 * hpb_exec(name: str, globals=None, locals=None) -> None
 *
 * Lazily decrypt and exec a registered code object.
 */
static PyObject *py_hpb_exec(PyObject *self, PyObject *args)
{
    const char *name;
    PyObject   *globs = Py_None, *locs = Py_None;
    HpbEntry   *entry;
    PyObject   *code, *result;

    if (!PyArg_ParseTuple(args, "s|OO", &name, &globs, &locs)) return NULL;

    entry = find_entry(name);
    if (!entry) {
        PyErr_Format(PyExc_KeyError, "hpb: '%s' not registered", name);
        return NULL;
    }

    code = decrypt_entry(entry);
    if (!code) return NULL;

    if (globs == Py_None) globs = PyEval_GetGlobals();
    if (locs  == Py_None) locs  = globs;

    result = PyEval_EvalCode(code, globs, locs);
    Py_DECREF(code);

    if (!result) return NULL;
    Py_DECREF(result);
    Py_RETURN_NONE;
}

/*
 * hpb_chacha20(data: bytes, key: bytes, nonce: bytes) -> bytes
 *
 * Expose raw ChaCha20 XOR to Python (used by the Python-side encryptor).
 */
static PyObject *py_hpb_chacha20(PyObject *self, PyObject *args)
{
    const uint8_t *data;
    Py_ssize_t     data_len;
    const uint8_t *key;
    Py_ssize_t     key_len;
    const uint8_t *nonce;
    Py_ssize_t     nonce_len;
    uint8_t       *buf;
    PyObject      *result;

    if (!PyArg_ParseTuple(args, "y#y#y#",
                          &data,  &data_len,
                          &key,   &key_len,
                          &nonce, &nonce_len))
        return NULL;

    if (key_len < 32 || nonce_len < 12) {
        PyErr_SetString(PyExc_ValueError, "hpb: key>=32, nonce>=12 required");
        return NULL;
    }

    buf = (uint8_t *)PyMem_Malloc(data_len);
    if (!buf) return PyErr_NoMemory();

    memcpy(buf, data, data_len);
    chacha20_xor(key, nonce, buf, data_len);

    result = PyBytes_FromStringAndSize((const char *)buf, data_len);
    memset(buf, 0, data_len);
    PyMem_Free(buf);
    return result;
}

/* ── Module cleanup ──────────────────────────────────────────────────────── */

static void free_registry(void)
{
    HpbEntry *e = g_registry, *next;
    while (e) {
        next = e->next;
        if (e->blob) {
            memset(e->blob, 0, e->blob_len);
            PyMem_Free(e->blob);
        }
        memset(e->key,   0, sizeof(e->key));
        memset(e->nonce, 0, sizeof(e->nonce));
        PyMem_Free(e->name);
        Py_XDECREF(e->code_cache);
        PyMem_Free(e);
        e = next;
    }
    g_registry = NULL;
}

/* ── Method table & module init ─────────────────────────────────────────── */

static PyMethodDef HpbMethods[] = {
    {"load_encrypted", py_hpb_load_encrypted, METH_VARARGS,
     "load_encrypted(blob, key, nonce) -> code_object\n"
     "Decrypt a ChaCha20-encrypted marshal blob and return the code object."},
    {"exec_encrypted", py_hpb_exec_encrypted, METH_VARARGS,
     "exec_encrypted(blob, key, nonce[, globals[, locals]]) -> None\n"
     "Decrypt and immediately exec a code object. Minimises exposure window."},
    {"register",       py_hpb_register,       METH_VARARGS,
     "register(name, blob, key, nonce) -> None\n"
     "Register an encrypted blob for lazy loading."},
    {"get",            py_hpb_get,            METH_VARARGS,
     "get(name) -> code_object\n"
     "Lazily decrypt and return a registered code object."},
    {"exec",           py_hpb_exec,           METH_VARARGS,
     "exec(name[, globals[, locals]]) -> None\n"
     "Lazily decrypt and exec a registered code object."},
    {"chacha20",       py_hpb_chacha20,       METH_VARARGS,
     "chacha20(data, key, nonce) -> bytes\n"
     "Raw ChaCha20 XOR (encrypt = decrypt)."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef HpbModule = {
    PyModuleDef_HEAD_INIT,
    "helioporbit_loader",
    "Helioporbit encrypted bytecode loader (C extension).\n"
    "Provides lazy ChaCha20 decryption of marshal'd code objects.",
    -1,
    HpbMethods,
    NULL, NULL, NULL,
    (freefunc)free_registry   /* called on interpreter shutdown */
};

PyMODINIT_FUNC PyInit_helioporbit_loader(void)
{
    PyObject *m = PyModule_Create(&HpbModule);
    if (!m) return NULL;

    PyModule_AddStringConstant(m, "__version__", "1.0.0");
    PyModule_AddStringConstant(m, "__author__",  "Helioporbit");
    return m;
}

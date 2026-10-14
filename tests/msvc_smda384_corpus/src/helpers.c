/* Out-of-line helpers for cases.c. A separate translation unit (and no /GL), so the calls in
   cases.c stay real calls and keep values live across them, which is what makes MSVC save
   callee-saved registers in a prologue. */
#include "repro.h"

static int g_sink;

REPRO_API int h_safety(Db *db) { return db->magic == 0xa029a697u || db->magic == 0xf03b7906u; }
REPRO_API int h_misuse(int line) { g_sink += line; return 21; }
REPRO_API void *h_alloc(Ctx *c, long long n) { static char buf[256]; c->rc = (int)n; return n < 256 ? buf : 0; }
REPRO_API void h_free(void *p) { g_sink += (p != 0); }
REPRO_API int h_utf8(const char **pz) { int v = (unsigned char)**pz; (*pz)++; return v; }
REPRO_API void h_result(Ctx *c, char *z, int n) { c->rc = n; g_sink += z[0]; }
REPRO_API void h_error(Ctx *c, const char *msg) { c->rc = 1; g_sink += msg[0]; }
REPRO_API int h_cmp(const Value *a, const Value *b) { return a->n - b->n; }
REPRO_API void h_append(Ctx *c, const char *z, int n) { c->rc += n; g_sink += z[0]; }
REPRO_API double h_julian(const Value *v) { return (double)v->n * 0.5; }
REPRO_API void h_fatal(const char *msg) { g_sink += msg[0]; for (;;) { } }

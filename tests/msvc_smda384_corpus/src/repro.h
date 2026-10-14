/* Minimal reproducer for danielplohmann/smda#384: function shapes MSVC lays out with an
   early-exit check before the prologue (arm64 shrink-wrapping) or with blocks after a ret
   that only a conditional branch reaches. The shapes follow sqlite 3.53.4 functions SMDA
   split in an MSVC /O2 build (unistrFunc, groupConcatStep, strftimeFunc, sqlite3_errcode,
   exprImpliesNotNull, json5Whitespace); the code is written for this test. */
#ifndef REPRO_H
#define REPRO_H

#define REPRO_API __declspec(dllexport)

typedef struct Db {
  unsigned magic;
  int errCode;
  int errMask;
  unsigned char mallocFailed;
} Db;

typedef struct Value {
  unsigned short flags;
  int n;
  const char *z;
} Value;

typedef struct Ctx {
  Db *db;
  Value *out;
  int rc;
} Ctx;

REPRO_API int h_safety(Db *db);
REPRO_API int h_misuse(int line);
REPRO_API void *h_alloc(Ctx *c, long long n);
REPRO_API void h_free(void *p);
REPRO_API int h_utf8(const char **pz);
REPRO_API void h_result(Ctx *c, char *z, int n);
REPRO_API void h_error(Ctx *c, const char *msg);
REPRO_API int h_cmp(const Value *a, const Value *b);
REPRO_API void h_append(Ctx *c, const char *z, int n);
REPRO_API double h_julian(const Value *v);
REPRO_API __declspec(noreturn) void h_fatal(const char *msg);

#endif

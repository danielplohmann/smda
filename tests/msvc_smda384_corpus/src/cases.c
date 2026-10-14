/* Cases for smda#384. The map and PDB name every function. Pattern A: an early-exit check
   before work that needs callee-saved registers (arm64: the check is placed before
   `stp x19, x20, [sp, #-N]!`). The A functions are static and reached only through the
   function table at the end, as sqlite's built-in SQL functions are, so without a PDB SMDA
   has no export or call to their true entry. Pattern B: several returns, so blocks follow a
   ret and are reached only by a conditional branch; the B functions are exported. */
#include "repro.h"

static const unsigned char aType[64] = {
    5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1,
    2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3,
    4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3};

/* A1, as sqlite3_errcode: a null check returns a constant before the prologue. */
static int case_a1_errcode(Db *db) {
  if (!db) return 7;
  if (!h_safety(db)) return h_misuse(__LINE__);
  if (db->mallocFailed) return 7;
  return db->errCode & db->errMask;
}

/* A2, as unistrFunc: `if (argv[0] == 0) return;` (ldr x3, [x2]; cbz x3) before the body. */
static void case_a2_unistr(Ctx *ctx, int argc, Value **argv) {
  const char *zIn;
  char *zOut;
  int i, j, n;
  (void)argc;
  if (argv[0] == 0) return;
  zIn = argv[0]->z;
  n = argv[0]->n;
  zOut = (char *)h_alloc(ctx, (long long)n + 1);
  if (zOut == 0) return;
  for (i = j = 0; i < n; i++) {
    char c = zIn[i];
    if (c == '\\' && i + 1 < n) {
      zOut[j++] = (char)h_utf8(&zIn);
      i++;
    } else {
      zOut[j++] = c;
    }
  }
  zOut[j] = 0;
  h_result(ctx, zOut, j);
  h_free(zOut);
}

/* A3, as groupConcatStep: a table lookup on the first argument's type decides the exit. */
static void case_a3_concat(Ctx *ctx, int argc, Value **argv) {
  const char *zSep = ",";
  int nSep = 1;
  if (aType[argv[0]->flags & 0x3f] == 5) return;
  if (argc == 2) {
    zSep = argv[1]->z;
    nSep = argv[1]->n;
  }
  if (ctx->rc > 0) h_append(ctx, zSep, nSep);
  h_append(ctx, argv[0]->z, argv[0]->n);
  if (ctx->rc > 1000) h_error(ctx, "too long");
}

/* A4, as strftimeFunc: `if (argc == 0) return;` (cbz w1) before a body with a double live. */
static void case_a4_strftime(Ctx *ctx, int argc, Value **argv) {
  double jd;
  int i, n;
  char buf[64];
  if (argc == 0) return;
  jd = h_julian(argv[0]);
  n = argv[0]->n;
  for (i = 0; i < n && i < 63; i++) {
    char c = argv[0]->z[i];
    buf[i] = c == '%' ? (char)('0' + (int)jd % 10) : c;
    if (c == 'J') jd = h_julian(argv[i % argc]);
  }
  buf[i] = 0;
  h_result(ctx, buf, i);
}

/* B1, as exprImpliesNotNull: a switch with returns in most arms and a recursive tail. */
REPRO_API int case_b1_implies(const Value *p, int iTab, const Value *q) {
  while (p) {
    switch (p->flags & 0xff) {
      case 1:
        return 0;
      case 2:
        if (p->n == iTab) return 1;
        p = p + 1;
        break;
      case 3:
      case 4:
        if (h_cmp(p, q) == 0) return 1;
        return case_b1_implies(p + 1, iTab, q);
      case 5:
        return p->n > iTab ? case_b1_implies(p + 2, iTab, q) : 0;
      case 6:
        if (q && h_cmp(q, p) > 0) return case_b1_implies(q, iTab, 0);
        p = p->z ? (const Value *)p->z : 0;
        break;
      default:
        return h_cmp(q, p) < 0;
    }
  }
  return 0;
}

/* B2, as json5Whitespace: a scanning loop over characters with returns inside the cases. */
REPRO_API int case_b2_whitespace(const unsigned char *z) {
  int n = 0;
  for (;;) {
    switch (z[n]) {
      case 0x09:
      case 0x0a:
      case 0x0b:
      case 0x0c:
      case 0x0d:
      case 0x20:
        n++;
        break;
      case '/':
        if (z[n + 1] == '*' && z[n + 2] != 0) {
          int j;
          for (j = n + 3; z[j] != '/' || z[j - 1] != '*'; j++) {
            if (z[j] == 0) return n;
          }
          n = j + 1;
          break;
        } else if (z[n + 1] == '/') {
          int j;
          for (j = n + 2; z[j] != 0 && z[j] != '\n'; j++) {
          }
          n = j;
          break;
        }
        return n;
      case 0xc2:
        if (z[n + 1] == 0xa0) {
          n += 2;
          break;
        }
        return n;
      case 0xe2:
        if (z[n + 1] == 0x80 && (z[n + 2] == 0xa8 || z[n + 2] == 0xa9)) {
          n += 3;
          break;
        }
        return n;
      default:
        return n;
    }
  }
}

/* B3, as winFileControl: a big switch over an opcode, each arm returning, plus a cold error
   path that calls a noreturn helper (arm64: brk after the call). */
REPRO_API int case_b3_control(Ctx *ctx, int op, Value *arg) {
  switch (op) {
    case 1:
      if (!arg) return 12;
      ctx->rc = arg->n;
      return 0;
    case 4:
      if (arg && arg->n < 0) h_fatal("negative");
      return h_cmp(arg, ctx->out);
    case 5:
      h_append(ctx, arg->z, arg->n);
      return ctx->rc > 100 ? 13 : 0;
    case 6:
      ctx->out = arg;
      return 0;
    case 9:
      if (ctx->db && !h_safety(ctx->db)) return h_misuse(__LINE__);
      return ctx->db ? ctx->db->errCode : 1;
    case 11:
      h_error(ctx, "unsupported");
      return 1;
    default:
      return 12;
  }
}

/* B4, as analyzeAggregate: nested ifs with an early return in the middle of the body. */
REPRO_API int case_b4_aggregate(Ctx *ctx, Value *p, int iAgg) {
  int i;
  if (p->flags & 0x100) {
    for (i = 0; i < iAgg; i++) {
      if (p[i].n == iAgg) {
        ctx->rc = i;
        return 1;
      }
    }
    if (iAgg > 8) h_error(ctx, "too many");
    p->flags |= 0x200;
    return 2;
  }
  if (p->flags & 0x400) return 0;
  h_append(ctx, p->z, p->n);
  return ctx->rc == 0;
}

/* A5 / A6, the exact order of sqlite3_errcode, which MSVC arm64 lays out as
   `cbnz x0, body; mov w0, #7; ret; body: stp ...`: exported (A5) and static (A6). */
REPRO_API int case_a5_errcode(Db *db) {
  if (db && !h_safety(db)) return h_misuse(__LINE__);
  if (!db || db->mallocFailed) return 7;
  return db->errCode & db->errMask;
}

static int case_a6_errcode(Db *db) {
  if (db && !h_safety(db)) return h_misuse(__LINE__ + 1000);
  if (!db || db->mallocFailed) return 7;
  return db->errCode ^ db->errMask;
}

/* The function table: the only reference to the static A functions. */
typedef struct FuncDef {
  const char *zName;
  void (*xFunc)(Ctx *, int, Value **);
  int (*xCode)(Db *);
} FuncDef;

static const FuncDef aFunc[] = {
    {"unistr", case_a2_unistr, 0},
    {"group_concat", case_a3_concat, 0},
    {"strftime", case_a4_strftime, 0},
    {"errcode", 0, case_a1_errcode},
    {"errcode2", 0, case_a6_errcode},
};

REPRO_API const FuncDef *repro_functions(int *pn) {
  *pn = (int)(sizeof(aFunc) / sizeof(aFunc[0]));
  return aFunc;
}

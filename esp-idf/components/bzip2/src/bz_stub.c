/* With BZ_NO_STDIO the application must supply bz_internal_error (the
 * stdio default in bzlib.c is compiled out). It fires only on a genuine
 * internal inconsistency — a bug or memory corruption, never on malformed
 * input (decompress reports bad streams via BZ_DATA_ERROR return codes, and
 * the only callers are compress-side, over our own data). Abort so the
 * panic handler reboots rather than continuing in a corrupt state. */
#include <stdlib.h>

void bz_internal_error(int errcode);

void bz_internal_error(int errcode)
{
    (void)errcode;
    abort();
}

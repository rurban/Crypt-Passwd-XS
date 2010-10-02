#include "md5.h"

static void
MD5Init(MD5_CTX *ctx)
{
  /* Start state */
  ctx->A = 0x67452301;
  ctx->B = 0xefcdab89;
  ctx->C = 0x98badcfe;
  ctx->D = 0x10325476;

  /* message length */
  ctx->bytes_low = ctx->bytes_high = 0;
}

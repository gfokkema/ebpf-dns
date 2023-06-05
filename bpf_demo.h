#pragma once

#include "common.h"

static __always_inline
void cursor_init(struct cursor *c, struct __sk_buff *ctx)
{
    c->end = (void *)(long)ctx->data_end;
    c->pos = (void *)(long)ctx->data;
}
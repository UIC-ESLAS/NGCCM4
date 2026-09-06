/*
 * Keep the historical test target, but exercise the maintained public
 * polynomial interface.  The old test depended on removed private block
 * helpers and an obsolete twiddle-table name, so it no longer linked against
 * any current ZEN/DAWN Cortex-M4 backend.
 */
#define ZENM4SPEED_ITERS 1u
#include "zenm4speed.c"

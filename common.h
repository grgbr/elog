#ifndef _ELOG_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "elog/elog.h"

#if defined(CONFIG_ELOG_ASSERT)

#include <utils/assert.h>

#define elog_assert(_expr) \
	uassert("elog", _expr)

#else  /* !defined(CONFIG_ELOG_ASSERT) */

#define elog_assert(_expr) \
	do { } while (0)

#endif /* defined(CONFIG_ELOG_ASSERT) */

#endif /* _ELOG_COMMON_H */

/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLog.
 * Copyright (C) 2017-2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOG_COMMON_H
#define _ELOG_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "elog/elog.h"

#if defined(CONFIG_ELOG_ASSERT)

#include <stroll/assert.h>

#define elog_assert(_expr) \
	stroll_assert("elog", _expr)

#else  /* !defined(CONFIG_ELOG_ASSERT) */

#define elog_assert(_expr) \
	do { } while (0)

#endif /* defined(CONFIG_ELOG_ASSERT) */

#endif /* _ELOG_COMMON_H */

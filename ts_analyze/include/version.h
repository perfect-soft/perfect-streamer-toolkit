/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * version.h — single source of truth for the ts_analyze version string.
 *
 * Bump VERSION here for any user-visible release; all banners, usage text
 * and report headers pick it up automatically.
 */

#define TS_ANALYZE_VERSION "2.5"

inline const char *ts_analyze_version()
{
    return TS_ANALYZE_VERSION;
}

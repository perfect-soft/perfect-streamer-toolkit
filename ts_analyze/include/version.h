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

#define TS_ANALYZE_VERSION "2.6.2"

// The attribution line of NOTICE; the XML root and the JSON object carry it too.
#define TS_ANALYZE_TOOLKIT "Perfect Streamer Toolkit by Perfect Soft — https://meshwork.pstreamer.tv"

inline const char *ts_analyze_version()
{
    return TS_ANALYZE_VERSION;
}

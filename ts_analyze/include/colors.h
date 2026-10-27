/*
 * Copyright 2026 Perfect Soft
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
/*
 * colors.h — ANSI color helpers for status output (PASS / WARN / ERROR / FAIL).
 *
 * Colors are enabled by default. Disable globally by setting Color::enabled = false
 * (e.g. in response to the --no-color CLI option).
 */

#include <string>
#include <sstream>
#include <iomanip>

namespace Color
{

// Master switch — set to false to suppress all color escape codes.
inline bool enabled = true;

// ANSI escape codes
constexpr const char *RESET  = "\033[0m";
constexpr const char *RED    = "\033[31m";
constexpr const char *GREEN  = "\033[32m";
constexpr const char *YELLOW = "\033[33m";

// Wrap text in a color code (no-op if colors disabled or code is null).
inline std::string wrap(const char *code, const std::string &text)
{
    if (!enabled || !code) return text;
    return std::string(code) + text + RESET;
}

// Render `text` padded to `width` characters via std::setw, then colorize.
// Padding spaces are inside the color escape — that is harmless (a space has
// no visible color), but ensures that std::setw/std::left applied at the
// caller will see the visually-correct width because the returned string
// already contains the padding.
inline std::string padded(const char *code, const std::string &text, int width, bool left_align = false)
{
    std::ostringstream tmp;
    if (left_align) tmp << std::left;
    tmp << std::setw(width) << text;
    return wrap(code, tmp.str());
}

} // namespace Color

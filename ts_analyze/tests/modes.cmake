# Copyright 2026 Perfect Soft
# SPDX-License-Identifier: Apache-2.0
# The OVERALL verdict and the exit code must not depend on the report mode:
# a clean stream exits 0 and a stream without SDT/EIT exits 65 in the short,
# full and XML reports alike.
# cmake -DBIN=<ts_analyze> -DOUT=<dir> -P modes.cmake
find_package(Python3 REQUIRED COMPONENTS Interpreter)
file(MAKE_DIRECTORY "${OUT}")

foreach(case clean nosi)
    set(ts "${OUT}/${case}.ts")
    if(case STREQUAL "nosi")
        set(gen_args --no-si)
        set(want 65)
    else()
        set(gen_args)
        set(want 0)
    endif()
    execute_process(
        COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_LIST_DIR}/gen_ts.py"
                ${gen_args} "${ts}" 5
        RESULT_VARIABLE rc)
    if(NOT rc EQUAL 0)
        message(FATAL_ERROR "gen_ts.py ${case} failed: ${rc}")
    endif()
    foreach(mode -s -f --xml)
        execute_process(
            COMMAND "${BIN}" ${mode} --no-color -b 2 "${ts}"
            RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_QUIET)
        if(NOT rc EQUAL want)
            message(FATAL_ERROR "${case} ${mode}: exit ${rc}, want ${want}\n${out}")
        endif()
    endforeach()
endforeach()
message(STATUS "modes OK")

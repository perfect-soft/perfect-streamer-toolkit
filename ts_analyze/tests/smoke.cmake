# Copyright 2026 Perfect Soft
# SPDX-License-Identifier: Apache-2.0
# Smoke test: generate a clean synthetic TS file, analyse it, and check that
# the program, its PCR PID and a clean Priority 1 verdict are reported.
# cmake -DBIN=<ts_analyze> -DOUT=<dir> -P smoke.cmake
find_package(Python3 REQUIRED COMPONENTS Interpreter)
file(MAKE_DIRECTORY "${OUT}")
set(ts "${OUT}/smoke.ts")

execute_process(
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_LIST_DIR}/gen_ts.py" "${ts}" 5
    RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "gen_ts.py failed: ${rc}")
endif()

execute_process(
    COMMAND "${BIN}" --xml -b 2 "${ts}"
    RESULT_VARIABLE rc OUTPUT_VARIABLE xml ERROR_VARIABLE err)
file(WRITE "${OUT}/smoke.xml" "${xml}")
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "ts_analyze exited ${rc}: ${err}")
endif()

# The generator makes every applicable check clean; check the discovered
# program, the main P1/P2 checks and the overall verdict (exit code 0).
set(EXPECT
    [[<program number="1" pmt_pid="0x0100" pcr_pid="0x0101">]]
    [[<check id="1.1" name="TS Sync Byte Error" applicable="true" errors="0" result="PASS"/>]]
    [[<check id="1.3" name="PAT Error" applicable="true" errors="0" result="PASS"/>]]
    [[<check id="1.4" name="Continuity Count Error" applicable="true" errors="0" result="PASS"/>]]
    [[<check id="1.5" name="PMT Error" applicable="true" errors="0" result="PASS"/>]]
    [[<check id="2.2" name="CRC Error" applicable="true" errors="0" result="PASS"/>]]
    [[<check id="2.3" name="PCR Repetition Error" applicable="true" errors="0" result="PASS"]]
    [[<check id="2.6" name="PTS Error" applicable="true" errors="0" result="PASS"/>]]
    [[<overall result="PASS"/>]])
foreach(want IN LISTS EXPECT)
    string(FIND "${xml}" "${want}" pos)
    if(pos EQUAL -1)
        message(FATAL_ERROR "missing in XML report: ${want}\n${xml}")
    endif()
endforeach()
message(STATUS "smoke OK")

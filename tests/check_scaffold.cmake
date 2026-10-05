# Verify that the scaffold CLI fails explicitly instead of pretending to work.
#
# Usage: cmake -DEXECUTABLE=<path to cvault-cli> -P check_scaffold.cmake
execute_process(
    COMMAND "${EXECUTABLE}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
    TIMEOUT 5)

if(NOT result STREQUAL "1" OR NOT error MATCHES "not implemented")
    message(FATAL_ERROR
        "Expected an explicit scaffold failure. "
        "Exit: ${result}; stdout: ${output}; stderr: ${error}")
endif()

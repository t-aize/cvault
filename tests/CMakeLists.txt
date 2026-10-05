add_executable(cvault-test-core test_core.c)
target_link_libraries(cvault-test-core PRIVATE cvault_core cvault_options)
cvault_copy_runtime(cvault-test-core)
add_test(NAME core_smoke COMMAND cvault-test-core)

add_executable(cvault-test-hashtable test_hashtable.c)
target_link_libraries(cvault-test-hashtable PRIVATE cvault_core cvault_options)
cvault_copy_runtime(cvault-test-hashtable)
add_test(NAME hashtable COMMAND cvault-test-hashtable)
set_tests_properties(hashtable PROPERTIES TIMEOUT 30)

# Compile the real implementation with private allocation/hash redirects.
# Production targets retain the normal allocator and keyed SipHash.
add_executable(cvault-test-hashtable-faults
    test_hashtable_faults.c hashtable_under_test.c ../src/crypto.c)
target_include_directories(cvault-test-hashtable-faults PRIVATE ../include)
target_link_libraries(cvault-test-hashtable-faults PRIVATE Sodium::Sodium cvault_options)
cvault_copy_runtime(cvault-test-hashtable-faults)
add_test(NAME hashtable_faults COMMAND cvault-test-hashtable-faults)
set_tests_properties(hashtable_faults PROPERTIES TIMEOUT 30)

add_executable(cvault-test-sodium test_sodium.c)
target_link_libraries(cvault-test-sodium PRIVATE cvault_core Sodium::Sodium cvault_options)
cvault_copy_runtime(cvault-test-sodium)
add_test(NAME sodium_dependency COMMAND cvault-test-sodium)

add_executable(cvault-network-fixture network_fixture.c)
target_link_libraries(cvault-network-fixture PRIVATE cvault_core cvault_options)
cvault_copy_runtime(cvault-network-fixture)
add_test(NAME network_api COMMAND cvault-network-fixture --api-tests)
set_tests_properties(network_api PROPERTIES TIMEOUT 15)

option(CVAULT_REQUIRE_NETWORK_TESTS "Require Python for TCP, persistence and security integration tests" OFF)
add_executable(cvault-persistence-fixture persistence_fixture.c)
target_link_libraries(cvault-persistence-fixture PRIVATE cvault_core cvault_options)
cvault_copy_runtime(cvault-persistence-fixture)
add_executable(cvault-persistence-faults persistence_fixture.c persist_under_test.c persist_codec_under_test.c)
target_compile_definitions(cvault-persistence-faults PRIVATE CV_PERSIST_FAULT_TEST)
target_include_directories(cvault-persistence-faults PRIVATE ../src)
target_link_libraries(cvault-persistence-faults PRIVATE cvault_core Sodium::Sodium cvault_options)
cvault_copy_runtime(cvault-persistence-faults)
add_executable(cvault-test-persistence-codec test_persistence_codec.c)
target_include_directories(cvault-test-persistence-codec PRIVATE ../src)
target_link_libraries(cvault-test-persistence-codec PRIVATE cvault_core cvault_options)
cvault_copy_runtime(cvault-test-persistence-codec)
add_test(NAME persistence_codec COMMAND cvault-test-persistence-codec)
set_tests_properties(persistence_codec PROPERTIES TIMEOUT 15)
if(WIN32)
    find_program(CVAULT_POWERSHELL NAMES pwsh powershell REQUIRED)
    add_test(NAME bootstrap_windows_download
        COMMAND "${CVAULT_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass -File
            "${CMAKE_CURRENT_SOURCE_DIR}/test_bootstrap_windows.ps1")
    set_tests_properties(bootstrap_windows_download PROPERTIES TIMEOUT 30)
endif()
add_executable(cvault-security-fixture security_fixture.c audit_under_test.c)
target_include_directories(cvault-security-fixture PRIVATE ../src)
target_link_libraries(cvault-security-fixture PRIVATE cvault_core Sodium::Sodium cvault_options)
cvault_copy_runtime(cvault-security-fixture)

find_package(Python3 3.12 QUIET COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(NAME security
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/test_security.py"
            --server "$<TARGET_FILE:cvault-server>" --fixture "$<TARGET_FILE:cvault-security-fixture>")
    set_tests_properties(security PROPERTIES TIMEOUT 120)
    add_test(NAME bootstrap_download
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/test_bootstrap.py")
    set_tests_properties(bootstrap_download PROPERTIES TIMEOUT 15)
    add_test(NAME persistence
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/test_persistence.py"
            --fixture "$<TARGET_FILE:cvault-persistence-fixture>"
            --faults "$<TARGET_FILE:cvault-persistence-faults>" --server "$<TARGET_FILE:cvault-server>")
    set_tests_properties(persistence PROPERTIES TIMEOUT 120)
    set(network_backends poll)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        list(APPEND network_backends epoll)
    endif()
    foreach(backend IN LISTS network_backends)
        add_test(NAME network_${backend}
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/test_network.py"
                --fixture "$<TARGET_FILE:cvault-network-fixture>"
                --server "$<TARGET_FILE:cvault-server>" --backend "${backend}")
        set_tests_properties(network_${backend} PROPERTIES TIMEOUT 90)
    endforeach()
elseif(CVAULT_REQUIRE_NETWORK_TESTS)
    message(FATAL_ERROR "TCP/persistence/security integration tests require Python 3.12+; set Python3_EXECUTABLE.")
else()
    message(STATUS "Python 3.12+ unavailable: TCP/persistence/security integration tests skipped; network_api remains enabled.")
endif()

add_test(NAME server_help COMMAND cvault-server --help)
add_test(NAME cli_help COMMAND cvault-cli --help)
set_tests_properties(server_help PROPERTIES PASS_REGULAR_EXPRESSION "TCP transport")
set_tests_properties(cli_help PROPERTIES PASS_REGULAR_EXPRESSION "Project scaffold")
foreach(program IN ITEMS cvault-cli)
    add_test(NAME "${program}_scaffold_guard"
        COMMAND "${CMAKE_COMMAND}" "-DEXECUTABLE=$<TARGET_FILE:${program}>"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/check_scaffold.cmake")
endforeach()
set_tests_properties(core_smoke sodium_dependency server_help cli_help
    cvault-cli_scaffold_guard PROPERTIES TIMEOUT 10)

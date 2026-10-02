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

add_test(NAME server_help COMMAND cvault-server --help)
add_test(NAME cli_help COMMAND cvault-cli --help)
set_tests_properties(server_help cli_help PROPERTIES PASS_REGULAR_EXPRESSION "Project scaffold")
foreach(program IN ITEMS cvault-server cvault-cli)
    add_test(NAME "${program}_scaffold_guard"
        COMMAND "${CMAKE_COMMAND}" "-DEXECUTABLE=$<TARGET_FILE:${program}>"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/check_scaffold.cmake")
endforeach()
set_tests_properties(core_smoke sodium_dependency server_help cli_help
    cvault-server_scaffold_guard cvault-cli_scaffold_guard PROPERTIES TIMEOUT 10)

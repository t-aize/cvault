# Prefer an explicit prefix, then the local bootstrap, then system paths.
set(SODIUM_ROOT "$ENV{SODIUM_ROOT}" CACHE PATH "libsodium installation prefix (include/ and lib/)")
if(NOT SODIUM_ROOT AND WIN32 AND EXISTS "${PROJECT_SOURCE_DIR}/.deps/paths.json")
    file(READ "${PROJECT_SOURCE_DIR}/.deps/paths.json" _sodium_local_paths)
    if(MSVC)
        set(_sodium_local_key msvcSodiumRoot)
    elseif(MINGW)
        set(_sodium_local_key sodiumRoot)
    endif()
    if(_sodium_local_key)
        string(JSON _sodium_local_root ERROR_VARIABLE _sodium_local_error
            GET "${_sodium_local_paths}" "${_sodium_local_key}")
        if(NOT _sodium_local_error AND _sodium_local_root
                AND EXISTS "${_sodium_local_root}/include/sodium.h")
            file(TO_CMAKE_PATH "${_sodium_local_root}" _sodium_local_root)
            set(SODIUM_ROOT "${_sodium_local_root}" CACHE PATH
                "libsodium installation prefix (include/ and lib/)" FORCE)
        endif()
    endif()
endif()
if(NOT SODIUM_ROOT)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(PC_SODIUM QUIET libsodium)
    endif()
endif()
find_path(Sodium_INCLUDE_DIR NAMES sodium.h
    HINTS "${SODIUM_ROOT}/include" ${PC_SODIUM_INCLUDE_DIRS})
if(MSVC AND EXISTS "${SODIUM_ROOT}/x64/Release/v143/static/libsodium.lib")
    # Official stable MSVC archive: non-LTCG static libraries, compatible with VS 2026.
    set(Sodium_LIBRARY "${SODIUM_ROOT}/x64/Release/v143/static/libsodium.lib")
    set(Sodium_LIBRARY_DEBUG "${SODIUM_ROOT}/x64/Debug/v143/static/libsodium.lib")
    set(_sodium_static TRUE)
elseif(MINGW AND SODIUM_ROOT)
    # Use the official DLL and its import library to preserve upstream CRT compatibility.
    find_library(_sodium_import_library NAMES libsodium.dll.a
        PATHS "${SODIUM_ROOT}/lib" NO_DEFAULT_PATH NO_CACHE)
    set(Sodium_LIBRARY "${_sodium_import_library}")
    find_file(Sodium_RUNTIME_DLL NAMES libsodium-26.dll
        PATHS "${SODIUM_ROOT}/bin" NO_DEFAULT_PATH)
else()
    find_library(Sodium_LIBRARY NAMES sodium libsodium
        HINTS "${SODIUM_ROOT}/lib" ${PC_SODIUM_LIBRARY_DIRS})
endif()
if(Sodium_INCLUDE_DIR AND EXISTS "${Sodium_INCLUDE_DIR}/sodium/version.h")
    file(STRINGS "${Sodium_INCLUDE_DIR}/sodium/version.h" _sodium_version_line
        REGEX "^#define SODIUM_VERSION_STRING")
    string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" Sodium_VERSION "${_sodium_version_line}")
endif()
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sodium
    REQUIRED_VARS Sodium_INCLUDE_DIR Sodium_LIBRARY VERSION_VAR Sodium_VERSION
    REASON_FAILURE_MESSAGE "Install libsodium-dev (Linux), run scripts/bootstrap-windows.ps1 (CLion MinGW x64), or set SODIUM_ROOT.")
if(Sodium_FOUND AND NOT TARGET Sodium::Sodium)
    add_library(Sodium::Sodium UNKNOWN IMPORTED)
    set_target_properties(Sodium::Sodium PROPERTIES
        IMPORTED_LOCATION "${Sodium_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${Sodium_INCLUDE_DIR}")
    if(Sodium_LIBRARY_DEBUG)
        set_target_properties(Sodium::Sodium PROPERTIES
            IMPORTED_CONFIGURATIONS "DEBUG;RELEASE"
            IMPORTED_LOCATION_DEBUG "${Sodium_LIBRARY_DEBUG}"
            IMPORTED_LOCATION_RELEASE "${Sodium_LIBRARY}"
            MAP_IMPORTED_CONFIG_RELWITHDEBINFO Release
            MAP_IMPORTED_CONFIG_MINSIZEREL Release)
    endif()
    if(WIN32 AND (_sodium_static OR (Sodium_LIBRARY MATCHES "\\.a$" AND NOT Sodium_LIBRARY MATCHES "\\.dll\\.a$")))
        set_property(TARGET Sodium::Sodium PROPERTY INTERFACE_COMPILE_DEFINITIONS SODIUM_STATIC)
        set_property(TARGET Sodium::Sodium PROPERTY INTERFACE_LINK_LIBRARIES bcrypt)
    endif()
endif()
mark_as_advanced(Sodium_INCLUDE_DIR Sodium_LIBRARY)

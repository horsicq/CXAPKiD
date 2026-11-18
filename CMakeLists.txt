cmake_minimum_required(VERSION 3.21)

# CXAPKiD - a C port of APKiD (https://github.com/rednaga/APKiD).
# Uses only xxyara (YARA-X in C) and xxfclib; no other third-party code.
project(CXAPKiD VERSION 1.0.0 DESCRIPTION "C port of APKiD, the Android Application Identifier" LANGUAGES C)

include(CTest)
include(GNUInstallDirs)

# The APKiD release whose scanner logic and rules this port follows.
set(CXAPKID_APKID_VERSION "3.2.0")

foreach(_library xxyara xxfclib)
    string(TOUPPER "${_library}" _upper)
    set(_default "${CMAKE_CURRENT_SOURCE_DIR}/dep/${_library}")
    if(NOT EXISTS "${_default}/CMakeLists.txt")
        set(_default "${CMAKE_CURRENT_SOURCE_DIR}/../_mylibs/${_library}")
    endif()
    set(CXAPKID_${_upper}_DIR "${_default}" CACHE PATH "Location of the ${_library} source tree")
    get_filename_component(CXAPKID_${_upper}_DIR "${CXAPKID_${_upper}_DIR}" ABSOLUTE)
    if(NOT EXISTS "${CXAPKID_${_upper}_DIR}/CMakeLists.txt")
        message(FATAL_ERROR "${_library} was not found. Set CXAPKID_${_upper}_DIR to its source directory.")
    endif()
endforeach()

# xxfclib's bzip2 and LZMA decoders have MASM kernels on MSVC; enable the
# language before any target that compiles them is created.
set(CXAPKID_MSVC_ARCH "")
if(MSVC)
    if(CMAKE_C_COMPILER_ARCHITECTURE_ID MATCHES "^(x64|AMD64)$")
        set(CXAPKID_MSVC_ARCH x64)
        enable_language(ASM_MASM)
    elseif(CMAKE_C_COMPILER_ARCHITECTURE_ID MATCHES "^(X86|x86)$")
        set(CXAPKID_MSVC_ARCH x86)
        enable_language(ASM_MASM)
    endif()
endif()

# xxyara builds the focused set of xxfclib components its scanner needs.
# The application owns its console; dependency tools and tests stay disabled.
function(cxapkid_add_dependencies)
    set(XXYARA_BUILD_CLI OFF CACHE BOOL "Build the dependency console" FORCE)
    set(XXYARA_BUILD_TESTS OFF CACHE BOOL "Build the dependency tests" FORCE)
    set(XXYARA_XXFCLIB_SOURCE_DIR "${CXAPKID_XXFCLIB_DIR}" CACHE PATH "xxfclib used by xxyara" FORCE)
    add_subdirectory("${CXAPKID_XXYARA_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/deps/xxyara" EXCLUDE_FROM_ALL)
endfunction()
cxapkid_add_dependencies()

# APKiD reads ZIP members with Python's zipfile: stored, Deflate, bzip2 and
# LZMA, plus XZ for method 95 (xxfclib's xx_zip_py). xxyara's closure has
# Deflate, CRC and SHA; add xxfclib's zipfile-exact reader, YARA 3.11's legacy
# dex values (xx_dex_legacy), the bzip2 and LZMA codecs and the file-system
# API to the same library.
set(_cxapkid_xxfclib_extra
    src/formats/archive/zip/xx_zip_py.c
    src/formats/executable/dex/xx_dex_legacy.c
    src/algo/bzip2/xx_bzip2.c
    src/algo/bzip2/xx_bzip2_bwt.c
    src/algo/bzip2/xx_bzip2_dec.c
    src/algo/bzip2/xx_bzip2_enc.c
    src/algo/bzip2/xx_bzip2_huffman.c
    src/algo/bzip2/xx_bzip2_mtf.c
    src/algo/lzma/xx_lzma.c
    src/algo/lzma/xx_lzma2_filters.c
    src/algo/lzma/xx_lzma_dec.c
    src/algo/lzma/xx_lzma_enc.c
    src/algo/lzma/xx_lzma_stream.c
    src/algo/lzma/platforms/xx_lzma_avx2.c
    src/algo/lzma/platforms/xx_lzma_neon.c
    src/algo/lzma/platforms/xx_lzma_sse2.c
    src/buf/xx_buf.c
    src/fs/xx_fs.c
    src/list/xx_list.c
    src/sort/xx_sort.c
    src/sort/platforms/xx_sort_avx2.c
    src/sort/platforms/xx_sort_neon.c
    src/sort/platforms/xx_sort_sse2.c)
if(WIN32)
    list(APPEND _cxapkid_xxfclib_extra
        src/fs/platforms/xx_fs_windows.c
        src/sort/platforms/xx_sort_windows.c)
else()
    list(APPEND _cxapkid_xxfclib_extra
        src/fs/platforms/xx_fs_posix.c
        src/sort/platforms/xx_sort_posix.c)
endif()
if(CXAPKID_MSVC_ARCH STREQUAL "x64")
    list(APPEND _cxapkid_xxfclib_extra
        src/algo/lzma/asm/lzma_windows_x64.asm
        src/algo/bzip2/asm/bzip2_windows_x64.asm)
elseif(CXAPKID_MSVC_ARCH STREQUAL "x86")
    list(APPEND _cxapkid_xxfclib_extra src/algo/bzip2/asm/bzip2_windows_x86.asm)
endif()
if(TARGET xxyara_xxfclib)
    get_target_property(_cxapkid_existing xxyara_xxfclib SOURCES)
    set(_cxapkid_added)
    foreach(_source IN LISTS _cxapkid_xxfclib_extra)
        set(_path "${CXAPKID_XXFCLIB_DIR}/${_source}")
        if(NOT EXISTS "${_path}")
            file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/xxfclib-revision.txt"
                _cxapkid_xxfclib_revision LIMIT_COUNT 1)
            message(FATAL_ERROR "xxfclib source file is missing: ${_path}\n"
                "CXAPKiD uses xxfclib revision ${_cxapkid_xxfclib_revision}.\n"
                "Update the checkout with git submodule update --init --recursive, "
                "or set CXAPKID_XXFCLIB_DIR to a compatible source tree.")
        endif()
        if(NOT _path IN_LIST _cxapkid_existing)
            list(APPEND _cxapkid_added "${_path}")
        endif()
    endforeach()
    target_sources(xxyara_xxfclib PRIVATE ${_cxapkid_added})
    # The sort kernels dispatch at run time; their AVX2 unit needs the ISA.
    set(_cxapkid_sort_avx2 "${CXAPKID_XXFCLIB_DIR}/src/sort/platforms/xx_sort_avx2.c")
    if(MSVC AND CXAPKID_MSVC_ARCH)
        set_source_files_properties("${_cxapkid_sort_avx2}" TARGET_DIRECTORY xxyara_xxfclib
            PROPERTIES COMPILE_OPTIONS /arch:AVX2)
    elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64|i[3-6]86)$")
        set_source_files_properties("${_cxapkid_sort_avx2}" TARGET_DIRECTORY xxyara_xxfclib
            PROPERTIES COMPILE_OPTIONS -mavx2)
    endif()
    if(CXAPKID_MSVC_ARCH STREQUAL "x86")
        set_source_files_properties("${CXAPKID_XXFCLIB_DIR}/src/algo/bzip2/asm/bzip2_windows_x86.asm"
            TARGET_DIRECTORY xxyara_xxfclib PROPERTIES COMPILE_OPTIONS /safeseh)
    endif()
elseif(NOT TARGET xxfclib::xxfclib)
    message(FATAL_ERROR "CXAPKiD needs xxyara's xxfclib closure or a complete xxfclib::xxfclib target")
endif()

add_executable(CXAPKiD
    src/main.c
    src/cx_common.c
    src/cx_output.c
    src/cx_rules.c
    src/cx_scan.c)
set_target_properties(CXAPKiD PROPERTIES
    OUTPUT_NAME cxapkid
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin")
target_include_directories(CXAPKiD PRIVATE src)
target_compile_definitions(CXAPKiD PRIVATE
    CXAPKID_VERSION="${PROJECT_VERSION}"
    CXAPKID_APKID_VERSION="${CXAPKID_APKID_VERSION}")
target_link_libraries(CXAPKiD PRIVATE xxyara::xxyara)
if(WIN32)
    target_link_libraries(CXAPKiD PRIVATE shell32)
    target_compile_definitions(CXAPKiD PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()
if(MSVC)
    target_compile_options(CXAPKiD PRIVATE /W4 /utf-8)
    # Complex rule conditions need more than Windows' default 1 MiB stack.
    target_link_options(CXAPKiD PRIVATE /STACK:8388608)
    target_compile_definitions(CXAPKiD PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(CXAPKiD PRIVATE -Wall -Wextra -Wpedantic)
    if(WIN32)
        # Same 8 MiB stack as the MSVC build (ld's default is 2 MiB).
        target_link_options(CXAPKiD PRIVATE -Wl,--stack,8388608)
    endif()
endif()

install(TARGETS CXAPKiD RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES README.md LICENSE DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/doc/CXAPKiD")
# Packaging prepares the external rules/ folder next to the executable.
# Install only notices available in the selected dependency checkouts.
foreach(_library xxyara xxfclib)
    string(TOUPPER "${_library}" _upper)
    file(GLOB _licenses LIST_DIRECTORIES false "${CXAPKID_${_upper}_DIR}/LICENSE*")
    if(_licenses)
        install(FILES ${_licenses} DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/doc/CXAPKiD/licenses/${_library}")
    endif()
endforeach()

if(BUILD_TESTING AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli.cmake")
    # The private source tree keeps adapted rule fixtures for the CLI suite.
    # Exported checkouts have neither tests/ nor rules/: only packaging stages
    # production rules, so a normal build never copies or embeds them.
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/rules")
        add_custom_command(TARGET CXAPKiD POST_BUILD
            COMMAND "${CMAKE_COMMAND}" -E copy_directory
                "${CMAKE_CURRENT_SOURCE_DIR}/rules" "$<TARGET_FILE_DIR:CXAPKiD>/rules"
            COMMENT "Staging rule fixtures for CLI tests"
            VERBATIM)
    endif()
    add_test(NAME cxapkid.cli
        COMMAND "${CMAKE_COMMAND}"
            "-DCXAPKID=$<TARGET_FILE:CXAPKiD>"
            "-DDATA=${CMAKE_CURRENT_SOURCE_DIR}/tests/data"
            "-DTEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/tests/cli"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli.cmake")
    set_tests_properties(cxapkid.cli PROPERTIES TIMEOUT 120)
    foreach(_regression path rules thread runtime_rules)
        if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/${_regression}_regressions.cmake")
            continue()
        endif()
        add_test(NAME cxapkid.${_regression}
            COMMAND "${CMAKE_COMMAND}"
                "-DCXAPKID=$<TARGET_FILE:CXAPKiD>"
                "-DDATA=${CMAKE_CURRENT_SOURCE_DIR}/tests/data"
                "-DTEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/tests/${_regression}"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/${_regression}_regressions.cmake")
        set_tests_properties(cxapkid.${_regression} PROPERTIES TIMEOUT 120)
    endforeach()
endif()

if(BUILD_TESTING AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/packaging_regressions.cmake")
    set(CXAPKID_APKID_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dep/APKiD" CACHE PATH
        "APKiD checkout used by the optional packaging regression test")
    get_filename_component(CXAPKID_APKID_DIR "${CXAPKID_APKID_DIR}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
    if(EXISTS "${CXAPKID_APKID_DIR}/apkid/rules" AND EXISTS "${CXAPKID_APKID_DIR}/LICENSE.GPL")
        # Python is only needed to assemble/test packages, never to run the scanner.
        find_package(Python3 QUIET COMPONENTS Interpreter)
        if(Python3_Interpreter_FOUND)
            add_test(NAME cxapkid.packaging
                COMMAND "${CMAKE_COMMAND}"
                    "-DCXAPKID=$<TARGET_FILE:CXAPKiD>"
                    "-DPYTHON=${Python3_EXECUTABLE}"
                    "-DAPKID_SOURCE=${CXAPKID_APKID_DIR}"
                    "-DTEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/tests/packaging"
                    -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/packaging_regressions.cmake")
            set_tests_properties(cxapkid.packaging PROPERTIES TIMEOUT 120)
        endif()
    endif()
endif()

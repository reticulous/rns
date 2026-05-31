# Vendored bzip2 1.0.8 (libarchive maintained mirror), decompress + compress.
# Only the buffer-to-buffer API is used (BZ2_bzBuffToBuff{Compress,Decompress});
# BZ_NO_STDIO drops the FILE-based bzopen/bzread/... so there is no stdio
# surface to drag in. Used by the µR Resource engine for NomadNet/Reticulum
# bz2-compressed Resource payloads (every client speaks bz2).
idf_component_register(
    SRCS
        "src/blocksort.c"
        "src/huffman.c"
        "src/crctable.c"
        "src/randtable.c"
        "src/compress.c"
        "src/decompress.c"
        "src/bzlib.c"
        "src/bz_stub.c"
    INCLUDE_DIRS "include"
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE BZ_NO_STDIO)

# Vendored third-party: quiet its (benign, modern-GCC) warnings and make sure
# they never trip the project's -Werror= categories. Component-PRIVATE flags
# win over IDF's forced -Werror= (same approach as the microreticulum fork).
target_compile_options(${COMPONENT_LIB} PRIVATE
    -w
    -Wno-error=implicit-fallthrough
    -Wno-error=maybe-uninitialized
    -Wno-error=unused-but-set-variable
    -Wno-error=sign-compare
    -Wno-error=stringop-truncation
    -Wno-error=format-truncation
    -Wno-error=switch
)

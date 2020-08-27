find_path(LIBZIP_ROOT_DIR
    NAMES include/libzip/libzip.h
)

find_library(LIBZIP_LIBRARIES
    NAMES libzip.so
    HINTS ${LIBZIP_ROOT_DIR}/lib
    PATH_SUFFIXES ${CMAKE_LIBRARY_ARCHITECTURE}
)

find_path(LIBZIP_INCLUDE_DIR
    NAMES zip.h
    HINTS ${LIBZIP_ROOT_DIR}/include/libzip
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libzip DEFAULT_MSG
    LIBZIP_LIBRARIES
    LIBZIP_INCLUDE_DIR
)

mark_as_advanced(
    LIBZIP_ROOT_DIR
    LIBZIP_LIBRARIES
    LIBZIP_INCLUDE_DIR
)


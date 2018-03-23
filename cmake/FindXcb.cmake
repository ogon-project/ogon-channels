#  LIBXCB_FOUND - system has libxcb
#  LIBXCB_LIBRARIES - Link these to use libxcb
#  LIBXCB_INCLUDE_DIR - the libxcb include dir
#  LIBXCB_CFLAGS - compiler switches required for using libxcb

if (LIBXCB_INCLUDE_DIR AND LIBXCB_LIBRARIES)
	# in cache already
	set(XCB_FIND_QUIETLY TRUE)
endif()

find_package(PkgConfig)
pkg_check_modules(PKG_XCB xcb)

set(LIBXCB_CFLAGS ${PKG_XCB_CFLAGS})

find_path(LIBXCB_INCLUDE_DIR xcb/xcb.h ${PKG_XCB_INCLUDE_DIRS})
find_library(LIBXCB_LIBRARIES NAMES xcb libxcb PATHS ${PKG_XCB_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(XCB DEFAULT_MSG LIBXCB_LIBRARIES LIBXCB_INCLUDE_DIR)

MARK_AS_ADVANCED(LIBXCB_INCLUDE_DIR LIBXCB_LIBRARIES XCBPROC_EXECUTABLE)

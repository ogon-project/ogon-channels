set(MODULE_NAME "rdpdr")

include(FindQT5)

if (UNIX)
	find_package(FUSE REQUIRED)
endif()

set(${MODULE_NAME}_SRCS
	rdpdr.cpp
	rdpdrchannelserver.cpp
	rdpdrchannelserver.h
        )

add_executable(${MODULE_NAME} ${${MODULE_NAME}_SRCS})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QT_EXECUTEABLE_FLAGS}")

add_definitions(${FUSE_DEFINITIONS})
include_directories(${FUSE_INCLUDE_DIRS})


target_link_libraries(${MODULE_NAME} ${QT_LIBRARIES} ${FUSE_LIBRARIES} ogon-qtrdpchannelserver)

install(TARGETS ${MODULE_NAME} DESTINATION "${CMAKE_INSTALL_BINDIR}")


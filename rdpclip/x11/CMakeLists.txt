set(MODULE_NAME "rdpclip")

include(FindQT5)

if (UNIX AND NOT APPLE)
	find_package(Xcb REQUIRED)
endif()

set(${MODULE_NAME}_SRCS
	rdpclip.cpp
	rdpx11clipchannelserver.cpp
	rdpx11clipchannelserver.h
        )

add_executable(${MODULE_NAME} ${${MODULE_NAME}_SRCS})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QT_EXECUTEABLE_FLAGS}")

target_link_libraries(${MODULE_NAME} ${LIBXCB_LIBRARIES} ${QT_LIBRARIES} ogon-qtrdpclipchannelserver)

install(TARGETS ${MODULE_NAME} DESTINATION "${CMAKE_INSTALL_BINDIR}")

set(MODULE_NAME "example-channel")

include(FindQT5)

set(${MODULE_NAME}_SRCS
	example-channel.cpp
	example-channelserver.cpp
	example-channelserver.h
)

add_executable(${MODULE_NAME} ${${MODULE_NAME}_SRCS})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QT_EXECUTEABLE_FLAGS}")

target_link_libraries(${MODULE_NAME} ${QT_LIBRARIES} ${OGON_QTRDPCHANNELSERVER_LIBRARIES} ogon-qtrdpchannelserver)

install(TARGETS ${MODULE_NAME} DESTINATION "${CMAKE_INSTALL_BINDIR}")


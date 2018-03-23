set(MODULE_NAME "ogon-qtrdpclipchannelserver")

set(MODULE_VERSION_MAJOR ${OGON_CHANNELS_VERSION_MAJOR})
set(MODULE_VERSION_MINOR ${OGON_CHANNELS_VERSION_MINOR})
set(MODULE_VERSION_PATCH ${OGON_CHANNELS_VERSION_PATCH})
set(MODULE_VERSION_FULL "${MODULE_VERSION_MAJOR}.${MODULE_VERSION_MINOR}.${MODULE_VERSION_PATCH}")

include(FindQT5)

set(${MODULE_NAME}_SRCS
	rdpclipchannelserver.cpp
	../../include/ogon-channels/qt/rdpclipchannelserver.h
        )

add_library(${MODULE_NAME} SHARED ${${MODULE_NAME}_SRCS})

target_link_libraries(${MODULE_NAME} ${QT_LIBRARIES} ogon-qtrdpchannelserver)

set_target_properties(${MODULE_NAME} PROPERTIES PREFIX "lib")
set_target_properties(${MODULE_NAME} PROPERTIES VERSION ${MODULE_VERSION_FULL} SOVERSION ${MODULE_VERSION_MAJOR})
install(TARGETS ${MODULE_NAME} DESTINATION "${CMAKE_INSTALL_LIBDIR}")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ogon-qtrdpclipchannelserver.pc.in ${CMAKE_CURRENT_BINARY_DIR}/ogon-qtrdpclipchannelserver${MODULE_VERSION_MAJOR}.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ogon-qtrdpclipchannelserver${MODULE_VERSION_MAJOR}.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

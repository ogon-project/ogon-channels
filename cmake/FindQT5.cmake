# Tell cmake to run moc when necessary
set(CMAKE_AUTOMOC ON)

# moc files are generated in current directory
set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(Qt5Core REQUIRED)
find_package(Qt5Widgets REQUIRED)
find_package(Qt5Gui REQUIRED)

include_directories(${Qt5Core_INCLUDE_DIRS})
set(QT_LIBRARIES "${Qt5Core_LIBRARIES}")
add_definitions(${Qt5Core_DEFINITIONS})
set(QT_EXECUTEABLE_FLAGS "${QT_EXECUTEABLE_FLAGS} ${Qt5Core_EXECUTABLE_COMPILE_FLAGS}")

include_directories(${Qt5Widgets_INCLUDE_DIRS})
set(QT_LIBRARIES "${QT_LIBRARIES};${Qt5Widgets_LIBRARIES}")
add_definitions(${Qt5Widgets_DEFINITIONS})
set(QT_EXECUTEABLE_FLAGS "${QT_EXECUTEABLE_FLAGS} ${Qt5Widgets_EXECUTABLE_COMPILE_FLAGS}")

include_directories(${Qt5Gui_INCLUDE_DIRS})
set(QT_LIBRARIES "${QT_LIBRARIES};${Qt5Gui_LIBRARIES}")
add_definitions(${Qt5Gui_DEFINITIONS})
set(QT_EXECUTEABLE_FLAGS "${QT_EXECUTEABLE_FLAGS} ${Qt5Gui_EXECUTABLE_COMPILE_FLAGS}")

if (UNIX AND NOT APPLE)
	find_package(Qt5DBus REQUIRED)
	include_directories(${Qt5DBus_INCLUDE_DIRS})
	set(QT_LIBRARIES "${QT_LIBRARIES};${Qt5DBus_LIBRARIES}")
	add_definitions(${Qt5DBus_DEFINITIONS})
	set(QT_EXECUTEABLE_FLAGS "${QT_EXECUTEABLE_FLAGS} ${Qt5Dbus_EXECUTABLE_COMPILE_FLAGS}")
endif()

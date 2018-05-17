cmake_minimum_required (VERSION 3.11)
project (cq C CXX)
set(PROJECT_VERSION "18.5.14")
set(PROJECT_NAME luketune)

set (BUILD_TYPE ${CMAKE_BUILD_TYPE})
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
    set(BUILD_TYPE Debug)
endif ()

if( CMAKE_BUILD_TYPE STREQUAL "Debug" )
    message( "Debug Build >>>" )
    add_definitions(-DDEBUG)
    add_definitions(-DDebug)
endif()

# Export compile commands
set( CMAKE_EXPORT_COMPILE_COMMANDS 1 ) 

set (CMAKE_C_STANDARD 11)
set (CMAKE_CXX_STANDARD 14)
set (CMAKE_MACOSX_RPATH TRUE)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)

# Detect linux
if (UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif ()

message(STATUS "Running cmake version ${CMAKE_VERSION}")

# disable all warnings
# add_compile_options( -w  )
# if (APPLE) 
# 	message(STATUS "Disable deprecated warnings")
# 	add_compile_options( -Wno-deprecated)
# endif ()

#------------------------------------- Boost -----------------------------------------#
# Linux: sudo apt install libboost-all-dev 
# Mac: brew install boost
# find_package( Boost 1.67 REQUIRED COMPONENTS atomic chrono context coroutine date_time exception filesystem graph iostreams locale log program_options random regex serialization signals timer system thread wave )
find_package( Boost 1.67 REQUIRED COMPONENTS filesystem system iostream program_options)
include_directories( ${Boost_INCLUDE_DIR} )

#------------------------------------- project header and lib path -----------------#
# Other external source headers
# include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/external/include )
# include_directories( ${CMAKE_BINARY_DIR}/libs/mariadb-connector-c/include/ )
# link_directories( ${CMAKE_CURRENT_SOURCE_DIR}/external/lib )
# include_directories( "libs/asio/include" )

#------------------------------------- Source File List ----------------------------------------#
# set(client_SRC_LIST 1.cpp 2.hpp 3.h 4.cxx ) # add files manually
# Not include subfolder, use file(GLOB srclist "*.cpp" "*.h")
# file(GLOB COMMON_SRC_LIST
# 	"common/*.hpp"
# 	"common/*.h"
# 	"common/*.cc"
# 	"common/*.cpp"
# 	"common/*.cxx"
# 	)
# file(GLOB_RECURSE SRC_LIST
# 	"src/*.hpp" 
# 	"src/*.h"
# 	"src/*.cpp" 
# 	"src/*.cc" 
# 	"src/*.cxx"
# 	)

#------------------------------------- DEP Libs ----------------------------------------#
set (DEP_LIBS 
	${Boost_LIBRARIES} 
	)

#------------------------------------- Targets ----------------------------------------#
set(DB_SRC_LIST
	src/blowfish.cpp
	src/lkserver.cpp
	)
add_executable(lkserver ${DB_SRC_LIST} )
target_link_libraries (lkserver ${DEP_LIBS})

set(DB_SRC_LIST
	src/blowfish.cpp
	src/lkclient.cpp
	)
add_executable(lkclient ${DB_SRC_LIST} )
target_link_libraries (lkclient ${DEP_LIBS})

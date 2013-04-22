SET(CCOAPAPPS_LIB_SRC client_tasks/tasks.c 
                      server_handlers/handlers.c)

#LINK_DIRECTORIES(${PROJECT_BINARY_DIR}/lib)
TARGET_LINK_LIBRARIES(pthread)

IF(CMAKE_COMPILER_IS_GNUCC)
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fmessage-length=0 -Wl,-flat_namespace,-undefined,dynamic_lookup")
ENDIF(CMAKE_COMPILER_IS_GNUCC)
IF(CMAKE_COMPILER_IS_GNUCXX)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fmessage-length=0 -Wl,-flat_namespace,-undefined,dynamic_lookup")
ENDIF(CMAKE_COMPILER_IS_GNUCXX)
                 
ADD_LIBRARY(ccoapapps SHARED ${CCOAPAPPS_LIB_SRC})
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

INSTALL(TARGETS ccoapapps
        DESTINATION lib
        PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)

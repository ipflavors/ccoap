SET(CCOAP_LIB_SRC coap.c queue.c client.c server.c debug.c)

#LINK_DIRECTORIES(${PROJECT_BINARY_DIR}/lib)
TARGET_LINK_LIBRARIES(pthread)

IF(CMAKE_COMPILER_IS_GNUCC)
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fmessage-length=0 -Wl,-flat_namespace,-undefined,dynamic_lookup")
ENDIF(CMAKE_COMPILER_IS_GNUCC)
IF(CMAKE_COMPILER_IS_GNUCXX)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fmessage-length=0 -Wl,-flat_namespace,-undefined,dynamic_lookup")
ENDIF(CMAKE_COMPILER_IS_GNUCXX)
                 
ADD_LIBRARY(ccoap SHARED ${CCOAP_LIB_SRC})
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

INSTALL(TARGETS ccoap
        DESTINATION lib
        PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)

SET(coap_client_time_src client_main.c ../shared/tasks_demo.c)
SET(coap_server_time_src server_main.c server_handler.c)

#LINK_DIRECTORIES(${PROJECT_BINARY_DIR}/lib)
TARGET_LINK_LIBRARIES(pthread)

SET(PROGRAMS coap_client_time coap_server_time)
SET(LIBS ccoap ccoapapps)

foreach(program ${PROGRAMS})
    ADD_EXECUTABLE(${program} ${${program}_src})
    SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
    TARGET_LINK_LIBRARIES(${program} ${LIBS} pthread)  
    INSTALL(TARGETS ${program}
            RUNTIME
            DESTINATION bin
            PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endforeach(program)

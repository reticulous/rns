file(GLOB RNSD_SRCS "src/*.cpp")

# Cross-straddle REQUIRES come through spangap_requires.cmake — spangap-core
# (hard) plus spangap-lcd if staged. The lcdSetting* call sites in rnsd.cpp
# gate on CONFIG_SPANGAP_LCD, which is set iff spangap-lcd is in SPANGAP_REQUIRES.
include(${CMAKE_CURRENT_LIST_DIR}/spangap_requires.cmake)
idf_component_register(
    SRCS ${RNSD_SRCS}
    INCLUDE_DIRS "include"
    REQUIRES
        ${SPANGAP_REQUIRES}
        json  # cJSON for path-table marshalling
    PRIV_REQUIRES
        # rnsd.cpp is the only consumer that touches the mR types directly.
        # The header surface (rnsd.h / ports.h) exposes only byte arrays.
        microreticulum
)

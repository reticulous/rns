file(GLOB RNSD_SRCS "src/*.cpp")

# Cross-straddle REQUIRES come through spangap_requires.cmake — spangap-core
# (hard) plus spangap-lcd if staged. The on-device Settings panes live in
# conditional/spangap-lcd/ and register via the when:-gated rnsdLcdRegister
# hook — compiled only when spangap-lcd is staged, so no #if anywhere.
include(${CMAKE_CURRENT_LIST_DIR}/spangap_requires.cmake)
idf_component_register(
    SRCS
        ${RNSD_SRCS}
        ${SPANGAP_CONDITIONAL_SRCS}
    INCLUDE_DIRS "include" ${SPANGAP_CONDITIONAL_INCLUDE_DIRS}
    REQUIRES
        ${SPANGAP_REQUIRES}
        json  # cJSON for path-table marshalling
    PRIV_REQUIRES
        # rnsd.cpp is the only consumer that touches the mR types directly.
        # The header surface (rnsd.h / ports.h) exposes only byte arrays.
        microreticulum
)

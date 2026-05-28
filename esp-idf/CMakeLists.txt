file(GLOB RNSD_SRCS "src/*.cpp")

idf_component_register(
    SRCS ${RNSD_SRCS}
    INCLUDE_DIRS "include"
    REQUIRES
        spangap-core
        # CMake REQUIRES is broader than straddle.yaml's logical requires:
        # rnsd.cpp's #include "ports.h" pulls in "its.h" (spangap-core), and
        # it uses cJSON for path-table marshalling.
        json
        # rnsd.cpp registers on-device Settings panes via lcd.h's lcdSetting*
        # helpers (gated by CONFIG_SPANGAP_LCD). Same plan-aligned future
        # move into an esp-idf/lcd/ slice as the spangap-net case.
        spangap-lcd
    PRIV_REQUIRES
        # rnsd.cpp is the only consumer that touches the mR types directly.
        # The header surface (rnsd.h / ports.h) exposes only byte arrays.
        microreticulum
)

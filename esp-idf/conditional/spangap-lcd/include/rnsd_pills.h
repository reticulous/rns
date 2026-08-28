#pragma once
/**
 * rnsd_pills — the interface-class pills in the shell status bar.
 *
 * Compiled only when spangap-lcd is staged (this whole directory is), so the
 * class exists exactly where there is a status bar to put it in.
 */
#include "service.h"

/** Installs the status-bar indicator and its storage subscription. Registered
 *  through rns's `services:` block, `when: spangap/spangap-lcd`. */
class RnsdPillsService : public Service {
public:
    void onInit() override;
};

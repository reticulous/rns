/**
 * rnsd_lcd.cpp — on-device Settings panes for Reticulum (RNS) core.
 *
 * Registers the Settings → Reticulum → General pane (mirrors the web
 * RnsdPanel) via a when:-gated init: hook (spangap/spangap-lcd). This whole
 * file lives under conditional/spangap-lcd/, compiled only when the lcd
 * straddle is staged, so no #if is needed. Plain C++ linkage to match the
 * generated dispatcher's forward decl.
 */
#include "lcd.h"

/* Settings → Reticulum → General. Mirrors the web RnsdPanel. */
static void rnsdSettingsPane(void* arg) {
    lv_obj_t* p = static_cast<lv_obj_t*>(arg);
    lcdSettingSection(p, "Reticulum");
    lcdSettingValue  (p, "Identity", "rnsd.identity_hash");
    lcdSettingSwitch (p, "Enable", "s.rnsd.enable");
    lcdSettingSwitch (p, "Transport node", "s.rnsd.transport_enabled");
    lcdSettingText   (p, "Node name", "s.rnsd.name");
    lcdSettingSlider (p, "Announce (s)", "s.rnsd.announce.interval", 0, 21600);
    lcdSettingSection(p, "Path Table");
    lcdSettingSlider (p, "Capacity", "s.rnsd.path.max", 64, 512);
    lcdSettingSlider (p, "TTL (s)", "s.rnsd.path.ttl", 3600, 604800);
}

void rnsdLcdRegister(void) {
    lcdRegisterSettings("Reticulum/General", "General", rnsdSettingsPane);
}

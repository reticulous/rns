/*
 * Copyright (c) 2023 Chad Attermann
 * Apache-2.0. Full license in LICENSE.upstream at component root.
 *
 * Diptych fork: replaced upstream's Serial.print* / printf log sink with
 * diptych's info()/warn()/err()/dbg()/verb() macros so all µR diagnostics
 * land in the diptych log task (`[taskname]` prefix added by the macros
 * themselves).
 *
 * Per §3 of docs/component-plan.md, the upstream non-Arduino branch printed
 * straight to stdout — fine for native, wrong for ESP-IDF. The Arduino
 * branch wrote to Serial — we never define ARDUINO. Both are now gone.
 */

#include "Log.h"

// FIXME: rename µR's `Log.h` to something unique (e.g. `RnsLog.h`) so we
// can `#include <log.h>` here and route through diptych's err/warn/info/
// dbg/verb macros directly. Right now src/ is on the component's -I list,
// and on case-insensitive filesystems (macOS APFS default) `log.h`
// resolves to this directory's `Log.h` (µR's own header) — even with
// angle brackets — because src/ is searched first. The proper fix is the
// rename; the workaround below inlines the same expansion that diptych's
// macros use (`pcTaskGetName(NULL)` for the per-task tag), so the
// per-caller-task `[rnsd]`/`[lxmf]`/etc. prefix is preserved. ESP-IDF's
// vprintf hook (installed by the diptych log task) still catches the
// output, so DRAM ring + fan-out + log file all behave identically.
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <stdio.h>

using namespace RNS;

//LogLevel _level = LOG_VERBOSE;
LogLevel _level = LOG_TRACE;
//LogLevel _level = LOG_MEM;
RNS::log_callback _on_log = nullptr;

const char* RNS::getLevelName(LogLevel level) {
	switch (level) {
	case LOG_CRITICAL: return "!!!";
	case LOG_ERROR:    return "ERR";
	case LOG_WARNING:  return "WRN";
	case LOG_NOTICE:   return "NOT";
	case LOG_INFO:     return "INF";
	case LOG_VERBOSE:  return "VRB";
	case LOG_DEBUG:    return "DBG";
	case LOG_TRACE:    return "---";
	case LOG_MEM:      return "...";
	default:           return "";
	}
}

const char* RNS::getTimeString() {
	// Diptych's log macros prepend their own timestamp via ESP_LOGx, so the
	// per-message time string is unused. Kept as a stub so anything that
	// references getTimeString() (none in our build) still links.
	return "";
}

void RNS::loglevel(LogLevel level) { _level = level; }
LogLevel RNS::loglevel() { return _level; }

void RNS::set_log_callback(log_callback on_log) { _on_log = on_log; }

void RNS::doLog(LogLevel level, const char* msg) {
	if (level > _level) return;
	if (_on_log != nullptr) { _on_log(msg, level); return; }

	// Map µR LogLevel onto diptych's coarser level set. CRITICAL/ERROR → err,
	// WARNING/NOTICE → warn, INFO → info, VERBOSE/MEM → verb, DEBUG/TRACE → dbg.
	// The `pcTaskGetName(NULL)` tag mirrors diptych's err()/warn()/info()/
	// dbg()/verb() macros — see the include block above for why we expand
	// inline here instead of #including log.h.
	const char* tag = pcTaskGetName(NULL);
	switch (level) {
	case LOG_CRITICAL:
	case LOG_ERROR:
		ESP_LOGE(tag, "%s", msg);
		break;
	case LOG_WARNING:
	case LOG_NOTICE:
		ESP_LOGW(tag, "%s", msg);
		break;
	case LOG_INFO:
		ESP_LOGI(tag, "%s", msg);
		break;
	case LOG_VERBOSE:
	case LOG_MEM:
		ESP_LOGV(tag, "%s", msg);
		break;
	case LOG_DEBUG:
	case LOG_TRACE:
	default:
		ESP_LOGD(tag, "%s", msg);
		break;
	}
}

void RNS::doHeadLog(LogLevel level, const char* msg) {
	// Upstream prefixed a blank line; we drop it — diptych's log task framing
	// makes it unnecessary noise.
	doLog(level, msg);
}

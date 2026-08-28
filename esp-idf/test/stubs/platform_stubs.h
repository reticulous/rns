/**
 * Host stubs for the platform surface netgraph.cpp uses.
 *
 * netgraph.cpp is not free of the platform the way iface-lora's supe.cpp is —
 * it talks to storage, ITS and rnsd by design. But the RECORD is pure: compose
 * → encode → parse → resolve is arithmetic over tables, and that is what breaks
 * in ways a device cannot show you. So the platform is stubbed just far enough
 * to link, the rnsd tables are stubbed as data the test writes, and the record
 * path runs for real.
 */
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <map>

/* ── freertos ── */
typedef void* TaskHandle_t;
typedef uint32_t TickType_t;
#define portMAX_DELAY 0xFFFFFFFFu
#define portTICK_PERIOD_MS 1
#define pdMS_TO_TICKS(x) ((TickType_t)(x))
extern uint32_t g_ticks;
inline TickType_t xTaskGetTickCount() { return g_ticks; }
inline void xTaskNotifyGive(TaskHandle_t) {}

/* ── mem ── */
#define PSRAM_BSS
inline void* gp_alloc(size_t n) { return malloc(n); }
inline void  gp_free(void* p) { free(p); }

/* ── log ── */
#define err(...)  do { printf("  E "); printf(__VA_ARGS__); printf("\n"); } while (0)
#define warn(...) do { printf("  W "); printf(__VA_ARGS__); printf("\n"); } while (0)
#define info(...) do { if (g_verbose) { printf("  I "); printf(__VA_ARGS__); printf("\n"); } } while (0)
#define verb(...) do { } while (0)
#define dbg(...)  do { } while (0)
extern bool g_verbose;

/* ── compat ── */
inline char* safeStrncpy(char* d, const char* s, size_t n) {
    if (!n) return d;
    strncpy(d, s, n - 1); d[n - 1] = '\0'; return d;
}
inline void delay(uint32_t) {}
enum stack_caps_t { STACK_PSRAM, STACK_DRAM };
inline TaskHandle_t spawnTask(void (*)(void*), const char*, uint32_t, void*,
                              unsigned, int, stack_caps_t = STACK_PSRAM) { return nullptr; }

/* ── storage: a flat map, which is all netgraph.cpp needs of it ── */
extern std::map<std::string, std::string> g_store;
int  storageGetInt(const char* k, int def = 0);
void storageGetStr(const char* k, char* out, size_t n, const char* def = "");
void storageSet(const char* k, int v);
void storageSet(const char* k, const char* v);
void storageBegin();
void storageEnd();
void storageDeleteTree(const char* prefix);
bool storageDefaultTree(const char* prefix, const char* json);
typedef void (*storage_change_cb_t)(const char*, const char*);
void storageSubscribeChanges(const char* scope, storage_change_cb_t cb, bool onStorageTask = false);
#define ON_CHANGE [](const char* key, const char* val)

/* ── ITS: netgraph only sends into the void here ── */
#define ITS_MAX_MSG_DATA 320
enum its_port_kind_t { ITS_STREAM, ITS_PACKET_LEGACY, ITS_PACKET };
typedef void (*its_recv_cb_t)(int, size_t);
typedef void (*its_disconnect_cb_t)(int);
typedef int  (*its_connect_cb_t)(int, const void*, size_t);
inline bool itsServerInit(size_t = 0, size_t = 0, bool = false) { return true; }
inline void itsClientInit(int, size_t = 0, size_t = 0) {}
inline bool itsServerPortOpen(uint16_t, its_port_kind_t, int, size_t, size_t,
                              size_t = 0, size_t = 0) { return true; }
inline void itsServerOnConnect(uint16_t, its_connect_cb_t) {}
inline void itsServerOnRecv(uint16_t, its_recv_cb_t) {}
inline void itsServerOnDisconnect(uint16_t, its_disconnect_cb_t) {}
inline int  itsConnect(const char*, uint16_t, const void*, size_t, TickType_t,
                       int = -1, its_recv_cb_t = nullptr, its_disconnect_cb_t = nullptr) { return -1; }
inline void itsDisconnect(int) {}
inline bool itsPoll(TickType_t = portMAX_DELAY) { return false; }
inline size_t itsSend(int, const void*, size_t len, TickType_t) { return len; }
inline size_t itsRecv(int, void*, size_t, TickType_t) { return 0; }

/* ── cli ── */
typedef void (*cli_cmd_cb_t)(const char*);
inline void cliRegisterCmd(const char*, cli_cmd_cb_t) {}
inline bool cliWantsHelp(const char*) { return false; }
inline bool cliVerbIs(const char*, const char*, size_t) { return false; }
int cliPrintf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

/* ── service ── */
class Service { public: virtual ~Service() {} virtual void onStart() {} virtual void onInit() {} };

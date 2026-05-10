/*
 * Copyright (c) 2023 Chad Attermann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */

#pragma once

#include "../Bytes.h"

#include <microStore/FileSystem.h>

#include <cmath>
#include <memory>
#include <functional>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <sys/time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#ifdef ARDUINO
#include <Arduino.h>
#if defined(ESP32)
#include "esp_task_wdt.h"
#endif
#endif

#undef round

namespace RNS { namespace Utilities {

	class OS {

	public:
		using LoopCallback = std::function<void()>;

	private:
		static microStore::FileSystem _filesystem;
		static uint64_t _time_offset;
		static LoopCallback _on_loop;

	public:
		inline static uint64_t getTimeOffset() { return _time_offset; }
		inline static void setTimeOffset(uint64_t offset) { _time_offset = offset; }

#ifdef ARDUINO
        // return current time in milliseconds since first boot
		inline static uint64_t ltime() {
			// handle roll-over of 32-bit millis (approx. 49 days)
			static uint32_t low32, high32;
			uint32_t new_low32 = millis();
			if (new_low32 < low32) high32++;
			low32 = new_low32;
			return ((uint64_t)high32 << 32 | low32) + _time_offset;
		}
#else
        // return current time in milliseconds since 00:00:00, January 1, 1970 (Unix Epoch)
		inline static uint64_t ltime() { timeval time; ::gettimeofday(&time, NULL); return (uint64_t)(time.tv_sec * 1000) + (uint64_t)(time.tv_usec / 1000); }
#endif

#ifdef ARDUINO
        // return current time in float seconds since startup
		inline static double time() { return (double)(ltime() / 1000.0); }
#else
        // return current time in float seconds since 00:00:00, January 1, 1970 (Unix Epoch)
		inline static double time() { timeval time; ::gettimeofday(&time, NULL); return (double)time.tv_sec + ((double)time.tv_usec / 1000000); }
#endif

        // sleep for specified milliseconds
		//inline static void sleep(float seconds) { ::sleep(seconds); }
#ifdef ARDUINO
		inline static void sleep(float seconds) { delay((uint32_t)(seconds * 1000)); }
#else
		// Diptych fork: ESP-IDF's newlib doesn't ship nanosleep. Use vTaskDelay
		// (FreeRTOS yields the CPU instead of busy-spinning, matching the
		// upstream intent on Arduino).
		inline static void sleep(float seconds) {
			vTaskDelay(pdMS_TO_TICKS((uint32_t)(seconds * 1000.0f)));
		}
#endif
		//inline static void sleep(uint32_t milliseconds) { ::sleep((float)milliseconds / 1000.0); }

		// round decimal number to specified precision
		//inline static float round(float value, uint8_t precision) { return std::round(value / precision) * precision; }
		//inline static double round(double value, uint8_t precision) { return std::round(value / precision) * precision; }
		inline static double round(double value, uint8_t precision) { return std::round(value / precision) * precision; }

		inline static uint64_t from_bytes_big_endian(const uint8_t* data, size_t len) {
			uint64_t result = 0;
			for (size_t i = 0; i < len; ++i) {
				result = (result << 8) | data[i];
			}
			return result;
		}

		// Detect endianness at runtime
		inline static int is_big_endian(void) {
			uint16_t test = 0x0102;
			return ((uint8_t*)&test)[0] == 0x01;
		}

		// Byte swap functions
		inline static uint16_t swap16(uint16_t val) {
			return (val << 8) | (val >> 8);
		}

		inline static uint32_t swap32(uint32_t val) {
			return ((val << 24) & 0xFF000000) |
				((val << 8)  & 0x00FF0000) |
				((val >> 8)  & 0x0000FF00) |
				((val >> 24) & 0x000000FF);
		}

		// Platform-independent replacements

		inline static uint16_t portable_htons(uint16_t val) {
			return is_big_endian() ? val : swap16(val);
		}

		inline static uint32_t portable_htonl(uint32_t val) {
			return is_big_endian() ? val : swap32(val);
		}

		inline static uint16_t portable_ntohs(uint16_t val) {
			return is_big_endian() ? val : swap16(val);
		}

		inline static uint32_t portable_ntohl(uint32_t val) {
			return is_big_endian() ? val : swap32(val);
		}

		inline static void reset_watchdog() {
#if defined(ESP32)
			esp_task_wdt_reset();
#endif
		}

		inline static void set_loop_callback(LoopCallback on_loop = nullptr) { _on_loop = on_loop; }
		inline static void run_loop() {
			if (_on_loop) {
				try {
					_on_loop();
				}
				catch (const std::exception& e) {
					ERRORF("run_loop: exception while looping: %s", e.what());
				}
			}
		}

		inline static void register_filesystem(microStore::FileSystem& filesystem) {
			//TRACE("Registering filesystem...");
			_filesystem = filesystem;
		}

		inline static void deregister_filesystem() {
			//TRACE("Deregistering filesystem...");
			_filesystem = {};
		}

		inline static microStore::FileSystem& get_filesystem() {
			return _filesystem;
		}


		// Diptych fork: file I/O is no-op'd per docs/component-plan.md §10.5.
		// We own all persistence via the rnsd CLI/cron path; mR's hourly
		// auto-save calls (destination_table, packet_hashlist, known_destinations,
		// tunnels, time_offset) become silent no-ops. Returning 0 / false /
		// empty matches "nothing on disk", which is the cold-boot shape that
		// callers already handle. register_filesystem() is still functional
		// in case anything wants to attach a real backing store later.
		inline static bool   file_exists(const char* file_path)              { (void)file_path; return false; }
		inline static size_t read_file(const char* file_path, Bytes& data)   { (void)file_path; (void)data; return 0; }
		inline static size_t write_file(const char* file_path, const Bytes& data) { (void)file_path; (void)data; return 0; }
		inline static microStore::File open_file(const char* file_path, microStore::File::Mode file_mode) {
			(void)file_path; (void)file_mode; return microStore::File();
		}
		inline static bool   remove_file(const char* file_path)              { (void)file_path; return false; }
		inline static bool   rename_file(const char* from_file_path, const char* to_file_path) { (void)from_file_path; (void)to_file_path; return false; }
		inline static bool   directory_exists(const char* directory_path)    { (void)directory_path; return false; }
		inline static bool   create_directory(const char* directory_path)    { (void)directory_path; return false; }
		inline static bool   remove_directory(const char* directory_path)    { (void)directory_path; return false; }
		inline static std::list<std::string> list_directory(const char* directory_path, microStore::FileSystem::Callbacks::DirectoryListing callback = nullptr) {
			(void)directory_path; (void)callback; return std::list<std::string>();
		}
		inline static size_t storage_size()      { return 0; }
		inline static size_t storage_available() { return 0; }
	
    };

} }

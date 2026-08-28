/**
 * rnsd_pills_lcd — one pill per switched-on interface class in the shell's top
 * status bar: the medium's letter and how many peers are on it. `L3` is three
 * peers on LoRa, the same three `lora n` lists.
 *
 * Nothing about any medium is here. Each interface straddle publishes its own
 * pill under `rns.pill.<id>.{text,color,order}` (rnsdPillSet), and this renders
 * whatever is there — a medium added later needs no edit to this file. The
 * browser's IfacePills.vue reads exactly the same keys, which is why the two
 * status lines agree without either knowing about the other.
 */
#include "rnsd_pills.h"
#include "rnsd.h"

#include "lcd.h"
#include "storage.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

/* A pill with no text is one taken down — the firmware empties rather than
 * deletes, because a delete fires no change callback and this subscriber would
 * never hear about it. */
struct Pill {
    std::string id, text, color;
    int order = 0;
};

lv_obj_t* s_slot = nullptr;
std::vector<Pill> s_pills;

Pill& pillFor(const char* id) {
    for (auto& p : s_pills) if (p.id == id) return p;
    s_pills.push_back({ id, "", "888888", 0 });
    return s_pills.back();
}

/* storageForEach hands one leaf at a time with no context pointer, so the
 * collection lands in the file-static vector above. Keys are full dot paths:
 * rns.pill.<id>.<field>. */
void collectLeaf(const char* key, const char* val) {
    const char* rest = key + std::strlen("rns.pill.");
    const char* dot  = std::strrchr(rest, '.');
    if (!dot || dot == rest) return;
    std::string id(rest, dot - rest);
    const char* field = dot + 1;
    Pill& p = pillFor(id.c_str());
    if      (std::strcmp(field, "text")  == 0) p.text  = val ? val : "";
    else if (std::strcmp(field, "color") == 0) p.color = val && *val ? val : "888888";
    else if (std::strcmp(field, "order") == 0) p.order = val ? atoi(val) : 0;
}

uint32_t parseColor(const std::string& c) {
    return (uint32_t)strtoul(c.c_str(), nullptr, 16) & 0xFFFFFFu;
}

/* Rebuild the whole row. There are a handful of pills and they change at
 * announce/connection rates, so redrawing the lot is cheaper than tracking
 * which label belongs to which id across a class appearing or leaving. */
void rebuild(const char* = nullptr, const char* = nullptr) {
    if (!s_slot || !lv_obj_is_valid(s_slot)) return;
    s_pills.clear();
    storageForEach("rns.pill", collectLeaf);
    std::sort(s_pills.begin(), s_pills.end(), [](const Pill& a, const Pill& b) {
        return a.order != b.order ? a.order < b.order : a.id < b.id;
    });

    lv_obj_clean(s_slot);
    const lv_font_t* f = lcdFont(LcdFace::MONO_BOLD, lcdPx(10));
    for (const auto& p : s_pills) {
        if (p.text.empty()) continue;
        lv_color_t col = lv_color_hex(parseColor(p.color));
        lv_obj_t* l = lv_label_create(s_slot);
        lv_label_set_text(l, p.text.c_str());
        lv_obj_set_style_text_color(l, col, 0);
        if (f) lv_obj_set_style_text_font(l, f, 0);
        lv_obj_set_style_border_color(l, col, 0);
        lv_obj_set_style_border_width(l, 1, 0);
        lv_obj_set_style_border_opa(l, LV_OPA_70, 0);
        lv_obj_set_style_radius(l, lcdPx(3), 0);
        lv_obj_set_style_pad_hor(l, lcdPx(3), 0);
        lv_obj_set_style_pad_ver(l, lcdPx(1), 0);
    }
}

}  // namespace

void RnsdPillsService::onInit()
{
    /* On the lcd task, so the callback may touch LVGL directly, and at init
     * rather than from any app, so the pills are there from boot whatever is
     * on screen. The slot lives in the shell status bar and outlives every app
     * layer, so nothing ever nulls it. */
    lcdRun([](void*) {
        s_slot = lcdStatusbarAddIndicator();
        if (!s_slot) return;
        lv_obj_set_style_pad_column(s_slot, lcdPx(3), 0);
        storageSubscribeChanges("rns.pill", rebuild);
        rebuild();
    });
}

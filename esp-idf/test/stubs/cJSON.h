/* Host stand-in for cJSON, reached only by the settings collection's add
 * sentinel — the one place netgraph parses JSON, because that is the shape a
 * settings form submits.
 *
 * A REAL parser, small and strict, rather than a null one: the sentinel's job
 * is to reject a malformed identity hash before it reaches the allow list, and
 * a stub that always answered "no such field" would let a test pass while the
 * validation it exercises never ran. It handles exactly what a form sends —
 * a flat object of string values — and refuses everything else.
 *
 * Children are owned by the object they came from, so one cJSON_Delete on the
 * parse result frees the lot, which is the ownership the callers assume. */
#pragma once
#include <cstring>
#include <cstdlib>
#include <string>
#include <map>
#include <memory>
#include <vector>

struct cJSON {
    std::map<std::string, std::string>   fields;
    bool                                 is_string = false;
    std::string                          text;
    const char*                          valuestring = nullptr;
    std::vector<std::unique_ptr<cJSON>>  children;
};

inline void cJSON_Delete(cJSON* o) { delete o; }

inline cJSON* cJSON_Parse(const char* s) {
    if (!s) return nullptr;
    const char* p = s;
    auto skip = [&] { while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++; };
    auto str = [&](std::string& out) -> bool {
        skip();
        if (*p != '"') return false;
        p++;
        while (*p && *p != '"') {
            if (*p == '\\' && p[1]) p++;
            out += *p++;
        }
        if (*p != '"') return false;
        p++;
        return true;
    };

    skip();
    if (*p != '{') return nullptr;
    p++;
    std::unique_ptr<cJSON> o(new cJSON());
    skip();
    if (*p == '}') return o.release();
    for (;;) {
        std::string k, v;
        if (!str(k)) return nullptr;
        skip();
        if (*p != ':') return nullptr;
        p++;
        if (!str(v)) return nullptr;      /* string values only */
        o->fields[k] = v;
        skip();
        if (*p == ',') { p++; continue; }
        if (*p == '}') break;
        return nullptr;
    }
    return o.release();
}

inline cJSON* cJSON_GetObjectItem(cJSON* o, const char* key) {
    if (!o) return nullptr;
    auto it = o->fields.find(key);
    if (it == o->fields.end()) return nullptr;
    o->children.emplace_back(new cJSON());
    cJSON* v = o->children.back().get();
    v->is_string  = true;
    v->text       = it->second;
    v->valuestring = v->text.c_str();
    return v;
}

inline bool cJSON_IsString(const cJSON* v) { return v && v->is_string; }

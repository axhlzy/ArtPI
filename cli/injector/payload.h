//
// payload.h - Embedded payload extraction for ArtPI injector
//
#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Trailer layout: [payload bytes][magic 8B][size u64le 8B]
bool ExtractEmbeddedPayload(std::vector<uint8_t> &out, std::string &err, const char* magic = "PPAYLOAD");
bool ReadFileAll(const std::string &path, std::vector<uint8_t> &out, std::string &err);

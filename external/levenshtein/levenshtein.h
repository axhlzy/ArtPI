#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <algorithm>
#include <cctype>

namespace artpi { namespace utils {

inline size_t LevenshteinDistance(std::string_view s1, std::string_view s2, bool caseSensitive = false) {
    const size_t len1 = s1.size();
    const size_t len2 = s2.size();
    if (len1 == 0) return len2;
    if (len2 == 0) return len1;

    std::vector<size_t> prev(len2 + 1);
    std::vector<size_t> curr(len2 + 1);

    for (size_t j = 0; j <= len2; ++j) prev[j] = j;

    for (size_t i = 1; i <= len1; ++i) {
        curr[0] = i;
        char c1 = caseSensitive ? s1[i - 1] : static_cast<char>(std::tolower(static_cast<unsigned char>(s1[i - 1])));
        for (size_t j = 1; j <= len2; ++j) {
            char c2 = caseSensitive ? s2[j - 1] : static_cast<char>(std::tolower(static_cast<unsigned char>(s2[j - 1])));
            size_t cost = (c1 == c2) ? 0 : 1;
            curr[j] = std::min({ prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost });
        }
        prev = curr;
    }
    return prev[len2];
}

inline double LevenshteinSimilarity(std::string_view s1, std::string_view s2, bool caseSensitive = false) {
    if (s1.empty() && s2.empty()) return 1.0;
    size_t maxLen = std::max(s1.size(), s2.size());
    if (maxLen == 0) return 1.0;
    size_t dist = LevenshteinDistance(s1, s2, caseSensitive);
    return 1.0 - (static_cast<double>(dist) / static_cast<double>(maxLen));
}

}} // namespace artpi::utils

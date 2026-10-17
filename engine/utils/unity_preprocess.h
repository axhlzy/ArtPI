//
// unity_preprocess.h - Lexer-aware rewrite for hyphenated Unity assembly names.
//
// JavaScript has no way to spell `dynamic.unity.assembly.Assembly-CSharp` as a
// property chain, so we rewrite only that exact chain into bracket notation.
// The rewrite is deliberately restricted to normal code context: string
// literals, template literals, comments, and common regex literals are copied
// verbatim. This prevents a source line such as
//
//   console.log("dynamic.unity.assembly.Assembly-CSharp")
//
// from being corrupted into an invalid string.
//
#pragma once

#include <cctype>
#include <string>

namespace artpi { namespace utils {

inline bool IsUnityJsIdentChar(char ch) {
    unsigned char c = static_cast<unsigned char>(ch);
    return std::isalnum(c) != 0 || c == '_' || c == '$';
}

inline bool IsUnityAssemblyNameChar(char ch) {
    unsigned char c = static_cast<unsigned char>(ch);
    return std::isalnum(c) != 0 || c == '_' || c == '$' || c == '-';
}

inline bool IsUnityRegexContext(const std::string& input, size_t slash) {
    size_t p = slash;
    while (p > 0) {
        char c = input[p - 1];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            --p;
            continue;
        }
        return c == '=' || c == '(' || c == '[' || c == '{' || c == ',' ||
               c == ':' || c == ';' || c == '!' || c == '&' || c == '|' ||
               c == '?' || c == '+' || c == '-' || c == '*' || c == '%' ||
               c == '^' || c == '~' || c == '<' || c == '>';
    }
    return true;
}

inline std::string PreprocessUnityLine(const std::string& input) {
    static const char kPrefix[] = "dynamic.unity.assembly.";
    static constexpr size_t kPrefixLen = sizeof(kPrefix) - 1;

    enum class State {
        Code,
        SingleQuote,
        DoubleQuote,
        Template,
        LineComment,
        BlockComment,
        Regex,
        RegexClass
    };

    State state = State::Code;
    std::string out;
    out.reserve(input.size() + 32);

    size_t i = 0;
    while (i < input.size()) {
        char c = input[i];

        if (state == State::Code) {
            if (c == '/' && i + 1 < input.size() && input[i + 1] == '/') {
                out.append("//");
                i += 2;
                state = State::LineComment;
                continue;
            }
            if (c == '/' && i + 1 < input.size() && input[i + 1] == '*') {
                out.append("/*");
                i += 2;
                state = State::BlockComment;
                continue;
            }
            if (c == '\'') {
                out.push_back(c);
                ++i;
                state = State::SingleQuote;
                continue;
            }
            if (c == '"') {
                out.push_back(c);
                ++i;
                state = State::DoubleQuote;
                continue;
            }
            if (c == '`') {
                out.push_back(c);
                ++i;
                state = State::Template;
                continue;
            }
            if (c == '/' && IsUnityRegexContext(input, i)) {
                out.push_back(c);
                ++i;
                state = State::Regex;
                continue;
            }

            if (i + kPrefixLen <= input.size() &&
                input.compare(i, kPrefixLen, kPrefix) == 0 &&
                (i == 0 || !IsUnityJsIdentChar(input[i - 1]))) {
                size_t nameStart = i + kPrefixLen;
                size_t nameEnd = nameStart;
                while (nameEnd < input.size() && IsUnityAssemblyNameChar(input[nameEnd])) {
                    ++nameEnd;
                }
                std::string name = input.substr(nameStart, nameEnd - nameStart);
                if (!name.empty() && name.find('-') != std::string::npos) {
                    out += "dynamic.unity.assembly[\"";
                    out += name;
                    out += "\"]";
                } else {
                    out.append(input, i, nameEnd - i);
                }
                i = nameEnd;
                continue;
            }

            out.push_back(c);
            ++i;
            continue;
        }

        if (state == State::LineComment) {
            out.push_back(c);
            ++i;
            if (c == '\n') state = State::Code;
            continue;
        }

        if (state == State::BlockComment) {
            out.push_back(c);
            ++i;
            if (c == '*' && i < input.size() && input[i] == '/') {
                out.push_back('/');
                ++i;
                state = State::Code;
            }
            continue;
        }

        if (state == State::Regex) {
            if (c == '\\' && i + 1 < input.size()) {
                out.push_back(c);
                out.push_back(input[i + 1]);
                i += 2;
                continue;
            }
            out.push_back(c);
            ++i;
            if (c == '[') {
                state = State::RegexClass;
            } else if (c == '/') {
                while (i < input.size() &&
                       std::isalpha(static_cast<unsigned char>(input[i])) != 0) {
                    out.push_back(input[i]);
                    ++i;
                }
                state = State::Code;
            } else if (c == '\n') {
                state = State::Code;
            }
            continue;
        }

        if (state == State::RegexClass) {
            if (c == '\\' && i + 1 < input.size()) {
                out.push_back(c);
                out.push_back(input[i + 1]);
                i += 2;
                continue;
            }
            out.push_back(c);
            ++i;
            if (c == ']') state = State::Regex;
            continue;
        }

        // String / template literal states.
        out.push_back(c);
        ++i;
        if (c == '\\' && i < input.size()) {
            out.push_back(input[i]);
            ++i;
            continue;
        }
        if ((state == State::SingleQuote && c == '\'') ||
            (state == State::DoubleQuote && c == '"') ||
            (state == State::Template && c == '`')) {
            state = State::Code;
        }
    }

    return out;
}

}} // namespace artpi::utils

//
// mpack.h - Minimal single-header MessagePack serializer & deserializer for ArtPI
// Spec compatible with standard MessagePack (FixMap, FixArray, Str, Int, Nil, Bool)
//
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <cstring>

namespace artpi { namespace msgpack {

enum class Type {
    NIL,
    BOOL,
    INT,
    UINT,
    FLOAT,
    DOUBLE,
    STR,
    BIN,
    ARRAY,
    MAP
};

struct Value {
    Type type = Type::NIL;
    int64_t i64 = 0;
    uint64_t u64 = 0;
    double f64 = 0.0;
    bool b = false;
    std::string str;
    std::vector<uint8_t> bin;
    std::vector<Value> arr;
    std::vector<std::pair<std::string, Value>> map;

    Value() = default;
    explicit Value(bool val) : type(Type::BOOL), b(val) {}
    explicit Value(int val) : type(Type::INT), i64(val) {}
    explicit Value(int64_t val) : type(Type::INT), i64(val) {}
    explicit Value(uint64_t val) : type(Type::UINT), u64(val) {}
    explicit Value(double val) : type(Type::DOUBLE), f64(val) {}
    explicit Value(const char* val) : type(Type::STR), str(val ? val : "") {}
    explicit Value(const std::string& val) : type(Type::STR), str(val) {}
    explicit Value(std::vector<uint8_t> val) : type(Type::BIN), bin(std::move(val)) {}

    static Value makeMap() {
        Value v;
        v.type = Type::MAP;
        return v;
    }

    static Value makeArray() {
        Value v;
        v.type = Type::ARRAY;
        return v;
    }

    void set(const std::string& key, Value val) {
        if (type != Type::MAP) type = Type::MAP;
        for (auto& p : map) {
            if (p.first == key) {
                p.second = std::move(val);
                return;
            }
        }
        map.emplace_back(key, std::move(val));
    }

    const Value* get(const std::string& key) const {
        if (type != Type::MAP) return nullptr;
        for (const auto& p : map) {
            if (p.first == key) return &p.second;
        }
        return nullptr;
    }

    std::string getString(const std::string& key, const std::string& def = "") const {
        const Value* v = get(key);
        return (v && v->type == Type::STR) ? v->str : def;
    }

    int64_t getInt(const std::string& key, int64_t def = 0) const {
        const Value* v = get(key);
        if (!v) return def;
        if (v->type == Type::INT) return v->i64;
        if (v->type == Type::UINT) return (int64_t)v->u64;
        return def;
    }

    bool getBool(const std::string& key, bool def = false) const {
        const Value* v = get(key);
        return (v && v->type == Type::BOOL) ? v->b : def;
    }

    void push(Value val) {
        if (type != Type::ARRAY) type = Type::ARRAY;
        arr.push_back(std::move(val));
    }
};

// Serializer
class Writer {
public:
    std::vector<uint8_t> buffer;

    void writeNil() {
        buffer.push_back(0xc0);
    }

    void writeBool(bool b) {
        buffer.push_back(b ? 0xc3 : 0xc2);
    }

    void writeInt(int64_t v) {
        if (v >= -32 && v <= 127) {
            buffer.push_back((uint8_t)v);
        } else if (v >= -128 && v <= 127) {
            buffer.push_back(0xd0);
            buffer.push_back((uint8_t)v);
        } else if (v >= -32768 && v <= 32767) {
            buffer.push_back(0xd1);
            write16((uint16_t)v);
        } else if (v >= -2147483648LL && v <= 2147483647LL) {
            buffer.push_back(0xd2);
            write32((uint32_t)v);
        } else {
            buffer.push_back(0xd3);
            write64((uint64_t)v);
        }
    }

    void writeUInt(uint64_t v) {
        if (v <= 127) {
            buffer.push_back((uint8_t)v);
        } else if (v <= 0xff) {
            buffer.push_back(0xcc);
            buffer.push_back((uint8_t)v);
        } else if (v <= 0xffff) {
            buffer.push_back(0xcd);
            write16((uint16_t)v);
        } else if (v <= 0xffffffff) {
            buffer.push_back(0xce);
            write32((uint32_t)v);
        } else {
            buffer.push_back(0xcf);
            write64(v);
        }
    }

    void writeDouble(double v) {
        buffer.push_back(0xcb);
        uint64_t u;
        std::memcpy(&u, &v, sizeof(u));
        write64(u);
    }

    void writeString(const std::string& s) {
        size_t len = s.size();
        if (len <= 31) {
            buffer.push_back((uint8_t)(0xa0 | len));
        } else if (len <= 0xff) {
            buffer.push_back(0xd9);
            buffer.push_back((uint8_t)len);
        } else if (len <= 0xffff) {
            buffer.push_back(0xda);
            write16((uint16_t)len);
        } else {
            buffer.push_back(0xdb);
            write32((uint32_t)len);
        }
        buffer.insert(buffer.end(), s.begin(), s.end());
    }

    void writeBinary(const std::vector<uint8_t>& bin) {
        size_t len = bin.size();
        if (len <= 0xff) {
            buffer.push_back(0xc4);
            buffer.push_back((uint8_t)len);
        } else if (len <= 0xffff) {
            buffer.push_back(0xc5);
            write16((uint16_t)len);
        } else {
            buffer.push_back(0xc6);
            write32((uint32_t)len);
        }
        buffer.insert(buffer.end(), bin.begin(), bin.end());
    }

    void writeArrayHeader(size_t size) {
        if (size <= 15) {
            buffer.push_back((uint8_t)(0x90 | size));
        } else if (size <= 0xffff) {
            buffer.push_back(0xdc);
            write16((uint16_t)size);
        } else {
            buffer.push_back(0xdd);
            write32((uint32_t)size);
        }
    }

    void writeMapHeader(size_t size) {
        if (size <= 15) {
            buffer.push_back((uint8_t)(0x80 | size));
        } else if (size <= 0xffff) {
            buffer.push_back(0xde);
            write16((uint16_t)size);
        } else {
            buffer.push_back(0xdf);
            write32((uint32_t)size);
        }
    }

    void writeValue(const Value& v) {
        switch (v.type) {
            case Type::NIL:    writeNil(); break;
            case Type::BOOL:   writeBool(v.b); break;
            case Type::INT:    writeInt(v.i64); break;
            case Type::UINT:   writeUInt(v.u64); break;
            case Type::FLOAT:
            case Type::DOUBLE: writeDouble(v.f64); break;
            case Type::STR:    writeString(v.str); break;
            case Type::BIN:    writeBinary(v.bin); break;
            case Type::ARRAY:
                writeArrayHeader(v.arr.size());
                for (const auto& item : v.arr) writeValue(item);
                break;
            case Type::MAP:
                writeMapHeader(v.map.size());
                for (const auto& item : v.map) {
                    writeString(item.first);
                    writeValue(item.second);
                }
                break;
        }
    }

private:
    void write16(uint16_t v) {
        buffer.push_back((uint8_t)(v >> 8));
        buffer.push_back((uint8_t)v);
    }
    void write32(uint32_t v) {
        buffer.push_back((uint8_t)(v >> 24));
        buffer.push_back((uint8_t)(v >> 16));
        buffer.push_back((uint8_t)(v >> 8));
        buffer.push_back((uint8_t)v);
    }
    void write64(uint64_t v) {
        for (int i = 7; i >= 0; i--) {
            buffer.push_back((uint8_t)(v >> (i * 8)));
        }
    }
};

// Parser
class Reader {
public:
    const uint8_t* data;
    size_t size;
    size_t pos = 0;

    Reader(const void* buf, size_t len)
        : data(static_cast<const uint8_t*>(buf)), size(len) {}

    bool readValue(Value& out) {
        if (pos >= size) return false;
        uint8_t tag = data[pos++];

        // positive fixint
        if (tag <= 0x7f) {
            out = Value((int64_t)tag);
            return true;
        }
        // fixmap
        if ((tag & 0xf0) == 0x80) {
            size_t count = tag & 0x0f;
            return readMap(count, out);
        }
        // fixarray
        if ((tag & 0xf0) == 0x90) {
            size_t count = tag & 0x0f;
            return readArray(count, out);
        }
        // fixstr
        if ((tag & 0xe0) == 0xa0) {
            size_t len = tag & 0x1f;
            return readStringContent(len, out);
        }
        // negative fixint
        if ((tag & 0xe0) == 0xe0) {
            out = Value((int64_t)(int8_t)tag);
            return true;
        }

        switch (tag) {
            case 0xc0: out = Value(); return true; // nil
            case 0xc2: out = Value(false); return true;
            case 0xc3: out = Value(true); return true;
            case 0xcc: { // uint8
                uint8_t v; if (!read8(v)) return false;
                out = Value((uint64_t)v); return true;
            }
            case 0xcd: { // uint16
                uint16_t v; if (!read16(v)) return false;
                out = Value((uint64_t)v); return true;
            }
            case 0xce: { // uint32
                uint32_t v; if (!read32(v)) return false;
                out = Value((uint64_t)v); return true;
            }
            case 0xcf: { // uint64
                uint64_t v; if (!read64(v)) return false;
                out = Value(v); return true;
            }
            case 0xd0: { // int8
                int8_t v; if (!read8((uint8_t&)v)) return false;
                out = Value((int64_t)v); return true;
            }
            case 0xd1: { // int16
                int16_t v; if (!read16((uint16_t&)v)) return false;
                out = Value((int64_t)v); return true;
            }
            case 0xd2: { // int32
                int32_t v; if (!read32((uint32_t&)v)) return false;
                out = Value((int64_t)v); return true;
            }
            case 0xd3: { // int64
                int64_t v; if (!read64((uint64_t&)v)) return false;
                out = Value(v); return true;
            }
            case 0xcb: { // float64
                uint64_t u; if (!read64(u)) return false;
                double d; std::memcpy(&d, &u, sizeof(d));
                out = Value(d); return true;
            }
            case 0xd9: { // str8
                uint8_t len; if (!read8(len)) return false;
                return readStringContent(len, out);
            }
            case 0xda: { // str16
                uint16_t len; if (!read16(len)) return false;
                return readStringContent(len, out);
            }
            case 0xdb: { // str32
                uint32_t len; if (!read32(len)) return false;
                return readStringContent(len, out);
            }
            case 0xdc: { // array16
                uint16_t count; if (!read16(count)) return false;
                return readArray(count, out);
            }
            case 0xdd: { // array32
                uint32_t count; if (!read32(count)) return false;
                return readArray(count, out);
            }
            case 0xde: { // map16
                uint16_t count; if (!read16(count)) return false;
                return readMap(count, out);
            }
            case 0xdf: { // map32
                uint32_t count; if (!read32(count)) return false;
                return readMap(count, out);
            }
            default:
                return false;
        }
    }

private:
    bool read8(uint8_t& out) {
        if (pos >= size) return false;
        out = data[pos++];
        return true;
    }
    bool read16(uint16_t& out) {
        if (pos + 2 > size) return false;
        out = ((uint16_t)data[pos] << 8) | data[pos + 1];
        pos += 2;
        return true;
    }
    bool read32(uint32_t& out) {
        if (pos + 4 > size) return false;
        out = ((uint32_t)data[pos] << 24) |
              ((uint32_t)data[pos + 1] << 16) |
              ((uint32_t)data[pos + 2] << 8) |
              data[pos + 3];
        pos += 4;
        return true;
    }
    bool read64(uint64_t& out) {
        if (pos + 8 > size) return false;
        out = 0;
        for (int i = 0; i < 8; i++) {
            out = (out << 8) | data[pos + i];
        }
        pos += 8;
        return true;
    }
    bool readStringContent(size_t len, Value& out) {
        if (pos + len > size) return false;
        out.type = Type::STR;
        out.str.assign(reinterpret_cast<const char*>(data + pos), len);
        pos += len;
        return true;
    }
    bool readArray(size_t count, Value& out) {
        out.type = Type::ARRAY;
        out.arr.clear();
        out.arr.reserve(count);
        for (size_t i = 0; i < count; i++) {
            Value item;
            if (!readValue(item)) return false;
            out.arr.push_back(std::move(item));
        }
        return true;
    }
    bool readMap(size_t count, Value& out) {
        out.type = Type::MAP;
        out.map.clear();
        out.map.reserve(count);
        for (size_t i = 0; i < count; i++) {
            Value key;
            if (!readValue(key) || key.type != Type::STR) return false;
            Value val;
            if (!readValue(val)) return false;
            out.map.emplace_back(std::move(key.str), std::move(val));
        }
        return true;
    }
};

}} // namespace artpi::msgpack

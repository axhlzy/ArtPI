//
// pi_dex_writer.cpp - Runtime Dalvik bytecode generator based on Dexter (Slicer)
//

#include "pi_dex_writer.h"

#include <algorithm>
#include <cctype>
#include <set>
#include <sstream>

namespace PI {
namespace DexWriter {

namespace {

std::string Trim(const std::string& str) {
    size_t start = 0;
    while (start < str.size() && std::isspace(static_cast<unsigned char>(str[start]))) {
        ++start;
    }
    size_t end = str.size();
    while (end > start && std::isspace(static_cast<unsigned char>(str[end - 1]))) {
        --end;
    }
    return str.substr(start, end - start);
}

} // namespace

// Canonicalizes class names into descriptors: "java.lang.String" -> "Ljava/lang/String;"
std::string NormalizeType(const std::string& raw) {
    std::string s = Trim(raw);
    if (s.empty()) return "V";
    if (s == "void" || s == "V") return "V";
    if (s == "boolean" || s == "Z") return "Z";
    if (s == "byte" || s == "B") return "B";
    if (s == "short" || s == "S") return "S";
    if (s == "char" || s == "C") return "C";
    if (s == "int" || s == "I") return "I";
    if (s == "long" || s == "J") return "J";
    if (s == "float" || s == "F") return "F";
    if (s == "double" || s == "D") return "D";

    if (s.front() == '[') {
        std::string elem = NormalizeType(s.substr(1));
        return "[" + elem;
    }

    if (s.front() == 'L' && s.back() == ';') {
        for (char& c : s) if (c == '.') c = '/';
        return s;
    }

    for (char& c : s) if (c == '.') c = '/';
    return "L" + s + ";";
}

namespace {

// Parses "Lcom/foo/Bar;->method(I)V" or "com.foo.Bar.method(I)V"
bool ParseMethodSpec(const std::string& raw,
                     std::string* out_parent,
                     std::string* out_name,
                     std::string* out_sig) {
    std::string s = Trim(raw);
    size_t arrow = s.find("->");
    if (arrow != std::string::npos) {
        *out_parent = NormalizeType(s.substr(0, arrow));
        std::string rest = s.substr(arrow + 2);
        size_t lparen = rest.find('(');
        if (lparen == std::string::npos) return false;
        *out_name = rest.substr(0, lparen);
        *out_sig = rest.substr(lparen);
        return true;
    }

    // Try dotted form: "com.foo.Bar.method(I)V"
    size_t lparen = s.find('(');
    if (lparen == std::string::npos) return false;
    std::string full_name = s.substr(0, lparen);
    *out_sig = s.substr(lparen);

    size_t last_dot = full_name.find_last_of("./");
    if (last_dot == std::string::npos) return false;
    *out_parent = NormalizeType(full_name.substr(0, last_dot));
    *out_name = full_name.substr(last_dot + 1);
    return true;
}

// Parses "Lcom/foo/Bar;->field:I" or "com.foo.Bar.field:I"
bool ParseFieldSpec(const std::string& raw,
                    std::string* out_parent,
                    std::string* out_name,
                    std::string* out_type) {
    std::string s = Trim(raw);
    size_t colon = s.find_last_of(':');
    if (colon == std::string::npos) return false;
    *out_type = NormalizeType(s.substr(colon + 1));
    std::string prefix = s.substr(0, colon);

    size_t arrow = prefix.find("->");
    if (arrow != std::string::npos) {
        *out_parent = NormalizeType(prefix.substr(0, arrow));
        *out_name = prefix.substr(arrow + 2);
        return true;
    }

    size_t last_dot = prefix.find_last_of("./");
    if (last_dot == std::string::npos) return false;
    *out_parent = NormalizeType(prefix.substr(0, last_dot));
    *out_name = prefix.substr(last_dot + 1);
    return true;
}

} // namespace

Writer::Writer() {}

void Writer::SetRegisters(uint16_t total, uint16_t ins, uint16_t outs) {
    registers_ = std::max<uint16_t>(total, ins);
    ins_ = ins;
    outs_ = outs;
}

int Writer::MakeLabel() {
    return next_label_id_++;
}

bool Writer::PutLabel(int label_id) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Label;
    si.label_id = label_id;
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutGoto(int label_id) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_GOTO;
    SymbolicOperand op;
    op.kind = OperandKind::LabelTarget;
    op.label_id = label_id;
    si.operands.push_back(op);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutIfEqz(uint32_t reg, int label_id) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_IF_EQZ;
    SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
    SymbolicOperand l; l.kind = OperandKind::LabelTarget; l.label_id = label_id;
    si.operands.push_back(r);
    si.operands.push_back(l);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutIfNez(uint32_t reg, int label_id) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_IF_NEZ;
    SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
    SymbolicOperand l; l.kind = OperandKind::LabelTarget; l.label_id = label_id;
    si.operands.push_back(r);
    si.operands.push_back(l);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutIfLtz(uint32_t reg, int label_id) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_IF_LTZ;
    SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
    SymbolicOperand l; l.kind = OperandKind::LabelTarget; l.label_id = label_id;
    si.operands.push_back(r);
    si.operands.push_back(l);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutIfGez(uint32_t reg, int label_id) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_IF_GEZ;
    SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
    SymbolicOperand l; l.kind = OperandKind::LabelTarget; l.label_id = label_id;
    si.operands.push_back(r);
    si.operands.push_back(l);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutIfGtz(uint32_t reg, int label_id) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_IF_GTZ;
    SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
    SymbolicOperand l; l.kind = OperandKind::LabelTarget; l.label_id = label_id;
    si.operands.push_back(r);
    si.operands.push_back(l);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutIfLez(uint32_t reg, int label_id) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_IF_LEZ;
    SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
    SymbolicOperand l; l.kind = OperandKind::LabelTarget; l.label_id = label_id;
    si.operands.push_back(r);
    si.operands.push_back(l);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutIfEq(uint32_t reg1, uint32_t reg2, int label_id) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_IF_EQ;
    SymbolicOperand r1; r1.kind = OperandKind::VReg; r1.reg = reg1;
    SymbolicOperand r2; r2.kind = OperandKind::VReg; r2.reg = reg2;
    SymbolicOperand l; l.kind = OperandKind::LabelTarget; l.label_id = label_id;
    si.operands.push_back(r1);
    si.operands.push_back(r2);
    si.operands.push_back(l);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutIfNe(uint32_t reg1, uint32_t reg2, int label_id) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_IF_NE;
    SymbolicOperand r1; r1.kind = OperandKind::VReg; r1.reg = reg1;
    SymbolicOperand r2; r2.kind = OperandKind::VReg; r2.reg = reg2;
    SymbolicOperand l; l.kind = OperandKind::LabelTarget; l.label_id = label_id;
    si.operands.push_back(r1);
    si.operands.push_back(r2);
    si.operands.push_back(l);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutIfLt(uint32_t reg1, uint32_t reg2, int label_id) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_IF_LT;
    SymbolicOperand r1; r1.kind = OperandKind::VReg; r1.reg = reg1;
    SymbolicOperand r2; r2.kind = OperandKind::VReg; r2.reg = reg2;
    SymbolicOperand l; l.kind = OperandKind::LabelTarget; l.label_id = label_id;
    si.operands.push_back(r1);
    si.operands.push_back(r2);
    si.operands.push_back(l);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutIfGe(uint32_t reg1, uint32_t reg2, int label_id) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_IF_GE;
    SymbolicOperand r1; r1.kind = OperandKind::VReg; r1.reg = reg1;
    SymbolicOperand r2; r2.kind = OperandKind::VReg; r2.reg = reg2;
    SymbolicOperand l; l.kind = OperandKind::LabelTarget; l.label_id = label_id;
    si.operands.push_back(r1);
    si.operands.push_back(r2);
    si.operands.push_back(l);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutIfGt(uint32_t reg1, uint32_t reg2, int label_id) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_IF_GT;
    SymbolicOperand r1; r1.kind = OperandKind::VReg; r1.reg = reg1;
    SymbolicOperand r2; r2.kind = OperandKind::VReg; r2.reg = reg2;
    SymbolicOperand l; l.kind = OperandKind::LabelTarget; l.label_id = label_id;
    si.operands.push_back(r1);
    si.operands.push_back(r2);
    si.operands.push_back(l);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutIfLe(uint32_t reg1, uint32_t reg2, int label_id) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_IF_LE;
    SymbolicOperand r1; r1.kind = OperandKind::VReg; r1.reg = reg1;
    SymbolicOperand r2; r2.kind = OperandKind::VReg; r2.reg = reg2;
    SymbolicOperand l; l.kind = OperandKind::LabelTarget; l.label_id = label_id;
    si.operands.push_back(r1);
    si.operands.push_back(r2);
    si.operands.push_back(l);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutConst4(uint32_t reg, int32_t val) {
    if (reg > 15 || val < -8 || val > 7) {
        return PutConst(reg, val);
    }
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_CONST_4;
    SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
    SymbolicOperand c; c.kind = OperandKind::Const32; c.const32 = val;
    si.operands.push_back(r);
    si.operands.push_back(c);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutConst16(uint32_t reg, int32_t val) {
    if (reg > 255 || val < -32768 || val > 32767) {
        return PutConst(reg, val);
    }
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_CONST_16;
    SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
    SymbolicOperand c; c.kind = OperandKind::Const32; c.const32 = val;
    si.operands.push_back(r);
    si.operands.push_back(c);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutConst(uint32_t reg, int32_t val) {
    if (reg <= 15 && val >= -8 && val <= 7) {
        SymbolicInstruction si;
        si.kind = SymbolicInstruction::Kind::Bytecode;
        si.opcode = dex::OP_CONST_4;
        SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
        SymbolicOperand c; c.kind = OperandKind::Const32; c.const32 = val;
        si.operands.push_back(r);
        si.operands.push_back(c);
        instructions_.push_back(std::move(si));
        return true;
    }
    if (reg <= 255 && val >= -32768 && val <= 32767) {
        SymbolicInstruction si;
        si.kind = SymbolicInstruction::Kind::Bytecode;
        si.opcode = dex::OP_CONST_16;
        SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
        SymbolicOperand c; c.kind = OperandKind::Const32; c.const32 = val;
        si.operands.push_back(r);
        si.operands.push_back(c);
        instructions_.push_back(std::move(si));
        return true;
    }

    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_CONST;
    SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
    SymbolicOperand c; c.kind = OperandKind::Const32; c.const32 = val;
    si.operands.push_back(r);
    si.operands.push_back(c);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutConstString(uint32_t reg, const std::string& str) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_CONST_STRING;
    SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
    SymbolicOperand s; s.kind = OperandKind::String; s.str_val = str;
    si.operands.push_back(r);
    si.operands.push_back(s);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutConstClass(uint32_t reg, const std::string& type_name) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_CONST_CLASS;
    SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
    SymbolicOperand t; t.kind = OperandKind::Type; t.str_val = NormalizeType(type_name);
    si.operands.push_back(r);
    si.operands.push_back(t);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutMove(uint32_t dst, uint32_t src) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    if (dst <= 15 && src <= 15) {
        si.opcode = dex::OP_MOVE;
    } else if (dst <= 255 && src <= 65535) {
        si.opcode = dex::OP_MOVE_FROM16;
    } else {
        si.opcode = dex::OP_MOVE_16;
    }
    SymbolicOperand d; d.kind = OperandKind::VReg; d.reg = dst;
    SymbolicOperand s; s.kind = OperandKind::VReg; s.reg = src;
    si.operands.push_back(d);
    si.operands.push_back(s);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutMoveObject(uint32_t dst, uint32_t src) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    if (dst <= 15 && src <= 15) {
        si.opcode = dex::OP_MOVE_OBJECT;
    } else if (dst <= 255 && src <= 65535) {
        si.opcode = dex::OP_MOVE_OBJECT_FROM16;
    } else {
        si.opcode = dex::OP_MOVE_OBJECT_16;
    }
    SymbolicOperand d; d.kind = OperandKind::VReg; d.reg = dst;
    SymbolicOperand s; s.kind = OperandKind::VReg; s.reg = src;
    si.operands.push_back(d);
    si.operands.push_back(s);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutMoveResult(uint32_t dst) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_MOVE_RESULT;
    SymbolicOperand d; d.kind = OperandKind::VReg; d.reg = dst;
    si.operands.push_back(d);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutMoveResultObject(uint32_t dst) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_MOVE_RESULT_OBJECT;
    SymbolicOperand d; d.kind = OperandKind::VReg; d.reg = dst;
    si.operands.push_back(d);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutReturnVoid() {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_RETURN_VOID;
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutReturn(uint32_t reg) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_RETURN;
    SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
    si.operands.push_back(r);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutReturnObject(uint32_t reg) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_RETURN_OBJECT;
    SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
    si.operands.push_back(r);
    instructions_.push_back(std::move(si));
    return true;
}

static bool PutInvokeInternal(std::vector<SymbolicInstruction>* instructions,
                              dex::Opcode opcode,
                              const std::string& method_sig,
                              const std::vector<uint32_t>& regs,
                              uint16_t* outs) {
    if (regs.size() > 5) return false;
    for (uint32_t r : regs) {
        if (r > 15) return false;
    }

    std::string parent, name, sig;
    if (!ParseMethodSpec(method_sig, &parent, &name, &sig)) return false;

    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = opcode;

    SymbolicOperand r;
    r.kind = OperandKind::VRegList;
    r.reg_list = regs;

    SymbolicOperand m;
    m.kind = OperandKind::Method;
    m.str_val = parent;
    m.extra_type = name;
    m.extra_sig = sig;

    si.operands.push_back(r);
    si.operands.push_back(m);
    instructions->push_back(std::move(si));

    if (outs != nullptr) {
        *outs = std::max<uint16_t>(*outs, static_cast<uint16_t>(regs.size()));
    }
    return true;
}

bool Writer::PutInvokeVirtual(const std::string& method_sig, const std::vector<uint32_t>& regs) {
    return PutInvokeInternal(&instructions_, dex::OP_INVOKE_VIRTUAL, method_sig, regs, &outs_);
}

bool Writer::PutInvokeDirect(const std::string& method_sig, const std::vector<uint32_t>& regs) {
    return PutInvokeInternal(&instructions_, dex::OP_INVOKE_DIRECT, method_sig, regs, &outs_);
}

bool Writer::PutInvokeStatic(const std::string& method_sig, const std::vector<uint32_t>& regs) {
    return PutInvokeInternal(&instructions_, dex::OP_INVOKE_STATIC, method_sig, regs, &outs_);
}

bool Writer::PutInvokeSuper(const std::string& method_sig, const std::vector<uint32_t>& regs) {
    return PutInvokeInternal(&instructions_, dex::OP_INVOKE_SUPER, method_sig, regs, &outs_);
}

bool Writer::PutInvokeInterface(const std::string& method_sig, const std::vector<uint32_t>& regs) {
    return PutInvokeInternal(&instructions_, dex::OP_INVOKE_INTERFACE, method_sig, regs, &outs_);
}

bool Writer::PutNewInstance(uint32_t reg, const std::string& type_name) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_NEW_INSTANCE;
    SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
    SymbolicOperand t; t.kind = OperandKind::Type; t.str_val = NormalizeType(type_name);
    si.operands.push_back(r);
    si.operands.push_back(t);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutCheckCast(uint32_t reg, const std::string& type_name) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_CHECK_CAST;
    SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
    SymbolicOperand t; t.kind = OperandKind::Type; t.str_val = NormalizeType(type_name);
    si.operands.push_back(r);
    si.operands.push_back(t);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutInstanceOf(uint32_t dst_reg, uint32_t obj_reg, const std::string& type_name) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_INSTANCE_OF;
    SymbolicOperand d; d.kind = OperandKind::VReg; d.reg = dst_reg;
    SymbolicOperand o; o.kind = OperandKind::VReg; o.reg = obj_reg;
    SymbolicOperand t; t.kind = OperandKind::Type; t.str_val = NormalizeType(type_name);
    si.operands.push_back(d);
    si.operands.push_back(o);
    si.operands.push_back(t);
    instructions_.push_back(std::move(si));
    return true;
}

static bool PutIFieldInternal(std::vector<SymbolicInstruction>* instructions,
                              dex::Opcode opcode,
                              uint32_t val_reg,
                              uint32_t obj_reg,
                              const std::string& field_spec) {
    std::string parent, name, type;
    if (!ParseFieldSpec(field_spec, &parent, &name, &type)) return false;

    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = opcode;

    SymbolicOperand v; v.kind = OperandKind::VReg; v.reg = val_reg;
    SymbolicOperand o; o.kind = OperandKind::VReg; o.reg = obj_reg;
    SymbolicOperand f; f.kind = OperandKind::Field; f.str_val = parent; f.extra_type = name; f.extra_sig = type;

    si.operands.push_back(v);
    si.operands.push_back(o);
    si.operands.push_back(f);
    instructions->push_back(std::move(si));
    return true;
}

bool Writer::PutIget(uint32_t val_reg, uint32_t obj_reg, const std::string& field_spec) {
    return PutIFieldInternal(&instructions_, dex::OP_IGET, val_reg, obj_reg, field_spec);
}

bool Writer::PutIput(uint32_t val_reg, uint32_t obj_reg, const std::string& field_spec) {
    return PutIFieldInternal(&instructions_, dex::OP_IPUT, val_reg, obj_reg, field_spec);
}

bool Writer::PutIgetObject(uint32_t val_reg, uint32_t obj_reg, const std::string& field_spec) {
    return PutIFieldInternal(&instructions_, dex::OP_IGET_OBJECT, val_reg, obj_reg, field_spec);
}

bool Writer::PutIputObject(uint32_t val_reg, uint32_t obj_reg, const std::string& field_spec) {
    return PutIFieldInternal(&instructions_, dex::OP_IPUT_OBJECT, val_reg, obj_reg, field_spec);
}

bool Writer::PutIgetBoolean(uint32_t val_reg, uint32_t obj_reg, const std::string& field_spec) {
    return PutIFieldInternal(&instructions_, dex::OP_IGET_BOOLEAN, val_reg, obj_reg, field_spec);
}

bool Writer::PutIputBoolean(uint32_t val_reg, uint32_t obj_reg, const std::string& field_spec) {
    return PutIFieldInternal(&instructions_, dex::OP_IPUT_BOOLEAN, val_reg, obj_reg, field_spec);
}

static bool PutSFieldInternal(std::vector<SymbolicInstruction>* instructions,
                              dex::Opcode opcode,
                              uint32_t val_reg,
                              const std::string& field_spec) {
    std::string parent, name, type;
    if (!ParseFieldSpec(field_spec, &parent, &name, &type)) return false;

    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = opcode;

    SymbolicOperand v; v.kind = OperandKind::VReg; v.reg = val_reg;
    SymbolicOperand f; f.kind = OperandKind::Field; f.str_val = parent; f.extra_type = name; f.extra_sig = type;

    si.operands.push_back(v);
    si.operands.push_back(f);
    instructions->push_back(std::move(si));
    return true;
}

bool Writer::PutSget(uint32_t val_reg, const std::string& field_spec) {
    return PutSFieldInternal(&instructions_, dex::OP_SGET, val_reg, field_spec);
}

bool Writer::PutSput(uint32_t val_reg, const std::string& field_spec) {
    return PutSFieldInternal(&instructions_, dex::OP_SPUT, val_reg, field_spec);
}

bool Writer::PutSgetObject(uint32_t val_reg, const std::string& field_spec) {
    return PutSFieldInternal(&instructions_, dex::OP_SGET_OBJECT, val_reg, field_spec);
}

bool Writer::PutSputObject(uint32_t val_reg, const std::string& field_spec) {
    return PutSFieldInternal(&instructions_, dex::OP_SPUT_OBJECT, val_reg, field_spec);
}

bool Writer::PutThrow(uint32_t reg) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = dex::OP_THROW;
    SymbolicOperand r; r.kind = OperandKind::VReg; r.reg = reg;
    si.operands.push_back(r);
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutNop() {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Nop;
    si.opcode = dex::OP_NOP;
    instructions_.push_back(std::move(si));
    return true;
}

bool Writer::PutBinaryOp(dex::Opcode op, uint32_t dst, uint32_t src1, uint32_t src2) {
    SymbolicInstruction si;
    si.kind = SymbolicInstruction::Kind::Bytecode;
    si.opcode = op;
    SymbolicOperand d; d.kind = OperandKind::VReg; d.reg = dst;
    SymbolicOperand s1; s1.kind = OperandKind::VReg; s1.reg = src1;
    SymbolicOperand s2; s2.kind = OperandKind::VReg; s2.reg = src2;
    si.operands.push_back(d);
    si.operands.push_back(s1);
    si.operands.push_back(s2);
    instructions_.push_back(std::move(si));
    return true;
}

// ---------------------------------------------------------------------------
// Smali Text Parser (Option B)
// ---------------------------------------------------------------------------

namespace {

int ParseRegister(const std::string& token, uint16_t totalRegs, uint16_t insRegs) {
    if (token.empty()) return -1;
    char prefix = token[0];
    if (prefix != 'v' && prefix != 'p' && prefix != 'V' && prefix != 'P') return -1;
    int num = std::atoi(token.c_str() + 1);
    if (num < 0) return -1;
    if (prefix == 'v' || prefix == 'V') return num;
    // pX parameter registers: p0 is v(total - ins)
    int base = static_cast<int>(totalRegs) - static_cast<int>(insRegs);
    if (base < 0) base = 0;
    return base + num;
}

int64_t ParseLiteral(const std::string& token) {
    std::string s = Trim(token);
    if (s.empty()) return 0;
    if (s.size() > 2 && (s.substr(0, 2) == "0x" || s.substr(0, 2) == "0X")) {
        return std::strtoll(s.c_str(), nullptr, 16);
    }
    return std::strtoll(s.c_str(), nullptr, 10);
}

std::vector<std::string> TokenizeLine(const std::string& line) {
    std::vector<std::string> tokens;
    std::string cur;
    bool in_quote = false;
    bool escaped = false;

    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (in_quote) {
            if (escaped) {
                if (c == 'n') cur += '\n';
                else if (c == 'r') cur += '\r';
                else if (c == 't') cur += '\t';
                else cur += c;
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_quote = false;
                tokens.push_back(cur);
                cur.clear();
            } else {
                cur += c;
            }
            continue;
        }

        if (c == '#') break; // Comment
        if (c == '"') {
            in_quote = true;
            continue;
        }

        if (std::isspace(static_cast<unsigned char>(c)) || c == ',') {
            if (!cur.empty()) {
                tokens.push_back(cur);
                cur.clear();
            }
            continue;
        }

        if (c == '{' || c == '}') {
            if (!cur.empty()) {
                tokens.push_back(cur);
                cur.clear();
            }
            tokens.push_back(std::string(1, c));
            continue;
        }

        cur += c;
    }
    if (!cur.empty()) tokens.push_back(cur);
    return tokens;
}

} // namespace

bool Writer::EmitSmali(const std::string& smali_code, std::string* error) {
    std::istringstream stream(smali_code);
    std::string raw_line;
    int line_no = 0;

    auto getOrCreateNamedLabel = [this](const std::string& name) -> int {
        std::string n = name;
        if (!n.empty() && n.front() == ':') n = n.substr(1);
        auto it = named_labels_.find(n);
        if (it != named_labels_.end()) return it->second;
        int id = MakeLabel();
        named_labels_[n] = id;
        return id;
    };

    while (std::getline(stream, raw_line)) {
        ++line_no;
        std::string detail_err;
        std::vector<std::string> tokens = TokenizeLine(raw_line);
        if (tokens.empty()) continue;

        const std::string& op = tokens[0];

        // Directive: .registers <n>
        if (op == ".registers") {
            if (tokens.size() > 1) {
                uint16_t r = static_cast<uint16_t>(ParseLiteral(tokens[1]));
                SetRegisters(r, ins_, outs_);
            }
            continue;
        }
        // Directive: .locals <n>
        if (op == ".locals") {
            if (tokens.size() > 1) {
                uint16_t loc = static_cast<uint16_t>(ParseLiteral(tokens[1]));
                SetRegisters(loc + ins_, ins_, outs_);
            }
            continue;
        }

        // Label: :label_name
        if (op.front() == ':') {
            int lbl = getOrCreateNamedLabel(op);
            PutLabel(lbl);
            continue;
        }

        // Instructions
        bool ok = true;
        if (op == "return-void") {
            ok = PutReturnVoid();
        } else if (op == "return") {
            if (tokens.size() < 2) goto syntax_err;
            int r = ParseRegister(tokens[1], registers_, ins_);
            if (r < 0) goto syntax_err;
            ok = PutReturn(r);
        } else if (op == "return-object") {
            if (tokens.size() < 2) goto syntax_err;
            int r = ParseRegister(tokens[1], registers_, ins_);
            if (r < 0) goto syntax_err;
            ok = PutReturnObject(r);
        } else if (op == "const/4" || op == "const/16" || op == "const") {
            if (tokens.size() < 3) goto syntax_err;
            int r = ParseRegister(tokens[1], registers_, ins_);
            int32_t val = static_cast<int32_t>(ParseLiteral(tokens[2]));
            if (r < 0) goto syntax_err;
            if (op == "const/4") ok = PutConst4(r, val);
            else if (op == "const/16") ok = PutConst16(r, val);
            else ok = PutConst(r, val);
        } else if (op == "const-string") {
            if (tokens.size() < 3) goto syntax_err;
            int r = ParseRegister(tokens[1], registers_, ins_);
            if (r < 0) goto syntax_err;
            ok = PutConstString(r, tokens[2]);
        } else if (op == "const-class") {
            if (tokens.size() < 3) goto syntax_err;
            int r = ParseRegister(tokens[1], registers_, ins_);
            if (r < 0) goto syntax_err;
            ok = PutConstClass(r, tokens[2]);
        } else if (op == "move") {
            if (tokens.size() < 3) goto syntax_err;
            int d = ParseRegister(tokens[1], registers_, ins_);
            int s = ParseRegister(tokens[2], registers_, ins_);
            if (d < 0 || s < 0) goto syntax_err;
            ok = PutMove(d, s);
        } else if (op == "move-object") {
            if (tokens.size() < 3) goto syntax_err;
            int d = ParseRegister(tokens[1], registers_, ins_);
            int s = ParseRegister(tokens[2], registers_, ins_);
            if (d < 0 || s < 0) goto syntax_err;
            ok = PutMoveObject(d, s);
        } else if (op == "move-result") {
            if (tokens.size() < 2) goto syntax_err;
            int d = ParseRegister(tokens[1], registers_, ins_);
            if (d < 0) goto syntax_err;
            ok = PutMoveResult(d);
        } else if (op == "move-result-object") {
            if (tokens.size() < 2) goto syntax_err;
            int d = ParseRegister(tokens[1], registers_, ins_);
            if (d < 0) goto syntax_err;
            ok = PutMoveResultObject(d);
        } else if (op == "goto") {
            if (tokens.size() < 2) goto syntax_err;
            int l = getOrCreateNamedLabel(tokens[1]);
            ok = PutGoto(l);
        } else if (op == "if-eqz") {
            if (tokens.size() < 3) goto syntax_err;
            int r = ParseRegister(tokens[1], registers_, ins_);
            int l = getOrCreateNamedLabel(tokens[2]);
            ok = PutIfEqz(r, l);
        } else if (op == "if-nez") {
            if (tokens.size() < 3) goto syntax_err;
            int r = ParseRegister(tokens[1], registers_, ins_);
            int l = getOrCreateNamedLabel(tokens[2]);
            ok = PutIfNez(r, l);
        } else if (op == "if-eq") {
            if (tokens.size() < 4) goto syntax_err;
            int r1 = ParseRegister(tokens[1], registers_, ins_);
            int r2 = ParseRegister(tokens[2], registers_, ins_);
            int l = getOrCreateNamedLabel(tokens[3]);
            ok = PutIfEq(r1, r2, l);
        } else if (op == "if-ne") {
            if (tokens.size() < 4) goto syntax_err;
            int r1 = ParseRegister(tokens[1], registers_, ins_);
            int r2 = ParseRegister(tokens[2], registers_, ins_);
            int l = getOrCreateNamedLabel(tokens[3]);
            ok = PutIfNe(r1, r2, l);
        } else if (op == "if-ltz") {
            if (tokens.size() < 3) goto syntax_err;
            int r = ParseRegister(tokens[1], registers_, ins_);
            int l = getOrCreateNamedLabel(tokens[2]);
            ok = PutIfLtz(r, l);
        } else if (op == "if-gez") {
            if (tokens.size() < 3) goto syntax_err;
            int r = ParseRegister(tokens[1], registers_, ins_);
            int l = getOrCreateNamedLabel(tokens[2]);
            ok = PutIfGez(r, l);
        } else if (op == "if-gtz") {
            if (tokens.size() < 3) goto syntax_err;
            int r = ParseRegister(tokens[1], registers_, ins_);
            int l = getOrCreateNamedLabel(tokens[2]);
            ok = PutIfGtz(r, l);
        } else if (op == "if-lez") {
            if (tokens.size() < 3) goto syntax_err;
            int r = ParseRegister(tokens[1], registers_, ins_);
            int l = getOrCreateNamedLabel(tokens[2]);
            ok = PutIfLez(r, l);
        } else if (op == "if-lt") {
            if (tokens.size() < 4) goto syntax_err;
            int r1 = ParseRegister(tokens[1], registers_, ins_);
            int r2 = ParseRegister(tokens[2], registers_, ins_);
            int l = getOrCreateNamedLabel(tokens[3]);
            ok = PutIfLt(r1, r2, l);
        } else if (op == "if-ge") {
            if (tokens.size() < 4) goto syntax_err;
            int r1 = ParseRegister(tokens[1], registers_, ins_);
            int r2 = ParseRegister(tokens[2], registers_, ins_);
            int l = getOrCreateNamedLabel(tokens[3]);
            ok = PutIfGe(r1, r2, l);
        } else if (op == "if-gt") {
            if (tokens.size() < 4) goto syntax_err;
            int r1 = ParseRegister(tokens[1], registers_, ins_);
            int r2 = ParseRegister(tokens[2], registers_, ins_);
            int l = getOrCreateNamedLabel(tokens[3]);
            ok = PutIfGt(r1, r2, l);
        } else if (op == "if-le") {
            if (tokens.size() < 4) goto syntax_err;
            int r1 = ParseRegister(tokens[1], registers_, ins_);
            int r2 = ParseRegister(tokens[2], registers_, ins_);
            int l = getOrCreateNamedLabel(tokens[3]);
            ok = PutIfLe(r1, r2, l);
        } else if (op.rfind("invoke-", 0) == 0) {
            std::vector<uint32_t> regs;
            size_t idx = 1;
            if (idx < tokens.size() && tokens[idx] == "{") {
                ++idx;
                while (idx < tokens.size() && tokens[idx] != "}") {
                    int r = ParseRegister(tokens[idx], registers_, ins_);
                    if (r >= 0) regs.push_back(r);
                    ++idx;
                }
                if (idx < tokens.size() && tokens[idx] == "}") ++idx;
            }
            if (regs.size() > 5) {
                detail_err = "invoke register list exceeds DEX limit of 5 (got " + std::to_string(regs.size()) + ")";
                goto syntax_err;
            }
            if (idx >= tokens.size()) {
                detail_err = "missing target method in invoke instruction";
                goto syntax_err;
            }
            const std::string& meth = tokens[idx];
            if (op == "invoke-virtual") ok = PutInvokeVirtual(meth, regs);
            else if (op == "invoke-direct") ok = PutInvokeDirect(meth, regs);
            else if (op == "invoke-static") ok = PutInvokeStatic(meth, regs);
            else if (op == "invoke-super") ok = PutInvokeSuper(meth, regs);
            else if (op == "invoke-interface") ok = PutInvokeInterface(meth, regs);
            else {
                detail_err = "unsupported invoke opcode: " + op;
                goto syntax_err;
            }
            if (!ok && detail_err.empty()) {
                detail_err = "failed to encode " + op + " (invalid signature or registers)";
            }
        } else if (op == "new-instance") {
            if (tokens.size() < 3) goto syntax_err;
            int r = ParseRegister(tokens[1], registers_, ins_);
            ok = PutNewInstance(r, tokens[2]);
        } else if (op == "check-cast") {
            if (tokens.size() < 3) goto syntax_err;
            int r = ParseRegister(tokens[1], registers_, ins_);
            ok = PutCheckCast(r, tokens[2]);
        } else if (op == "instance-of") {
            if (tokens.size() < 4) goto syntax_err;
            int d = ParseRegister(tokens[1], registers_, ins_);
            int o = ParseRegister(tokens[2], registers_, ins_);
            ok = PutInstanceOf(d, o, tokens[3]);
        } else if (op == "iget") {
            if (tokens.size() < 4) goto syntax_err;
            int v = ParseRegister(tokens[1], registers_, ins_);
            int o = ParseRegister(tokens[2], registers_, ins_);
            ok = PutIget(v, o, tokens[3]);
        } else if (op == "iput") {
            if (tokens.size() < 4) goto syntax_err;
            int v = ParseRegister(tokens[1], registers_, ins_);
            int o = ParseRegister(tokens[2], registers_, ins_);
            ok = PutIput(v, o, tokens[3]);
        } else if (op == "iget-object") {
            if (tokens.size() < 4) goto syntax_err;
            int v = ParseRegister(tokens[1], registers_, ins_);
            int o = ParseRegister(tokens[2], registers_, ins_);
            ok = PutIgetObject(v, o, tokens[3]);
        } else if (op == "iput-object") {
            if (tokens.size() < 4) goto syntax_err;
            int v = ParseRegister(tokens[1], registers_, ins_);
            int o = ParseRegister(tokens[2], registers_, ins_);
            ok = PutIputObject(v, o, tokens[3]);
        } else if (op == "iget-boolean") {
            if (tokens.size() < 4) goto syntax_err;
            int v = ParseRegister(tokens[1], registers_, ins_);
            int o = ParseRegister(tokens[2], registers_, ins_);
            ok = PutIgetBoolean(v, o, tokens[3]);
        } else if (op == "iput-boolean") {
            if (tokens.size() < 4) goto syntax_err;
            int v = ParseRegister(tokens[1], registers_, ins_);
            int o = ParseRegister(tokens[2], registers_, ins_);
            ok = PutIputBoolean(v, o, tokens[3]);
        } else if (op == "sget") {
            if (tokens.size() < 3) goto syntax_err;
            int v = ParseRegister(tokens[1], registers_, ins_);
            ok = PutSget(v, tokens[2]);
        } else if (op == "sput") {
            if (tokens.size() < 3) goto syntax_err;
            int v = ParseRegister(tokens[1], registers_, ins_);
            ok = PutSput(v, tokens[2]);
        } else if (op == "sget-object") {
            if (tokens.size() < 3) goto syntax_err;
            int v = ParseRegister(tokens[1], registers_, ins_);
            ok = PutSgetObject(v, tokens[2]);
        } else if (op == "sput-object") {
            if (tokens.size() < 3) goto syntax_err;
            int v = ParseRegister(tokens[1], registers_, ins_);
            ok = PutSputObject(v, tokens[2]);
        } else if (op == "throw") {
            if (tokens.size() < 2) goto syntax_err;
            int r = ParseRegister(tokens[1], registers_, ins_);
            ok = PutThrow(r);
        } else if (op == "nop") {
            ok = PutNop();
        } else if (op == "add-int" || op == "sub-int" || op == "mul-int" ||
                   op == "div-int" || op == "rem-int" || op == "and-int" ||
                   op == "or-int" || op == "xor-int" || op == "shl-int" ||
                   op == "shr-int" || op == "ushr-int") {
            if (tokens.size() < 4) goto syntax_err;
            int d = ParseRegister(tokens[1], registers_, ins_);
            int s1 = ParseRegister(tokens[2], registers_, ins_);
            int s2 = ParseRegister(tokens[3], registers_, ins_);
            if (d < 0 || s1 < 0 || s2 < 0) goto syntax_err;
            dex::Opcode binOp = dex::OP_NOP;
            if (op == "add-int") binOp = dex::OP_ADD_INT;
            else if (op == "sub-int") binOp = dex::OP_SUB_INT;
            else if (op == "mul-int") binOp = dex::OP_MUL_INT;
            else if (op == "div-int") binOp = dex::OP_DIV_INT;
            else if (op == "rem-int") binOp = dex::OP_REM_INT;
            else if (op == "and-int") binOp = dex::OP_AND_INT;
            else if (op == "or-int") binOp = dex::OP_OR_INT;
            else if (op == "xor-int") binOp = dex::OP_XOR_INT;
            else if (op == "shl-int") binOp = dex::OP_SHL_INT;
            else if (op == "shr-int") binOp = dex::OP_SHR_INT;
            else if (op == "ushr-int") binOp = dex::OP_USHR_INT;
            ok = PutBinaryOp(binOp, d, s1, s2);
        } else {
            detail_err = "unrecognized or unsupported opcode '" + op + "'";
            goto syntax_err;
        }

        if (!ok) {
            if (detail_err.empty()) {
                detail_err = "failed to encode opcode '" + op + "' (check operands and register range)";
            }
            goto syntax_err;
        }
        continue;

    syntax_err:
        if (error) {
            *error = "Smali syntax error at line " + std::to_string(line_no) + ": " + raw_line;
            if (!detail_err.empty()) {
                *error += " (" + detail_err + ")";
            }
        }
        return false;
    }

    return true;
}

size_t Writer::GetBytecodeInstructionCount() const {
    size_t count = 0;
    for (const auto& si : instructions_) {
        if (si.kind == SymbolicInstruction::Kind::Bytecode) {
            ++count;
        }
    }
    return count;
}

// ---------------------------------------------------------------------------
// Dexter LIR Assembly Bridge
// ---------------------------------------------------------------------------

bool Writer::AssembleInto(IrContext* ctx,
                          ir::EncodedMethod* encoded_method,
                          ir::Code* ir_code,
                          std::string* error) {
    if (ctx == nullptr || encoded_method == nullptr || ir_code == nullptr) {
        if (error) *error = "invalid DexWriter assembly context";
        return false;
    }

    if (GetBytecodeInstructionCount() == 0) {
        if (error) *error = "empty bytecode writer (no instructions emitted)";
        return false;
    }

    // 1. Verify terminal instruction (return, throw, or goto)
    dex::Opcode last_op = dex::OP_NOP;
    for (auto it = instructions_.rbegin(); it != instructions_.rend(); ++it) {
        if (it->kind == SymbolicInstruction::Kind::Bytecode) {
            last_op = it->opcode;
            break;
        }
    }
    switch (last_op) {
        case dex::OP_RETURN_VOID:
        case dex::OP_RETURN:
        case dex::OP_RETURN_WIDE:
        case dex::OP_RETURN_OBJECT:
        case dex::OP_THROW:
        case dex::OP_GOTO:
        case dex::OP_GOTO_16:
        case dex::OP_GOTO_32:
            break;
        default:
            if (error) *error = "bytecode method must end with a return, throw, or goto instruction";
            return false;
    }

    // 2. Validate register bounds
    for (const auto& si : instructions_) {
        if (si.kind != SymbolicInstruction::Kind::Bytecode) continue;
        dex::Opcode eff_op = (si.opcode == dex::OP_GOTO) ? dex::OP_GOTO_16 : si.opcode;
        auto fmt = dex::GetFormatFromOpcode(eff_op);

        for (const auto& op : si.operands) {
            if (op.kind == OperandKind::VReg) {
                if (op.reg >= registers_) {
                    if (error) *error = "register v" + std::to_string(op.reg) + " exceeds declared register count (" + std::to_string(registers_) + ")";
                    return false;
                }
                if (fmt == dex::k12x || fmt == dex::k22c || fmt == dex::k22t) {
                    if (op.reg > 15) {
                        if (error) *error = "register v" + std::to_string(op.reg) + " exceeds 4-bit limit (0..15)";
                        return false;
                    }
                } else if (fmt == dex::k21c || fmt == dex::k21t || fmt == dex::k23x || fmt == dex::k11x || fmt == dex::k22b) {
                    if (op.reg > 255) {
                        if (error) *error = "register v" + std::to_string(op.reg) + " exceeds 8-bit limit (0..255)";
                        return false;
                    }
                }
            } else if (op.kind == OperandKind::VRegList) {
                if (op.reg_list.size() > 5) {
                    if (error) *error = "invoke instruction register list exceeds 5 registers (format 35c limit)";
                    return false;
                }
                for (uint32_t r : op.reg_list) {
                    if (r >= registers_) {
                        if (error) *error = "register v" + std::to_string(r) + " exceeds declared register count (" + std::to_string(registers_) + ")";
                        return false;
                    }
                    if (r > 15) {
                        if (error) *error = "invoke register v" + std::to_string(r) + " exceeds 4-bit limit (0..15)";
                        return false;
                    }
                }
            }
        }
    }

    // 3. Pre-calculate code unit offsets to check label existence, zero-offset branches, and 16-bit limits
    dex::u4 sim_offset = 0;
    std::map<int, dex::u4> label_sim_offsets;
    struct BranchCheck {
        dex::u4 branch_offset;
        int target_label_id;
        dex::Opcode opcode;
    };
    std::vector<BranchCheck> branch_checks;

    for (const auto& si : instructions_) {
        if (si.kind == SymbolicInstruction::Kind::Label) {
            label_sim_offsets[si.label_id] = sim_offset;
            continue;
        }
        if (si.kind == SymbolicInstruction::Kind::Nop) {
            sim_offset += 1;
            continue;
        }
        dex::u4 cur_offset = sim_offset;
        dex::Opcode eff_op = (si.opcode == dex::OP_GOTO) ? dex::OP_GOTO_16 : si.opcode;
        auto fmt = dex::GetFormatFromOpcode(eff_op);
        sim_offset += dex::GetWidthFromFormat(fmt);

        for (const auto& op : si.operands) {
            if (op.kind == OperandKind::LabelTarget) {
                branch_checks.push_back({cur_offset, op.label_id, eff_op});
            }
        }
    }

    for (const auto& bc : branch_checks) {
        auto it = label_sim_offsets.find(bc.target_label_id);
        if (it == label_sim_offsets.end()) {
            if (error) *error = "unresolved label reference in bytecode";
            return false;
        }
        dex::u4 target_offset = it->second;
        if (target_offset == bc.branch_offset) {
            if (error) *error = "branch instruction has offset 0 (branches to itself)";
            return false;
        }
        int32_t rel_offset = static_cast<int32_t>(target_offset) - static_cast<int32_t>(bc.branch_offset);
        auto fmt = dex::GetFormatFromOpcode(bc.opcode);
        if (fmt == dex::k20t || fmt == dex::k21t || fmt == dex::k22t) {
            if (rel_offset < -32768 || rel_offset > 32767) {
                if (error) *error = "16-bit branch offset out of range: " + std::to_string(rel_offset);
                return false;
            }
        }
    }

    lir::CodeIr code_ir(encoded_method, ctx->ir);
    std::map<int, lir::Label*> label_nodes;

    // Pass 1: pre-allocate all labels so forward references work
    for (const auto& si : instructions_) {
        if (si.kind == SymbolicInstruction::Kind::Label) {
            if (label_nodes.find(si.label_id) == label_nodes.end()) {
                label_nodes[si.label_id] = code_ir.Alloc<lir::Label>(0);
            }
        }
    }

    std::set<int> emitted_labels;
    // Pass 2: emit instructions and link operands
    for (const auto& si : instructions_) {
        if (si.kind == SymbolicInstruction::Kind::Label) {
            if (emitted_labels.insert(si.label_id).second) {
                auto it = label_nodes.find(si.label_id);
                if (it != label_nodes.end()) {
                    code_ir.instructions.push_back(it->second);
                }
            }
            continue;
        }

        if (si.kind == SymbolicInstruction::Kind::Nop) {
            auto* bc = code_ir.Alloc<lir::Bytecode>();
            bc->opcode = dex::OP_NOP;
            code_ir.instructions.push_back(bc);
            continue;
        }

        auto* bc = code_ir.Alloc<lir::Bytecode>();
        bc->opcode = si.opcode;

        for (const auto& op : si.operands) {
            switch (op.kind) {
                case OperandKind::VReg: {
                    bc->operands.push_back(code_ir.Alloc<lir::VReg>(op.reg));
                } break;

                case OperandKind::VRegList: {
                    auto* vl = code_ir.Alloc<lir::VRegList>();
                    vl->registers = op.reg_list;
                    bc->operands.push_back(vl);
                } break;

                case OperandKind::Const32: {
                    bc->operands.push_back(code_ir.Alloc<lir::Const32>(
                        static_cast<dex::u4>(op.const32)));
                } break;

                case OperandKind::String: {
                    ir::String* s = ctx->get_str(op.str_val);
                    bc->operands.push_back(code_ir.Alloc<lir::String>(s, s->orig_index));
                } break;

                case OperandKind::Type: {
                    ir::Type* t = ctx->get_type(op.str_val);
                    bc->operands.push_back(code_ir.Alloc<lir::Type>(t, t->orig_index));
                } break;

                case OperandKind::Field: {
                    ir::FieldDecl* f = ctx->get_field(op.str_val, op.extra_type, op.extra_sig);
                    bc->operands.push_back(code_ir.Alloc<lir::Field>(f, f->orig_index));
                } break;

                case OperandKind::Method: {
                    ir::MethodDecl* m = ctx->get_method(op.str_val, op.extra_type, op.extra_sig);
                    bc->operands.push_back(code_ir.Alloc<lir::Method>(m, m->orig_index));
                } break;

                case OperandKind::LabelTarget: {
                    auto it = label_nodes.find(op.label_id);
                    assert(it != label_nodes.end());
                    bc->operands.push_back(code_ir.Alloc<lir::CodeLocation>(it->second));
                } break;
            }
        }

        code_ir.instructions.push_back(bc);
    }

    // Final assemble: BytecodeEncoder encodes bytecode, fixes label offsets, and sets outs_count
    // Protected with RunGuarded so internal SLICER_CHECK never aborts the process
    bool ok = slicer::RunGuarded([&]() {
        code_ir.Assemble();
    }, error);
    if (!ok) return false;

    return true;
}

}} // namespace PI::DexWriter

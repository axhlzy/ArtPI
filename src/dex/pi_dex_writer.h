//
// pi_dex_writer.h - Runtime Dalvik bytecode generator based on Dexter (Slicer)
//
// Provides a fluent, instruction-level assembler (similar to Frida-Gum's
// Arm64Writer) and a Smali text parser to emit pure Dalvik bytecode into
// runtime-synthesized DEX classes (Java.registerClass).
//

#ifndef PI_DEX_WRITER_H
#define PI_DEX_WRITER_H

#include "slicer/common.h"
#include "slicer/dex_bytecode.h"
#include "slicer/dex_ir.h"
#include "slicer/code_ir.h"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace PI {
namespace DexWriter {

// Canonicalizes class names into descriptors: "java.lang.String" -> "Ljava/lang/String;"
std::string NormalizeType(const std::string& raw);

// Context interface provided by pi_dex_gen to intern strings, types, methods, fields
struct IrContext {
    std::shared_ptr<ir::DexFile> ir;
    std::function<ir::String*(const std::string&)> get_str;
    std::function<ir::Type*(const std::string&)> get_type;
    std::function<ir::Proto*(const std::string&)> get_proto;
    std::function<ir::FieldDecl*(const std::string& parent,
                                 const std::string& name,
                                 const std::string& type)> get_field;
    std::function<ir::MethodDecl*(const std::string& parent,
                                  const std::string& name,
                                  const std::string& sig)> get_method;
};

enum class OperandKind {
    VReg,
    VRegList,
    Const32,
    String,
    Type,
    Field,
    Method,
    LabelTarget
};

struct SymbolicOperand {
    OperandKind kind;
    uint32_t reg = 0;
    std::vector<uint32_t> reg_list;
    int32_t const32 = 0;
    std::string str_val;
    std::string extra_type; // For field: field type
    std::string extra_sig;  // For method: signature
    int label_id = 0;
};

struct SymbolicInstruction {
    enum class Kind { Bytecode, Label, Nop };
    Kind kind = Kind::Bytecode;
    dex::Opcode opcode = dex::OP_NOP;
    int label_id = 0;
    std::vector<SymbolicOperand> operands;
};

class Writer {
public:
    Writer();
    ~Writer() = default;

    // Registers configuration
    void SetRegisters(uint16_t total, uint16_t ins = 0, uint16_t outs = 0);
    uint16_t GetRegisters() const { return registers_; }
    uint16_t GetIns() const { return ins_; }
    uint16_t GetOuts() const { return outs_; }
    size_t GetInstructionCount() const { return instructions_.size(); }
    size_t GetBytecodeInstructionCount() const;

    // Label management
    int MakeLabel();
    bool PutLabel(int label_id);

    // Branching & jumps
    bool PutGoto(int label_id);
    bool PutIfEqz(uint32_t reg, int label_id);
    bool PutIfNez(uint32_t reg, int label_id);
    bool PutIfLtz(uint32_t reg, int label_id);
    bool PutIfGez(uint32_t reg, int label_id);
    bool PutIfGtz(uint32_t reg, int label_id);
    bool PutIfLez(uint32_t reg, int label_id);

    bool PutIfEq(uint32_t reg1, uint32_t reg2, int label_id);
    bool PutIfNe(uint32_t reg1, uint32_t reg2, int label_id);
    bool PutIfLt(uint32_t reg1, uint32_t reg2, int label_id);
    bool PutIfGe(uint32_t reg1, uint32_t reg2, int label_id);
    bool PutIfGt(uint32_t reg1, uint32_t reg2, int label_id);
    bool PutIfLe(uint32_t reg1, uint32_t reg2, int label_id);

    // Constants
    bool PutConst4(uint32_t reg, int32_t val);
    bool PutConst16(uint32_t reg, int32_t val);
    bool PutConst(uint32_t reg, int32_t val);
    bool PutConstString(uint32_t reg, const std::string& str);
    bool PutConstClass(uint32_t reg, const std::string& type_name);

    // Moves
    bool PutMove(uint32_t dst, uint32_t src);
    bool PutMoveObject(uint32_t dst, uint32_t src);
    bool PutMoveResult(uint32_t dst);
    bool PutMoveResultObject(uint32_t dst);

    // Returns
    bool PutReturnVoid();
    bool PutReturn(uint32_t reg);
    bool PutReturnObject(uint32_t reg);

    // Invokes (method_sig: "Lcom/foo/Bar;->method(I)V" or "com.foo.Bar.method(I)V")
    bool PutInvokeVirtual(const std::string& method_sig, const std::vector<uint32_t>& regs);
    bool PutInvokeDirect(const std::string& method_sig, const std::vector<uint32_t>& regs);
    bool PutInvokeStatic(const std::string& method_sig, const std::vector<uint32_t>& regs);
    bool PutInvokeSuper(const std::string& method_sig, const std::vector<uint32_t>& regs);
    bool PutInvokeInterface(const std::string& method_sig, const std::vector<uint32_t>& regs);

    // Objects & Fields
    bool PutNewInstance(uint32_t reg, const std::string& type_name);
    bool PutCheckCast(uint32_t reg, const std::string& type_name);
    bool PutInstanceOf(uint32_t dst_reg, uint32_t obj_reg, const std::string& type_name);

    // field_spec: "Lcom/foo/Bar;->field:I" or "com.foo.Bar.field:I"
    bool PutIget(uint32_t val_reg, uint32_t obj_reg, const std::string& field_spec);
    bool PutIput(uint32_t val_reg, uint32_t obj_reg, const std::string& field_spec);
    bool PutIgetObject(uint32_t val_reg, uint32_t obj_reg, const std::string& field_spec);
    bool PutIputObject(uint32_t val_reg, uint32_t obj_reg, const std::string& field_spec);
    bool PutIgetBoolean(uint32_t val_reg, uint32_t obj_reg, const std::string& field_spec);
    bool PutIputBoolean(uint32_t val_reg, uint32_t obj_reg, const std::string& field_spec);

    bool PutSget(uint32_t val_reg, const std::string& field_spec);
    bool PutSput(uint32_t val_reg, const std::string& field_spec);
    bool PutSgetObject(uint32_t val_reg, const std::string& field_spec);
    bool PutSputObject(uint32_t val_reg, const std::string& field_spec);

    bool PutThrow(uint32_t reg);
    bool PutNop();
    bool PutBinaryOp(dex::Opcode op, uint32_t dst, uint32_t src1, uint32_t src2);

    // Smali text assembler (Option B)
    bool EmitSmali(const std::string& smali_code, std::string* error = nullptr);

    // Dexter Assembly bridge called by pi_dex_gen.cpp
    bool AssembleInto(IrContext* ctx,
                      ir::EncodedMethod* encoded_method,
                      ir::Code* ir_code,
                      std::string* error);

private:
    uint16_t registers_ = 4;
    uint16_t ins_ = 1;
    uint16_t outs_ = 4;
    int next_label_id_ = 1;

    std::vector<SymbolicInstruction> instructions_;
    std::map<std::string, int> named_labels_; // for smali parsing ":label" -> id
};

}} // namespace PI::DexWriter

#endif // PI_DEX_WRITER_H

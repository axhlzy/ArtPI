//
// agent_dex_writer.h - QuickJS bindings for DexWriter
//

#ifndef ARTPI_AGENT_DEX_WRITER_H
#define ARTPI_AGENT_DEX_WRITER_H

#include "quickjs.h"
#include "dex/pi_dex_writer.h"
#include <memory>

namespace artpi { namespace agent {

// Returns the underlying PI::DexWriter::Writer if val is a DexWriter JS object, or nullptr.
PI::DexWriter::Writer* GetDexWriterInstance(JSContext* ctx, JSValueConst val);

// Create a new DexWriter JS object wrapping the given C++ Writer.
JSValue CreateDexWriterObject(JSContext* ctx, std::shared_ptr<PI::DexWriter::Writer> writer);

// Initializes the DexWriter class in the QuickJS context.
void RegisterDexWriterApis(JSContext* ctx, JSValue global, JSValue java);

// Resets cached QuickJS class ID on runtime tear-down
void ResetDexWriterClassId();

}} // namespace artpi::agent

#endif // ARTPI_AGENT_DEX_WRITER_H

#pragma once

#include <map>
#include <string>

namespace x402bch {

struct BchDiagnostic {
  std::string stage;
  std::string code;
  std::string message;
  std::map<std::string, std::string> context;
};

inline constexpr const char* kDiagnosticRedacted = "[redacted]";

BchDiagnostic create_bch_diagnostic(const std::string& stage, const std::string& code,
                                    const std::string& message,
                                    const std::map<std::string, std::string>& context);

}  // namespace x402bch

#include "x402_bch/diagnostics.hpp"

#include <algorithm>
#include <cctype>

namespace x402bch {

BchDiagnostic create_bch_diagnostic(const std::string& stage, const std::string& code,
                                    const std::string& message,
                                    const std::map<std::string, std::string>& context) {
  BchDiagnostic result{stage, code, message, {}};
  for (const auto& [key, value] : context) {
    std::string lowered = key;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    const bool sensitive = lowered == "mnemonic" || lowered == "privatekey" || lowered == "seed" || lowered == "secret" || lowered == "authorization" || lowered == "transaction" || lowered == "rawtransaction" || lowered == "signedtransaction";
    result.context[key] = sensitive ? kDiagnosticRedacted : value;
  }
  return result;
}

}

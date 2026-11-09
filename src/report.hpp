// Rendering of an Analysis as stable JSON or terminal text.
#pragma once

#include "analysis.hpp"

#include <string>

namespace vmpstatic {

std::string renderJson(const Analysis& analysis, const std::string& path);
std::string renderText(const Analysis& analysis, const std::string& path);

}  // namespace vmpstatic

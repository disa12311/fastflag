#pragma once

#include "Types.hpp"

#include <ostream>

namespace fastflag {

class ResultDumper {
public:
    static void dumpCandidate(const ScanCandidate& candidate, std::ostream& output);
};

} // namespace fastflag

#pragma once

#ifdef _DEBUG
#define DEBUG_LOG(x) std::cout << x
#else
#define DEBUG_LOG(x)
#endif
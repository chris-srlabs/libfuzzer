// Section delimiters normally supplied by compiler-rt's sanitizer runtime.
// COFF linkers do not synthesize these when fuzzing without a sanitizer.
#ifdef _WIN32
#include <stdint.h>

extern "C" {
// LLVM skips the 8-byte start marker; the stop marker must have byte alignment
// so padding does not change the number of counters relative to the PC table.
#pragma section(".SCOV$CA", read, write)
__declspec(allocate(".SCOV$CA")) uint64_t __start___sancov_cntrs = 0;
#pragma section(".SCOV$CZ", read, write)
__declspec(allocate(".SCOV$CZ")) __declspec(align(1)) uint8_t
    __stop___sancov_cntrs = 0;

#pragma section(".SCOVP$A", read)
__declspec(allocate(".SCOVP$A")) uint64_t __start___sancov_pcs = 0;
#pragma section(".SCOVP$Z", read)
__declspec(allocate(".SCOVP$Z")) __declspec(align(1)) uint8_t
    __stop___sancov_pcs = 0;

#pragma comment(linker, "/MERGE:.SCOV=.data")
#pragma comment(linker, "/MERGE:.SCOVP=.rdata")
}
#endif

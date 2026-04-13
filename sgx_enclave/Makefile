# Makefile for mixrand SGX entropy enclave
#
# Prerequisites:
#   - Intel SGX SDK installed (source /opt/intel/sgxsdk/environment)
#   - SGX signing key (generate with: openssl genrsa -out enclave_private.pem 3072)
#
# Usage:
#   make              # Build debug-signed enclave
#   make SGX_DEBUG=0  # Build release enclave (requires production signing key)
#   make clean        # Remove build artifacts

SGX_SDK ?= /opt/intel/sgxsdk
SGX_DEBUG ?= 1
SGX_MODE ?= HW

SGX_COMMON_CFLAGS := -m64
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_SIGN := $(SGX_SDK)/bin/x64/sgx_sign

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

ENCLAVE_NAME := mixrand_entropy_enclave
SIGNED_ENCLAVE := $(ENCLAVE_NAME).signed.so
SIGNING_KEY ?= enclave_private.pem

# Trusted (enclave) build settings
TRTS_INCDIR := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc
TRTS_CFLAGS := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(TRTS_INCDIR)
TRTS_LDFLAGS := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-L$(SGX_SDK)/lib64 \
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcrypto -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=enclave.lds

.PHONY: all clean

all: $(SIGNED_ENCLAVE)

# Generate trusted bridge code from EDL
enclave_t.c enclave_t.h: enclave.edl
	$(SGX_EDGER8R) --trusted $< --search-path $(SGX_SDK)/include

# Compile enclave
enclave.o: enclave.c enclave_t.h
	gcc $(TRTS_CFLAGS) -c $< -o $@

enclave_t.o: enclave_t.c
	gcc $(TRTS_CFLAGS) -c $< -o $@

# Link enclave shared object
$(ENCLAVE_NAME).so: enclave.o enclave_t.o
	gcc $^ -o $@ $(TRTS_LDFLAGS)

# Generate signing key if it doesn't exist (debug only)
$(SIGNING_KEY):
	openssl genrsa -out $@ 3072

# Sign the enclave
$(SIGNED_ENCLAVE): $(ENCLAVE_NAME).so $(SIGNING_KEY) enclave.config.xml
	$(SGX_SIGN) sign -key $(SIGNING_KEY) -enclave $< -out $@ -config enclave.config.xml

# Linker version script
enclave.lds:
	@echo "{ global: g_global_data_sim; g_global_data; enclave_entry; g_peak_heap_used; g_peak_rsrv_mem_committed; local: *; };" > $@

clean:
	rm -f enclave.o enclave_t.o enclave_t.c enclave_t.h enclave.lds
	rm -f $(ENCLAVE_NAME).so $(SIGNED_ENCLAVE)

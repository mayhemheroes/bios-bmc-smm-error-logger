// mayhem/harnesses/rde_fuzz.cpp
//
// Sandbox-friendly libFuzzer harness for openbmc bios-bmc-smm-error-logger's BIOS<->BMC
// shared-memory error-log parser. This is an ADDITIVE harness: it does NOT modify any upstream
// source. The repo also ships src/fuzzer.cpp (meson -Dfuzzing=true), but that one opens a live
// DBus connection (sdbusplus request_name) in its init path and therefore aborts on the very first
// input outside a real openbmc system bus — i.e. it never iterates in a fuzzing sandbox.
//
// This harness exercises the SAME parse surface without DBus: it builds a BufferImpl over an
// in-memory "shared memory" region, pre-seeds the CircularBufferHeader with the project's valid
// magic/queue/UE constants (so the header validation is reached, not short-circuited), copies the
// attacker bytes into the region, and drives readLoop() once. readLoop reads + validates the
// circular-buffer header, performs the wraparound queue read, decodes each error-log entry, and
// hands the RDE operation/dictionary payloads to RdeCommandHandler (libbej decode). The RDE result
// is published through a mock ExternalStorer (no DBus, no filesystem).
//
// Built by mayhem/build.sh against the project's own static libs.

#include "config.h"

#include "buffer.hpp"
#include "pci_handler.hpp"
#include "read_loop.hpp"
#include "rde/external_storer_interface.hpp"
#include "rde/rde_handler.hpp"

#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

using namespace bios_bmc_smm_error_logger;

namespace
{
constexpr std::size_t memoryRegionSize = MEMORY_REGION_SIZE;
constexpr uint32_t bmcInterfaceVersion = BMC_INTERFACE_VERSION;
constexpr uint16_t queueSize = QUEUE_REGION_SIZE;
constexpr uint16_t ueRegionSize = UE_REGION_SIZE;
constexpr std::array<uint32_t, 4> magicNumber = {
    MAGIC_NUMBER_BYTE1, MAGIC_NUMBER_BYTE2, MAGIC_NUMBER_BYTE3,
    MAGIC_NUMBER_BYTE4};

// Publishes the decoded RDE JSON nowhere — keeps the fuzzer free of DBus / filesystem side effects.
class MockExternalStorerInterface : public rde::ExternalStorerInterface
{
  public:
    bool publishJson(std::string_view /*json*/) override
    {
        return true;
    }
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // In-memory backing for the shared-memory region (no /dev/mem, no fd).
    static std::vector<uint8_t> region(memoryRegionSize, 0);

    // A fresh BufferImpl per input so cached header / read-pointer state never leaks across runs.
    std::unique_ptr<DataInterface> pci =
        std::make_unique<PciDataHandler>(region.data(), memoryRegionSize);
    std::shared_ptr<BufferInterface> bufferHandler =
        std::make_shared<BufferImpl>(std::move(pci));

    std::unique_ptr<rde::ExternalStorerInterface> exStorer =
        std::make_unique<MockExternalStorerInterface>();
    std::shared_ptr<rde::RdeCommandHandler> rdeCommandHandler =
        std::make_shared<rde::RdeCommandHandler>(std::move(exStorer));

    // Lay down a valid header (magic + sizes) so header validation passes and the queue/RDE parse
    // path is actually reached, then overlay the attacker-controlled bytes.
    bufferHandler->initialize(bmcInterfaceVersion, queueSize, ueRegionSize,
                              magicNumber);
    std::size_t n = std::min(size, region.size());
    std::copy(data, data + n, region.begin());

    try
    {
        readLoop(nullptr, bufferHandler, rdeCommandHandler,
                 boost::system::error_code());
    }
    catch (const std::exception&)
    {
        // Parser surfaces malformed input as exceptions; not a defect for the fuzzer.
    }
    return 0;
}

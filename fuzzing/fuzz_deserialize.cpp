#include "../lib/protocol.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Optimization 1: Return early if input is too small to be meaningful
    if (size < sizeof(MessagingProtocol::MessageHeader)) {
        return 0;
    }
    
    // Optimization 2: Cut off very large inputs to speed up fuzzing
    const size_t MAX_FUZZ_SIZE = 1024 * 1024; // 1MB limit
    if (size > MAX_FUZZ_SIZE) {
        size = MAX_FUZZ_SIZE;
    }
    
    // Optimization 3: Access header type field to trigger different code paths
    const MessagingProtocol::MessageHeader* header = 
        reinterpret_cast<const MessagingProtocol::MessageHeader*>(data);
    
    // Try to access type-specific fields based on header type to increase coverage
    if (size >= sizeof(MessagingProtocol::MessageHeader) + 4) {
        switch (header->type) {
            case MessagingProtocol::CHAT_MESSAGE:
                // Access chat-specific fields if there's enough data
                if (size >= sizeof(MessagingProtocol::MessageHeader) + 12) {
                    // Access timestamp and priority fields
                    volatile uint32_t timestamp = *reinterpret_cast<const uint32_t*>(data + sizeof(MessagingProtocol::MessageHeader));
                    volatile uint8_t priority = data[sizeof(MessagingProtocol::MessageHeader) + 4];
                    (void)timestamp; (void)priority; // Suppress unused variable warnings
                }
                break;
                
            case MessagingProtocol::USER_INFO:
                // Access user-specific fields if there's enough data
                if (size >= sizeof(MessagingProtocol::MessageHeader) + 8) {
                    // Access user_id and status fields
                    volatile uint32_t user_id = *reinterpret_cast<const uint32_t*>(data + sizeof(MessagingProtocol::MessageHeader));
                    volatile uint16_t status = *reinterpret_cast<const uint16_t*>(data + sizeof(MessagingProtocol::MessageHeader) + 4);
                    volatile uint16_t tag_count = *reinterpret_cast<const uint16_t*>(data + sizeof(MessagingProtocol::MessageHeader) + 6);
                    (void)user_id; (void)status; (void)tag_count; // Suppress unused variable warnings
                }
                break;
                
            case MessagingProtocol::FILE_CHUNK:
                // Access file-specific fields if there's enough data
                if (size >= sizeof(MessagingProtocol::MessageHeader) + 12) {
                    // Access chunk_id, total_chunks, and chunk_size fields
                    volatile uint32_t chunk_id = *reinterpret_cast<const uint32_t*>(data + sizeof(MessagingProtocol::MessageHeader));
                    volatile uint32_t total_chunks = *reinterpret_cast<const uint32_t*>(data + sizeof(MessagingProtocol::MessageHeader) + 4);
                    volatile uint32_t chunk_size = *reinterpret_cast<const uint32_t*>(data + sizeof(MessagingProtocol::MessageHeader) + 8);
                    (void)chunk_id; (void)total_chunks; (void)chunk_size; // Suppress unused variable warnings
                }
                break;
        }
    }
    
    // Path 1: Deserialize untrusted input
    auto* msg = MessagingProtocol::Serializer::deserialize(data, size);
    if (msg) {
        // Path 2: Serialize potentially corrupted object
        auto serialized = MessagingProtocol::Serializer::serialize(*msg);
        delete msg;
    }
    return 0;
}
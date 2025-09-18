#include "../lib/protocol.h"
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cstdlib>

// Helper function to create a valid message from fuzzer input by casting data
MessagingProtocol::Message* parse_fuzzer_input_to_message(const uint8_t *data, size_t size) {
    if (size < sizeof(MessagingProtocol::MessageHeader)) return nullptr;  // Need at least a full header
    
    // Parse the entire MessageHeader from input data
    const MessagingProtocol::MessageHeader* input_header = 
        reinterpret_cast<const MessagingProtocol::MessageHeader*>(data);
    
    // Determine message type from header, but validate it
    uint8_t msg_type = (input_header->type % 3) + 1; // Ensure valid type: 1=CHAT_MESSAGE, 2=USER_INFO, 3=FILE_CHUNK
    
    auto* msg = new MessagingProtocol::Message(static_cast<MessagingProtocol::MessageType>(msg_type));
    
    // Use the parsed header values (but fix magic and version for validity)
    msg->header.magic = MessagingProtocol::MAGIC_NUMBER;  // Use correct magic
    msg->header.version = 1;  // Use correct version
    msg->header.type = static_cast<MessagingProtocol::MessageType>(msg_type);
    msg->header.message_id = input_header->message_id;  // Use input message ID
    // payload_size will be calculated later per message type
    
    size_t offset = sizeof(MessagingProtocol::MessageHeader);
    
    switch (msg_type) {
        case 1: { // CHAT_MESSAGE
            msg->header.type = MessagingProtocol::CHAT_MESSAGE;
            
            // Create username from fuzzer data
            size_t username_len = offset < size ? std::min((size_t)data[offset], size / 4) : 0;
            offset++;
            if (username_len > 0 && offset + username_len <= size) {
                std::string username(reinterpret_cast<const char*>(data + offset), username_len);
                msg->chat->username.set_data(username);
                offset += username_len;
            } else {
                msg->chat->username.set_data("fuzzer_user");
            }
            
            // Create message from remaining data
            size_t msg_len = offset < size ? std::min((size_t)data[offset], size - offset) : 0;
            offset++;
            if (msg_len > 0 && offset + msg_len <= size) {
                std::string message(reinterpret_cast<const char*>(data + offset), msg_len);
                msg->chat->message.set_data(message);
                offset += msg_len;
            } else {
                msg->chat->message.set_data("fuzzer_message");
            }
            
            // Set timestamp and priority from remaining data
            msg->chat->timestamp = offset + 4 <= size ? *reinterpret_cast<const uint32_t*>(data + offset) : 1234567890;
            msg->chat->priority = offset + 4 < size ? data[offset + 4] : 1;
            
            msg->header.payload_size = sizeof(uint32_t) + sizeof(uint8_t) + 
                                     sizeof(uint16_t) + msg->chat->username.length +
                                     sizeof(uint16_t) + msg->chat->message.length;
            break;
        }
        
        case 2: { // USER_INFO
            msg->header.type = MessagingProtocol::USER_INFO;
            
            // Set user_id and status from data
            msg->user_info->user_id = offset + 4 <= size ? *reinterpret_cast<const uint32_t*>(data + offset) : 12345;
            offset += 4;
            msg->user_info->status = offset + 2 <= size ? *reinterpret_cast<const uint16_t*>(data + offset) : 1;
            offset += 2;
            
            // Create username from fuzzer data
            size_t username_len = offset < size ? std::min((size_t)data[offset], size / 6) : 0;
            offset++;
            if (username_len > 0 && offset + username_len <= size) {
                std::string username(reinterpret_cast<const char*>(data + offset), username_len);
                msg->user_info->username.set_data(username);
                offset += username_len;
            } else {
                msg->user_info->username.set_data("fuzzer_user");
            }
            
            // Create email from remaining data
            size_t email_len = offset < size ? std::min((size_t)data[offset], size / 6) : 0;
            offset++;
            if (email_len > 0 && offset + email_len <= size) {
                std::string email(reinterpret_cast<const char*>(data + offset), email_len);
                msg->user_info->email.set_data(email);
                offset += email_len;
            } else {
                msg->user_info->email.set_data("fuzzer@test.com");
            }
            
            // Create tags from remaining data
            uint16_t tag_count = offset < size ? std::min((uint16_t)data[offset], (uint16_t)10) : 0; // Limit to 10 tags
            msg->user_info->tag_count = tag_count;
            offset++;
            
            if (tag_count > 0) {
                msg->user_info->tags = new MessagingProtocol::ProtocolString[tag_count];
                for (uint16_t i = 0; i < tag_count && offset < size; i++) {
                    size_t tag_len = offset < size ? std::min((size_t)data[offset], (size - offset) / (tag_count - i)) : 0;
                    offset++;
                    if (tag_len > 0 && offset + tag_len <= size) {
                        std::string tag(reinterpret_cast<const char*>(data + offset), tag_len);
                        msg->user_info->tags[i].set_data(tag);
                        offset += tag_len;
                    } else {
                        msg->user_info->tags[i].set_data("tag" + std::to_string(i));
                    }
                }
            } else {
                msg->user_info->tags = nullptr;
            }
            
            msg->header.payload_size = sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) +
                                     sizeof(uint16_t) + msg->user_info->username.length +
                                     sizeof(uint16_t) + msg->user_info->email.length;
            for (uint16_t i = 0; i < tag_count; i++) {
                msg->header.payload_size += sizeof(uint16_t) + msg->user_info->tags[i].length;
            }
            break;
        }
        
        case 3: { // FILE_CHUNK
            msg->header.type = MessagingProtocol::FILE_CHUNK;
            
            // Create filename from fuzzer data
            size_t filename_len = offset < size ? std::min((size_t)data[offset], size / 4) : 0;
            offset++;
            if (filename_len > 0 && offset + filename_len <= size) {
                std::string filename(reinterpret_cast<const char*>(data + offset), filename_len);
                msg->file_chunk->filename.set_data(filename);
                offset += filename_len;
            } else {
                msg->file_chunk->filename.set_data("fuzzer_file.txt");
            }
            
            // Set chunk info from data
            msg->file_chunk->chunk_id = offset + 4 <= size ? *reinterpret_cast<const uint32_t*>(data + offset) : 0;
            offset += 4;
            msg->file_chunk->total_chunks = offset + 4 <= size ? *reinterpret_cast<const uint32_t*>(data + offset) : 1;
            offset += 4;
            
            // Create chunk data from remaining data, but limit size to prevent OOM
            size_t chunk_size = offset < size ? std::min((size_t)(size - offset), (size_t)4096) : 0; // Limit to 4KB
            msg->file_chunk->chunk_size = static_cast<uint32_t>(chunk_size);
            
            if (chunk_size > 0) {
                msg->file_chunk->data = new uint8_t[chunk_size];
                std::memcpy(msg->file_chunk->data, data + offset, chunk_size);
            } else {
                msg->file_chunk->data = nullptr;
                msg->file_chunk->chunk_size = 0;
            }
            
            msg->header.payload_size = sizeof(uint16_t) + msg->file_chunk->filename.length +
                                     sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + chunk_size;
            break;
        }
    }
    
    return msg;
}

// Helper function to compare two messages for data integrity
bool compare_messages(const MessagingProtocol::Message* original, const MessagingProtocol::Message* roundtrip) {
    if (!original || !roundtrip) return false;
    
    // Compare headers
    if (original->header.magic != roundtrip->header.magic ||
        original->header.version != roundtrip->header.version ||
        original->header.type != roundtrip->header.type ||
        original->header.message_id != roundtrip->header.message_id) {
        return false;
    }
    
    // Compare message-specific data
    switch (original->header.type) {
        case MessagingProtocol::CHAT_MESSAGE:
            if (!original->chat || !roundtrip->chat) return false;
            return (original->chat->username.length == roundtrip->chat->username.length &&
                   original->chat->message.length == roundtrip->chat->message.length &&
                   original->chat->timestamp == roundtrip->chat->timestamp &&
                   original->chat->priority == roundtrip->chat->priority);
                   
        case MessagingProtocol::USER_INFO:
            if (!original->user_info || !roundtrip->user_info) return false;
            return (original->user_info->user_id == roundtrip->user_info->user_id &&
                   original->user_info->status == roundtrip->user_info->status &&
                   original->user_info->tag_count == roundtrip->user_info->tag_count &&
                   original->user_info->username.length == roundtrip->user_info->username.length &&
                   original->user_info->email.length == roundtrip->user_info->email.length);
                   
        case MessagingProtocol::FILE_CHUNK:
            if (!original->file_chunk || !roundtrip->file_chunk) return false;
            return (original->file_chunk->chunk_id == roundtrip->file_chunk->chunk_id &&
                   original->file_chunk->total_chunks == roundtrip->file_chunk->total_chunks &&
                   original->file_chunk->chunk_size == roundtrip->file_chunk->chunk_size &&
                   original->file_chunk->filename.length == roundtrip->file_chunk->filename.length);
    }
    
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(MessagingProtocol::MessageHeader)) return 0;  // Need at least a full header
    
    // Parse fuzzer input to create valid message structure
    MessagingProtocol::Message* original = parse_fuzzer_input_to_message(data, size);
    if (!original) return 0;
    
    try {
        // Serialize the constructed message
        std::vector<uint8_t> serialized = MessagingProtocol::Serializer::serialize(*original);
        
        // If serialization succeeded, deserialize it back
        if (!serialized.empty()) {
            MessagingProtocol::Message* roundtrip = 
                MessagingProtocol::Serializer::deserialize(serialized.data(), serialized.size());
            
            if (roundtrip) {
                // Compare original vs roundtrip for data integrity
                bool integrity_check = compare_messages(original, roundtrip);
                
                // Crash on comparison failures so fuzzer treats them as bugs
                if (!integrity_check) {
                    // Print debug info before crashing
                    fprintf(stderr, "INTEGRITY FAILURE: Roundtrip comparison failed for input size %zu, type %d\n", 
                           size, (int)original->header.type);
                    fprintf(stderr, "Input bytes: ");
                    for (size_t i = 0; i < std::min(size, (size_t)16); i++) {
                        fprintf(stderr, "%02x ", data[i]);
                    }
                    fprintf(stderr, "\n");
                    
                    // Crash to signal fuzzer that this is a bug
                    abort();
                }
                
                delete roundtrip;
            }
        }
        
        delete original;
    } catch (...) {
        // Catch any exceptions and clean up
        delete original;
    }
    
    return 0;
}
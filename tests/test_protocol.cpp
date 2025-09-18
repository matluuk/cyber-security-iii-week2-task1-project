/**
 * Basic unit tests for our protocol
 *
 * PURPOSE: These tests verify basic functionality but are intentionally LIMITED.
 * They test the "happy path" scenarios where everything works correctly.
 *
 * This demonstrates why unit tests alone are insufficient
 * for memory safety. These tests will all pass even though the code contains
 * serious memory bugs that can cause crashes, data corruption, and security
 * vulnerabilities.
 *
 * WHAT THESE TESTS MAY MISS:
 * - Memory leaks in assignment operators
 * - Double-free bugs in copy constructors
 * - Buffer overflows in deserialization
 * - Integer overflows
 * - Malformed input handling that result to even other scenarios
 *
 * TO FIND THE REAL BUGS: Use AddressSanitizer, Valgrind, or fuzzing tools.
 */

#include "../lib/protocol.h"
#include <cassert>
#include <iostream>
#include <cstring>
#include <chrono>

using namespace MessagingProtocol;

// Tests basic chat message serialization round-trip
// This only tests the happy path - valid input, normal sizes
void test_chat_message_basic() {
    std::cout << "Testing basic chat message..." << std::endl;

    Message msg(CHAT_MESSAGE);
    msg.chat->username.set_data("alice");
    msg.chat->message.set_data("Hello World!");
    msg.chat->timestamp = 1234567890;
    msg.chat->priority = 5;

    // Test serialization - convert Message object to binary format
    auto buffer = Serializer::serialize(msg);
    assert(buffer.size() > sizeof(MessageHeader));  // Sanity check: has header + payload

    // Test deserialization - convert binary back to Message object
    // NOTE: This only tests with valid, well-formed data from our own serializer
    Message* deserialized = Serializer::deserialize(buffer.data(), buffer.size());
    assert(deserialized != nullptr);
    assert(deserialized->header.type == CHAT_MESSAGE);
    assert(deserialized->chat->timestamp == 1234567890);
    assert(deserialized->chat->priority == 5);
    assert(deserialized->chat->username.to_string() == "alice");
    assert(deserialized->chat->message.to_string() == "Hello World!");

    delete deserialized;
    std::cout << "✓ Chat message test passed" << std::endl;
}

// Tests UserInfo message type
void test_user_info_basic() {
    std::cout << "Testing basic user info..." << std::endl;

    Message msg(USER_INFO);
    msg.user_info->username.set_data("bob");
    msg.user_info->email.set_data("bob@example.com");
    msg.user_info->user_id = 42;
    msg.user_info->status = 1;

    // Simple case - no tags
    msg.user_info->tag_count = 0;
    msg.user_info->tags = nullptr;

    auto buffer = Serializer::serialize(msg);
    Message* deserialized = Serializer::deserialize(buffer.data(), buffer.size());

    assert(deserialized != nullptr);
    assert(deserialized->header.type == USER_INFO);
    assert(deserialized->user_info->user_id == 42);
    assert(deserialized->user_info->username.to_string() == "bob");
    assert(deserialized->user_info->email.to_string() == "bob@example.com");

    delete deserialized;
    std::cout << "✓ User info test passed" << std::endl;
}

// Tests binary data handling with small, well-formed chunk
void test_file_chunk_basic() {
    std::cout << "Testing basic file chunk..." << std::endl;

    Message msg(FILE_CHUNK);
    msg.file_chunk->filename.set_data("test.txt");
    msg.file_chunk->chunk_id = 0;
    msg.file_chunk->total_chunks = 1;
    msg.file_chunk->chunk_size = 5;

    // Small data chunk - using tiny size avoids triggering bounds checking bugs
    msg.file_chunk->data = new uint8_t[5];
    memcpy(msg.file_chunk->data, "hello", 5);  // Known safe: size matches allocation

    // Serialize and deserialize - this creates a NEW Message object
    auto buffer = Serializer::serialize(msg);
    Message* deserialized = Serializer::deserialize(buffer.data(), buffer.size());

    assert(deserialized != nullptr);
    assert(deserialized->header.type == FILE_CHUNK);
    assert(deserialized->file_chunk->chunk_id == 0);
    assert(deserialized->file_chunk->filename.to_string() == "test.txt");
    assert(deserialized->file_chunk->chunk_size == 5);
    assert(memcmp(deserialized->file_chunk->data, "hello", 5) == 0);

    delete deserialized;
    std::cout << "✓ File chunk test passed" << std::endl;
}

// Tests ProtocolString operations - but won't catch memory management bugs
// These operations look correct but have hidden memory safety issues
void test_string_operations() {
    std::cout << "Testing string operations..." << std::endl;

    ProtocolString str1;
    str1.set_data("test string");
    assert(str1.to_string() == "test string");
    assert(str1.length == 11);

    // Test copy constructor - LOOKS correct but has memory safety bug
    ProtocolString str2(str1);
    assert(str2.to_string() == "test string");

    // Test assignment operator - LOOKS correct but leaks memory
    // Memory leak happens here but won't be detected by this test
    ProtocolString str3;
    str3 = str1;
    assert(str3.to_string() == "test string");

    std::cout << "✓ String operations test passed" << std::endl;
}

// Tests edge case of empty strings - this is actually important!
// Empty/null strings often trigger boundary condition bugs
void test_empty_strings() {
    std::cout << "Testing empty strings..." << std::endl;

    Message msg(CHAT_MESSAGE);
    msg.chat->username.set_data("");
    msg.chat->message.set_data("");

    auto buffer = Serializer::serialize(msg);
    Message* deserialized = Serializer::deserialize(buffer.data(), buffer.size());

    assert(deserialized != nullptr);
    assert(deserialized->chat->username.to_string() == "");
    assert(deserialized->chat->message.to_string() == "");

    delete deserialized;
    std::cout << "✓ Empty strings test passed" << std::endl;
}

// Tests UserInfo with tags array
void test_user_with_tags_simple() {
    std::cout << "Testing user with tags (simple)..." << std::endl;

    Message msg(USER_INFO);
    msg.user_info->username.set_data("charlie");
    msg.user_info->email.set_data("charlie@test.com");
    msg.user_info->user_id = 123;
    msg.user_info->tag_count = 2;

    msg.user_info->tags = new ProtocolString[2];
    msg.user_info->tags[0].set_data("admin");
    msg.user_info->tags[1].set_data("vip");

    auto buffer = Serializer::serialize(msg);
    Message* deserialized = Serializer::deserialize(buffer.data(), buffer.size());

    assert(deserialized != nullptr);
    assert(deserialized->user_info->tag_count == 2);
    assert(deserialized->user_info->tags[0].to_string() == "admin");
    assert(deserialized->user_info->tags[1].to_string() == "vip");

    delete deserialized;  // This deletion is safe - deserialized object owns its memory
    std::cout << "✓ User with tags test passed" << std::endl;
}

void test_large_tag_count_vulnerability() {
    std::cout << "Testing large tag count handling..." << std::endl;
    
    // Create malformed input with huge tag_count but insufficient data
    std::vector<uint8_t> malformed_input;
    
    // Craft a USER_INFO message header
    MessageHeader header;
    header.magic = MAGIC_NUMBER;
    header.version = PROTOCOL_VERSION;
    header.type = USER_INFO;
    header.payload_size = 100;  // Claim small payload but set huge tag_count
    header.message_id = 1;
    
    // Add header to buffer
    malformed_input.resize(sizeof(MessageHeader));
    memcpy(malformed_input.data(), &header, sizeof(MessageHeader));
    
    // Add USER_INFO fields
    uint32_t user_id = 123;
    uint16_t status = 1;
    uint16_t malicious_tag_count = 0xffff;  // Claim 65535 tags!
    
    size_t offset = sizeof(MessageHeader);
    
    // Add basic fields
    malformed_input.resize(offset + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t));
    memcpy(malformed_input.data() + offset, &user_id, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(malformed_input.data() + offset, &status, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    memcpy(malformed_input.data() + offset, &malicious_tag_count, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    
    // Add minimal username and email (empty strings)
    malformed_input.resize(offset + 4);  // 2 bytes for each empty string length
    uint16_t empty_len = 0;
    memcpy(malformed_input.data() + offset, &empty_len, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    memcpy(malformed_input.data() + offset, &empty_len, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    
    // DON'T add tag data - this creates the malformed condition:
    // tag_count = 65535 but no tag data provided
    
    std::cout << "Attempting to deserialize malformed input with tag_count=" << malicious_tag_count 
              << " but insufficient data..." << std::endl;
    
    // This should NOT crash or allocate gigabytes
    Message* result = Serializer::deserialize(malformed_input.data(), malformed_input.size());
    
    // Should return nullptr for malformed input
    assert(result == nullptr);
    
    std::cout << "✓ Large tag count properly rejected" << std::endl;
}

// Test for specific slow input found during fuzzing
void test_slow_fuzzer_input() {
    std::cout << "Testing slow fuzzer input (base64: DQBdy11dXV1dA11dQ0NDQ0NDQ51DQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0O9...)..." << std::endl;
    
    // This is the decoded slow input from fuzzing
    std::vector<uint8_t> slow_input = {
        0x0d, 0x00, 0x5d, 0xcb, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x03, 0x5d, 0x5d, 0x43, 0x43, 0x43, 0x43,
        0x43, 0x43, 0x43, 0x9d, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43,
        0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0xbd, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
        0xa2, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d,
        0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x00, 0x3e, 0x20, 0x00, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe2,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xe5, 0xe5, 0x23, 0x3f, 0x04,
        0x8a, 0x8a, 0x8a, 0x27, 0x27, 0x27, 0x8a, 0x8a, 0x2c, 0x02
    };
    
    std::cout << "Input size: " << slow_input.size() << " bytes" << std::endl;
    
    // Analyze the header if it's large enough
    if (slow_input.size() >= sizeof(MessageHeader)) {
        const MessageHeader* header = reinterpret_cast<const MessageHeader*>(slow_input.data());
        std::cout << "Header analysis:" << std::endl;
        std::cout << "  Magic: 0x" << std::hex << header->magic << std::dec 
                  << " (expected: 0x" << std::hex << MAGIC_NUMBER << std::dec << ")" << std::endl;
        std::cout << "  Version: " << (int)header->version << std::endl;
        std::cout << "  Type: " << (int)header->type << std::endl;
        std::cout << "  Payload size: " << header->payload_size << std::endl;
        std::cout << "  Message ID: " << header->message_id << std::endl;
    }
    
    // Time the deserialization to ensure it doesn't take too long
    auto start = std::chrono::high_resolution_clock::now();
    
    // This should either:
    // 1. Return nullptr quickly (invalid input)
    // 2. Return a valid message quickly (after bug fixes)
    // 3. NOT hang or take excessive time
    Message* result = Serializer::deserialize(slow_input.data(), slow_input.size());
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "Deserialization took " << duration.count() << " ms" << std::endl;
    
    // Verify performance: should not take more than 100ms for any input
    if (duration.count() > 100) {
        std::cout << "⚠ WARNING: Deserialization took too long (" << duration.count() << " ms)" << std::endl;
        std::cout << "This might indicate a performance issue or inefficient algorithm" << std::endl;
    }
    
    if (result) {
        std::cout << "Deserialization succeeded, message type: " << (int)result->header.type << std::endl;
        
        // Test serialization as well to check for round-trip issues
        auto start_ser = std::chrono::high_resolution_clock::now();
        auto serialized = Serializer::serialize(*result);
        auto end_ser = std::chrono::high_resolution_clock::now();
        auto ser_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_ser - start_ser);
        
        std::cout << "Serialization took " << ser_duration.count() << " ms" << std::endl;
        std::cout << "Serialized size: " << serialized.size() << " bytes" << std::endl;
        
        if (ser_duration.count() > 100) {
            std::cout << "⚠ WARNING: Serialization took too long (" << ser_duration.count() << " ms)" << std::endl;
        }
        
        delete result;
    } else {
        std::cout << "Deserialization returned nullptr (input rejected)" << std::endl;
    }
    
    std::cout << "✓ Slow input test completed" << std::endl;
}

int main() {
    std::cout << "Running protocol tests..." << std::endl;

    try {
        test_chat_message_basic();
        test_user_info_basic();
        test_file_chunk_basic();
        test_string_operations();
        test_empty_strings();
        test_user_with_tags_simple();

        // Test cases for bugs found during fuzzing
        test_large_tag_count_vulnerability();
        test_slow_fuzzer_input();

        std::cout << "\n✓ All basic tests passed!" << std::endl;
        std::cout << "Note: These tests only cover happy path scenarios." << std::endl;
        std::cout << "Memory bugs and edge cases require fuzzing and sanitizers to detect." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

#include "sig-net.hpp"
#include "sig-net-parse.hpp"

#include "imgui.h"
#include "backends/imgui_impl_opengl3.h"
#include "backends/imgui_impl_sdl2.h"

#include <SDL.h>
#include <SDL_opengl.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

constexpr int kVisibleDmxChannels = 24;
constexpr Uint32 kKeepAliveIntervalMs = 900;
constexpr Uint32 kDynamicIntervalMs = 1000 / SigNet::MAX_ACTIVE_RATE_HZ;

struct InterfaceInfo {
    std::string label;
    std::string ip;
};

struct PacketPreview {
    std::string hex_dump;
    std::string destination_ip;
};

struct ReceivedPacketPreview {
    std::string hex_dump;
    std::string source_ip;
    std::string uri;
    std::string packet_kind;
    uint16_t source_port = 0;
    uint16_t payload_length = 0;
    uint32_t session_id = 0;
    uint32_t seq_num = 0;
    uint32_t received_tick = 0;
    bool verify_attempted = false;
    bool hmac_verified = false;
};

struct DiscoveredNode {
    std::array<uint8_t, 6> tuid{};
    std::string tuid_hex;
    std::string source_ip;
    std::string uri;
    std::string firmware_version_string;
    uint32_t firmware_version_id = 0;
    uint16_t manufacturer_code = 0;
    uint16_t product_variant_id = 0;
    uint16_t change_count = 0;
    uint8_t protocol_version = 0;
    uint32_t role_capability_bits = 0;
    uint32_t session_id = 0;
    uint32_t seq_num = 0;
    uint32_t announce_count = 0;
    uint32_t last_seen_tick = 0;
    bool verify_attempted = false;
    bool hmac_verified = false;
};

struct ReceivedDatagram {
    std::vector<uint8_t> payload;
    std::string source_ip;
    uint16_t source_port = 0;
};

ImVec4 ColorFromBytes(int r, int g, int b, int a = 255) {
    return ImVec4(r / 255.0f, g / 255.0f, b / 255.0f, a / 255.0f);
}

void ApplyCustomStyle() {
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowPadding = ImVec2(12.0f, 12.0f);
    style.FramePadding = ImVec2(9.0f, 7.0f);
    style.CellPadding = ImVec2(8.0f, 8.0f);
    style.ItemSpacing = ImVec2(8.0f, 8.0f);
    style.ItemInnerSpacing = ImVec2(6.0f, 5.0f);
    style.WindowRounding = 18.0f;
    style.ChildRounding = 16.0f;
    style.FrameRounding = 10.0f;
    style.PopupRounding = 12.0f;
    style.ScrollbarRounding = 12.0f;
    style.GrabRounding = 10.0f;
    style.TabRounding = 14.0f;
    style.WindowBorderSize = 0.0f;
    style.PopupBorderSize = 0.0f;
    style.FrameBorderSize = 0.0f;
    style.ChildBorderSize = 1.0f;
    style.IndentSpacing = 16.0f;

    ImVec4* colors = style.Colors;
    colors[ImGuiCol_Text] = ColorFromBytes(241, 244, 248);
    colors[ImGuiCol_TextDisabled] = ColorFromBytes(134, 149, 168);
    colors[ImGuiCol_WindowBg] = ColorFromBytes(11, 16, 25);
    colors[ImGuiCol_ChildBg] = ColorFromBytes(18, 24, 36, 232);
    colors[ImGuiCol_PopupBg] = ColorFromBytes(18, 24, 36, 245);
    colors[ImGuiCol_Border] = ColorFromBytes(42, 53, 72, 170);
    colors[ImGuiCol_FrameBg] = ColorFromBytes(24, 32, 46);
    colors[ImGuiCol_FrameBgHovered] = ColorFromBytes(33, 45, 66);
    colors[ImGuiCol_FrameBgActive] = ColorFromBytes(43, 58, 82);
    colors[ImGuiCol_TitleBg] = ColorFromBytes(13, 18, 28);
    colors[ImGuiCol_TitleBgActive] = ColorFromBytes(13, 18, 28);
    colors[ImGuiCol_MenuBarBg] = ColorFromBytes(17, 23, 34);
    colors[ImGuiCol_ScrollbarBg] = ColorFromBytes(15, 21, 31);
    colors[ImGuiCol_ScrollbarGrab] = ColorFromBytes(69, 88, 116);
    colors[ImGuiCol_ScrollbarGrabHovered] = ColorFromBytes(90, 112, 144);
    colors[ImGuiCol_ScrollbarGrabActive] = ColorFromBytes(116, 142, 178);
    colors[ImGuiCol_CheckMark] = ColorFromBytes(255, 191, 92);
    colors[ImGuiCol_SliderGrab] = ColorFromBytes(82, 184, 214);
    colors[ImGuiCol_SliderGrabActive] = ColorFromBytes(124, 214, 239);
    colors[ImGuiCol_Button] = ColorFromBytes(35, 50, 71);
    colors[ImGuiCol_ButtonHovered] = ColorFromBytes(50, 70, 98);
    colors[ImGuiCol_ButtonActive] = ColorFromBytes(68, 94, 129);
    colors[ImGuiCol_Header] = ColorFromBytes(34, 49, 70);
    colors[ImGuiCol_HeaderHovered] = ColorFromBytes(48, 68, 96);
    colors[ImGuiCol_HeaderActive] = ColorFromBytes(61, 86, 121);
    colors[ImGuiCol_Separator] = ColorFromBytes(47, 59, 80);
    colors[ImGuiCol_ResizeGrip] = ColorFromBytes(82, 184, 214, 100);
    colors[ImGuiCol_ResizeGripHovered] = ColorFromBytes(82, 184, 214, 180);
    colors[ImGuiCol_ResizeGripActive] = ColorFromBytes(82, 184, 214, 230);
    colors[ImGuiCol_Tab] = ColorFromBytes(24, 33, 48);
    colors[ImGuiCol_TabHovered] = ColorFromBytes(46, 63, 88);
    colors[ImGuiCol_TabActive] = ColorFromBytes(51, 73, 104);
    colors[ImGuiCol_TableHeaderBg] = ColorFromBytes(20, 28, 40);
    colors[ImGuiCol_TableBorderStrong] = ColorFromBytes(44, 56, 77);
    colors[ImGuiCol_TableBorderLight] = ColorFromBytes(31, 40, 56);
}

std::string Trim(const std::string& value) {
    const auto start = value.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return std::string();
    }
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(start, end - start + 1);
}

std::string ToLowerHex(const uint8_t* data, size_t length) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        stream << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    return stream.str();
}

void CopyString(char* destination, size_t size, const std::string& source) {
    if (!destination || size == 0) {
        return;
    }
    std::snprintf(destination, size, "%s", source.c_str());
}

std::string TimestampNow() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm local_tm{};
#ifdef _WIN32
    localtime_s(&local_tm, &now_time);
#else
    localtime_r(&now_time, &local_tm);
#endif
    char buffer[16];
    std::strftime(buffer, sizeof(buffer), "%H:%M:%S", &local_tm);
    return std::string(buffer);
}

std::string FormatString(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    std::vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    return std::string(buffer);
}

bool ParseFixedHex(const std::string& text, uint8_t* output, size_t output_length) {
    const std::string value = Trim(text);
    if (value.size() != output_length * 2) {
        return false;
    }

    for (size_t i = 0; i < output_length; ++i) {
        const char hi = value[i * 2];
        const char lo = value[i * 2 + 1];
        if (!std::isxdigit(static_cast<unsigned char>(hi)) ||
            !std::isxdigit(static_cast<unsigned char>(lo))) {
            return false;
        }

        char byte_buffer[3] = { hi, lo, '\0' };
        output[i] = static_cast<uint8_t>(std::strtoul(byte_buffer, nullptr, 16));
    }

    return true;
}

bool ParseUint16(const std::string& text, uint16_t& value, int base) {
    const std::string trimmed = Trim(text);
    if (trimmed.empty()) {
        return false;
    }

    char* end_ptr = nullptr;
    const unsigned long parsed = std::strtoul(trimmed.c_str(), &end_ptr, base);
    if (!end_ptr || *end_ptr != '\0' || parsed > 0xFFFFUL) {
        return false;
    }

    value = static_cast<uint16_t>(parsed);
    return true;
}

bool ParseMfgCode(const std::string& text, uint16_t& value) {
    std::string trimmed = Trim(text);
    if (trimmed.empty()) {
        return false;
    }
    if (trimmed.rfind("0x", 0) != 0 && trimmed.rfind("0X", 0) != 0) {
        trimmed = "0x" + trimmed;
    }
    return ParseUint16(trimmed, value, 0);
}

std::string HexDump(const uint8_t* data, size_t length) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (size_t offset = 0; offset < length; offset += 16) {
        stream << std::setw(4) << offset << "  ";
        for (size_t i = 0; i < 16; ++i) {
            if (offset + i < length) {
                stream << std::setw(2) << static_cast<unsigned int>(data[offset + i]) << ' ';
            } else {
                stream << "   ";
            }
        }
        stream << " |";
        for (size_t i = 0; i < 16 && offset + i < length; ++i) {
            const unsigned char c = data[offset + i];
            stream << (std::isprint(c) ? static_cast<char>(c) : '.');
        }
        stream << "|\n";
    }
    return stream.str();
}

bool DecodeCoapNibble(const uint8_t* packet, uint16_t packet_length, uint16_t& position,
                      uint8_t nibble, uint16_t& value) {
    if (nibble <= 12) {
        value = nibble;
        return true;
    }
    if (nibble == 13) {
        if (position >= packet_length) {
            return false;
        }
        value = static_cast<uint16_t>(packet[position++]) + 13;
        return true;
    }
    if (nibble == 14) {
        if (position + 1 >= packet_length) {
            return false;
        }
        const uint16_t ext = static_cast<uint16_t>((packet[position] << 8) | packet[position + 1]);
        position += 2;
        value = static_cast<uint16_t>(ext + 269);
        return true;
    }
    return false;
}

bool FindCoapOptionAndPayload(uint8_t* packet, uint16_t packet_length, uint16_t target_option,
                              uint16_t& option_offset, uint16_t& option_length,
                              uint16_t& payload_offset) {
    if (!packet || packet_length < 4) {
        return false;
    }

    const uint8_t token_length = packet[0] & 0x0F;
    uint16_t position = static_cast<uint16_t>(4 + token_length);
    uint16_t previous_option = 0;

    option_offset = 0;
    option_length = 0;
    payload_offset = packet_length;

    while (position < packet_length) {
        if (packet[position] == SigNet::COAP_PAYLOAD_MARKER) {
            payload_offset = static_cast<uint16_t>(position + 1);
            return option_length > 0;
        }

        const uint8_t header = packet[position++];
        const uint8_t delta_nibble = static_cast<uint8_t>((header >> 4) & 0x0F);
        const uint8_t length_nibble = static_cast<uint8_t>(header & 0x0F);
        uint16_t delta = 0;
        uint16_t length = 0;

        if (!DecodeCoapNibble(packet, packet_length, position, delta_nibble, delta) ||
            !DecodeCoapNibble(packet, packet_length, position, length_nibble, length)) {
            return false;
        }

        const uint16_t option_number = static_cast<uint16_t>(previous_option + delta);
        if (position + length > packet_length) {
            return false;
        }

        if (option_number == target_option) {
            option_offset = position;
            option_length = length;
        }

        position = static_cast<uint16_t>(position + length);
        previous_option = option_number;
    }

    return option_length > 0;
}

bool InjectBadFrame(SigNet::PacketBuffer& buffer) {
    static const char* kBadText = "This is an intentionally bad HMAC.";
    uint8_t* packet = buffer.GetMutableBuffer();
    const uint16_t packet_length = buffer.GetSize();
    uint16_t hmac_offset = 0;
    uint16_t hmac_length = 0;
    uint16_t payload_offset = packet_length;

    if (!FindCoapOptionAndPayload(packet, packet_length, SigNet::SIGNET_OPTION_HMAC,
                                  hmac_offset, hmac_length, payload_offset)) {
        return false;
    }
    if (hmac_length != SigNet::HMAC_SHA256_LENGTH) {
        return false;
    }

    for (uint16_t i = 0; i < hmac_length; ++i) {
        packet[hmac_offset + i] = static_cast<uint8_t>(~packet[hmac_offset + i]);
    }

    if (payload_offset < packet_length) {
        const uint16_t payload_length = static_cast<uint16_t>(packet_length - payload_offset);
        const uint16_t marker_length = static_cast<uint16_t>(std::strlen(kBadText));
        const uint16_t copy_length = std::min(payload_length, marker_length);
        std::memset(packet + payload_offset, 0, payload_length);
        std::memcpy(packet + payload_offset, kBadText, copy_length);
    }

    return true;
}

std::vector<InterfaceInfo> EnumerateIPv4Interfaces() {
    std::vector<InterfaceInfo> interfaces;
    std::set<std::string> seen;

    interfaces.push_back({"Loopback (127.0.0.1)", "127.0.0.1"});
    seen.insert("127.0.0.1");

#ifndef _WIN32
    ifaddrs* raw_ifaddrs = nullptr;
    if (getifaddrs(&raw_ifaddrs) == 0) {
        for (ifaddrs* current = raw_ifaddrs; current; current = current->ifa_next) {
            if (!current->ifa_addr || current->ifa_addr->sa_family != AF_INET) {
                continue;
            }

            sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(current->ifa_addr);
            char address_buffer[INET_ADDRSTRLEN] = {0};
            if (!inet_ntop(AF_INET, &ipv4->sin_addr, address_buffer, sizeof(address_buffer))) {
                continue;
            }

            const std::string ip = address_buffer;
            if (seen.insert(ip).second) {
                const bool loopback = (current->ifa_flags & IFF_LOOPBACK) != 0;
                interfaces.push_back({
                    std::string(current->ifa_name ? current->ifa_name : "iface") +
                        (loopback ? " (loopback) " : " ") + ip,
                    ip
                });
            }
        }
        freeifaddrs(raw_ifaddrs);
    }
#endif

    return interfaces;
}

class UdpMulticastSender {
public:
    UdpMulticastSender() = default;

    ~UdpMulticastSender() {
        Shutdown();
    }

    bool EnsureInitialized(std::string& error_message) {
        if (initialized_ && socket_fd_ != InvalidSocket()) {
            return true;
        }

#ifdef _WIN32
        if (!winsock_started_) {
            WSADATA wsa_data;
            const int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
            if (result != 0) {
                error_message = FormatString("WSAStartup failed: %d", result);
                return false;
            }
            winsock_started_ = true;
        }
#endif

        socket_fd_ = static_cast<int>(::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
        if (socket_fd_ == InvalidSocket()) {
            error_message = LastSocketError("Socket creation failed");
            return false;
        }

        sockaddr_in local_addr{};
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        local_addr.sin_port = 0;

        if (::bind(socket_fd_, reinterpret_cast<sockaddr*>(&local_addr), sizeof(local_addr)) < 0) {
            error_message = LastSocketError("Socket bind failed");
        }

        unsigned char loopback = 1;
        if (::setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_LOOP,
                         reinterpret_cast<const char*>(&loopback), sizeof(loopback)) < 0) {
            error_message = LastSocketError("Set loopback failed");
        }

        unsigned char ttl = 16;
        if (::setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_TTL,
                         reinterpret_cast<const char*>(&ttl), sizeof(ttl)) < 0) {
            error_message = LastSocketError("Set TTL failed");
        }

        int broadcast = 1;
        ::setsockopt(socket_fd_, SOL_SOCKET, SO_BROADCAST,
                     reinterpret_cast<const char*>(&broadcast), sizeof(broadcast));

        initialized_ = true;
        return true;
    }

    void Shutdown() {
        if (socket_fd_ != InvalidSocket()) {
#ifdef _WIN32
            closesocket(socket_fd_);
#else
            close(socket_fd_);
#endif
            socket_fd_ = InvalidSocket();
        }

        initialized_ = false;

#ifdef _WIN32
        if (winsock_started_) {
            WSACleanup();
            winsock_started_ = false;
        }
#endif
    }

    bool Send(const std::string& destination_ip, uint16_t destination_port,
              const uint8_t* payload, size_t payload_size,
              const std::string& source_ip, std::string& error_message) {
        if (!payload || payload_size == 0) {
            error_message = "No payload to send.";
            return false;
        }

        if (!EnsureInitialized(error_message)) {
            return false;
        }

        const std::string trimmed_source = Trim(source_ip);
        const bool use_loopback = trimmed_source.rfind("127.", 0) == 0;
        if (!trimmed_source.empty() && !use_loopback) {
            in_addr iface_addr{};
            if (::inet_pton(AF_INET, trimmed_source.c_str(), &iface_addr) != 1) {
                error_message = "Invalid source interface IPv4 address.";
            } else if (::setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_IF,
                                    reinterpret_cast<const char*>(&iface_addr),
                                    sizeof(iface_addr)) < 0) {
                error_message = LastSocketError("IP_MULTICAST_IF failed");
            }
        }

        sockaddr_in dest_addr{};
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(destination_port);
        if (::inet_pton(AF_INET, destination_ip.c_str(), &dest_addr.sin_addr) != 1) {
            error_message = "Invalid destination IPv4 address.";
            return false;
        }

        const int bytes_sent = static_cast<int>(::sendto(
            socket_fd_,
            reinterpret_cast<const char*>(payload),
            static_cast<int>(payload_size),
            0,
            reinterpret_cast<sockaddr*>(&dest_addr),
            sizeof(dest_addr)
        ));

        if (bytes_sent < 0) {
            if (!trimmed_source.empty() && !use_loopback) {
                in_addr any_addr{};
                any_addr.s_addr = htonl(INADDR_ANY);
                ::setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_IF,
                             reinterpret_cast<const char*>(&any_addr), sizeof(any_addr));

                const int retry_bytes_sent = static_cast<int>(::sendto(
                    socket_fd_,
                    reinterpret_cast<const char*>(payload),
                    static_cast<int>(payload_size),
                    0,
                    reinterpret_cast<sockaddr*>(&dest_addr),
                    sizeof(dest_addr)
                ));

                if (retry_bytes_sent == static_cast<int>(payload_size)) {
                    return true;
                }
            }

            error_message = LastSocketError("sendto() failed");
            return false;
        }

        if (bytes_sent != static_cast<int>(payload_size)) {
            error_message = FormatString("Partial send: %d of %zu bytes", bytes_sent, payload_size);
            return false;
        }

        return true;
    }

private:
#ifdef _WIN32
    static int InvalidSocket() {
        return static_cast<int>(INVALID_SOCKET);
    }
#else
    static int InvalidSocket() {
        return -1;
    }
#endif

    std::string LastSocketError(const char* prefix) const {
#ifdef _WIN32
        return FormatString("%s: WSA error %d", prefix, WSAGetLastError());
#else
        return FormatString("%s: %s", prefix, std::strerror(errno));
#endif
    }

    int socket_fd_ = InvalidSocket();
    bool initialized_ = false;
#ifdef _WIN32
    bool winsock_started_ = false;
#endif
};

class UdpMulticastReceiver {
public:
    UdpMulticastReceiver() = default;

    ~UdpMulticastReceiver() {
        Shutdown();
    }

    bool Configure(const std::vector<std::string>& group_ips,
                   const std::string& interface_ip,
                   std::string& error_message) {
        std::vector<std::string> requested_groups;
        for (const std::string& group_ip : group_ips) {
            const std::string trimmed_group = Trim(group_ip);
            if (!trimmed_group.empty()) {
                requested_groups.push_back(trimmed_group);
            }
        }
        std::sort(requested_groups.begin(), requested_groups.end());
        requested_groups.erase(std::unique(requested_groups.begin(), requested_groups.end()), requested_groups.end());

        const std::string trimmed_interface = Trim(interface_ip);
        if (requested_groups.empty()) {
            Shutdown();
            interface_ip_ = trimmed_interface;
            return true;
        }

        if (socket_fd_ != InvalidSocket() && requested_groups == joined_groups_ &&
            trimmed_interface == interface_ip_) {
            return true;
        }

        Shutdown();

#ifdef _WIN32
        if (!winsock_started_) {
            WSADATA wsa_data;
            const int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
            if (result != 0) {
                error_message = FormatString("WSAStartup failed: %d", result);
                return false;
            }
            winsock_started_ = true;
        }
#endif

        socket_fd_ = static_cast<int>(::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
        if (socket_fd_ == InvalidSocket()) {
            error_message = LastSocketError("Receiver socket creation failed");
            return false;
        }

        int reuse = 1;
        if (::setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR,
                         reinterpret_cast<const char*>(&reuse), sizeof(reuse)) < 0) {
            error_message = LastSocketError("Receiver SO_REUSEADDR failed");
            Shutdown();
            return false;
        }

#ifdef SO_REUSEPORT
        ::setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEPORT,
                     reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#endif

        sockaddr_in local_addr{};
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        local_addr.sin_port = htons(SigNet::SIGNET_UDP_PORT);
        if (::bind(socket_fd_, reinterpret_cast<sockaddr*>(&local_addr), sizeof(local_addr)) < 0) {
            error_message = LastSocketError("Receiver bind failed");
            Shutdown();
            return false;
        }

        if (!SetNonBlocking(error_message)) {
            Shutdown();
            return false;
        }

        for (const std::string& group_ip : requested_groups) {
            if (!JoinGroup(group_ip, trimmed_interface, error_message)) {
                Shutdown();
                return false;
            }
        }

        joined_groups_ = requested_groups;
        interface_ip_ = trimmed_interface;
        return true;
    }

    bool Poll(std::vector<ReceivedDatagram>& datagrams, std::string& error_message) {
        datagrams.clear();
        if (socket_fd_ == InvalidSocket()) {
            return true;
        }

        for (int i = 0; i < 32; ++i) {
            std::array<uint8_t, SigNet::MAX_UDP_PAYLOAD> buffer{};
            sockaddr_in source_addr{};
#ifdef _WIN32
            int source_addr_len = sizeof(source_addr);
#else
            socklen_t source_addr_len = sizeof(source_addr);
#endif
            const int bytes_read = static_cast<int>(::recvfrom(
                socket_fd_,
                reinterpret_cast<char*>(buffer.data()),
                static_cast<int>(buffer.size()),
                0,
                reinterpret_cast<sockaddr*>(&source_addr),
                &source_addr_len
            ));

            if (bytes_read < 0) {
                if (IsWouldBlockError()) {
                    return true;
                }
                error_message = LastSocketError("recvfrom() failed");
                return false;
            }
            if (bytes_read == 0) {
                break;
            }

            ReceivedDatagram datagram;
            datagram.payload.assign(buffer.begin(), buffer.begin() + bytes_read);
            char source_ip[INET_ADDRSTRLEN] = {0};
            if (::inet_ntop(AF_INET, &source_addr.sin_addr, source_ip, sizeof(source_ip))) {
                datagram.source_ip = source_ip;
            } else {
                datagram.source_ip = "0.0.0.0";
            }
            datagram.source_port = ntohs(source_addr.sin_port);
            datagrams.push_back(std::move(datagram));
        }

        return true;
    }

    void Shutdown() {
        if (socket_fd_ != InvalidSocket()) {
#ifdef _WIN32
            closesocket(socket_fd_);
#else
            close(socket_fd_);
#endif
            socket_fd_ = InvalidSocket();
        }

        joined_groups_.clear();
        interface_ip_.clear();

#ifdef _WIN32
        if (winsock_started_) {
            WSACleanup();
            winsock_started_ = false;
        }
#endif
    }

    bool IsActive() const {
        return socket_fd_ != InvalidSocket();
    }

private:
#ifdef _WIN32
    static int InvalidSocket() {
        return static_cast<int>(INVALID_SOCKET);
    }
#else
    static int InvalidSocket() {
        return -1;
    }
#endif

    std::string LastSocketError(const char* prefix) const {
#ifdef _WIN32
        return FormatString("%s: WSA error %d", prefix, WSAGetLastError());
#else
        return FormatString("%s: %s", prefix, std::strerror(errno));
#endif
    }

    bool SetNonBlocking(std::string& error_message) {
#ifdef _WIN32
        u_long non_blocking = 1;
        if (ioctlsocket(socket_fd_, FIONBIO, &non_blocking) != 0) {
            error_message = LastSocketError("Receiver non-blocking mode failed");
            return false;
        }
#else
        const int flags = fcntl(socket_fd_, F_GETFL, 0);
        if (flags < 0) {
            error_message = LastSocketError("Receiver F_GETFL failed");
            return false;
        }
        if (fcntl(socket_fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
            error_message = LastSocketError("Receiver F_SETFL failed");
            return false;
        }
#endif
        return true;
    }

    bool JoinGroup(const std::string& group_ip,
                   const std::string& interface_ip,
                   std::string& error_message) {
        ip_mreq membership{};
        if (::inet_pton(AF_INET, group_ip.c_str(), &membership.imr_multiaddr) != 1) {
            error_message = FormatString("Invalid multicast group address: %s", group_ip.c_str());
            return false;
        }

        membership.imr_interface.s_addr = htonl(INADDR_ANY);
        if (!interface_ip.empty() && interface_ip.rfind("127.", 0) != 0) {
            if (::inet_pton(AF_INET, interface_ip.c_str(), &membership.imr_interface) != 1) {
                error_message = FormatString("Invalid receive interface address: %s", interface_ip.c_str());
                return false;
            }
        }

        if (::setsockopt(socket_fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         reinterpret_cast<const char*>(&membership), sizeof(membership)) < 0) {
            error_message = LastSocketError("Receiver IP_ADD_MEMBERSHIP failed");
            return false;
        }

        return true;
    }

    bool IsWouldBlockError() const {
#ifdef _WIN32
        const int error_code = WSAGetLastError();
        return error_code == WSAEWOULDBLOCK;
#else
        return errno == EWOULDBLOCK || errno == EAGAIN;
#endif
    }

    int socket_fd_ = InvalidSocket();
    std::vector<std::string> joined_groups_;
    std::string interface_ip_;
#ifdef _WIN32
    bool winsock_started_ = false;
#endif
};

struct AppState {
    std::array<uint8_t, 32> k0_key{};
    std::array<uint8_t, 32> sender_key{};
    std::array<uint8_t, 32> citizen_key{};
    std::array<uint8_t, 512> dmx_buffer{};
    std::array<uint8_t, 6> tuid{};

    char k0_hex[65] = {0};
    char sender_key_hex[65] = {0};
    char citizen_key_hex[65] = {0};
    char passphrase[128] = "Ge2p$E$4*A";
    char passphrase_report[256] = {0};
    char tuid_hex[13] = {0};
    char source_ip[64] = "127.0.0.1";
    char announce_version_string[64] = "v0.15-test";
    char announce_mfg_code[16] = "0x5379";
    char announce_product_variant[16] = "0001";

    bool keys_valid = false;
    bool k0_set = false;
    bool keep_alive_enabled = false;
    bool insert_bad_frames = false;
    bool auto_scroll_log = true;
    bool receiver_enabled = false;
    bool receiver_listen_announces = true;
    bool receiver_listen_universe = true;
    bool receiver_active = false;
    bool auto_scroll_receive_log = true;

    int passphrase_status = SigNet::SIGNET_PASSPHRASE_TOO_SHORT;
    int endpoint = 1;
    int universe = 1;
    int bad_frame_interval = 50;
    int dmx_scroll_position = 0;
    int announce_version_num = 3;
    int selected_interface_index = 0;
    int selected_discovered_node = -1;

    uint32_t session_id = 1;
    uint32_t sequence_num = 1;
    uint16_t message_id = 1;
    uint32_t send_count = 0;
    uint32_t error_count = 0;
    uint32_t last_packet_size = 0;
    uint32_t good_frames_since_bad = 0;
    uint32_t last_send_tick = 0;
    uint32_t last_dynamic_tick = 0;
    uint32_t received_packet_count = 0;
    uint32_t received_announce_count = 0;
    uint32_t receive_error_count = 0;

    uint8_t rgb_r = 255;
    uint8_t rgb_g = 0;
    uint8_t rgb_b = 0;
    uint8_t rgb_phase = 0;

    PacketPreview last_preview;
    ReceivedPacketPreview last_received_preview;
    std::vector<std::string> log_lines;
    std::vector<std::string> receive_log_lines;
    std::vector<InterfaceInfo> interfaces;
    std::vector<DiscoveredNode> discovered_nodes;
    std::string receiver_last_error;

    enum DmxMode {
        Manual,
        Dynamic
    } dmx_mode = Manual;

    enum ViewMode {
        ViewTransmit,
        ViewReceive
    } view_mode = ViewTransmit;

    UdpMulticastSender udp_sender;
    UdpMulticastReceiver udp_receiver;
};

void LogMessage(AppState& state, const std::string& message) {
    state.log_lines.push_back("[" + TimestampNow() + "] " + message);
    if (state.log_lines.size() > 200) {
        state.log_lines.erase(state.log_lines.begin(), state.log_lines.begin() + 1);
    }
}

void LogError(AppState& state, const std::string& message) {
    LogMessage(state, "ERROR: " + message);
}

void LogReceiveMessage(AppState& state, const std::string& message) {
    state.receive_log_lines.push_back("[" + TimestampNow() + "] " + message);
    if (state.receive_log_lines.size() > 250) {
        state.receive_log_lines.erase(state.receive_log_lines.begin(), state.receive_log_lines.begin() + 1);
    }
}

void LogReceiveError(AppState& state, const std::string& message) {
    ++state.receive_error_count;
    LogReceiveMessage(state, "ERROR: " + message);
}

void UpdateKeyHexDisplays(AppState& state) {
    CopyString(state.k0_hex, sizeof(state.k0_hex), ToLowerHex(state.k0_key.data(), state.k0_key.size()));
    CopyString(state.sender_key_hex, sizeof(state.sender_key_hex), ToLowerHex(state.sender_key.data(), state.sender_key.size()));
    CopyString(state.citizen_key_hex, sizeof(state.citizen_key_hex), ToLowerHex(state.citizen_key.data(), state.citizen_key.size()));
}

void RefreshPassphraseReport(AppState& state) {
    char report[256] = {0};
    state.passphrase_status = SigNet::Crypto::GetPassphraseValidationReport(
        state.passphrase,
        static_cast<uint32_t>(std::strlen(state.passphrase)),
        report,
        sizeof(report)
    );
    CopyString(state.passphrase_report, sizeof(state.passphrase_report), report);
}

bool DeriveKeysFromK0(AppState& state) {
    if (SigNet::Crypto::DeriveSenderKey(state.k0_key.data(), state.sender_key.data()) != SigNet::SIGNET_SUCCESS) {
        LogError(state, "Failed to derive sender key.");
        state.keys_valid = false;
        state.k0_set = false;
        return false;
    }

    if (SigNet::Crypto::DeriveCitizenKey(state.k0_key.data(), state.citizen_key.data()) != SigNet::SIGNET_SUCCESS) {
        LogError(state, "Failed to derive citizen key.");
        state.keys_valid = false;
        state.k0_set = false;
        return false;
    }

    state.keys_valid = true;
    state.k0_set = true;
    UpdateKeyHexDisplays(state);
    return true;
}

bool ApplyK0Hex(AppState& state) {
    if (!ParseFixedHex(state.k0_hex, state.k0_key.data(), state.k0_key.size())) {
        LogError(state, "K0 must be 64 hex characters.");
        return false;
    }

    if (!DeriveKeysFromK0(state)) {
        return false;
    }

    LogMessage(state, "K0 applied and Ks/Kc derived successfully.");
    return true;
}

bool DeriveK0FromPassphrase(AppState& state) {
    RefreshPassphraseReport(state);
    if (state.passphrase_status != SigNet::SIGNET_PASSPHRASE_VALID) {
        LogError(state, "Passphrase does not meet Sig-Net complexity requirements.");
        return false;
    }

    if (SigNet::Crypto::DeriveK0FromPassphrase(
            state.passphrase,
            static_cast<uint32_t>(std::strlen(state.passphrase)),
            state.k0_key.data()) != SigNet::SIGNET_SUCCESS) {
        LogError(state, "Failed to derive K0 from passphrase.");
        return false;
    }

    if (!DeriveKeysFromK0(state)) {
        return false;
    }

    LogMessage(state, "Derived K0 from passphrase and updated Ks/Kc.");
    return true;
}

bool GenerateRandomK0(AppState& state) {
    if (SigNet::Crypto::GenerateRandomK0(state.k0_key.data()) != SigNet::SIGNET_SUCCESS) {
        LogError(state, "Failed to generate random K0.");
        return false;
    }

    if (!DeriveKeysFromK0(state)) {
        return false;
    }

    LogMessage(state, "Generated random K0 and updated Ks/Kc.");
    return true;
}

bool GenerateRandomPassphrase(AppState& state) {
    char output[32] = {0};
    if (SigNet::Crypto::GenerateRandomPassphrase(output, sizeof(output)) != SigNet::SIGNET_SUCCESS) {
        LogError(state, "Failed to generate random passphrase.");
        return false;
    }

    CopyString(state.passphrase, sizeof(state.passphrase), output);
    RefreshPassphraseReport(state);
    LogMessage(state, "Generated random passphrase.");
    return true;
}

bool ParseTuid(AppState& state) {
    if (SigNet::Crypto::TUID_FromHexString(state.tuid_hex, state.tuid.data()) != SigNet::SIGNET_SUCCESS) {
        LogError(state, "TUID must be 12 hex characters.");
        return false;
    }
    return true;
}

void UpdateInterfaceSelection(AppState& state) {
    state.interfaces = EnumerateIPv4Interfaces();
    state.selected_interface_index = 0;
    const std::string current_ip = Trim(state.source_ip);
    for (size_t i = 0; i < state.interfaces.size(); ++i) {
        if (state.interfaces[i].ip == current_ip) {
            state.selected_interface_index = static_cast<int>(i);
            break;
        }
    }
}

void AdvanceSequence(AppState& state) {
    if (state.sequence_num == 0xFFFFFFFFu) {
        ++state.session_id;
        state.sequence_num = 1;
        LogMessage(state, FormatString("Session rolled over to %u", state.session_id));
    } else {
        state.sequence_num = SigNet::IncrementSequence(state.sequence_num);
    }
    ++state.message_id;
}

void RecordPreview(AppState& state, const SigNet::PacketBuffer& buffer, const std::string& destination_ip) {
    state.last_preview.destination_ip = destination_ip;
    state.last_preview.hex_dump = HexDump(buffer.GetBuffer(), buffer.GetSize());
    state.last_packet_size = buffer.GetSize();
}

bool SendBuffer(AppState& state, SigNet::PacketBuffer& buffer, const std::string& destination_ip) {
    RecordPreview(state, buffer, destination_ip);

    std::string send_error;
    if (!state.udp_sender.Send(destination_ip, SigNet::SIGNET_UDP_PORT,
                               buffer.GetBuffer(), buffer.GetSize(),
                               state.source_ip, send_error)) {
        ++state.error_count;
        LogError(state, send_error);
        return false;
    }

    ++state.send_count;
    state.last_send_tick = SDL_GetTicks();
    AdvanceSequence(state);
    return true;
}

bool SendLevelPacket(AppState& state, const char* reason) {
    if (!state.keys_valid) {
        ++state.error_count;
        LogError(state, "Cannot send level packet before Ks/Kc are derived.");
        return false;
    }

    if (!ParseTuid(state)) {
        ++state.error_count;
        return false;
    }

    if (state.endpoint < 1) {
        state.endpoint = 1;
    }

    const uint16_t universe = static_cast<uint16_t>(std::clamp(state.universe,
        static_cast<int>(SigNet::MIN_UNIVERSE), static_cast<int>(SigNet::MAX_UNIVERSE)));
    state.universe = universe;

    SigNet::PacketBuffer buffer;
    const int32_t build_result = SigNet::BuildDMXPacket(
        buffer,
        universe,
        state.dmx_buffer.data(),
        static_cast<uint16_t>(state.dmx_buffer.size()),
        state.tuid.data(),
        static_cast<uint16_t>(state.endpoint),
        0x0000,
        state.session_id,
        state.sequence_num,
        state.sender_key.data(),
        state.message_id
    );

    if (build_result != SigNet::SIGNET_SUCCESS) {
        ++state.error_count;
        LogError(state, FormatString("Failed to build level packet: error %d", build_result));
        return false;
    }

    bool injected_bad_frame = false;
    if (state.insert_bad_frames) {
        if (state.bad_frame_interval < 1) {
            state.bad_frame_interval = 1;
        }
        if (state.good_frames_since_bad >= static_cast<uint32_t>(state.bad_frame_interval)) {
            injected_bad_frame = InjectBadFrame(buffer);
            if (!injected_bad_frame) {
                LogError(state, "Failed to inject intentionally bad frame; sending normal frame.");
            }
        }
    }

    char multicast_ip[32] = {0};
    SigNet::CalculateMulticastAddress(universe, multicast_ip);

    const uint32_t sent_sequence = state.sequence_num;
    if (!SendBuffer(state, buffer, multicast_ip)) {
        return false;
    }

    if (state.insert_bad_frames) {
        if (injected_bad_frame) {
            state.good_frames_since_bad = 0;
            LogMessage(state, "Inserted intentionally bad frame.");
        } else {
            ++state.good_frames_since_bad;
        }
    }

    LogMessage(state, FormatString("Level packet sent (%s): seq=%u size=%u dest=%s",
        reason, sent_sequence, state.last_packet_size, multicast_ip));
    return true;
}

bool SendAnnouncePacket(AppState& state) {
    if (!state.keys_valid) {
        ++state.error_count;
        LogError(state, "Cannot send announce before Ks/Kc are derived.");
        return false;
    }

    if (!ParseTuid(state)) {
        ++state.error_count;
        return false;
    }

    uint16_t firmware_version_id = 0;
    uint16_t manufacturer_code = 0;
    uint16_t product_variant_id = 0;

    if (state.announce_version_num < 0 || state.announce_version_num > 0xFFFF) {
        ++state.error_count;
        LogError(state, "Announce version number must fit in 16 bits.");
        return false;
    }
    firmware_version_id = static_cast<uint16_t>(state.announce_version_num);

    if (!ParseMfgCode(state.announce_mfg_code, manufacturer_code)) {
        ++state.error_count;
        LogError(state, "Manufacturer code must be valid hex, for example 5379 or 0x5379.");
        return false;
    }

    if (!ParseUint16(state.announce_product_variant, product_variant_id, 16)) {
        ++state.error_count;
        LogError(state, "Product variant must be valid hexadecimal.");
        return false;
    }

    const std::string version_string = Trim(state.announce_version_string);
    if (version_string.empty()) {
        ++state.error_count;
        LogError(state, "Version string cannot be empty.");
        return false;
    }

    SigNet::PacketBuffer buffer;
    const int32_t build_result = SigNet::BuildAnnouncePacket(
        buffer,
        state.tuid.data(),
        manufacturer_code,
        product_variant_id,
        firmware_version_id,
        version_string.c_str(),
        0x01,
        SigNet::ROLE_CAP_SENDER,
        0x0000,
        state.session_id,
        state.sequence_num,
        state.citizen_key.data(),
        state.message_id
    );

    if (build_result != SigNet::SIGNET_SUCCESS) {
        ++state.error_count;
        LogError(state, FormatString("Failed to build announce packet: error %d", build_result));
        return false;
    }

    const uint32_t sent_sequence = state.sequence_num;
    if (!SendBuffer(state, buffer, SigNet::MULTICAST_NODE_SEND_IP)) {
        return false;
    }

    LogMessage(state, FormatString("Announce packet sent: seq=%u size=%u dest=%s",
        sent_sequence, state.last_packet_size, SigNet::MULTICAST_NODE_SEND_IP));
    return true;
}

void UpdateDynamicPattern(AppState& state) {
    if (state.rgb_phase == 0) {
        if (state.rgb_r > 0) {
            --state.rgb_r;
        }
        if (state.rgb_g < 255) {
            ++state.rgb_g;
        }
        if (state.rgb_r == 0 && state.rgb_g == 255) {
            state.rgb_phase = 1;
        }
    } else if (state.rgb_phase == 1) {
        if (state.rgb_g > 0) {
            --state.rgb_g;
        }
        if (state.rgb_b < 255) {
            ++state.rgb_b;
        }
        if (state.rgb_g == 0 && state.rgb_b == 255) {
            state.rgb_phase = 2;
        }
    } else {
        if (state.rgb_b > 0) {
            --state.rgb_b;
        }
        if (state.rgb_r < 255) {
            ++state.rgb_r;
        }
        if (state.rgb_b == 0 && state.rgb_r == 255) {
            state.rgb_phase = 0;
        }
    }

    for (size_t i = 0; i < state.dmx_buffer.size(); ++i) {
        const int slot = static_cast<int>(i % 3);
        if (slot == 0) {
            state.dmx_buffer[i] = state.rgb_r;
        } else if (slot == 1) {
            state.dmx_buffer[i] = state.rgb_g;
        } else {
            state.dmx_buffer[i] = state.rgb_b;
        }
    }
}

void RunSelfTest(AppState& state) {
    SigNet::SelfTest::TestSuiteResults results;
    const int32_t rc = SigNet::SelfTest::RunAllTests(results);
    LogMessage(state, FormatString("Self-test finished: %zu/%zu passed.", results.passed_count, results.test_count));
    for (size_t i = 0; i < results.test_count; ++i) {
        if (!results.tests[i].passed) {
            LogError(state, FormatString("Self-test failed: %s %s",
                results.tests[i].name,
                results.tests[i].error_message[0] ? results.tests[i].error_message : ""));
        }
    }
    if (rc == SigNet::SIGNET_SUCCESS) {
        LogMessage(state, "All self-tests passed.");
    }
}

const char* DmxModeLabel(const AppState& state) {
    return state.dmx_mode == AppState::Manual ? "Manual" : "Dynamic RGB";
}

ImVec4 PassphraseStatusColor(int status) {
    if (status == SigNet::SIGNET_PASSPHRASE_VALID) {
        return ColorFromBytes(90, 201, 131);
    }
    if (status == SigNet::SIGNET_PASSPHRASE_TOO_SHORT ||
        status == SigNet::SIGNET_PASSPHRASE_TOO_LONG) {
        return ColorFromBytes(255, 191, 92);
    }
    return ColorFromBytes(247, 108, 94);
}

const char* PassphraseStatusLabel(int status) {
    if (status == SigNet::SIGNET_PASSPHRASE_VALID) {
        return "Ready";
    }
    if (status == SigNet::SIGNET_PASSPHRASE_TOO_SHORT) {
        return "Too Short";
    }
    if (status == SigNet::SIGNET_PASSPHRASE_TOO_LONG) {
        return "Too Long";
    }
    if (status == SigNet::SIGNET_PASSPHRASE_INSUFFICIENT_CLASSES) {
        return "Needs More Classes";
    }
    if (status == SigNet::SIGNET_PASSPHRASE_CONSECUTIVE_IDENTICAL) {
        return "Repeated Chars";
    }
    if (status == SigNet::SIGNET_PASSPHRASE_CONSECUTIVE_SEQUENTIAL) {
        return "Sequential Pattern";
    }
    return "Check Passphrase";
}

std::string CurrentMulticastPreview(const AppState& state) {
    if (state.universe < static_cast<int>(SigNet::MIN_UNIVERSE) ||
        state.universe > static_cast<int>(SigNet::MAX_UNIVERSE)) {
        return "n/a";
    }

    char multicast_ip[32] = {0};
    if (SigNet::CalculateMulticastAddress(static_cast<uint16_t>(state.universe), multicast_ip) != SigNet::SIGNET_SUCCESS) {
        return "n/a";
    }

    return multicast_ip;
}

uint16_t ReadUInt16BE(const uint8_t* data) {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
}

uint32_t ReadUInt32BE(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

bool LocatePayloadOffset(const uint8_t* packet, uint16_t packet_length, uint16_t& payload_offset) {
    if (!packet || packet_length < 4) {
        return false;
    }

    const uint8_t token_length = packet[0] & 0x0F;
    if (4 + token_length > packet_length) {
        return false;
    }

    uint16_t position = static_cast<uint16_t>(4 + token_length);
    uint16_t previous_option = 0;
    payload_offset = packet_length;

    while (position < packet_length) {
        if (packet[position] == SigNet::COAP_PAYLOAD_MARKER) {
            payload_offset = static_cast<uint16_t>(position + 1);
            return true;
        }

        const uint8_t header = packet[position++];
        uint16_t delta = 0;
        uint16_t length = 0;
        if (!DecodeCoapNibble(packet, packet_length, position, static_cast<uint8_t>((header >> 4) & 0x0F), delta) ||
            !DecodeCoapNibble(packet, packet_length, position, static_cast<uint8_t>(header & 0x0F), length)) {
            return false;
        }
        if (position + length > packet_length) {
            return false;
        }
        position = static_cast<uint16_t>(position + length);
        previous_option = static_cast<uint16_t>(previous_option + delta);
    }

    return true;
}

bool ParseAnnouncePayload(const uint8_t* payload,
                         uint16_t payload_length,
                         DiscoveredNode& node,
                         std::string& error_message) {
    SigNet::Parse::PacketReader reader(payload, payload_length);
    bool found_poll_reply = false;

    while (reader.GetRemaining() > 0) {
        SigNet::TLVBlock tlv;
        const int32_t rc = SigNet::Parse::ParseTLVBlock(reader, tlv);
        if (rc != SigNet::SIGNET_SUCCESS) {
            error_message = FormatString("TLV parse failed: %d", rc);
            return false;
        }

        switch (tlv.type_id) {
            case SigNet::TID_POLL_REPLY:
                if (tlv.length < 12) {
                    error_message = "TID_POLL_REPLY too short.";
                    return false;
                }
                std::copy(tlv.value, tlv.value + 6, node.tuid.begin());
                node.tuid_hex = ToLowerHex(node.tuid.data(), node.tuid.size());
                node.manufacturer_code = ReadUInt16BE(tlv.value + 6);
                node.product_variant_id = ReadUInt16BE(tlv.value + 8);
                node.change_count = ReadUInt16BE(tlv.value + 10);
                found_poll_reply = true;
                break;
            case SigNet::TID_RT_FIRMWARE_VERSION:
                if (tlv.length < 4) {
                    error_message = "TID_RT_FIRMWARE_VERSION too short.";
                    return false;
                }
                node.firmware_version_id = ReadUInt32BE(tlv.value);
                node.firmware_version_string.assign(
                    reinterpret_cast<const char*>(tlv.value + 4),
                    reinterpret_cast<const char*>(tlv.value + tlv.length)
                );
                break;
            case SigNet::TID_RT_PROTOCOL_VERSION:
                if (tlv.length >= 1) {
                    node.protocol_version = tlv.value[0];
                }
                break;
            case SigNet::TID_RT_ROLE_CAPABILITY:
                // v0.15 widened this TID to a 32-bit big-endian role bitfield.
                // Tolerate 1-byte legacy encodings by zero-extending.
                if (tlv.length >= 4) {
                    node.role_capability_bits =
                        (static_cast<uint32_t>(tlv.value[0]) << 24) |
                        (static_cast<uint32_t>(tlv.value[1]) << 16) |
                        (static_cast<uint32_t>(tlv.value[2]) << 8)  |
                        (static_cast<uint32_t>(tlv.value[3]));
                } else if (tlv.length >= 1) {
                    node.role_capability_bits = tlv.value[0];
                }
                break;
            default:
                break;
        }
    }

    if (!found_poll_reply) {
        error_message = "Announce payload missing TID_POLL_REPLY.";
        return false;
    }

    return true;
}

bool ParseIncomingPacket(const ReceivedDatagram& datagram,
                        const AppState& state,
                        ReceivedPacketPreview& preview,
                        DiscoveredNode& discovered_node,
                        bool& has_discovered_node,
                        std::string& error_message) {
    has_discovered_node = false;
    if (datagram.payload.size() < SigNet::COAP_HEADER_SIZE) {
        error_message = "Packet too small for CoAP header.";
        return false;
    }

    SigNet::Parse::PacketReader reader(datagram.payload.data(), static_cast<uint16_t>(datagram.payload.size()));
    SigNet::CoAPHeader header{};
    int32_t rc = SigNet::Parse::ParseCoAPHeader(reader, header);
    if (rc != SigNet::SIGNET_SUCCESS) {
        error_message = FormatString("CoAP header parse failed: %d", rc);
        return false;
    }
    if (header.GetVersion() != SigNet::COAP_VERSION) {
        error_message = FormatString("Unexpected CoAP version %u.", header.GetVersion());
        return false;
    }
    if (header.GetType() != SigNet::COAP_TYPE_NON || header.code != SigNet::COAP_CODE_POST) {
        error_message = "Only CoAP NON POST packets are supported in receive mode.";
        return false;
    }

    rc = SigNet::Parse::SkipToken(reader, header.GetTokenLength());
    if (rc != SigNet::SIGNET_SUCCESS) {
        error_message = FormatString("CoAP token parse failed: %d", rc);
        return false;
    }

    char uri_buffer[128] = {0};
    uint16_t uri_length = 0;
    rc = SigNet::Parse::ExtractURIString(reader, uri_buffer, sizeof(uri_buffer), uri_length);
    if (rc != SigNet::SIGNET_SUCCESS || uri_length == 0) {
        error_message = FormatString("URI extraction failed: %d", rc);
        return false;
    }

    SigNet::SigNetOptions options;
    rc = SigNet::Parse::ParseSigNetOptions(reader, options);
    if (rc != SigNet::SIGNET_SUCCESS) {
        error_message = FormatString("Sig-Net option parse failed: %d", rc);
        return false;
    }

    uint16_t payload_offset = static_cast<uint16_t>(datagram.payload.size());
    if (!LocatePayloadOffset(datagram.payload.data(), static_cast<uint16_t>(datagram.payload.size()), payload_offset)) {
        error_message = "Failed to locate CoAP payload marker.";
        return false;
    }

    const uint8_t* payload = payload_offset < datagram.payload.size() ? datagram.payload.data() + payload_offset : nullptr;
    const uint16_t payload_length = payload_offset < datagram.payload.size()
        ? static_cast<uint16_t>(datagram.payload.size() - payload_offset)
        : 0;

    preview.hex_dump = HexDump(datagram.payload.data(), datagram.payload.size());
    preview.source_ip = datagram.source_ip;
    preview.source_port = datagram.source_port;
    preview.uri.assign(uri_buffer, uri_length);
    preview.packet_kind = "Sig-Net";
    preview.payload_length = payload_length;
    preview.session_id = options.session_id;
    preview.seq_num = options.seq_num;
    preview.received_tick = SDL_GetTicks();

    // URIs now carry a scope segment: /sig-net/v1/{scope}/node/... or
    // /sig-net/v1/{scope}/level/... Build the expected prefixes from the
    // configured scope so matching tracks SetURIScope() at runtime.
    const std::string node_prefix = std::string("/sig-net/v1/") + SigNet::CoAP::GetURIScope() + "/node/";
    const std::string level_prefix = std::string("/sig-net/v1/") + SigNet::CoAP::GetURIScope() + "/level/";

    const uint8_t* verification_key = nullptr;
    if (state.keys_valid) {
        if (preview.uri.find(node_prefix) == 0) {
            verification_key = state.citizen_key.data();
        } else if (preview.uri.find(level_prefix) == 0) {
            verification_key = state.sender_key.data();
        }
    }
    if (verification_key) {
        preview.verify_attempted = true;
        preview.hmac_verified = SigNet::Parse::VerifyPacketHMAC(
            preview.uri.c_str(),
            options,
            payload,
            payload_length,
            verification_key
        ) == SigNet::SIGNET_SUCCESS;
    }

    if (preview.uri.find(node_prefix) == 0) {
        preview.packet_kind = "Announce";
        if (payload_length == 0) {
            error_message = "Announce packet does not contain a TLV payload.";
            return false;
        }
        if (!ParseAnnouncePayload(payload, payload_length, discovered_node, error_message)) {
            return false;
        }
        discovered_node.source_ip = datagram.source_ip;
        discovered_node.uri = preview.uri;
        discovered_node.session_id = options.session_id;
        discovered_node.seq_num = options.seq_num;
        discovered_node.last_seen_tick = preview.received_tick;
        discovered_node.announce_count = 1;
        discovered_node.verify_attempted = preview.verify_attempted;
        discovered_node.hmac_verified = preview.hmac_verified;
        has_discovered_node = true;
        return true;
    }

    if (preview.uri.find(level_prefix) == 0) {
        preview.packet_kind = "Level";
        if (payload && payload_length >= 4) {
            SigNet::Parse::PacketReader tlv_reader(payload, payload_length);
            while (tlv_reader.GetRemaining() > 0) {
                SigNet::TLVBlock tlv;
                const int32_t tlv_rc = SigNet::Parse::ParseTLVBlock(tlv_reader, tlv);
                if (tlv_rc != SigNet::SIGNET_SUCCESS) {
                    break;
                }
                if (tlv.type_id == SigNet::TID_LEVEL) {
                    preview.packet_kind = FormatString("Level (%u slots)", tlv.length);
                    break;
                }
            }
        }
    }

    return true;
}

bool UpsertDiscoveredNode(AppState& state, const DiscoveredNode& node) {
    for (size_t i = 0; i < state.discovered_nodes.size(); ++i) {
        if (state.discovered_nodes[i].tuid_hex == node.tuid_hex) {
            const uint32_t next_announce_count = state.discovered_nodes[i].announce_count + 1;
            DiscoveredNode updated = node;
            updated.announce_count = next_announce_count;
            if (!updated.hmac_verified && state.discovered_nodes[i].hmac_verified) {
                updated.hmac_verified = true;
            }
            if (!updated.verify_attempted && state.discovered_nodes[i].verify_attempted) {
                updated.verify_attempted = true;
            }
            state.discovered_nodes[i] = updated;
            if (state.selected_discovered_node < 0) {
                state.selected_discovered_node = static_cast<int>(i);
            }
            return false;
        }
    }

    state.discovered_nodes.push_back(node);
    if (state.selected_discovered_node < 0) {
        state.selected_discovered_node = 0;
    }
    return true;
}

void ProcessReceivedDatagram(AppState& state, const ReceivedDatagram& datagram) {
    ReceivedPacketPreview preview;
    DiscoveredNode discovered_node;
    bool has_discovered_node = false;
    std::string error_message;
    if (!ParseIncomingPacket(datagram, state, preview, discovered_node, has_discovered_node, error_message)) {
        LogReceiveError(state, FormatString("%s from %s", error_message.c_str(), datagram.source_ip.c_str()));
        return;
    }

    ++state.received_packet_count;
    if (preview.packet_kind == "Announce") {
        ++state.received_announce_count;
    }
    state.last_received_preview = std::move(preview);

    if (has_discovered_node) {
        const bool is_new_node = UpsertDiscoveredNode(state, discovered_node);
        if (is_new_node) {
            LogReceiveMessage(state, FormatString(
                "Discovered node %s at %s",
                discovered_node.tuid_hex.c_str(),
                discovered_node.source_ip.c_str()
            ));
        }
        if (state.last_received_preview.verify_attempted && !state.last_received_preview.hmac_verified) {
            LogReceiveMessage(state, FormatString(
                "Announce HMAC mismatch for %s",
                discovered_node.tuid_hex.c_str()
            ));
        }
    }
}

void UpdateReceiver(AppState& state) {
    const bool was_active = state.receiver_active;

    if (!state.receiver_enabled) {
        state.udp_receiver.Shutdown();
        state.receiver_active = false;
        state.receiver_last_error.clear();
        if (was_active) {
            LogReceiveMessage(state, "Receiver stopped.");
        }
        return;
    }

    std::vector<std::string> groups;
    if (state.receiver_listen_announces) {
        groups.push_back(SigNet::MULTICAST_NODE_SEND_IP);
    }
    if (state.receiver_listen_universe) {
        const std::string multicast_preview = CurrentMulticastPreview(state);
        if (multicast_preview != "n/a") {
            groups.push_back(multicast_preview);
        }
    }

    if (groups.empty()) {
        state.udp_receiver.Shutdown();
        state.receiver_active = false;
        state.receiver_last_error.clear();
        return;
    }

    std::string error_message;
    if (!state.udp_receiver.Configure(groups, state.source_ip, error_message)) {
        state.receiver_active = false;
        if (state.receiver_last_error != error_message) {
            state.receiver_last_error = error_message;
            LogReceiveError(state, error_message);
        }
        return;
    }

    state.receiver_active = state.udp_receiver.IsActive();
    if (state.receiver_active && !was_active) {
        LogReceiveMessage(state, FormatString("Receiver listening on %zu multicast group(s).", groups.size()));
    }
    state.receiver_last_error.clear();

    std::vector<ReceivedDatagram> datagrams;
    if (!state.udp_receiver.Poll(datagrams, error_message)) {
        if (state.receiver_last_error != error_message) {
            state.receiver_last_error = error_message;
            LogReceiveError(state, error_message);
        }
        state.receiver_active = false;
        return;
    }

    for (const ReceivedDatagram& datagram : datagrams) {
        ProcessReceivedDatagram(state, datagram);
    }
}

uint32_t CountVerifiedNodes(const AppState& state) {
    return static_cast<uint32_t>(std::count_if(
        state.discovered_nodes.begin(),
        state.discovered_nodes.end(),
        [](const DiscoveredNode& node) { return node.hmac_verified; }
    ));
}

std::string RoleCapabilityLabel(uint32_t role_bits) {
    std::vector<std::string> roles;
    if ((role_bits & SigNet::ROLE_CAP_NODE) != 0) {
        roles.push_back("Node");
    }
    if ((role_bits & SigNet::ROLE_CAP_SENDER) != 0) {
        roles.push_back("Sender");
    }
    if ((role_bits & SigNet::ROLE_CAP_MANAGER) != 0) {
        roles.push_back("Manager");
    }
    if (roles.empty()) {
        return "Unknown";
    }

    std::ostringstream stream;
    for (size_t i = 0; i < roles.size(); ++i) {
        if (i > 0) {
            stream << " / ";
        }
        stream << roles[i];
    }
    return stream.str();
}

std::string FormatAgeLabel(uint32_t last_seen_tick, uint32_t now_ticks) {
    const uint32_t age_ms = now_ticks >= last_seen_tick ? now_ticks - last_seen_tick : 0;
    if (age_ms < 1000) {
        return FormatString("%ums", age_ms);
    }
    if (age_ms < 60000) {
        return FormatString("%.1fs", age_ms / 1000.0f);
    }
    return FormatString("%.1fm", age_ms / 60000.0f);
}

ImVec4 VerificationColor(bool attempted, bool verified) {
    if (!attempted) {
        return ColorFromBytes(255, 191, 92);
    }
    return verified ? ColorFromBytes(90, 201, 131) : ColorFromBytes(247, 108, 94);
}

const char* VerificationLabel(bool attempted, bool verified) {
    if (!attempted) {
        return "Unavailable";
    }
    return verified ? "Valid" : "Mismatch";
}

ImVec4 ReceiverStatusColor(const AppState& state) {
    if (!state.receiver_enabled) {
        return ColorFromBytes(145, 161, 182);
    }
    if (state.receiver_active) {
        return ColorFromBytes(90, 201, 131);
    }
    if (!state.receiver_last_error.empty()) {
        return ColorFromBytes(247, 108, 94);
    }
    return ColorFromBytes(255, 191, 92);
}

const char* ReceiverStatusLabel(const AppState& state) {
    if (!state.receiver_enabled) {
        return "Off";
    }
    if (state.receiver_active) {
        return "Listening";
    }
    if (!state.receiver_last_error.empty()) {
        return "Fault";
    }
    return "Idle";
}

void DrawAppBackdrop() {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImDrawList* draw_list = ImGui::GetBackgroundDrawList();
    const ImVec2 min = viewport->Pos;
    const ImVec2 max = ImVec2(viewport->Pos.x + viewport->Size.x, viewport->Pos.y + viewport->Size.y);

    draw_list->AddRectFilledMultiColor(
        min,
        max,
        ImGui::GetColorU32(ColorFromBytes(8, 12, 20)),
        ImGui::GetColorU32(ColorFromBytes(10, 18, 29)),
        ImGui::GetColorU32(ColorFromBytes(12, 20, 31)),
        ImGui::GetColorU32(ColorFromBytes(7, 10, 16))
    );
}

bool BeginCard(const char* id, const char* title, const char* subtitle, float height = 0.0f, bool show_header = true) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ColorFromBytes(19, 25, 38, 236));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 16.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    const bool open = ImGui::BeginChild(
        id,
        ImVec2(0.0f, height),
        true,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse
    );
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    const ImVec2 min = ImGui::GetWindowPos();
    const ImVec2 max = ImVec2(min.x + ImGui::GetWindowSize().x, min.y + ImGui::GetWindowSize().y);
    draw_list->AddRectFilled(
        min,
        ImVec2(max.x, min.y + 3.0f),
        ImGui::GetColorU32(ColorFromBytes(255, 183, 80, 220)),
        16.0f,
        ImDrawFlags_RoundCornersTop
    );
    if (show_header && title && title[0]) {
        ImGui::TextColored(ColorFromBytes(241, 244, 248), "%s", title);
        if (subtitle && subtitle[0]) {
            ImGui::TextColored(ColorFromBytes(135, 151, 176), "%s", subtitle);
        }
        ImGui::Spacing();
    }
    return open;
}

void InputLabel(const char* label) {
    ImGui::TextColored(ColorFromBytes(145, 161, 182), "%s", label);
}

void EndCard() {
    ImGui::EndChild();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor();
}

void DrawMetricTile(const char* id, const char* label, const std::string& value, const ImVec4& accent) {
    ImGui::PushID(id);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ColorFromBytes(14, 19, 29, 235));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 16.0f);
    ImGui::BeginChild("metric", ImVec2(0.0f, 70.0f), true);

    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    const ImVec2 min = ImGui::GetWindowPos();
    const ImVec2 max = ImVec2(min.x + ImGui::GetWindowSize().x, min.y + ImGui::GetWindowSize().y);
    draw_list->AddRectFilled(
        ImVec2(min.x, max.y - 4.0f),
        max,
        ImGui::GetColorU32(accent),
        12.0f,
        ImDrawFlags_RoundCornersBottom
    );

    ImGui::TextColored(ColorFromBytes(130, 146, 168), "%s", label);
    ImGui::SetWindowFontScale(1.15f);
    ImGui::TextColored(accent, "%s", value.c_str());
    ImGui::SetWindowFontScale(1.0f);

    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
    ImGui::PopID();
}

void RenderHeaderBand(AppState& state) {
    const std::string multicast_preview = CurrentMulticastPreview(state);

    ImGui::PushStyleColor(ImGuiCol_ChildBg, ColorFromBytes(14, 20, 31, 238));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 18.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::BeginChild("header-band", ImVec2(0.0f, 88.0f), true);

    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    const ImVec2 min = ImGui::GetWindowPos();
    const ImVec2 max = ImVec2(min.x + ImGui::GetWindowSize().x, min.y + ImGui::GetWindowSize().y);
    draw_list->AddRectFilledMultiColor(
        min,
        max,
        ImGui::GetColorU32(ColorFromBytes(22, 32, 49, 215)),
        ImGui::GetColorU32(ColorFromBytes(17, 26, 40, 200)),
        ImGui::GetColorU32(ColorFromBytes(11, 18, 28, 180)),
        ImGui::GetColorU32(ColorFromBytes(15, 22, 35, 215))
    );

    ImGui::BeginGroup();
    ImGui::TextColored(ColorFromBytes(255, 196, 102), "SIG-NET EXAMPLE IMGUI");
    ImGui::SetWindowFontScale(1.2f);
    ImGui::TextUnformatted("Cross-platform sender + receiver console");
    ImGui::SetWindowFontScale(1.0f);
    ImGui::TextColored(ColorFromBytes(145, 161, 182),
        "Transmit level data or listen for announces and live traffic.");
    ImGui::TextColored(ColorFromBytes(145, 161, 182), "View");
    ImGui::SameLine();
    if (ImGui::RadioButton("Transmit", state.view_mode == AppState::ViewTransmit)) {
        state.view_mode = AppState::ViewTransmit;
    }
    ImGui::SameLine();
    if (ImGui::RadioButton("Receive", state.view_mode == AppState::ViewReceive)) {
        state.view_mode = AppState::ViewReceive;
    }
    ImGui::SameLine(0.0f, 12.0f);
    ImGui::TextColored(ColorFromBytes(145, 161, 182), "DMX Mode");
    ImGui::SameLine();
    ImGui::TextColored(ColorFromBytes(90, 201, 131), "%s", DmxModeLabel(state));
    ImGui::SameLine(0.0f, 12.0f);
    ImGui::TextColored(ColorFromBytes(145, 161, 182), "Receiver");
    ImGui::SameLine();
    ImGui::TextColored(ReceiverStatusColor(state), "%s", ReceiverStatusLabel(state));
    ImGui::SameLine(0.0f, 12.0f);
    ImGui::TextColored(ColorFromBytes(145, 161, 182), "Interface");
    ImGui::SameLine();
    ImGui::TextColored(ColorFromBytes(82, 184, 214), "%s", state.source_ip);
    ImGui::SameLine(0.0f, 12.0f);
    ImGui::TextColored(ColorFromBytes(145, 161, 182), "Universe IP");
    ImGui::SameLine();
    ImGui::TextColored(ColorFromBytes(255, 191, 92), "%s", multicast_preview.c_str());
    ImGui::EndGroup();

    ImGui::SameLine(ImGui::GetWindowWidth() - 520.0f);
    ImGui::BeginGroup();
    if (state.view_mode == AppState::ViewTransmit) {
        ImGui::PushStyleColor(ImGuiCol_Button, ColorFromBytes(68, 130, 178));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ColorFromBytes(82, 155, 207));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ColorFromBytes(56, 112, 155));
        if (ImGui::Button("Send Level", ImVec2(118.0f, 30.0f))) {
            SendLevelPacket(state, "header action");
        }
        ImGui::PopStyleColor(3);
        ImGui::SameLine();
        if (ImGui::Button("Announce", ImVec2(118.0f, 30.0f))) {
            SendAnnouncePacket(state);
        }
        ImGui::SameLine();
        if (ImGui::Button("Self-Test", ImVec2(118.0f, 30.0f))) {
            RunSelfTest(state);
        }
        ImGui::SameLine();
        if (ImGui::Button("Refresh NICs", ImVec2(118.0f, 30.0f))) {
            UpdateInterfaceSelection(state);
            LogMessage(state, "Refreshed interface list.");
        }
    } else {
        ImGui::PushStyleColor(
            ImGuiCol_Button,
            state.receiver_enabled ? ColorFromBytes(90, 201, 131) : ColorFromBytes(68, 130, 178)
        );
        ImGui::PushStyleColor(
            ImGuiCol_ButtonHovered,
            state.receiver_enabled ? ColorFromBytes(113, 217, 150) : ColorFromBytes(82, 155, 207)
        );
        ImGui::PushStyleColor(
            ImGuiCol_ButtonActive,
            state.receiver_enabled ? ColorFromBytes(68, 173, 112) : ColorFromBytes(56, 112, 155)
        );
        if (ImGui::Button(state.receiver_enabled ? "Stop Listen" : "Start Listen", ImVec2(118.0f, 30.0f))) {
            state.receiver_enabled = !state.receiver_enabled;
            LogReceiveMessage(state, state.receiver_enabled ? "Receiver enabled." : "Receiver disabled.");
        }
        ImGui::PopStyleColor(3);
        ImGui::SameLine();
        if (ImGui::Button("Clear Nodes", ImVec2(118.0f, 30.0f))) {
            state.discovered_nodes.clear();
            state.selected_discovered_node = -1;
            LogReceiveMessage(state, "Cleared discovered node list.");
        }
        ImGui::SameLine();
        if (ImGui::Button("Clear Rx Log", ImVec2(118.0f, 30.0f))) {
            state.receive_log_lines.clear();
        }
        ImGui::SameLine();
        if (ImGui::Button("Refresh NICs", ImVec2(118.0f, 30.0f))) {
            UpdateInterfaceSelection(state);
            LogReceiveMessage(state, "Refreshed interface list.");
        }
    }
    ImGui::EndGroup();

    ImGui::EndChild();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor();
}

void RenderDmxSliders(AppState& state, float slider_region_height) {
    ImGui::TextColored(ColorFromBytes(130, 146, 168), "Direct per-channel transmission in manual mode.");
    ImGui::SliderInt("Offset", &state.dmx_scroll_position, 0, 512 - kVisibleDmxChannels);
    ImGui::SameLine();
    if (ImGui::Button("Zero All")) {
        std::fill(state.dmx_buffer.begin(), state.dmx_buffer.end(), 0);
        if (state.dmx_mode == AppState::Manual) {
            SendLevelPacket(state, "zero all");
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Full All")) {
        std::fill(state.dmx_buffer.begin(), state.dmx_buffer.end(), 255);
        if (state.dmx_mode == AppState::Manual) {
            SendLevelPacket(state, "full all");
        }
    }

    if (ImGui::BeginChild("dmx-sliders", ImVec2(0.0f, slider_region_height), true)) {
        bool changed = false;
        const float start_x = ImGui::GetCursorPosX();
        const float available_width = ImGui::GetContentRegionAvail().x;
        const float slider_width = 14.0f;
        const float slot_spacing = ImGui::GetStyle().ItemSpacing.x;
        const float total_width = (kVisibleDmxChannels * slider_width) + ((kVisibleDmxChannels - 1) * slot_spacing);
        if (available_width > total_width) {
            ImGui::SetCursorPosX(start_x + (available_width - total_width) * 0.42f);
        }
        for (int i = 0; i < kVisibleDmxChannels; ++i) {
            const int channel = state.dmx_scroll_position + i;
            int value = state.dmx_buffer[channel];
            ImGui::PushID(channel);
            if (i > 0) {
                ImGui::SameLine();
            }
            ImGui::BeginGroup();
            ImGui::Text("%d", channel + 1);
            if (ImGui::VSliderInt("##value", ImVec2(14.0f, 150.0f), &value, 255, 0, "")) {
                state.dmx_buffer[channel] = static_cast<uint8_t>(value);
                changed = true;
            }
            ImGui::Text("%03d", state.dmx_buffer[channel]);
            ImGui::EndGroup();
            ImGui::PopID();
        }
        if (changed && state.dmx_mode == AppState::Manual) {
            SendLevelPacket(state, "manual slider");
        }
    }
    ImGui::EndChild();
}

void RenderTransmitTopRegion(AppState& state, float top_height, Uint32 now_ticks) {
    if (ImGui::BeginChild("top-region", ImVec2(0.0f, top_height), false, ImGuiWindowFlags_NoScrollbar)) {
        if (ImGui::BeginTable("main-layout", 2, ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Controls", ImGuiTableColumnFlags_WidthFixed, 460.0f);
            ImGui::TableSetupColumn("Workspace", ImGuiTableColumnFlags_WidthStretch);

            ImGui::TableNextColumn();
            const float control_row_height = std::max(150.0f, (top_height - 12.0f) * 0.5f - 8.0f);
            if (ImGui::BeginTable("control-grid", 2, ImGuiTableFlags_SizingStretchSame)) {
                ImGui::TableNextColumn();
                if (BeginCard("key-card", "Key Setup", "Passphrase or hex provisioning.", control_row_height)) {
                    InputLabel("Passphrase");
                    ImGui::SetNextItemWidth(-1.0f);
                    if (ImGui::InputText("##passphrase", state.passphrase, sizeof(state.passphrase))) {
                        RefreshPassphraseReport(state);
                    }
                    ImGui::TextColored(PassphraseStatusColor(state.passphrase_status), "%s", PassphraseStatusLabel(state.passphrase_status));
                    if (ImGui::BeginChild("passphrase-report", ImVec2(0.0f, 40.0f), false)) {
                        ImGui::TextWrapped("%s", state.passphrase_report[0] ? state.passphrase_report : "");
                    }
                    ImGui::EndChild();
                    if (ImGui::Button("Derive", ImVec2(-60.0f, 0.0f))) {
                        DeriveK0FromPassphrase(state);
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Rnd##pass", ImVec2(52.0f, 0.0f))) {
                        GenerateRandomPassphrase(state);
                    }
                    InputLabel("K0 Hex");
                    ImGui::SetNextItemWidth(-1.0f);
                    ImGui::InputText("##k0hex", state.k0_hex, sizeof(state.k0_hex));
                    if (ImGui::Button("Apply", ImVec2(-60.0f, 0.0f))) {
                        ApplyK0Hex(state);
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Rnd##k0", ImVec2(52.0f, 0.0f))) {
                        GenerateRandomK0(state);
                    }
                    InputLabel("Sender Key");
                    ImGui::SetNextItemWidth(-1.0f);
                    ImGui::InputText("##senderkey", state.sender_key_hex, sizeof(state.sender_key_hex), ImGuiInputTextFlags_ReadOnly);
                    InputLabel("Citizen Key");
                    ImGui::SetNextItemWidth(-1.0f);
                    ImGui::InputText("##citizenkey", state.citizen_key_hex, sizeof(state.citizen_key_hex), ImGuiInputTextFlags_ReadOnly);
                }
                EndCard();

                ImGui::TableNextColumn();
                if (BeginCard("device-card", "Device + Network", "Identity and multicast source.", control_row_height)) {
                    const std::string multicast_preview = CurrentMulticastPreview(state);
                    InputLabel("TUID");
                    ImGui::SetNextItemWidth(-1.0f);
                    ImGui::InputText("##tuid", state.tuid_hex, sizeof(state.tuid_hex));
                    InputLabel("Endpoint");
                    ImGui::SetNextItemWidth(-1.0f);
                    ImGui::InputInt("##endpoint", &state.endpoint);
                    InputLabel("Universe");
                    ImGui::SetNextItemWidth(-1.0f);
                    ImGui::InputInt("##universe", &state.universe);
                    InputLabel("Source Interface");
                    if (ImGui::BeginCombo("Source Interface", state.interfaces.empty() ? "127.0.0.1" : state.interfaces[state.selected_interface_index].label.c_str())) {
                        for (size_t i = 0; i < state.interfaces.size(); ++i) {
                            const bool selected = static_cast<int>(i) == state.selected_interface_index;
                            if (ImGui::Selectable(state.interfaces[i].label.c_str(), selected)) {
                                state.selected_interface_index = static_cast<int>(i);
                                CopyString(state.source_ip, sizeof(state.source_ip), state.interfaces[i].ip);
                            }
                            if (selected) {
                                ImGui::SetItemDefaultFocus();
                            }
                        }
                        ImGui::EndCombo();
                    }
                    InputLabel("Source IP");
                    ImGui::SetNextItemWidth(-1.0f);
                    ImGui::InputText("##sourceip", state.source_ip, sizeof(state.source_ip));
                    ImGui::TextColored(ColorFromBytes(130, 146, 168), "Current Multicast");
                    ImGui::SameLine();
                    ImGui::TextUnformatted(multicast_preview.c_str());
                }
                EndCard();

                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                if (BeginCard("announce-card", "Announce Packet", "Root endpoint announce with Kc.", control_row_height)) {
                    InputLabel("Version Number");
                    ImGui::SetNextItemWidth(-1.0f);
                    ImGui::InputInt("##versionnum", &state.announce_version_num);
                    InputLabel("Version String");
                    ImGui::SetNextItemWidth(-1.0f);
                    ImGui::InputText("##versionstring", state.announce_version_string, sizeof(state.announce_version_string));
                    InputLabel("Manufacturer Code");
                    ImGui::SetNextItemWidth(-1.0f);
                    ImGui::InputText("##mfgcode", state.announce_mfg_code, sizeof(state.announce_mfg_code));
                    InputLabel("Product Variant");
                    ImGui::SetNextItemWidth(-1.0f);
                    ImGui::InputText("##productvariant", state.announce_product_variant, sizeof(state.announce_product_variant));
                    if (ImGui::Button("Send Announce", ImVec2(-1.0f, 0.0f))) {
                        SendAnnouncePacket(state);
                    }
                }
                EndCard();

                ImGui::TableNextColumn();
                if (BeginCard("transport-card", "Transmit Controls", "Manual or dynamic output.", control_row_height)) {
                    const int mode = state.dmx_mode == AppState::Manual ? 0 : 1;
                    if (ImGui::RadioButton("Manual", mode == 0)) {
                        state.dmx_mode = AppState::Manual;
                        LogMessage(state, "DMX mode set to Manual.");
                    }
                    ImGui::SameLine();
                    if (ImGui::RadioButton("Dynamic RGB", mode == 1)) {
                        state.dmx_mode = AppState::Dynamic;
                        state.last_dynamic_tick = now_ticks;
                        LogMessage(state, "DMX mode set to Dynamic RGB.");
                    }
                    ImGui::Checkbox("Keep Alive", &state.keep_alive_enabled);
                    ImGui::SameLine();
                    if (ImGui::Checkbox("Bad Frames", &state.insert_bad_frames)) {
                        state.good_frames_since_bad = 0;
                    }
                    InputLabel("Bad Frame Every");
                    ImGui::SetNextItemWidth(-1.0f);
                    ImGui::InputInt("##badframeevery", &state.bad_frame_interval);
                    if (ImGui::Button("Send Level Packet", ImVec2(-1.0f, 0.0f))) {
                        SendLevelPacket(state, "manual button");
                    }
                    ImGui::TextColored(ColorFromBytes(145, 161, 182), "RGB Pattern");
                    ImGui::SameLine();
                    ImGui::TextColored(ColorFromBytes(state.rgb_r, state.rgb_g, state.rgb_b), "%u  %u  %u", state.rgb_r, state.rgb_g, state.rgb_b);
                }
                EndCard();
                ImGui::EndTable();
            }

            ImGui::TableNextColumn();
            const float status_height = 104.0f;
            const float dmx_height = std::max(170.0f, top_height - status_height - 12.0f);
            if (BeginCard("status-card", "", "", status_height, false)) {
                if (ImGui::BeginTable("status-metrics", 4, ImGuiTableFlags_SizingStretchSame)) {
                    ImGui::TableNextColumn();
                    DrawMetricTile("sends", "Packets", std::to_string(state.send_count), ColorFromBytes(90, 201, 131));
                    ImGui::TableNextColumn();
                    DrawMetricTile("errors", "Errors", std::to_string(state.error_count), ColorFromBytes(247, 108, 94));
                    ImGui::TableNextColumn();
                    DrawMetricTile("session", "Session / Seq", FormatString("%u / %u", state.session_id, state.sequence_num), ColorFromBytes(82, 184, 214));
                    ImGui::TableNextColumn();
                    DrawMetricTile("bytes", "Last Size", std::to_string(state.last_packet_size), ColorFromBytes(255, 191, 92));
                    ImGui::EndTable();
                }
            }
            EndCard();

            ImGui::Dummy(ImVec2(0.0f, 8.0f));
            if (BeginCard("dmx-card", "DMX Surface", "", dmx_height)) {
                RenderDmxSliders(state, dmx_height - 56.0f);
            }
            EndCard();

            ImGui::EndTable();
        }
    }
    ImGui::EndChild();
}

void RenderTransmitBottomRegion(AppState& state, float bottom_height) {
    if (ImGui::BeginTable("inspect-layout", 2, ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("Packet", ImGuiTableColumnFlags_WidthStretch, 0.52f);
        ImGui::TableSetupColumn("Log", ImGuiTableColumnFlags_WidthStretch, 0.48f);

        ImGui::TableNextColumn();
        if (BeginCard("packet-card", "Packet Preview", "Hex dump of the most recently transmitted CoAP payload.", bottom_height)) {
            if (ImGui::BeginChild("packet-preview", ImVec2(0.0f, bottom_height - 58.0f), false)) {
                ImGui::TextUnformatted(state.last_preview.hex_dump.empty() ? "No packets sent yet." : state.last_preview.hex_dump.c_str());
            }
            ImGui::EndChild();
        }
        EndCard();

        ImGui::TableNextColumn();
        if (BeginCard("log-card", "Event Log", "Operational timeline, validation output, and transport errors.", bottom_height)) {
            ImGui::Checkbox("Auto-scroll log", &state.auto_scroll_log);
            if (ImGui::BeginChild("event-log", ImVec2(0.0f, bottom_height - 82.0f), false)) {
                for (const std::string& line : state.log_lines) {
                    ImGui::TextUnformatted(line.c_str());
                }
                if (state.auto_scroll_log && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
                    ImGui::SetScrollHereY(1.0f);
                }
            }
            ImGui::EndChild();
        }
        EndCard();

        ImGui::EndTable();
    }
}

void RenderSelectedNodeDetails(AppState& state, Uint32 now_ticks) {
    if (state.selected_discovered_node < 0 ||
        state.selected_discovered_node >= static_cast<int>(state.discovered_nodes.size())) {
        ImGui::TextColored(ColorFromBytes(145, 161, 182), "No discovered node selected yet.");
        ImGui::TextWrapped("Join the node announce multicast group and wait for traffic or send an announce from this app.");
        return;
    }

    const DiscoveredNode& node = state.discovered_nodes[state.selected_discovered_node];
    if (ImGui::BeginTable("selected-node-grid", 2, ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("Label", ImGuiTableColumnFlags_WidthFixed, 124.0f);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);

        const auto draw_row = [&](const char* label, const std::string& value) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextColored(ColorFromBytes(145, 161, 182), "%s", label);
            ImGui::TableNextColumn();
            ImGui::TextWrapped("%s", value.c_str());
        };

        draw_row("TUID", node.tuid_hex);
        draw_row("Source", FormatString("%s:%u", node.source_ip.c_str(), SigNet::SIGNET_UDP_PORT));
        draw_row("Roles", RoleCapabilityLabel(node.role_capability_bits));
        draw_row("Firmware", node.firmware_version_string.empty()
            ? FormatString("%u", node.firmware_version_id)
            : FormatString("%u  %s", node.firmware_version_id, node.firmware_version_string.c_str()));
        draw_row("Protocol", FormatString("v%u", node.protocol_version));
        draw_row("Mfg / Variant", FormatString("0x%04X / %04X", node.manufacturer_code, node.product_variant_id));
        draw_row("Change Count", std::to_string(node.change_count));
        draw_row("Announces", std::to_string(node.announce_count));
        draw_row("Last Seen", FormatAgeLabel(node.last_seen_tick, now_ticks));
        draw_row("HMAC", VerificationLabel(node.verify_attempted, node.hmac_verified));
        draw_row("URI", node.uri);

        ImGui::EndTable();
    }
}

void RenderDiscoveredNodesTable(AppState& state, float height, Uint32 now_ticks) {
    if (state.discovered_nodes.empty()) {
        ImGui::TextColored(ColorFromBytes(145, 161, 182), "No announce traffic captured yet.");
        ImGui::TextWrapped("Enable the receiver, stay on the node multicast group, or send an announce from this app to populate the list.");
        return;
    }

    const ImGuiTableFlags table_flags =
        ImGuiTableFlags_RowBg |
        ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable |
        ImGuiTableFlags_SizingStretchProp;

    if (ImGui::BeginTable("discovered-nodes", 7, table_flags, ImVec2(0.0f, height))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("TUID", ImGuiTableColumnFlags_WidthFixed, 126.0f);
        ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Roles", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Firmware", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 74.0f);
        ImGui::TableSetupColumn("HMAC", ImGuiTableColumnFlags_WidthFixed, 86.0f);
        ImGui::TableSetupColumn("Age", ImGuiTableColumnFlags_WidthFixed, 72.0f);
        ImGui::TableHeadersRow();

        for (size_t i = 0; i < state.discovered_nodes.size(); ++i) {
            const DiscoveredNode& node = state.discovered_nodes[i];
            const bool selected = static_cast<int>(i) == state.selected_discovered_node;
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            if (ImGui::Selectable(node.tuid_hex.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns)) {
                state.selected_discovered_node = static_cast<int>(i);
            }

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(node.source_ip.c_str());

            ImGui::TableNextColumn();
            ImGui::TextWrapped("%s", RoleCapabilityLabel(node.role_capability_bits).c_str());

            ImGui::TableNextColumn();
            if (node.firmware_version_string.empty()) {
                ImGui::Text("%u", node.firmware_version_id);
            } else {
                ImGui::TextWrapped("%s", node.firmware_version_string.c_str());
            }

            ImGui::TableNextColumn();
            ImGui::Text("v%u", node.protocol_version);

            ImGui::TableNextColumn();
            ImGui::TextColored(VerificationColor(node.verify_attempted, node.hmac_verified), "%s",
                VerificationLabel(node.verify_attempted, node.hmac_verified));

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(FormatAgeLabel(node.last_seen_tick, now_ticks).c_str());
        }

        ImGui::EndTable();
    }
}

void RenderReceiveTopRegion(AppState& state, float top_height) {
    const Uint32 now_ticks = SDL_GetTicks();
    if (ImGui::BeginChild("top-region", ImVec2(0.0f, top_height), false, ImGuiWindowFlags_NoScrollbar)) {
        if (ImGui::BeginTable("receive-layout", 2, ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Controls", ImGuiTableColumnFlags_WidthFixed, 460.0f);
            ImGui::TableSetupColumn("Discovery", ImGuiTableColumnFlags_WidthStretch);

            ImGui::TableNextColumn();
            const float receiver_height = 182.0f;
            const float security_height = 156.0f;
            const float selected_height = std::max(120.0f, top_height - receiver_height - security_height - 16.0f);

            if (BeginCard("receiver-card", "Receive Monitor", "Join announce and live universe traffic.", receiver_height)) {
                ImGui::Checkbox("Enable Receiver", &state.receiver_enabled);
                ImGui::SameLine();
                ImGui::Checkbox("Node Announces", &state.receiver_listen_announces);
                ImGui::SameLine();
                ImGui::Checkbox("Universe Traffic", &state.receiver_listen_universe);
                InputLabel("Universe");
                ImGui::SetNextItemWidth(-1.0f);
                ImGui::InputInt("##receiveuniverse", &state.universe);
                InputLabel("Source Interface");
                if (ImGui::BeginCombo("Receive Interface", state.interfaces.empty() ? "127.0.0.1" : state.interfaces[state.selected_interface_index].label.c_str())) {
                    for (size_t i = 0; i < state.interfaces.size(); ++i) {
                        const bool selected = static_cast<int>(i) == state.selected_interface_index;
                        if (ImGui::Selectable(state.interfaces[i].label.c_str(), selected)) {
                            state.selected_interface_index = static_cast<int>(i);
                            CopyString(state.source_ip, sizeof(state.source_ip), state.interfaces[i].ip);
                        }
                        if (selected) {
                            ImGui::SetItemDefaultFocus();
                        }
                    }
                    ImGui::EndCombo();
                }
                ImGui::TextColored(ColorFromBytes(145, 161, 182), "Status");
                ImGui::SameLine();
                ImGui::TextColored(ReceiverStatusColor(state), "%s", ReceiverStatusLabel(state));
                ImGui::SameLine(0.0f, 12.0f);
                ImGui::TextColored(ColorFromBytes(145, 161, 182), "Node Group");
                ImGui::SameLine();
                ImGui::TextUnformatted(SigNet::MULTICAST_NODE_SEND_IP);
                ImGui::TextColored(ColorFromBytes(145, 161, 182), "Universe Group");
                ImGui::SameLine();
                ImGui::TextUnformatted(CurrentMulticastPreview(state).c_str());
                if (!state.receiver_last_error.empty()) {
                    ImGui::TextWrapped("%s", state.receiver_last_error.c_str());
                }
            }
            EndCard();

            ImGui::Dummy(ImVec2(0.0f, 8.0f));
            if (BeginCard("receive-security-card", "Security + Identity", "Discovery works without keys; HMAC verification does not.", security_height)) {
                InputLabel("TUID");
                ImGui::SetNextItemWidth(-1.0f);
                ImGui::InputText("##receivetuid", state.tuid_hex, sizeof(state.tuid_hex));
                ImGui::TextColored(ColorFromBytes(145, 161, 182), "Keys");
                ImGui::SameLine();
                ImGui::TextColored(state.keys_valid ? ColorFromBytes(90, 201, 131) : ColorFromBytes(255, 191, 92),
                    "%s", state.keys_valid ? "Ready" : "Unavailable");
                ImGui::TextWrapped("Citizenship key verifies /node announces. Sender key verifies /level payloads on the selected universe.");
            }
            EndCard();

            ImGui::Dummy(ImVec2(0.0f, 8.0f));
            if (BeginCard("selected-node-card", "Selected Node", "Most recent announce data for the highlighted row.", selected_height)) {
                RenderSelectedNodeDetails(state, now_ticks);
            }
            EndCard();

            ImGui::TableNextColumn();
            const float status_height = 104.0f;
            const float table_height = std::max(170.0f, top_height - status_height - 12.0f);
            if (BeginCard("receive-status-card", "", "", status_height, false)) {
                if (ImGui::BeginTable("receive-status-metrics", 4, ImGuiTableFlags_SizingStretchSame)) {
                    ImGui::TableNextColumn();
                    DrawMetricTile("rx-packets", "Packets", std::to_string(state.received_packet_count), ColorFromBytes(90, 201, 131));
                    ImGui::TableNextColumn();
                    DrawMetricTile("rx-nodes", "Nodes", std::to_string(state.discovered_nodes.size()), ColorFromBytes(82, 184, 214));
                    ImGui::TableNextColumn();
                    DrawMetricTile("rx-verified", "Verified", std::to_string(CountVerifiedNodes(state)), ColorFromBytes(255, 191, 92));
                    ImGui::TableNextColumn();
                    DrawMetricTile("rx-kind", "Last Packet", state.last_received_preview.packet_kind.empty() ? "Idle" : state.last_received_preview.packet_kind, ColorFromBytes(247, 108, 94));
                    ImGui::EndTable();
                }
            }
            EndCard();

            ImGui::Dummy(ImVec2(0.0f, 8.0f));
            if (BeginCard("discovery-card", "Discovered Nodes", "Announce traffic updates this table in real time.", table_height)) {
                RenderDiscoveredNodesTable(state, table_height - 52.0f, now_ticks);
            }
            EndCard();

            ImGui::EndTable();
        }
    }
    ImGui::EndChild();
}

void RenderReceiveBottomRegion(AppState& state, float bottom_height) {
    if (ImGui::BeginTable("receive-inspect-layout", 2, ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("Packet", ImGuiTableColumnFlags_WidthStretch, 0.55f);
        ImGui::TableSetupColumn("Log", ImGuiTableColumnFlags_WidthStretch, 0.45f);

        ImGui::TableNextColumn();
        if (BeginCard("receive-packet-card", "Receive Packet Preview", "Most recent packet captured by the local receiver.", bottom_height)) {
            ImGui::TextColored(ColorFromBytes(145, 161, 182), "Source");
            ImGui::SameLine();
            ImGui::TextUnformatted(state.last_received_preview.source_ip.empty() ? "n/a" : state.last_received_preview.source_ip.c_str());
            ImGui::SameLine(0.0f, 12.0f);
            ImGui::TextColored(ColorFromBytes(145, 161, 182), "Kind");
            ImGui::SameLine();
            ImGui::TextUnformatted(state.last_received_preview.packet_kind.empty() ? "Idle" : state.last_received_preview.packet_kind.c_str());
            ImGui::SameLine(0.0f, 12.0f);
            ImGui::TextColored(ColorFromBytes(145, 161, 182), "HMAC");
            ImGui::SameLine();
            ImGui::TextColored(
                VerificationColor(state.last_received_preview.verify_attempted, state.last_received_preview.hmac_verified),
                "%s",
                VerificationLabel(state.last_received_preview.verify_attempted, state.last_received_preview.hmac_verified)
            );
            if (!state.last_received_preview.uri.empty()) {
                ImGui::TextWrapped("%s", state.last_received_preview.uri.c_str());
            }
            if (ImGui::BeginChild("receive-packet-preview", ImVec2(0.0f, bottom_height - 92.0f), false)) {
                ImGui::TextUnformatted(state.last_received_preview.hex_dump.empty()
                    ? "No packets received yet."
                    : state.last_received_preview.hex_dump.c_str());
            }
            ImGui::EndChild();
        }
        EndCard();

        ImGui::TableNextColumn();
        if (BeginCard("receive-log-card", "Receive Log", "Discovery events, HMAC failures, and receiver errors.", bottom_height)) {
            ImGui::Checkbox("Auto-scroll receive log", &state.auto_scroll_receive_log);
            if (ImGui::BeginChild("receive-log", ImVec2(0.0f, bottom_height - 82.0f), false)) {
                for (const std::string& line : state.receive_log_lines) {
                    ImGui::TextUnformatted(line.c_str());
                }
                if (state.auto_scroll_receive_log && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
                    ImGui::SetScrollHereY(1.0f);
                }
            }
            ImGui::EndChild();
        }
        EndCard();

        ImGui::EndTable();
    }
}

void InitializeState(AppState& state) {
    CopyString(state.tuid_hex, sizeof(state.tuid_hex), SigNet::TEST_TUID);
    RefreshPassphraseReport(state);
    UpdateInterfaceSelection(state);
    if (!state.interfaces.empty()) {
        CopyString(state.source_ip, sizeof(state.source_ip), state.interfaces[state.selected_interface_index].ip);
    }
    LogMessage(state, "Sig-Net ImGui example initialized.");
    LogMessage(state, "Compact dashboard mode enabled.");
    LogReceiveMessage(state, "Receive mode ready. Enable the receiver to discover announces.");
}

}  // namespace

int main(int, char**) {
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER | SDL_INIT_GAMECONTROLLER) != 0) {
        std::fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
        return 1;
    }

    const char* glsl_version = "#version 130";
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
    SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);

    SDL_Window* window = SDL_CreateWindow(
        "Sig-Net Example ImGui",
        SDL_WINDOWPOS_CENTERED,
        SDL_WINDOWPOS_CENTERED,
        1560,
        960,
        SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI
    );
    if (!window) {
        std::fprintf(stderr, "SDL_CreateWindow failed: %s\n", SDL_GetError());
        SDL_Quit();
        return 1;
    }

    SDL_GLContext gl_context = SDL_GL_CreateContext(window);
    if (!gl_context) {
        std::fprintf(stderr, "SDL_GL_CreateContext failed: %s\n", SDL_GetError());
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 1;
    }

    SDL_GL_MakeCurrent(window, gl_context);
    SDL_GL_SetSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ApplyCustomStyle();

    if (!ImGui_ImplSDL2_InitForOpenGL(window, gl_context)) {
        std::fprintf(stderr, "ImGui_ImplSDL2_InitForOpenGL failed.\n");
        ImGui::DestroyContext();
        SDL_GL_DeleteContext(gl_context);
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 1;
    }

    if (!ImGui_ImplOpenGL3_Init(glsl_version)) {
        std::fprintf(stderr, "ImGui_ImplOpenGL3_Init failed.\n");
        ImGui_ImplSDL2_Shutdown();
        ImGui::DestroyContext();
        SDL_GL_DeleteContext(gl_context);
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 1;
    }

    AppState state;
    InitializeState(state);

    bool done = false;
    while (!done) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            ImGui_ImplSDL2_ProcessEvent(&event);
            if (event.type == SDL_QUIT) {
                done = true;
            }
            if (event.type == SDL_WINDOWEVENT &&
                event.window.event == SDL_WINDOWEVENT_CLOSE &&
                event.window.windowID == SDL_GetWindowID(window)) {
                done = true;
            }
        }

        const Uint32 now_ticks = SDL_GetTicks();
        if (state.dmx_mode == AppState::Dynamic && now_ticks - state.last_dynamic_tick >= kDynamicIntervalMs) {
            UpdateDynamicPattern(state);
            SendLevelPacket(state, "dynamic heartbeat");
            state.last_dynamic_tick = now_ticks;
        }
        if (state.keep_alive_enabled && state.keys_valid &&
            now_ticks - state.last_send_tick >= kKeepAliveIntervalMs) {
            SendLevelPacket(state, "keep alive");
        }
        UpdateReceiver(state);

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        ImGui::NewFrame();

        DrawAppBackdrop();

        ImGuiViewport* viewport = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(viewport->WorkPos);
        ImGui::SetNextWindowSize(viewport->WorkSize);
        ImGui::Begin(
            "Sig-Net Example ImGui",
            nullptr,
            ImGuiWindowFlags_NoTitleBar |
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoScrollbar |
            ImGuiWindowFlags_NoScrollWithMouse
        );

        RenderHeaderBand(state);
        ImGui::Spacing();

        const float layout_gap = 8.0f;
        const ImVec2 remaining = ImGui::GetContentRegionAvail();
        const float bottom_height = std::max(248.0f, remaining.y * 0.34f);
        const float top_height = std::max(300.0f, remaining.y - bottom_height - layout_gap);

        if (state.view_mode == AppState::ViewTransmit) {
            RenderTransmitTopRegion(state, top_height, now_ticks);
        } else {
            RenderReceiveTopRegion(state, top_height);
        }

        ImGui::Dummy(ImVec2(0.0f, layout_gap));
        if (state.view_mode == AppState::ViewTransmit) {
            RenderTransmitBottomRegion(state, bottom_height);
        } else {
            RenderReceiveBottomRegion(state, bottom_height);
        }

        ImGui::End();

        ImGui::Render();
        int display_w = 0;
        int display_h = 0;
        SDL_GL_GetDrawableSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.04f, 0.05f, 0.08f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SDL_GL_SwapWindow(window);
    }

    state.udp_sender.Shutdown();
    state.udp_receiver.Shutdown();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    SDL_GL_DeleteContext(gl_context);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}
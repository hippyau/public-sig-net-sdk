//==============================================================================
// sig-net-example-imgui - Sig-Net Application Layer
//==============================================================================
//
// Holds the application state (keys, DMX buffer, sequence counters, discovered
// nodes) and the controller logic that builds/sends Sig-Net packets, parses
// incoming traffic, and manages the receiver. Depends on the Sig-Net SDK and
// the Network layer; has no ImGui dependency.
//
//==============================================================================

#ifndef SIG_NET_EXAMPLE_APP_HPP
#define SIG_NET_EXAMPLE_APP_HPP

#include "network.hpp"

#include "sig-net-parse.hpp"
#include "sig-net.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace App
{

//------------------------------------------------------------------------------

struct PacketPreview
{
		std::string hex_dump;
		std::string destination_ip;
};

//------------------------------------------------------------------------------

struct ReceivedPacketPreview
{
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

//------------------------------------------------------------------------------

struct DiscoveredNode
{
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

//------------------------------------------------------------------------------

struct AppState
{
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
		std::vector<Network::InterfaceInfo> interfaces;
		std::vector<DiscoveredNode> discovered_nodes;
		std::string receiver_last_error;

		enum DmxMode
		{
			Manual,
			Dynamic
		} dmx_mode = Manual;

		enum ViewMode
		{
			ViewTransmit,
			ViewReceive
		} view_mode = ViewTransmit;

		Network::UdpMulticastSender udp_sender;
		Network::UdpMulticastReceiver udp_receiver;
};

//==============================================================================
// String / formatting helpers
//==============================================================================

std::string Trim(const std::string &value);
std::string ToLowerHex(const uint8_t *data, size_t length);
void CopyString(char *destination, size_t size, const std::string &source);
std::string TimestampNow();
std::string FormatString(const char *format, ...);
bool ParseFixedHex(const std::string &text, uint8_t *output, size_t output_length);
bool ParseUint16(const std::string &text, uint16_t &value, int base);
bool ParseMfgCode(const std::string &text, uint16_t &value);
std::string HexDump(const uint8_t *data, size_t length);

//==============================================================================
// Logging
//==============================================================================

void LogMessage(AppState &state, const std::string &message);
void LogError(AppState &state, const std::string &message);
void LogReceiveMessage(AppState &state, const std::string &message);
void LogReceiveError(AppState &state, const std::string &message);

//==============================================================================
// Key management
//==============================================================================

void UpdateKeyHexDisplays(AppState &state);
void RefreshPassphraseReport(AppState &state);
bool DeriveKeysFromK0(AppState &state);
bool ApplyK0Hex(AppState &state);
bool DeriveK0FromPassphrase(AppState &state);
bool GenerateRandomK0(AppState &state);
bool GenerateRandomPassphrase(AppState &state);
bool ParseTuid(AppState &state);

//==============================================================================
// Interface / sequence / send
//==============================================================================

void UpdateInterfaceSelection(AppState &state);
void AdvanceSequence(AppState &state);
void RecordPreview(AppState &state, const SigNet::PacketBuffer &buffer, const std::string &destination_ip);
bool SendBuffer(AppState &state, SigNet::PacketBuffer &buffer, const std::string &destination_ip);
bool SendLevelPacket(AppState &state, const char *reason);
bool SendAnnouncePacket(AppState &state);

//==============================================================================
// Dynamic pattern + self-test
//==============================================================================

void UpdateDynamicPattern(AppState &state);
void RunSelfTest(AppState &state);

//==============================================================================
// Read-only queries used by the UI
//==============================================================================

const char *DmxModeLabel(const AppState &state);
std::string CurrentMulticastPreview(const AppState &state);
uint32_t CountVerifiedNodes(const AppState &state);
std::string RoleCapabilityLabel(uint32_t role_bits);
std::string FormatAgeLabel(uint32_t last_seen_tick, uint32_t now_ticks);

//==============================================================================
// Receiver / packet parsing
//==============================================================================

void ProcessReceivedDatagram(AppState &state, const Network::ReceivedDatagram &datagram);
void UpdateReceiver(AppState &state);

//==============================================================================
// Initialization
//==============================================================================

void InitializeState(AppState &state);

} // namespace App

#endif // SIG_NET_EXAMPLE_APP_HPP

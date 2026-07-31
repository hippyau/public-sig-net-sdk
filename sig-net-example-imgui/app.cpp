//==============================================================================
// sig-net-example-imgui - Sig-Net Application Layer
//==============================================================================
//
// Application state and controller logic: key derivation, packet build/send,
// incoming packet parsing, receiver management, and read-only queries for
// the UI.
//
//==============================================================================

#include "app.hpp"

#include "sig-net-send.hpp"
#include "sig-net-tlv.hpp"

#include <SDL.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace App
{

//==============================================================================
// String / formatting helpers
//==============================================================================

std::string Trim(const std::string &value)
{
	const auto start = value.find_first_not_of(" \t\r\n");
	if (start == std::string::npos)
		{
			return std::string();
		}
	const auto end = value.find_last_not_of(" \t\r\n");
	return value.substr(start, end - start + 1);
}

std::string ToLowerHex(const uint8_t *data, size_t length)
{
	std::ostringstream stream;
	stream << std::hex << std::setfill('0');
	for (size_t i = 0; i < length; ++i)
		{
			stream << std::setw(2) << static_cast<unsigned int>(data[i]);
		}
	return stream.str();
}

void CopyString(char *destination, size_t size, const std::string &source)
{
	if (!destination || size == 0)
		{
			return;
		}
	std::snprintf(destination, size, "%s", source.c_str());
}

std::string TimestampNow()
{
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

std::string FormatString(const char *format, ...)
{
	char buffer[1024];
	va_list args;
	va_start(args, format);
	std::vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	return std::string(buffer);
}

bool ParseFixedHex(const std::string &text, uint8_t *output, size_t output_length)
{
	const std::string value = Trim(text);
	if (value.size() != output_length * 2)
		{
			return false;
		}

	for (size_t i = 0; i < output_length; ++i)
		{
			const char hi = value[i * 2];
			const char lo = value[i * 2 + 1];
			if (!std::isxdigit(static_cast<unsigned char>(hi)) || !std::isxdigit(static_cast<unsigned char>(lo)))
				{
					return false;
				}

			char byte_buffer[3] = {hi, lo, '\0'};
			output[i] = static_cast<uint8_t>(std::strtoul(byte_buffer, nullptr, 16));
		}

	return true;
}

bool ParseUint16(const std::string &text, uint16_t &value, int base)
{
	const std::string trimmed = Trim(text);
	if (trimmed.empty())
		{
			return false;
		}

	char *end_ptr = nullptr;
	const unsigned long parsed = std::strtoul(trimmed.c_str(), &end_ptr, base);
	if (!end_ptr || *end_ptr != '\0' || parsed > 0xFFFFUL)
		{
			return false;
		}

	value = static_cast<uint16_t>(parsed);
	return true;
}

bool ParseMfgCode(const std::string &text, uint16_t &value)
{
	std::string trimmed = Trim(text);
	if (trimmed.empty())
		{
			return false;
		}
	if (trimmed.rfind("0x", 0) != 0 && trimmed.rfind("0X", 0) != 0)
		{
			trimmed = "0x" + trimmed;
		}
	return ParseUint16(trimmed, value, 0);
}

std::string HexDump(const uint8_t *data, size_t length)
{
	std::ostringstream stream;
	stream << std::hex << std::setfill('0');
	for (size_t offset = 0; offset < length; offset += 16)
		{
			stream << std::setw(4) << offset << "  ";
			for (size_t i = 0; i < 16; ++i)
				{
					if (offset + i < length)
						{
							stream << std::setw(2) << static_cast<unsigned int>(data[offset + i]) << ' ';
						}
					else
						{
							stream << "   ";
						}
				}
			stream << " |";
			for (size_t i = 0; i < 16 && offset + i < length; ++i)
				{
					const unsigned char c = data[offset + i];
					stream << (std::isprint(c) ? static_cast<char>(c) : '.');
				}
			stream << "|\n";
		}
	return stream.str();
}

//==============================================================================
// Logging
//==============================================================================

void LogMessage(AppState &state, const std::string &message)
{
	state.log_lines.push_back("[" + TimestampNow() + "] " + message);
	if (state.log_lines.size() > 200)
		{
			state.log_lines.erase(state.log_lines.begin(), state.log_lines.begin() + 1);
		}
}

void LogError(AppState &state, const std::string &message) { LogMessage(state, "ERROR: " + message); }

void LogReceiveMessage(AppState &state, const std::string &message)
{
	state.receive_log_lines.push_back("[" + TimestampNow() + "] " + message);
	if (state.receive_log_lines.size() > 250)
		{
			state.receive_log_lines.erase(state.receive_log_lines.begin(), state.receive_log_lines.begin() + 1);
		}
}

void LogReceiveError(AppState &state, const std::string &message)
{
	++state.receive_error_count;
	LogReceiveMessage(state, "ERROR: " + message);
}

//==============================================================================
// Internal CoAP / TLV helpers (anonymous namespace)
//==============================================================================

namespace
{

bool DecodeCoapNibble(const uint8_t *packet, uint16_t packet_length, uint16_t &position, uint8_t nibble, uint16_t &value)
{
	if (nibble <= 12)
		{
			value = nibble;
			return true;
		}
	if (nibble == 13)
		{
			if (position >= packet_length)
				{
					return false;
				}
			value = static_cast<uint16_t>(packet[position++]) + 13;
			return true;
		}
	if (nibble == 14)
		{
			if (position + 1 >= packet_length)
				{
					return false;
				}
			const uint16_t ext = static_cast<uint16_t>((packet[position] << 8) | packet[position + 1]);
			position += 2;
			value = static_cast<uint16_t>(ext + 269);
			return true;
		}
	return false;
}

bool FindCoapOptionAndPayload(uint8_t *packet, uint16_t packet_length, uint16_t target_option, uint16_t &option_offset, uint16_t &option_length, uint16_t &payload_offset)
{
	if (!packet || packet_length < 4)
		{
			return false;
		}

	const uint8_t token_length = packet[0] & 0x0F;
	uint16_t position = static_cast<uint16_t>(4 + token_length);
	uint16_t previous_option = 0;

	option_offset = 0;
	option_length = 0;
	payload_offset = packet_length;

	while (position < packet_length)
		{
			if (packet[position] == SigNet::COAP_PAYLOAD_MARKER)
				{
					payload_offset = static_cast<uint16_t>(position + 1);
					return option_length > 0;
				}

			const uint8_t header = packet[position++];
			const uint8_t delta_nibble = static_cast<uint8_t>((header >> 4) & 0x0F);
			const uint8_t length_nibble = static_cast<uint8_t>(header & 0x0F);
			uint16_t delta = 0;
			uint16_t length = 0;

			if (!DecodeCoapNibble(packet, packet_length, position, delta_nibble, delta) || !DecodeCoapNibble(packet, packet_length, position, length_nibble, length))
				{
					return false;
				}

			const uint16_t option_number = static_cast<uint16_t>(previous_option + delta);
			if (position + length > packet_length)
				{
					return false;
				}

			if (option_number == target_option)
				{
					option_offset = position;
					option_length = length;
				}

			position = static_cast<uint16_t>(position + length);
			previous_option = option_number;
		}

	return option_length > 0;
}

bool InjectBadFrame(SigNet::PacketBuffer &buffer)
{
	static const char *kBadText = "This is an intentionally bad HMAC.";
	uint8_t *packet = buffer.GetMutableBuffer();
	const uint16_t packet_length = buffer.GetSize();
	uint16_t hmac_offset = 0;
	uint16_t hmac_length = 0;
	uint16_t payload_offset = packet_length;

	if (!FindCoapOptionAndPayload(packet, packet_length, SigNet::SIGNET_OPTION_HMAC, hmac_offset, hmac_length, payload_offset))
		{
			return false;
		}
	if (hmac_length != SigNet::HMAC_SHA256_LENGTH)
		{
			return false;
		}

	for (uint16_t i = 0; i < hmac_length; ++i)
		{
			packet[hmac_offset + i] = static_cast<uint8_t>(~packet[hmac_offset + i]);
		}

	if (payload_offset < packet_length)
		{
			const uint16_t payload_length = static_cast<uint16_t>(packet_length - payload_offset);
			const uint16_t marker_length = static_cast<uint16_t>(std::strlen(kBadText));
			const uint16_t copy_length = std::min(payload_length, marker_length);
			std::memset(packet + payload_offset, 0, payload_length);
			std::memcpy(packet + payload_offset, kBadText, copy_length);
		}

	return true;
}

uint16_t ReadUInt16BE(const uint8_t *data) { return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]); }

uint32_t ReadUInt32BE(const uint8_t *data) { return (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) | (static_cast<uint32_t>(data[2]) << 8) | static_cast<uint32_t>(data[3]); }

bool LocatePayloadOffset(const uint8_t *packet, uint16_t packet_length, uint16_t &payload_offset)
{
	if (!packet || packet_length < 4)
		{
			return false;
		}

	const uint8_t token_length = packet[0] & 0x0F;
	if (4 + token_length > packet_length)
		{
			return false;
		}

	uint16_t position = static_cast<uint16_t>(4 + token_length);
	uint16_t previous_option = 0;
	payload_offset = packet_length;

	while (position < packet_length)
		{
			if (packet[position] == SigNet::COAP_PAYLOAD_MARKER)
				{
					payload_offset = static_cast<uint16_t>(position + 1);
					return true;
				}

			const uint8_t header = packet[position++];
			uint16_t delta = 0;
			uint16_t length = 0;
			if (!DecodeCoapNibble(packet, packet_length, position, static_cast<uint8_t>((header >> 4) & 0x0F), delta) || !DecodeCoapNibble(packet, packet_length, position, static_cast<uint8_t>(header & 0x0F), length))
				{
					return false;
				}
			if (position + length > packet_length)
				{
					return false;
				}
			position = static_cast<uint16_t>(position + length);
			previous_option = static_cast<uint16_t>(previous_option + delta);
		}

	return true;
}

bool ParseAnnouncePayload(const uint8_t *payload, uint16_t payload_length, DiscoveredNode &node, std::string &error_message)
{
	SigNet::Parse::PacketReader reader(payload, payload_length);
	bool found_poll_reply = false;

	while (reader.GetRemaining() > 0)
		{
			SigNet::TLVBlock tlv;
			const int32_t rc = SigNet::Parse::ParseTLVBlock(reader, tlv);
			if (rc != SigNet::SIGNET_SUCCESS)
				{
					error_message = FormatString("TLV parse failed: %d", rc);
					return false;
				}

			switch (tlv.type_id)
				{
					case SigNet::TID_POLL_REPLY:
						if (tlv.length < 12)
							{
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
						if (tlv.length < 4)
							{
								error_message = "TID_RT_FIRMWARE_VERSION too short.";
								return false;
							}
						node.firmware_version_id = ReadUInt32BE(tlv.value);
						node.firmware_version_string.assign(reinterpret_cast<const char *>(tlv.value + 4), reinterpret_cast<const char *>(tlv.value + tlv.length));
						break;
					case SigNet::TID_RT_PROTOCOL_VERSION:
						if (tlv.length >= 1)
							{
								node.protocol_version = tlv.value[0];
							}
						break;
					case SigNet::TID_RT_ROLE_CAPABILITY:
						// v0.15 widened this TID to a 32-bit big-endian role bitfield.
						// Tolerate 1-byte legacy encodings by zero-extending.
						if (tlv.length >= 4)
							{
								node.role_capability_bits = (static_cast<uint32_t>(tlv.value[0]) << 24) | (static_cast<uint32_t>(tlv.value[1]) << 16) | (static_cast<uint32_t>(tlv.value[2]) << 8) |
											    (static_cast<uint32_t>(tlv.value[3]));
							}
						else if (tlv.length >= 1)
							{
								node.role_capability_bits = tlv.value[0];
							}
						break;
					default:
						break;
				}
		}

	if (!found_poll_reply)
		{
			error_message = "Announce payload missing TID_POLL_REPLY.";
			return false;
		}

	return true;
}

bool ParseIncomingPacket(const Network::ReceivedDatagram &datagram, const AppState &state, ReceivedPacketPreview &preview, DiscoveredNode &discovered_node, bool &has_discovered_node, std::string &error_message)
{
	has_discovered_node = false;
	if (datagram.payload.size() < SigNet::COAP_HEADER_SIZE)
		{
			error_message = "Packet too small for CoAP header.";
			return false;
		}

	SigNet::Parse::PacketReader reader(datagram.payload.data(), static_cast<uint16_t>(datagram.payload.size()));
	SigNet::CoAPHeader header{};
	int32_t rc = SigNet::Parse::ParseCoAPHeader(reader, header);
	if (rc != SigNet::SIGNET_SUCCESS)
		{
			error_message = FormatString("CoAP header parse failed: %d", rc);
			return false;
		}
	if (header.GetVersion() != SigNet::COAP_VERSION)
		{
			error_message = FormatString("Unexpected CoAP version %u.", header.GetVersion());
			return false;
		}
	if (header.GetType() != SigNet::COAP_TYPE_NON || header.code != SigNet::COAP_CODE_POST)
		{
			error_message = "Only CoAP NON POST packets are supported in receive mode.";
			return false;
		}

	rc = SigNet::Parse::SkipToken(reader, header.GetTokenLength());
	if (rc != SigNet::SIGNET_SUCCESS)
		{
			error_message = FormatString("CoAP token parse failed: %d", rc);
			return false;
		}

	char uri_buffer[128] = {0};
	uint16_t uri_length = 0;
	rc = SigNet::Parse::ExtractURIString(reader, uri_buffer, sizeof(uri_buffer), uri_length);
	if (rc != SigNet::SIGNET_SUCCESS || uri_length == 0)
		{
			error_message = FormatString("URI extraction failed: %d", rc);
			return false;
		}

	SigNet::SigNetOptions options;
	rc = SigNet::Parse::ParseSigNetOptions(reader, options);
	if (rc != SigNet::SIGNET_SUCCESS)
		{
			error_message = FormatString("Sig-Net option parse failed: %d", rc);
			return false;
		}

	uint16_t payload_offset = static_cast<uint16_t>(datagram.payload.size());
	if (!LocatePayloadOffset(datagram.payload.data(), static_cast<uint16_t>(datagram.payload.size()), payload_offset))
		{
			error_message = "Failed to locate CoAP payload marker.";
			return false;
		}

	const uint8_t *payload = payload_offset < datagram.payload.size() ? datagram.payload.data() + payload_offset : nullptr;
	const uint16_t payload_length = payload_offset < datagram.payload.size() ? static_cast<uint16_t>(datagram.payload.size() - payload_offset) : 0;

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

	const uint8_t *verification_key = nullptr;
	if (state.keys_valid)
		{
			if (preview.uri.find(node_prefix) == 0)
				{
					verification_key = state.citizen_key.data();
				}
			else if (preview.uri.find(level_prefix) == 0)
				{
					verification_key = state.sender_key.data();
				}
		}
	if (verification_key)
		{
			preview.verify_attempted = true;
			preview.hmac_verified = SigNet::Parse::VerifyPacketHMAC(preview.uri.c_str(), options, payload, payload_length, verification_key) == SigNet::SIGNET_SUCCESS;
		}

	if (preview.uri.find(node_prefix) == 0)
		{
			preview.packet_kind = "Announce";
			if (payload_length == 0)
				{
					error_message = "Announce packet does not contain a TLV payload.";
					return false;
				}
			if (!ParseAnnouncePayload(payload, payload_length, discovered_node, error_message))
				{
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

	if (preview.uri.find(level_prefix) == 0)
		{
			preview.packet_kind = "Level";
			if (payload && payload_length >= 4)
				{
					SigNet::Parse::PacketReader tlv_reader(payload, payload_length);
					while (tlv_reader.GetRemaining() > 0)
						{
							SigNet::TLVBlock tlv;
							const int32_t tlv_rc = SigNet::Parse::ParseTLVBlock(tlv_reader, tlv);
							if (tlv_rc != SigNet::SIGNET_SUCCESS)
								{
									break;
								}
							if (tlv.type_id == SigNet::TID_LEVEL)
								{
									preview.packet_kind = FormatString("Level (%u slots)", tlv.length);
									break;
								}
						}
				}
		}

	return true;
}

bool UpsertDiscoveredNode(AppState &state, const DiscoveredNode &node)
{
	for (size_t i = 0; i < state.discovered_nodes.size(); ++i)
		{
			if (state.discovered_nodes[i].tuid_hex == node.tuid_hex)
				{
					const uint32_t next_announce_count = state.discovered_nodes[i].announce_count + 1;
					DiscoveredNode updated = node;
					updated.announce_count = next_announce_count;
					if (!updated.hmac_verified && state.discovered_nodes[i].hmac_verified)
						{
							updated.hmac_verified = true;
						}
					if (!updated.verify_attempted && state.discovered_nodes[i].verify_attempted)
						{
							updated.verify_attempted = true;
						}
					state.discovered_nodes[i] = updated;
					if (state.selected_discovered_node < 0)
						{
							state.selected_discovered_node = static_cast<int>(i);
						}
					return false;
				}
		}

	state.discovered_nodes.push_back(node);
	if (state.selected_discovered_node < 0)
		{
			state.selected_discovered_node = 0;
		}
	return true;
}

} // namespace

//==============================================================================
// Key management
//==============================================================================

void UpdateKeyHexDisplays(AppState &state)
{
	CopyString(state.k0_hex, sizeof(state.k0_hex), ToLowerHex(state.k0_key.data(), state.k0_key.size()));
	CopyString(state.sender_key_hex, sizeof(state.sender_key_hex), ToLowerHex(state.sender_key.data(), state.sender_key.size()));
	CopyString(state.citizen_key_hex, sizeof(state.citizen_key_hex), ToLowerHex(state.citizen_key.data(), state.citizen_key.size()));
}

void RefreshPassphraseReport(AppState &state)
{
	char report[256] = {0};
	state.passphrase_status = SigNet::Crypto::GetPassphraseValidationReport(state.passphrase, static_cast<uint32_t>(std::strlen(state.passphrase)), report, sizeof(report));
	CopyString(state.passphrase_report, sizeof(state.passphrase_report), report);
}

bool DeriveKeysFromK0(AppState &state)
{
	if (SigNet::Crypto::DeriveSenderKey(state.k0_key.data(), state.sender_key.data()) != SigNet::SIGNET_SUCCESS)
		{
			LogError(state, "Failed to derive sender key.");
			state.keys_valid = false;
			state.k0_set = false;
			return false;
		}

	if (SigNet::Crypto::DeriveCitizenKey(state.k0_key.data(), state.citizen_key.data()) != SigNet::SIGNET_SUCCESS)
		{
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

bool DeriveAllKeys(AppState &state)
{
	if (!DeriveKeysFromK0(state))
		{
			return false;
		}

	if (SigNet::Crypto::DeriveManagerGlobalKey(state.k0_key.data(), state.manager_global_key.data()) != SigNet::SIGNET_SUCCESS)
		{
			LogError(state, "Failed to derive manager global key.");
			return false;
		}

	if (SigNet::Crypto::DeriveManagerLocalKey(state.k0_key.data(), state.tuid.data(), state.manager_local_key.data()) != SigNet::SIGNET_SUCCESS)
		{
			LogError(state, "Failed to derive manager local key.");
			return false;
		}

	LogMessage(state, "Derived all keys: Ks, Kc, Km_global, Km_local.");
	return true;
}

bool ApplyK0Hex(AppState &state)
{
	if (!ParseFixedHex(state.k0_hex, state.k0_key.data(), state.k0_key.size()))
		{
			LogError(state, "K0 must be 64 hex characters.");
			return false;
		}

	if (!DeriveAllKeys(state))
		{
			return false;
		}

	LogMessage(state, "K0 applied and all keys derived successfully.");
	return true;
}

bool DeriveK0FromPassphrase(AppState &state)
{
	RefreshPassphraseReport(state);
	if (state.passphrase_status != SigNet::SIGNET_PASSPHRASE_VALID)
		{
			LogError(state, "Passphrase does not meet Sig-Net complexity requirements.");
			return false;
		}

	if (SigNet::Crypto::DeriveK0FromPassphrase(state.passphrase, static_cast<uint32_t>(std::strlen(state.passphrase)), state.k0_key.data()) != SigNet::SIGNET_SUCCESS)
		{
			LogError(state, "Failed to derive K0 from passphrase.");
			return false;
		}

	if (!DeriveAllKeys(state))
		{
			return false;
		}

	LogMessage(state, "Derived K0 from passphrase and updated all keys.");
	return true;
}

bool GenerateRandomK0(AppState &state)
{
	if (SigNet::Crypto::GenerateRandomK0(state.k0_key.data()) != SigNet::SIGNET_SUCCESS)
		{
			LogError(state, "Failed to generate random K0.");
			return false;
		}

	if (!DeriveAllKeys(state))
		{
			return false;
		}

	LogMessage(state, "Generated random K0 and updated all keys.");
	return true;
}

bool GenerateRandomPassphrase(AppState &state)
{
	char output[32] = {0};
	if (SigNet::Crypto::GenerateRandomPassphrase(output, sizeof(output)) != SigNet::SIGNET_SUCCESS)
		{
			LogError(state, "Failed to generate random passphrase.");
			return false;
		}

	CopyString(state.passphrase, sizeof(state.passphrase), output);
	RefreshPassphraseReport(state);
	LogMessage(state, "Generated random passphrase.");
	return true;
}

bool ParseTuid(AppState &state)
{
	if (SigNet::Crypto::TUID_FromHexString(state.tuid_hex, state.tuid.data()) != SigNet::SIGNET_SUCCESS)
		{
			LogError(state, "TUID must be 12 hex characters.");
			return false;
		}
	return true;
}

//==============================================================================
// Interface / sequence / send
//==============================================================================

void UpdateInterfaceSelection(AppState &state)
{
	state.interfaces = Network::EnumerateIPv4Interfaces();
	state.selected_interface_index = 0;
	const std::string current_ip = Trim(state.source_ip);
	for (size_t i = 0; i < state.interfaces.size(); ++i)
		{
			if (state.interfaces[i].ip == current_ip)
				{
					state.selected_interface_index = static_cast<int>(i);
					break;
				}
		}
}

void AdvanceSequence(AppState &state)
{
	if (state.sequence_num == 0xFFFFFFFFu)
		{
			++state.session_id;
			state.sequence_num = 1;
			LogMessage(state, FormatString("Session rolled over to %u", state.session_id));
		}
	else
		{
			state.sequence_num = SigNet::IncrementSequence(state.sequence_num);
		}
	++state.message_id;
}

void RecordPreview(AppState &state, const SigNet::PacketBuffer &buffer, const std::string &destination_ip)
{
	state.last_preview.destination_ip = destination_ip;
	state.last_preview.hex_dump = HexDump(buffer.GetBuffer(), buffer.GetSize());
	state.last_packet_size = buffer.GetSize();
}

bool SendBuffer(AppState &state, SigNet::PacketBuffer &buffer, const std::string &destination_ip)
{
	RecordPreview(state, buffer, destination_ip);

	std::string send_error;
	if (!state.udp_sender.Send(destination_ip, SigNet::SIGNET_UDP_PORT, buffer.GetBuffer(), buffer.GetSize(), state.source_ip, send_error))
		{
			++state.error_count;
			LogError(state, send_error);
			return false;
		}

	++state.send_count;
	state.last_send_tick = SDL_GetTicks();
	AdvanceSequence(state);
	return true;
}

bool SendLevelPacket(AppState &state, const char *reason)
{
	if (!state.keys_valid)
		{
			++state.error_count;
			LogError(state, "Cannot send level packet before Ks/Kc are derived.");
			return false;
		}

	if (!ParseTuid(state))
		{
			++state.error_count;
			return false;
		}

	if (state.endpoint < 1)
		{
			state.endpoint = 1;
		}

	const uint16_t universe = static_cast<uint16_t>(std::clamp(state.universe, static_cast<int>(SigNet::MIN_UNIVERSE), static_cast<int>(SigNet::MAX_UNIVERSE)));
	state.universe = universe;

	SigNet::PacketBuffer buffer;
	const int32_t build_result = SigNet::BuildDMXPacket(buffer, universe, state.dmx_buffer.data(), static_cast<uint16_t>(state.dmx_buffer.size()), state.tuid.data(), static_cast<uint16_t>(state.endpoint), 0x0000, state.session_id,
							    state.sequence_num, state.sender_key.data(), state.message_id);

	if (build_result != SigNet::SIGNET_SUCCESS)
		{
			++state.error_count;
			LogError(state, FormatString("Failed to build level packet: error %d", build_result));
			return false;
		}

	bool injected_bad_frame = false;
	if (state.insert_bad_frames)
		{
			if (state.bad_frame_interval < 1)
				{
					state.bad_frame_interval = 1;
				}
			if (state.good_frames_since_bad >= static_cast<uint32_t>(state.bad_frame_interval))
				{
					injected_bad_frame = InjectBadFrame(buffer);
					if (!injected_bad_frame)
						{
							LogError(state, "Failed to inject intentionally bad frame; sending normal frame.");
						}
				}
		}

	char multicast_ip[32] = {0};
	SigNet::CalculateMulticastAddress(universe, multicast_ip, sizeof(multicast_ip));

	const uint32_t sent_sequence = state.sequence_num;
	if (!SendBuffer(state, buffer, multicast_ip))
		{
			return false;
		}

	if (state.insert_bad_frames)
		{
			if (injected_bad_frame)
				{
					state.good_frames_since_bad = 0;
					LogMessage(state, "Inserted intentionally bad frame.");
				}
			else
				{
					++state.good_frames_since_bad;
				}
		}

	LogMessage(state, FormatString("Level packet sent (%s): seq=%u size=%u dest=%s", reason, sent_sequence, state.last_packet_size, multicast_ip));
	return true;
}

bool SendAnnouncePacket(AppState &state)
{
	if (!state.keys_valid)
		{
			++state.error_count;
			LogError(state, "Cannot send announce before Ks/Kc are derived.");
			return false;
		}

	if (!ParseTuid(state))
		{
			++state.error_count;
			return false;
		}

	uint16_t firmware_version_id = 0;
	uint16_t manufacturer_code = 0;
	uint16_t product_variant_id = 0;

	if (state.announce_version_num < 0 || state.announce_version_num > 0xFFFF)
		{
			++state.error_count;
			LogError(state, "Announce version number must fit in 16 bits.");
			return false;
		}
	firmware_version_id = static_cast<uint16_t>(state.announce_version_num);

	if (!ParseMfgCode(state.announce_mfg_code, manufacturer_code))
		{
			++state.error_count;
			LogError(state, "Manufacturer code must be valid hex, for example 5379 or 0x5379.");
			return false;
		}

	if (!ParseUint16(state.announce_product_variant, product_variant_id, 16))
		{
			++state.error_count;
			LogError(state, "Product variant must be valid hexadecimal.");
			return false;
		}

	const std::string version_string = Trim(state.announce_version_string);
	if (version_string.empty())
		{
			++state.error_count;
			LogError(state, "Version string cannot be empty.");
			return false;
		}

	SigNet::PacketBuffer buffer;
	const int32_t build_result = SigNet::BuildAnnouncePacket(buffer, state.tuid.data(), manufacturer_code, product_variant_id, firmware_version_id, version_string.c_str(), 0x01, SigNet::ROLE_CAP_SENDER, 0x0000, state.session_id,
								 state.sequence_num, state.citizen_key.data(), state.message_id);

	if (build_result != SigNet::SIGNET_SUCCESS)
		{
			++state.error_count;
			LogError(state, FormatString("Failed to build announce packet: error %d", build_result));
			return false;
		}

	const uint32_t sent_sequence = state.sequence_num;
	if (!SendBuffer(state, buffer, SigNet::MULTICAST_NODE_SEND_IP))
		{
			return false;
		}

	LogMessage(state, FormatString("Announce packet sent: seq=%u size=%u dest=%s", sent_sequence, state.last_packet_size, SigNet::MULTICAST_NODE_SEND_IP));
	return true;
}

//==============================================================================
// Dynamic pattern + self-test
//==============================================================================

void UpdateDynamicPattern(AppState &state)
{
	if (state.rgb_phase == 0)
		{
			if (state.rgb_r > 0)
				{
					--state.rgb_r;
				}
			if (state.rgb_g < 255)
				{
					++state.rgb_g;
				}
			if (state.rgb_r == 0 && state.rgb_g == 255)
				{
					state.rgb_phase = 1;
				}
		}
	else if (state.rgb_phase == 1)
		{
			if (state.rgb_g > 0)
				{
					--state.rgb_g;
				}
			if (state.rgb_b < 255)
				{
					++state.rgb_b;
				}
			if (state.rgb_g == 0 && state.rgb_b == 255)
				{
					state.rgb_phase = 2;
				}
		}
	else
		{
			if (state.rgb_b > 0)
				{
					--state.rgb_b;
				}
			if (state.rgb_r < 255)
				{
					++state.rgb_r;
				}
			if (state.rgb_b == 0 && state.rgb_r == 255)
				{
					state.rgb_phase = 0;
				}
		}

	for (size_t i = 0; i < state.dmx_buffer.size(); ++i)
		{
			const int slot = static_cast<int>(i % 3);
			if (slot == 0)
				{
					state.dmx_buffer[i] = state.rgb_r;
				}
			else if (slot == 1)
				{
					state.dmx_buffer[i] = state.rgb_g;
				}
			else
				{
					state.dmx_buffer[i] = state.rgb_b;
				}
		}
}

void RunSelfTest(AppState &state)
{
	SigNet::SelfTest::TestSuiteResults results;
	const int32_t rc = SigNet::SelfTest::RunAllTests(results);
	LogMessage(state, FormatString("Self-test finished: %zu/%zu passed.", results.passed_count, results.test_count));
	for (size_t i = 0; i < results.test_count; ++i)
		{
			if (!results.tests[i].passed)
				{
					LogError(state, FormatString("Self-test failed: %s %s", results.tests[i].name, results.tests[i].error_message[0] ? results.tests[i].error_message : ""));
				}
		}
	if (rc == SigNet::SIGNET_SUCCESS)
		{
			LogMessage(state, "All self-tests passed.");
		}
}

//==============================================================================
// Read-only queries used by the UI
//==============================================================================

const char *DmxModeLabel(const AppState &state) { return state.dmx_mode == AppState::Manual ? "Manual" : "Dynamic RGB"; }

std::string CurrentMulticastPreview(const AppState &state)
{
	if (state.universe < static_cast<int>(SigNet::MIN_UNIVERSE) || state.universe > static_cast<int>(SigNet::MAX_UNIVERSE))
		{
			return "n/a";
		}

	char multicast_ip[32] = {0};
	if (SigNet::CalculateMulticastAddress(static_cast<uint16_t>(state.universe), multicast_ip, sizeof(multicast_ip)) != SigNet::SIGNET_SUCCESS)
		{
			return "n/a";
		}

	return multicast_ip;
}

uint32_t CountVerifiedNodes(const AppState &state)
{
	return static_cast<uint32_t>(std::count_if(state.discovered_nodes.begin(), state.discovered_nodes.end(), [](const DiscoveredNode &node) { return node.hmac_verified; }));
}

std::string RoleCapabilityLabel(uint32_t role_bits)
{
	std::vector<std::string> roles;
	if ((role_bits & SigNet::ROLE_CAP_NODE) != 0)
		{
			roles.push_back("Node");
		}
	if ((role_bits & SigNet::ROLE_CAP_SENDER) != 0)
		{
			roles.push_back("Sender");
		}
	if ((role_bits & SigNet::ROLE_CAP_MANAGER) != 0)
		{
			roles.push_back("Manager");
		}
	if (roles.empty())
		{
			return "Unknown";
		}

	std::ostringstream stream;
	for (size_t i = 0; i < roles.size(); ++i)
		{
			if (i > 0)
				{
					stream << " / ";
				}
			stream << roles[i];
		}
	return stream.str();
}

std::string FormatAgeLabel(uint32_t last_seen_tick, uint32_t now_ticks)
{
	const uint32_t age_ms = now_ticks >= last_seen_tick ? now_ticks - last_seen_tick : 0;
	if (age_ms < 1000)
		{
			return FormatString("%ums", age_ms);
		}
	if (age_ms < 60000)
		{
			return FormatString("%.1fs", age_ms / 1000.0f);
		}
	return FormatString("%.1fm", age_ms / 60000.0f);
}

//==============================================================================
// Node simulator helpers (anonymous namespace)
//==============================================================================

namespace
{

// Internal helper: send a response packet with TLV payload
bool SendNodeResponse(AppState &state, SigNet::PacketBuffer &payload_buffer, const char *destination_ip)
{
	SigNet::PacketBuffer buffer;
	int32_t rc = SigNet::BuildDMXPacket(buffer, static_cast<uint16_t>(state.universe), payload_buffer.GetBuffer(), static_cast<uint16_t>(payload_buffer.GetSize()), state.node_config.tuid, state.node_config.endpoint, 0x0000, state.session_id, state.sequence_num, state.citizen_key.data(), state.message_id);
	if (rc != SigNet::SIGNET_SUCCESS)
		{
			LogError(state, FormatString("Failed to build response packet: error %d", rc));
			return false;
		}
	return SendBuffer(state, buffer, destination_ip);
}

// Internal helper: emit security event
void EmitSecurityEvent(AppState &state, uint8_t event_code, const char *source_ip)
{
	if (!state.keys_valid)
		{
			return;
		}

	SigNet::PacketBuffer payload;
	uint8_t event_data[8];
	event_data[0] = event_code;
	std::memset(event_data + 1, 0, 7);
	SigNet::Node::AppendNodeTLVRaw(payload, SigNet::TID_DG_SECURITY_EVENT, event_data, sizeof(event_data));

	SigNet::PacketBuffer buffer;
	int32_t rc = SigNet::BuildDMXPacket(buffer, static_cast<uint16_t>(state.universe), payload.GetBuffer(), static_cast<uint16_t>(payload.GetSize()), state.node_config.tuid, state.node_config.endpoint, 0x0000, state.session_id, state.sequence_num, state.citizen_key.data(), state.message_id);
	if (rc == SigNet::SIGNET_SUCCESS)
		{
			SendBuffer(state, buffer, SigNet::MULTICAST_NODE_SEND_IP);
		}
}

// Handle TID_POLL — respond with poll reply at configured query level
bool HandlePoll(AppState &state, const char *destination_ip, uint32_t query_level)
{
	if (!state.node_simulator_respond_to_polls)
		{
			return false;
		}

	state.last_manager_poll_tick = SDL_GetTicks();
	if (state.in_lost_mode)
		{
			state.in_lost_mode = false;
			LogMessage(state, "Exited lost mode — manager poll received.");
		}

	LogReceiveMessage(state, FormatString("Received TID_POLL (query_level=%d)", query_level));

	SigNet::PacketBuffer payload;
	int32_t payload_len = SigNet::Node::BuildNodeQueryPayload(static_cast<uint8_t>(query_level), state.node_config.endpoint, state.node_user_data, state.node_config, payload);
	if (payload_len <= 0)
		{
			LogError(state, "Failed to build poll reply payload.");
			return false;
		}

	if (SendNodeResponse(state, payload, destination_ip))
		{
			LogMessage(state, FormatString("Poll reply sent (query_level=%d, payload=%d bytes).", query_level, payload_len));
			++state.node_stats_poll_responses;
			return true;
		}
	return false;
}

// Handle TID_GET — find the TID blob and respond
bool HandleGet(AppState &state, uint16_t tid, const char *destination_ip)
{
	if (!state.node_simulator_respond_to_gets)
		{
			return false;
		}

	LogReceiveMessage(state, FormatString("Received TID_GET for TID 0x%04X", tid));

	const auto *blob = SigNet::Node::FindSupportedTidBlob(state.node_user_data, tid);
	if (!blob || blob->length == 0)
		{
			LogReceiveMessage(state, FormatString("TID_GET 0x%04X: no data available", tid));
			return false;
		}

	SigNet::PacketBuffer payload;
	SigNet::Node::AppendNodeTLVRaw(payload, tid, blob->data.bytes, blob->length);

	if (SendNodeResponse(state, payload, destination_ip))
		{
			LogMessage(state, FormatString("GET reply sent for TID 0x%04X (%d bytes).", tid, blob->length));
			++state.node_stats_get_responses;
			return true;
		}
	return false;
}

// Handle TID_SET — validate, apply, and respond
bool HandleSet(AppState &state, uint16_t tid, const uint8_t *value, uint16_t length, const char *destination_ip)
{
	if (!state.node_simulator_respond_to_sets)
		{
			return false;
		}

	LogReceiveMessage(state, FormatString("Received TID_SET for TID 0x%04X (%d bytes)", tid, length));

	if (!SigNet::Node::IsValidSetPayload(tid, value, length))
		{
			LogReceiveMessage(state, FormatString("TID_SET 0x%04X: payload validation failed", tid));
			return false;
		}

	auto *blob = SigNet::Node::FindSupportedTidBlob(state.node_user_data, tid);
	if (!blob)
		{
			LogReceiveMessage(state, FormatString("TID_SET 0x%04X: TID not supported", tid));
			return false;
		}

	bool changed = false;
	if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(*blob, tid, value, length, 0, changed))
		{
			if (changed)
				{
					++state.node_config.change_count;
					blob->manager_is_stale = true;
					LogMessage(state, FormatString("TID_SET 0x%04X: value updated (change_count=%d).", tid, state.node_config.change_count));
				}

			SigNet::PacketBuffer payload;
			uint8_t reply_value = 0x01;
			SigNet::Node::AppendNodeTLVRaw(payload, SigNet::TID_SET_REPLY, &reply_value, 1);

			if (SendNodeResponse(state, payload, destination_ip))
				{
					++state.node_stats_set_responses;
					return true;
				}
		}

	return false;
}

} // namespace

//==============================================================================
// Receiver / packet parsing
//==============================================================================

void ProcessReceivedDatagram(AppState &state, const Network::ReceivedDatagram &datagram)
{
	ReceivedPacketPreview preview;
	DiscoveredNode discovered_node;
	bool has_discovered_node = false;
	std::string error_message;
	if (!ParseIncomingPacket(datagram, state, preview, discovered_node, has_discovered_node, error_message))
		{
			LogReceiveError(state, FormatString("%s from %s", error_message.c_str(), datagram.source_ip.c_str()));
			return;
		}

	++state.received_packet_count;
	if (preview.packet_kind == "Announce")
		{
			++state.received_announce_count;
		}
	state.last_received_preview = std::move(preview);

	if (has_discovered_node)
		{
			const bool is_new_node = UpsertDiscoveredNode(state, discovered_node);
			if (is_new_node)
				{
					LogReceiveMessage(state, FormatString("Discovered node %s at %s", discovered_node.tuid_hex.c_str(), discovered_node.source_ip.c_str()));
				}
			if (state.last_received_preview.verify_attempted && !state.last_received_preview.hmac_verified)
				{
					LogReceiveMessage(state, FormatString("Announce HMAC mismatch for %s", discovered_node.tuid_hex.c_str()));
				}
		}

	// Node simulator: dispatch incoming packets to handlers
	if (!state.node_simulator_enabled || !state.keys_valid)
		{
			return;
		}

	// Use SelectValidationKey for proper key selection per URI lane
	const uint8_t *validation_key = SigNet::Node::SelectValidationKey(
		preview.uri.c_str(),
		state.manager_global_key.data(),
		state.manager_local_key.data(),
		state.citizen_key.data(),
		state.sender_key.data());

	if (validation_key)
		{
			// Verify HMAC using the correct key
			SigNet::SigNetOptions options;
			SigNet::Parse::PacketReader reader(datagram.payload.data(), static_cast<uint16_t>(datagram.payload.size()));
			SigNet::CoAPHeader header{};
			int32_t rc = SigNet::Parse::ParseCoAPHeader(reader, header);
			if (rc == SigNet::SIGNET_SUCCESS)
				{
					SigNet::Parse::SkipToken(reader, header.GetTokenLength());
					SigNet::Parse::ParseSigNetOptions(reader, options);

					// Freshness/replay check
					uint32_t now_ms = SDL_GetTicks();
					if (!SigNet::Node::ValidateAndCommitFreshness(state.freshness_tracker, options, now_ms))
						{
							++state.node_stats_replay_rejected;
							LogReceiveMessage(state, FormatString("Replay rejected: session=%u seq=%u from %s", options.session_id, options.seq_num, datagram.source_ip.c_str()));
							EmitSecurityEvent(state, 0x02, datagram.source_ip.c_str()); // Replay detected
							return;
						}

					// HMAC verification
					uint16_t payload_offset = static_cast<uint16_t>(datagram.payload.size());
					if (!LocatePayloadOffset(datagram.payload.data(), static_cast<uint16_t>(datagram.payload.size()), payload_offset))
						{
							payload_offset = datagram.payload.size();
						}
					const uint8_t *payload = payload_offset < datagram.payload.size() ? datagram.payload.data() + payload_offset : nullptr;
					const uint16_t payload_length = payload_offset < datagram.payload.size() ? static_cast<uint16_t>(datagram.payload.size() - payload_offset) : 0;

					if (SigNet::Parse::VerifyPacketHMAC(preview.uri.c_str(), options, payload, payload_length, validation_key) != SigNet::SIGNET_SUCCESS)
						{
							++state.node_stats_hmac_failures;
							LogReceiveMessage(state, FormatString("HMAC verification failed for %s from %s", preview.uri.c_str(), datagram.source_ip.c_str()));
							EmitSecurityEvent(state, 0x01, datagram.source_ip.c_str()); // HMAC failure
							return;
						}
				}
		}

	// Parse CoAP code to determine packet type for dispatch
	SigNet::Parse::PacketReader dispatch_reader(datagram.payload.data(), static_cast<uint16_t>(datagram.payload.size()));
	SigNet::CoAPHeader dispatch_header{};
	int32_t dispatch_rc = SigNet::Parse::ParseCoAPHeader(dispatch_reader, dispatch_header);
	if (dispatch_rc != SigNet::SIGNET_SUCCESS)
		{
			return;
		}

	// Extract payload for SET/POLL handling
	uint16_t payload_offset = static_cast<uint16_t>(datagram.payload.size());
	if (!LocatePayloadOffset(datagram.payload.data(), static_cast<uint16_t>(datagram.payload.size()), payload_offset))
		{
			payload_offset = datagram.payload.size();
		}
	const uint8_t *payload = payload_offset < datagram.payload.size() ? datagram.payload.data() + payload_offset : nullptr;
	const uint16_t payload_length = payload_offset < datagram.payload.size() ? static_cast<uint16_t>(datagram.payload.size() - payload_offset) : 0;

	// Check URI lane for dispatch
	const std::string uri = preview.uri;
	const std::string poll_prefix = std::string("/sig-net/v1/") + SigNet::CoAP::GetURIScope() + "/poll";
	const std::string manager_prefix = std::string("/sig-net/v1/") + SigNet::CoAP::GetURIScope() + "/manager/";

	if (uri.find(poll_prefix) == 0)
		{
			// TID_POLL — extract query level from payload if present
			uint32_t query_level = state.node_simulator_query_level; // default to configured level
			if (payload && payload_length >= 4)
				{
					SigNet::Parse::PacketReader tlv_reader(payload, payload_length);
					while (tlv_reader.GetRemaining() > 0)
						{
							SigNet::TLVBlock tlv;
							if (SigNet::Parse::ParseTLVBlock(tlv_reader, tlv) != SigNet::SIGNET_SUCCESS)
								{
									break;
								}
							if (tlv.type_id == SigNet::TID_POLL)
								{
									if (tlv.length >= 1)
										{
											query_level = tlv.value[0];
										}
									break;
								}
						}
				}
			HandlePoll(state, datagram.source_ip.c_str(), query_level);
		}
	else if (uri.find(manager_prefix) == 0)
		{
			// Manager lane — check CoAP code for GET/SET
			if (dispatch_header.code == SigNet::COAP_CODE_GET)
				{
					// Extract TID from payload
					if (payload && payload_length >= 4)
						{
							SigNet::Parse::PacketReader tlv_reader(payload, payload_length);
							while (tlv_reader.GetRemaining() > 0)
								{
									SigNet::TLVBlock tlv;
									if (SigNet::Parse::ParseTLVBlock(tlv_reader, tlv) != SigNet::SIGNET_SUCCESS)
										{
											break;
										}
									HandleGet(state, tlv.type_id, datagram.source_ip.c_str());
								}
						}
				}
			else if (dispatch_header.code == SigNet::COAP_CODE_PUT || dispatch_header.code == SigNet::COAP_CODE_POST)
				{
					// SET request — parse TLV and apply
					if (payload && payload_length >= 4)
						{
							SigNet::Parse::PacketReader tlv_reader(payload, payload_length);
							while (tlv_reader.GetRemaining() > 0)
								{
									SigNet::TLVBlock tlv;
									if (SigNet::Parse::ParseTLVBlock(tlv_reader, tlv) != SigNet::SIGNET_SUCCESS)
										{
											break;
										}
									HandleSet(state, tlv.type_id, tlv.value, tlv.length, datagram.source_ip.c_str());
								}
						}
				}
		}
}

void UpdateReceiver(AppState &state)
{
	const bool was_active = state.receiver_active;

	if (!state.receiver_enabled)
		{
			state.udp_receiver.Shutdown();
			state.receiver_active = false;
			state.receiver_last_error.clear();
			if (was_active)
				{
					LogReceiveMessage(state, "Receiver stopped.");
				}
			return;
		}

	std::vector<std::string> groups;
	if (state.receiver_listen_announces)
		{
			groups.push_back(SigNet::MULTICAST_NODE_SEND_IP);
		}
	if (state.receiver_listen_universe)
		{
			const std::string multicast_preview = CurrentMulticastPreview(state);
			if (multicast_preview != "n/a")
				{
					groups.push_back(multicast_preview);
				}
		}

	if (groups.empty())
		{
			state.udp_receiver.Shutdown();
			state.receiver_active = false;
			state.receiver_last_error.clear();
			return;
		}

	state.udp_receiver.SetListenPort(SigNet::SIGNET_UDP_PORT);

	std::string error_message;
	if (!state.udp_receiver.Configure(groups, state.source_ip, error_message))
		{
			state.receiver_active = false;
			if (state.receiver_last_error != error_message)
				{
					state.receiver_last_error = error_message;
					LogReceiveError(state, error_message);
				}
			return;
		}

	state.receiver_active = state.udp_receiver.IsActive();
	if (state.receiver_active && !was_active)
		{
			LogReceiveMessage(state, FormatString("Receiver listening on %zu multicast group(s).", groups.size()));
		}
	state.receiver_last_error.clear();

	std::vector<Network::ReceivedDatagram> datagrams;
	if (!state.udp_receiver.Poll(datagrams, error_message))
		{
			if (state.receiver_last_error != error_message)
				{
					state.receiver_last_error = error_message;
					LogReceiveError(state, error_message);
				}
			state.receiver_active = false;
			return;
		}

	for (const Network::ReceivedDatagram &datagram : datagrams)
		{
			ProcessReceivedDatagram(state, datagram);
		}
}

//==============================================================================
// Node simulator
//==============================================================================

const char *QueryLevelLabel(int level)
{
	switch (level)
		{
			case SigNet::QUERY_HEARTBEAT:
				return "Heartbeat";
			case SigNet::QUERY_CONFIG:
				return "Config";
			case SigNet::QUERY_FULL:
				return "Full";
			case SigNet::QUERY_EXTENDED:
				return "Extended";
			default:
				return "Unknown";
		}
}

void InitializeNodeData(AppState &state)
{
	// Copy TUID from the app state
	std::memcpy(state.node_config.tuid, state.tuid.data(), 6);
	state.node_config.mfg_code = 0x5379;
	state.node_config.product_variant_id = 0x0001;
	state.node_config.endpoint = 1;
	state.node_config.change_count = 0;

	// Initialize all TID blobs with defaults (no SDK init function exists)
	for (int i = 0; i < SigNet::Node::GetSupportedRootBlobCount(); ++i)
	{
		auto *b = SigNet::Node::GetSupportedRootBlobByIndex(state.node_user_data, i);
		if (b)
		{
			b->tid = 0;
			b->length = 0;
			b->value_type = SigNet::TID_BLOB_EMPTY;
			b->manager_is_stale = false;
			b->ui_is_stale = false;
			memset(b->data.bytes, 0, sizeof(b->data.bytes));
			b->data.text[0] = 0;
		}
	}
	for (int i = 0; i < SigNet::Node::GetSupportedDataBlobCount(); ++i)
	{
		auto *b = SigNet::Node::GetSupportedDataBlobByIndex(state.node_user_data, i);
		if (b)
		{
			b->tid = 0;
			b->length = 0;
			b->value_type = SigNet::TID_BLOB_EMPTY;
			b->manager_is_stale = false;
			b->ui_is_stale = false;
			memset(b->data.bytes, 0, sizeof(b->data.bytes));
			b->data.text[0] = 0;
		}
	}

	// Sync TUID into the supported TIDs blob
	std::memcpy(state.node_user_data.root.tid_rt_supported_tids.data.bytes, state.tuid.data(), 6);
	state.node_user_data.root.tid_rt_supported_tids.length = 6;
	state.node_user_data.root.tid_rt_supported_tids.value_type = SigNet::TID_BLOB_BYTES;

	// Reset freshness tracker
	SigNet::Node::ResetFreshnessTracker(state.freshness_tracker);

	// Reset lost mode state
	state.in_lost_mode = false;
	state.last_manager_poll_tick = 0;

	LogMessage(state, "Node simulator data initialized.");
}

void SendProactiveResponses(AppState &state)
{
	if (!state.node_simulator_enabled || !state.node_simulator_proactive_responses || !state.keys_valid)
		{
			return;
		}

	// Check if any TID blob has manager_is_stale set
	bool any_stale = false;
	for (int i = 0; i < SigNet::Node::GetSupportedRootBlobCount(); ++i)
		{
			auto *blob = SigNet::Node::GetSupportedRootBlobByIndex(state.node_user_data, i);
			if (blob && blob->manager_is_stale)
				{
					any_stale = true;
					break;
				}
		}
		if (!any_stale)
		{
			for (int i = 0; i < SigNet::Node::GetSupportedDataBlobCount(); ++i)
				{
					auto *blob = SigNet::Node::GetSupportedDataBlobByIndex(state.node_user_data, i);
					if (blob && blob->manager_is_stale)
						{
							any_stale = true;
							break;
						}
				}
		}

	if (!any_stale)
		{
			return;
		}

	// Send a proactive poll reply at the configured query level
	SigNet::PacketBuffer payload;
	int32_t payload_len = SigNet::Node::BuildNodeQueryPayload(static_cast<uint8_t>(state.node_simulator_query_level), state.node_config.endpoint, state.node_user_data, state.node_config, payload);
	if (payload_len <= 0)
		{
			LogError(state, "Failed to build proactive poll reply payload.");
			return;
		}

	SigNet::PacketBuffer buffer;
	int32_t rc = SigNet::BuildDMXPacket(buffer, static_cast<uint16_t>(state.universe), payload.GetBuffer(), static_cast<uint16_t>(payload_len), state.node_config.tuid, state.node_config.endpoint, 0x0000, state.session_id, state.sequence_num, state.citizen_key.data(), state.message_id);
	if (rc != SigNet::SIGNET_SUCCESS)
		{
		LogError(state, FormatString("Failed to build proactive poll reply: error %d", rc));
		return;
	}

	// Clear stale flags
	SigNet::Node::ClearAllManagerStaleFlags(state.node_user_data);

	// Send to manager poll multicast (same as node send for proactive)
	char manager_ip[32] = {0};
	SigNet::CalculateMulticastAddress(static_cast<uint16_t>(state.universe), manager_ip, sizeof(manager_ip));
	if (SendBuffer(state, buffer, manager_ip))
		{
			LogMessage(state, FormatString("Proactive poll reply sent (stale TIDs cleared)."));
			++state.node_stats_poll_responses;
		}
}

void CheckLostMode(AppState &state)
{
	if (!state.node_simulator_enabled || !state.node_simulator_lost_mode)
		{
			return;
		}

	uint32_t current_tick = SDL_GetTicks();

	// If we've never received a poll, don't trigger lost mode yet
	if (state.last_manager_poll_tick == 0)
		{
			return;
		}

	uint32_t elapsed = current_tick - state.last_manager_poll_tick;
	if (elapsed >= state.node_lost_timeout_ms && !state.in_lost_mode)
		{
			state.in_lost_mode = true;
			LogMessage(state, FormatString("Lost mode entered after %lu ms without manager poll.", static_cast<unsigned long>(elapsed)));
			SendNodeLostAnnounce(state);
		}
}

void SendNodeLostAnnounce(AppState &state)
{
	if (!state.keys_valid)
		{
			LogError(state, "Cannot send node-lost announce: keys not valid.");
			return;
		}

	SigNet::PacketBuffer buffer;
	int32_t rc = SigNet::BuildAnnouncePacket(buffer, state.node_config.tuid, state.node_config.mfg_code, state.node_config.product_variant_id, 0, "", 0x01, SigNet::ROLE_CAP_NODE, 0x0000, state.session_id, state.sequence_num, state.citizen_key.data(), state.message_id);
	if (rc != SigNet::SIGNET_SUCCESS)
		{
			LogError(state, FormatString("Failed to build node-lost announce: error %d", rc));
			return;
		}

	if (SendBuffer(state, buffer, SigNet::MULTICAST_NODE_LOST_IP))
		{
			LogMessage(state, FormatString("Node-lost announce sent to %s", SigNet::MULTICAST_NODE_LOST_IP));
		}
}

void Deprovision(AppState &state)
{
	// Wipe all keys
	std::memset(state.k0_key.data(), 0, state.k0_key.size());
	std::memset(state.sender_key.data(), 0, state.sender_key.size());
	std::memset(state.citizen_key.data(), 0, state.citizen_key.size());
	std::memset(state.manager_global_key.data(), 0, state.manager_global_key.size());
	std::memset(state.manager_local_key.data(), 0, state.manager_local_key.size());
	state.keys_valid = false;
	state.k0_set = false;

	// Clear key hex displays
	std::memset(state.k0_hex, 0, sizeof(state.k0_hex));
	std::memset(state.sender_key_hex, 0, sizeof(state.sender_key_hex));
	std::memset(state.citizen_key_hex, 0, sizeof(state.citizen_key_hex));

	// Reset freshness tracker
	SigNet::Node::ResetFreshnessTracker(state.freshness_tracker);

	// Reset lost mode
	state.in_lost_mode = false;
	state.last_manager_poll_tick = 0;

	LogMessage(state, "Device deprovisioned — all keys wiped.");
}

void UpdateNodeSimulator(AppState &state, uint32_t current_tick)
{
	if (!state.node_simulator_enabled || !state.keys_valid)
		{
			return;
		}

	// Proactive response check (every interval)
	if (current_tick - state.last_proactive_check_tick >= state.node_simulator_proactive_interval_ms)
		{
			state.last_proactive_check_tick = current_tick;
			SendProactiveResponses(state);
		}

	// Lost mode check
	CheckLostMode(state);
}

//==============================================================================
// Initialization
//==============================================================================

void InitializeState(AppState &state)
{
	CopyString(state.tuid_hex, sizeof(state.tuid_hex), SigNet::TEST_TUID);
	RefreshPassphraseReport(state);
	UpdateInterfaceSelection(state);
	if (!state.interfaces.empty())
		{
			CopyString(state.source_ip, sizeof(state.source_ip), state.interfaces[state.selected_interface_index].ip);
		}

	// Initialize node simulator data
	InitializeNodeData(state);

	LogMessage(state, "Sig-Net ImGui example initialized.");
	LogMessage(state, "Compact dashboard mode enabled.");
	LogReceiveMessage(state, "Receive mode ready. Enable the receiver to discover announces.");
}

} // namespace App
//==============================================================================
// sig-net-example-imgui - Network Layer
//==============================================================================
//
// Platform-agnostic UDP multicast send/receive plus IPv4 interface enumeration.
// No Sig-Net SDK or ImGui dependency.
//
//==============================================================================

#ifndef SIG_NET_EXAMPLE_NETWORK_HPP
#define SIG_NET_EXAMPLE_NETWORK_HPP

#include <cstdint>
#include <set>
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

namespace Network
{

//------------------------------------------------------------------------------

struct InterfaceInfo
{
		std::string label;
		std::string ip;
};

//------------------------------------------------------------------------------

struct ReceivedDatagram
{
		std::vector<uint8_t> payload;
		std::string source_ip;
		uint16_t source_port = 0;
};

//------------------------------------------------------------------------------

// Enumerate non-loopback IPv4 interfaces plus a synthetic loopback entry.
std::vector<InterfaceInfo> EnumerateIPv4Interfaces();

//------------------------------------------------------------------------------

// UDP multicast sender. Binds to INADDR_ANY and optionally sets IP_MULTICAST_IF
// to a chosen source interface before each send.
class UdpMulticastSender
{
	public:

		UdpMulticastSender() = default;
		~UdpMulticastSender();

		bool EnsureInitialized(std::string &error_message);
		void Shutdown();

		bool Send(const std::string &destination_ip, uint16_t destination_port, const uint8_t *payload, size_t payload_size, const std::string &source_ip, std::string &error_message);

	private:

#ifdef _WIN32
		static int InvalidSocket() { return static_cast<int>(INVALID_SOCKET); }
#else
		static int InvalidSocket() { return -1; }
#endif

		std::string LastSocketError(const char *prefix) const;

		int socket_fd_ = InvalidSocket();
		bool initialized_ = false;
#ifdef _WIN32
		bool winsock_started_ = false;
#endif
};

//------------------------------------------------------------------------------

// UDP multicast receiver. Joins one or more multicast groups on a chosen
// interface and polls incoming datagrams in non-blocking batches.
class UdpMulticastReceiver
{
	public:

		UdpMulticastReceiver() = default;
		~UdpMulticastReceiver();

		bool Configure(const std::vector<std::string> &group_ips, const std::string &interface_ip, std::string &error_message);

		bool Poll(std::vector<ReceivedDatagram> &datagrams, std::string &error_message);

		void Shutdown();
		bool IsActive() const { return socket_fd_ != InvalidSocket(); }

		// UDP port to bind for incoming traffic (set before Configure()).
		void SetListenPort(uint16_t port) { listen_port_ = port; }

	private:

#ifdef _WIN32
		static int InvalidSocket() { return static_cast<int>(INVALID_SOCKET); }
#else
		static int InvalidSocket() { return -1; }
#endif

		std::string LastSocketError(const char *prefix) const;
		bool SetNonBlocking(std::string &error_message);
		bool JoinGroup(const std::string &group_ip, const std::string &interface_ip, std::string &error_message);
		bool IsWouldBlockError() const;

		int socket_fd_ = InvalidSocket();
		std::vector<std::string> joined_groups_;
		std::string interface_ip_;
		uint16_t listen_port_ = 0;
#ifdef _WIN32
		bool winsock_started_ = false;
#endif
};

} // namespace Network

#endif // SIG_NET_EXAMPLE_NETWORK_HPP

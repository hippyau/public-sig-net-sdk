//==============================================================================
// sig-net-example-imgui - Network Layer
//==============================================================================
//
// Platform-agnostic UDP multicast send/receive plus IPv4 interface enumeration.
//
//==============================================================================

#include "network.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <cstring>
#endif

namespace Network
{

//------------------------------------------------------------------------------

namespace
{

// Local string helpers so this translation unit has no dependency on the
// Sig-Net application layer.

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

std::string FormatString(const char *format, ...)
{
	char buffer[1024];
	va_list args;
	va_start(args, format);
	std::vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	return std::string(buffer);
}

} // namespace

//------------------------------------------------------------------------------

std::vector<InterfaceInfo> EnumerateIPv4Interfaces()
{
	std::vector<InterfaceInfo> interfaces;
	std::set<std::string> seen;

	interfaces.push_back({"Loopback (127.0.0.1)", "127.0.0.1"});
	seen.insert("127.0.0.1");

#ifndef _WIN32
	ifaddrs *raw_ifaddrs = nullptr;
	if (getifaddrs(&raw_ifaddrs) == 0)
		{
			for (ifaddrs *current = raw_ifaddrs; current; current = current->ifa_next)
				{
					if (!current->ifa_addr || current->ifa_addr->sa_family != AF_INET)
						{
							continue;
						}

					sockaddr_in *ipv4 = reinterpret_cast<sockaddr_in *>(current->ifa_addr);
					char address_buffer[INET_ADDRSTRLEN] = {0};
					if (!inet_ntop(AF_INET, &ipv4->sin_addr, address_buffer, sizeof(address_buffer)))
						{
							continue;
						}

					const std::string ip = address_buffer;
					if (seen.insert(ip).second)
						{
							const bool loopback = (current->ifa_flags & IFF_LOOPBACK) != 0;
							interfaces.push_back({std::string(current->ifa_name ? current->ifa_name : "iface") + (loopback ? " (loopback) " : " ") + ip, ip});
						}
				}
			freeifaddrs(raw_ifaddrs);
		}
#endif

	return interfaces;
}

//==============================================================================
// UdpMulticastSender
//==============================================================================

UdpMulticastSender::~UdpMulticastSender() { Shutdown(); }

bool UdpMulticastSender::EnsureInitialized(std::string &error_message)
{
	if (initialized_ && socket_fd_ != InvalidSocket())
		{
			return true;
		}

#ifdef _WIN32
	if (!winsock_started_)
		{
			WSADATA wsa_data;
			const int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
			if (result != 0)
				{
					error_message = FormatString("WSAStartup failed: %d", result);
					return false;
				}
			winsock_started_ = true;
		}
#endif

	socket_fd_ = static_cast<int>(::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
	if (socket_fd_ == InvalidSocket())
		{
			error_message = LastSocketError("Socket creation failed");
			return false;
		}

	sockaddr_in local_addr{};
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	local_addr.sin_port = 0;

	if (::bind(socket_fd_, reinterpret_cast<sockaddr *>(&local_addr), sizeof(local_addr)) < 0)
		{
			error_message = LastSocketError("Socket bind failed");
		}

	unsigned char loopback = 1;
	if (::setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_LOOP, reinterpret_cast<const char *>(&loopback), sizeof(loopback)) < 0)
		{
			error_message = LastSocketError("Set loopback failed");
		}

	unsigned char ttl = 16;
	if (::setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<const char *>(&ttl), sizeof(ttl)) < 0)
		{
			error_message = LastSocketError("Set TTL failed");
		}

	int broadcast = 1;
	::setsockopt(socket_fd_, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char *>(&broadcast), sizeof(broadcast));

	initialized_ = true;
	return true;
}

void UdpMulticastSender::Shutdown()
{
	if (socket_fd_ != InvalidSocket())
		{
#ifdef _WIN32
			closesocket(socket_fd_);
#else
			close(socket_fd_);
#endif
			socket_fd_ = InvalidSocket();
		}

	initialized_ = false;

#ifdef _WIN32
	if (winsock_started_)
		{
			WSACleanup();
			winsock_started_ = false;
		}
#endif
}

bool UdpMulticastSender::Send(const std::string &destination_ip, uint16_t destination_port, const uint8_t *payload, size_t payload_size, const std::string &source_ip, std::string &error_message)
{
	if (!payload || payload_size == 0)
		{
			error_message = "No payload to send.";
			return false;
		}

	if (!EnsureInitialized(error_message))
		{
			return false;
		}

	const std::string trimmed_source = Trim(source_ip);
	const bool use_loopback = trimmed_source.rfind("127.", 0) == 0;
	if (!trimmed_source.empty() && !use_loopback)
		{
			in_addr iface_addr{};
			if (::inet_pton(AF_INET, trimmed_source.c_str(), &iface_addr) != 1)
				{
					error_message = "Invalid source interface IPv4 address.";
				}
			else if (::setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_IF, reinterpret_cast<const char *>(&iface_addr), sizeof(iface_addr)) < 0)
				{
					error_message = LastSocketError("IP_MULTICAST_IF failed");
				}
		}

	sockaddr_in dest_addr{};
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(destination_port);
	if (::inet_pton(AF_INET, destination_ip.c_str(), &dest_addr.sin_addr) != 1)
		{
			error_message = "Invalid destination IPv4 address.";
			return false;
		}

	const int bytes_sent = static_cast<int>(::sendto(socket_fd_, reinterpret_cast<const char *>(payload), static_cast<int>(payload_size), 0, reinterpret_cast<sockaddr *>(&dest_addr), sizeof(dest_addr)));

	if (bytes_sent < 0)
		{
			if (!trimmed_source.empty() && !use_loopback)
				{
					in_addr any_addr{};
					any_addr.s_addr = htonl(INADDR_ANY);
					::setsockopt(socket_fd_, IPPROTO_IP, IP_MULTICAST_IF, reinterpret_cast<const char *>(&any_addr), sizeof(any_addr));

					const int retry_bytes_sent =
					    static_cast<int>(::sendto(socket_fd_, reinterpret_cast<const char *>(payload), static_cast<int>(payload_size), 0, reinterpret_cast<sockaddr *>(&dest_addr), sizeof(dest_addr)));

					if (retry_bytes_sent == static_cast<int>(payload_size))
						{
							return true;
						}
				}

			error_message = LastSocketError("sendto() failed");
			return false;
		}

	if (bytes_sent != static_cast<int>(payload_size))
		{
			error_message = FormatString("Partial send: %d of %zu bytes", bytes_sent, payload_size);
			return false;
		}

	return true;
}

std::string UdpMulticastSender::LastSocketError(const char *prefix) const
{
#ifdef _WIN32
	return FormatString("%s: WSA error %d", prefix, WSAGetLastError());
#else
	return FormatString("%s: %s", prefix, std::strerror(errno));
#endif
}

//==============================================================================
// UdpMulticastReceiver
//==============================================================================

UdpMulticastReceiver::~UdpMulticastReceiver() { Shutdown(); }

bool UdpMulticastReceiver::Configure(const std::vector<std::string> &group_ips, const std::string &interface_ip, std::string &error_message)
{
	std::vector<std::string> requested_groups;
	for (const std::string &group_ip : group_ips)
		{
			const std::string trimmed_group = Trim(group_ip);
			if (!trimmed_group.empty())
				{
					requested_groups.push_back(trimmed_group);
				}
		}
	std::sort(requested_groups.begin(), requested_groups.end());
	requested_groups.erase(std::unique(requested_groups.begin(), requested_groups.end()), requested_groups.end());

	const std::string trimmed_interface = Trim(interface_ip);
	if (requested_groups.empty())
		{
			Shutdown();
			interface_ip_ = trimmed_interface;
			return true;
		}

	if (socket_fd_ != InvalidSocket() && requested_groups == joined_groups_ && trimmed_interface == interface_ip_)
		{
			return true;
		}

	Shutdown();

#ifdef _WIN32
	if (!winsock_started_)
		{
			WSADATA wsa_data;
			const int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
			if (result != 0)
				{
					error_message = FormatString("WSAStartup failed: %d", result);
					return false;
				}
			winsock_started_ = true;
		}
#endif

	socket_fd_ = static_cast<int>(::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
	if (socket_fd_ == InvalidSocket())
		{
			error_message = LastSocketError("Receiver socket creation failed");
			return false;
		}

	int reuse = 1;
	if (::setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&reuse), sizeof(reuse)) < 0)
		{
			error_message = LastSocketError("Receiver SO_REUSEADDR failed");
			Shutdown();
			return false;
		}

#ifdef SO_REUSEPORT
	::setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<const char *>(&reuse), sizeof(reuse));
#endif

	sockaddr_in local_addr{};
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	local_addr.sin_port = htons(listen_port_);
	if (::bind(socket_fd_, reinterpret_cast<sockaddr *>(&local_addr), sizeof(local_addr)) < 0)
		{
			error_message = LastSocketError("Receiver bind failed");
			Shutdown();
			return false;
		}

	if (!SetNonBlocking(error_message))
		{
			Shutdown();
			return false;
		}

	for (const std::string &group_ip : requested_groups)
		{
			if (!JoinGroup(group_ip, trimmed_interface, error_message))
				{
					Shutdown();
					return false;
				}
		}

	joined_groups_ = requested_groups;
	interface_ip_ = trimmed_interface;
	return true;
}

bool UdpMulticastReceiver::Poll(std::vector<ReceivedDatagram> &datagrams, std::string &error_message)
{
	datagrams.clear();
	if (socket_fd_ == InvalidSocket())
		{
			return true;
		}

	for (int i = 0; i < 32; ++i)
		{
			std::array<uint8_t, 1500> buffer{};
			sockaddr_in source_addr{};
#ifdef _WIN32
			int source_addr_len = sizeof(source_addr);
#else
			socklen_t source_addr_len = sizeof(source_addr);
#endif
			const int bytes_read = static_cast<int>(::recvfrom(socket_fd_, reinterpret_cast<char *>(buffer.data()), static_cast<int>(buffer.size()), 0, reinterpret_cast<sockaddr *>(&source_addr), &source_addr_len));

			if (bytes_read < 0)
				{
					if (IsWouldBlockError())
						{
							return true;
						}
					error_message = LastSocketError("recvfrom() failed");
					return false;
				}
			if (bytes_read == 0)
				{
					break;
				}

			ReceivedDatagram datagram;
			datagram.payload.assign(buffer.begin(), buffer.begin() + bytes_read);
			char source_ip[INET_ADDRSTRLEN] = {0};
			if (::inet_ntop(AF_INET, &source_addr.sin_addr, source_ip, sizeof(source_ip)))
				{
					datagram.source_ip = source_ip;
				}
			else
				{
					datagram.source_ip = "0.0.0.0";
				}
			datagram.source_port = ntohs(source_addr.sin_port);
			datagrams.push_back(std::move(datagram));
		}

	return true;
}

void UdpMulticastReceiver::Shutdown()
{
	if (socket_fd_ != InvalidSocket())
		{
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
	if (winsock_started_)
		{
			WSACleanup();
			winsock_started_ = false;
		}
#endif
}

std::string UdpMulticastReceiver::LastSocketError(const char *prefix) const
{
#ifdef _WIN32
	return FormatString("%s: WSA error %d", prefix, WSAGetLastError());
#else
	return FormatString("%s: %s", prefix, std::strerror(errno));
#endif
}

bool UdpMulticastReceiver::SetNonBlocking(std::string &error_message)
{
#ifdef _WIN32
	u_long non_blocking = 1;
	if (ioctlsocket(socket_fd_, FIONBIO, &non_blocking) != 0)
		{
			error_message = LastSocketError("Receiver non-blocking mode failed");
			return false;
		}
#else
	const int flags = fcntl(socket_fd_, F_GETFL, 0);
	if (flags < 0)
		{
			error_message = LastSocketError("Receiver F_GETFL failed");
			return false;
		}
	if (fcntl(socket_fd_, F_SETFL, flags | O_NONBLOCK) < 0)
		{
			error_message = LastSocketError("Receiver F_SETFL failed");
			return false;
		}
#endif
	return true;
}

bool UdpMulticastReceiver::JoinGroup(const std::string &group_ip, const std::string &interface_ip, std::string &error_message)
{
	ip_mreq membership{};
	if (::inet_pton(AF_INET, group_ip.c_str(), &membership.imr_multiaddr) != 1)
		{
			error_message = FormatString("Invalid multicast group address: %s", group_ip.c_str());
			return false;
		}

	membership.imr_interface.s_addr = htonl(INADDR_ANY);
	if (!interface_ip.empty() && interface_ip.rfind("127.", 0) != 0)
		{
			if (::inet_pton(AF_INET, interface_ip.c_str(), &membership.imr_interface) != 1)
				{
					error_message = FormatString("Invalid receive interface address: %s", interface_ip.c_str());
					return false;
				}
		}

	if (::setsockopt(socket_fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP, reinterpret_cast<const char *>(&membership), sizeof(membership)) < 0)
		{
			error_message = LastSocketError("Receiver IP_ADD_MEMBERSHIP failed");
			return false;
		}

	return true;
}

bool UdpMulticastReceiver::IsWouldBlockError() const
{
#ifdef _WIN32
	const int error_code = WSAGetLastError();
	return error_code == WSAEWOULDBLOCK;
#else
	return errno == EWOULDBLOCK || errno == EAGAIN;
#endif
}

} // namespace Network


#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS 1
#endif

#include <stdio.h>

#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#define sleep(x) Sleep(x * 1000)
#define snprintf _snprintf
#else
#include <netdb.h>
#include <ifaddrs.h>
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif

// Alias some things to simulate recieving data to fuzz library
#if defined(MDNS_FUZZING)
#define recvfrom(sock, buffer, capacity, flags, src_addr, addrlen) ((mdns_ssize_t)capacity)
#define printf
#endif

#include "mdns.h"

#if defined(MDNS_FUZZING)
#undef recvfrom
#endif

typedef struct interface_t {
	struct interface_t *next;
	struct sockaddr_in ipv4_addr;
	struct in_addr ipv4_mask;
	struct sockaddr_in6 ipv6_addr;
	struct in6_addr ipv6_mask;
} interface_t;

// Data for our service including the mDNS records
typedef struct {
	mdns_string_t service;
	mdns_string_t hostname;
	mdns_string_t service_instance;
	mdns_string_t hostname_qualified;
	int port;
	mdns_record_t record_ptr;
	mdns_record_t record_srv;
	mdns_record_t record_a;
	mdns_record_t record_aaaa;

	interface_t *intf;
} service_t;

static mdns_string_t
ipv4_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in* addr,
					   size_t addrlen) {
	mdns_string_t str;
	char host[NI_MAXHOST] = {0};
	char service[NI_MAXSERV] = {0};
	int ret = getnameinfo((const struct sockaddr*)addr, (socklen_t)addrlen, host, NI_MAXHOST,
						  service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
	int len = 0;
	if (ret == 0) {
		if (addr->sin_port != 0)
			len = snprintf(buffer, capacity, "%s:%s", host, service);
		else
			len = snprintf(buffer, capacity, "%s", host);
	}
	if (len >= (int)capacity)
		len = (int)capacity - 1;
	str.str = buffer;
	str.length = len;
	return str;
}

static mdns_string_t
ipv6_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in6* addr,
					   size_t addrlen) {
	mdns_string_t str;
	char host[NI_MAXHOST] = {0};
	char service[NI_MAXSERV] = {0};
	int ret = getnameinfo((const struct sockaddr*)addr, (socklen_t)addrlen, host, NI_MAXHOST,
						  service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
	int len = 0;
	if (ret == 0) {
		if (addr->sin6_port != 0)
			len = snprintf(buffer, capacity, "[%s]:%s", host, service);
		else
			len = snprintf(buffer, capacity, "%s", host);
	}
	if (len >= (int)capacity)
		len = (int)capacity - 1;
	str.str = buffer;
	str.length = len;
	return str;
}

static mdns_string_t
ip_address_to_string(char* buffer, size_t capacity, const struct sockaddr* addr, size_t addrlen) {
	if (addr->sa_family == AF_INET6)
		return ipv6_address_to_string(buffer, capacity, (const struct sockaddr_in6*)addr, addrlen);
	return ipv4_address_to_string(buffer, capacity, (const struct sockaddr_in*)addr, addrlen);
}

static int mdns_intf_append(service_t* service, interface_t *intf) {
	if ((NULL == service) || (NULL == intf)) {
		return -1;
	}
	intf->next = service->intf;
	service->intf = intf;
	return 0;
}

static void mdns_intf_free(interface_t *intf) {
	interface_t *ptr;

	for (ptr = intf; NULL != ptr;) {
		ptr = intf->next;
		free(intf);
	}
}

static interface_t *mdns_intf_find(service_t* service, const struct sockaddr *addr) {
	interface_t *ptr;
	const struct sockaddr_in6 *in6_addr;
	const struct sockaddr_in *in_addr;

	for (ptr = service->intf; NULL != ptr; ptr = ptr->next) {
		if (addr->sa_family == AF_INET6) {
			in6_addr = (struct sockaddr_in6 *)addr;
			continue;
		}
		in_addr = (struct sockaddr_in *)addr;
		if ((ptr->ipv4_mask.s_addr & in_addr->sin_addr.s_addr)
		 == (ptr->ipv4_mask.s_addr & ptr->ipv4_addr.sin_addr.s_addr)) {
			break;
		}
	}

	return ptr;
}

// Callback handling parsing answers to queries sent
static int
query_callback(int sock, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
			   uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data,
			   size_t size, size_t name_offset, size_t name_length, size_t record_offset,
			   size_t record_length, void* user_data) {
	mdns_record_txt_t txtbuffer[128];
	char namebuffer[256];
	char entrybuffer[256];
	char addrbuffer[64];
	mdns_string_t addrstr;
	mdns_string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);
	const char* entrytype = (entry == MDNS_ENTRYTYPE_ANSWER) ?
								"answer" :
								((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
	mdns_string_t entrystr =
		mdns_string_extract(data, size, &name_offset, entrybuffer, sizeof(entrybuffer));
	(void)sizeof(sock);
	(void)sizeof(query_id);
	(void)sizeof(name_length);
	(void)sizeof(user_data);
	if (rtype == MDNS_RECORDTYPE_PTR) {
		mdns_string_t namestr = mdns_record_parse_ptr(data, size, record_offset, record_length,
													  namebuffer, sizeof(namebuffer));
		printf("%.*s : %s %.*s PTR %.*s rclass 0x%x ttl %u length %d\n",
			   MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr),
			   MDNS_STRING_FORMAT(namestr), rclass, ttl, (int)record_length);
	} else if (rtype == MDNS_RECORDTYPE_SRV) {
		mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length,
													  namebuffer, sizeof(namebuffer));
		printf("%.*s : %s %.*s SRV %.*s priority %d weight %d port %d\n",
			   MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr),
			   MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
	} else if (rtype == MDNS_RECORDTYPE_A) {
		struct sockaddr_in addr;
		mdns_record_parse_a(data, size, record_offset, record_length, &addr);
		addrstr =
			ipv4_address_to_string(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
		printf("%.*s : %s %.*s A %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
			   MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(addrstr));
	} else if (rtype == MDNS_RECORDTYPE_AAAA) {
		struct sockaddr_in6 addr;
		mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
		addrstr =
			ipv6_address_to_string(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
		printf("%.*s : %s %.*s AAAA %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
			   MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(addrstr));
	} else if (rtype == MDNS_RECORDTYPE_TXT) {
		size_t itxt;
		size_t parsed = mdns_record_parse_txt(data, size, record_offset, record_length, txtbuffer,
											  sizeof(txtbuffer) / sizeof(mdns_record_txt_t));
		for (itxt = 0; itxt < parsed; ++itxt) {
			if (txtbuffer[itxt].value.length) {
				printf("%.*s : %s %.*s TXT %.*s = %.*s\n", MDNS_STRING_FORMAT(fromaddrstr),
					   entrytype, MDNS_STRING_FORMAT(entrystr),
					   MDNS_STRING_FORMAT(txtbuffer[itxt].key),
					   MDNS_STRING_FORMAT(txtbuffer[itxt].value));
			} else {
				printf("%.*s : %s %.*s TXT %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
					   MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(txtbuffer[itxt].key));
			}
		}
	} else {
		printf("%.*s : %s %.*s type %u rclass 0x%x ttl %u length %d\n",
			   MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr), rtype,
			   rclass, ttl, (int)record_length);
	}
	return 0;
}

// Callback handling questions incoming on service sockets
static int
service_callback(int sock, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
				 uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data,
				 size_t size, size_t name_offset, size_t name_length, size_t record_offset,
				 size_t record_length, void* user_data) {
	char addrbuffer[64];
	char namebuffer[256];
	char sendbuffer[1024];
	interface_t *intf;

	const char dns_sd[] = "_services._dns-sd._udp.local.";
	service_t* service = (service_t*)user_data;

	mdns_string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);

	size_t offset = name_offset;
	mdns_string_t name = mdns_string_extract(data, size, &offset, namebuffer, sizeof(namebuffer));

	const char* record_name = 0;
	uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);

	(void)sizeof(ttl);
	if (entry != MDNS_ENTRYTYPE_QUESTION)
		return 0;

	if (rtype == MDNS_RECORDTYPE_PTR)
		record_name = "PTR";
	else if (rtype == MDNS_RECORDTYPE_SRV)
		record_name = "SRV";
	else if (rtype == MDNS_RECORDTYPE_A)
		record_name = "A";
	else if (rtype == MDNS_RECORDTYPE_AAAA)
		record_name = "AAAA";
	else if (rtype == MDNS_RECORDTYPE_ANY)
		record_name = "ANY";
	else
		return 0;
	printf("Query %s %.*s from %.*s\n", record_name, MDNS_STRING_FORMAT(name), MDNS_STRING_FORMAT(fromaddrstr));

	intf = mdns_intf_find(service, from);
	if (NULL == intf) {
		printf("Find interface failed\n");
		return 0;
	}

	if ((name.length == (sizeof(dns_sd) - 1)) &&
		(strncmp(name.str, dns_sd, sizeof(dns_sd) - 1) == 0)) {
		if ((rtype == MDNS_RECORDTYPE_PTR) || (rtype == MDNS_RECORDTYPE_ANY)) {
			// The PTR query was for the DNS-SD domain, send answer with a PTR record for the
			// service name we advertise, typically on the "<_service-name>._tcp.local." format

			// Answer PTR record reverse mapping "<_service-name>._tcp.local." to
			// "<hostname>.<_service-name>._tcp.local."
			mdns_record_t answer;

			answer.name = name;
			answer.type = MDNS_RECORDTYPE_PTR;
			answer.data.ptr.name = service->service;

			// Send the answer, unicast or multicast depending on flag in query
			printf("  --> answer %.*s (%s)\n", MDNS_STRING_FORMAT(answer.data.ptr.name),
				   (unicast ? "unicast" : "multicast"));

			if (unicast) {
				mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
										  query_id, rtype, name.str, name.length, answer, 0, 0, 0,
										  0);
			} else {
				mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, 0,
											0);
			}
		}
	} else if ((name.length == service->service.length) &&
			   (strncmp(name.str, service->service.str, name.length) == 0)) {
		if ((rtype == MDNS_RECORDTYPE_PTR) || (rtype == MDNS_RECORDTYPE_ANY)) {
			// The PTR query was for our service (usually "<_service-name._tcp.local"), answer a PTR
			// record reverse mapping the queried service name to our service instance name
			// (typically on the "<hostname>.<_service-name>._tcp.local." format), and add
			// additional records containing the SRV record mapping the service instance name to our
			// qualified hostname (typically "<hostname>.local.") and port, as well as any IPv4/IPv6
			// address for the hostname as A/AAAA records, and two test TXT records

			// Answer PTR record reverse mapping "<_service-name>._tcp.local." to
			// "<hostname>.<_service-name>._tcp.local."
			mdns_record_t answer = service->record_ptr;

			mdns_record_t additional[5] = {0};
			size_t additional_count = 0;

			// SRV record mapping "<hostname>.<_service-name>._tcp.local." to
			// "<hostname>.local." with port. Set weight & priority to 0.
			additional[additional_count++] = service->record_srv;

			// A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
			if (intf->ipv4_addr.sin_family == AF_INET) {
				service->record_a.data.a.addr = intf->ipv4_addr;
				additional[additional_count++] = service->record_a;
			}
			if (intf->ipv6_addr.sin6_family == AF_INET6) {
				service->record_aaaa.data.aaaa.addr = intf->ipv6_addr;
				additional[additional_count++] = service->record_aaaa;
			}

			// Send the answer, unicast or multicast depending on flag in query
			printf("  --> answer %.*s (%s)\n",
				   MDNS_STRING_FORMAT(service->record_ptr.data.ptr.name),
				   (unicast ? "unicast" : "multicast"));

			if (unicast) {
				mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
										  query_id, rtype, name.str, name.length, answer, 0, 0,
										  additional, additional_count);
			} else {
				mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0,
											additional, additional_count);
			}
		}
	} else if ((name.length == service->service_instance.length) &&
			   (strncmp(name.str, service->service_instance.str, name.length) == 0)) {
		if ((rtype == MDNS_RECORDTYPE_SRV) || (rtype == MDNS_RECORDTYPE_ANY)) {
			// The SRV query was for our service instance (usually
			// "<hostname>.<_service-name._tcp.local"), answer a SRV record mapping the service
			// instance name to our qualified hostname (typically "<hostname>.local.") and port, as
			// well as any IPv4/IPv6 address for the hostname as A/AAAA records, and two test TXT
			// records

			// Answer PTR record reverse mapping "<_service-name>._tcp.local." to
			// "<hostname>.<_service-name>._tcp.local."
			mdns_record_t answer = service->record_srv;

			mdns_record_t additional[5] = {0};
			size_t additional_count = 0;

			// A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
			if (intf->ipv4_addr.sin_family == AF_INET) {
				service->record_a.data.a.addr = intf->ipv4_addr;
				additional[additional_count++] = service->record_a;
			}
			if (intf->ipv6_addr.sin6_family == AF_INET6) {
				service->record_aaaa.data.aaaa.addr = intf->ipv6_addr;
				additional[additional_count++] = service->record_aaaa;
			}

			// Send the answer, unicast or multicast depending on flag in query
			printf("  --> answer %.*s port %d (%s)\n",
				   MDNS_STRING_FORMAT(service->record_srv.data.srv.name), service->port,
				   (unicast ? "unicast" : "multicast"));

			if (unicast) {
				mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
										  query_id, rtype, name.str, name.length, answer, 0, 0,
										  additional, additional_count);
			} else {
				mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0,
											additional, additional_count);
			}
		}
	} else if ((name.length == service->hostname_qualified.length) &&
			   (strncmp(name.str, service->hostname_qualified.str, name.length) == 0)) {
		if (((rtype == MDNS_RECORDTYPE_A) || (rtype == MDNS_RECORDTYPE_ANY)) &&
			(intf->ipv4_addr.sin_family == AF_INET)) {
			// The A query was for our qualified hostname (typically "<hostname>.local.") and we
			// have an IPv4 address, answer with an A record mappiing the hostname to an IPv4
			// address, as well as any IPv6 address for the hostname, and two test TXT records

			// Answer A records mapping "<hostname>.local." to IPv4 address
			mdns_record_t answer = service->record_a;

			mdns_record_t additional[5] = {0};
			size_t additional_count = 0;
			mdns_string_t addrstr;

			// A record mapping "<hostname>.local." to IPv4 addresses
			if (intf->ipv4_addr.sin_family == AF_INET) {
				service->record_a.data.a.addr = intf->ipv4_addr;
				additional[additional_count++] = service->record_a;
			}

			// Send the answer, unicast or multicast depending on flag in query
			addrstr = ip_address_to_string(
				addrbuffer, sizeof(addrbuffer), (struct sockaddr*)&service->record_a.data.a.addr,
				sizeof(service->record_a.data.a.addr));
			printf("  --> answer %.*s IPv4 %.*s (%s)\n", MDNS_STRING_FORMAT(service->record_a.name),
				   MDNS_STRING_FORMAT(addrstr), (unicast ? "unicast" : "multicast"));

			if (unicast) {
				mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
										  query_id, rtype, name.str, name.length, answer, 0, 0,
										  additional, additional_count);
			} else {
				mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0,
											additional, additional_count);
			}
		} else if (((rtype == MDNS_RECORDTYPE_AAAA) || (rtype == MDNS_RECORDTYPE_ANY)) &&
				   (intf->ipv6_addr.sin6_family == AF_INET6)) {
			// The AAAA query was for our qualified hostname (typically "<hostname>.local.") and we
			// have an IPv6 address, answer with an AAAA record mappiing the hostname to an IPv6
			// address, as well as any IPv4 address for the hostname, and two test TXT records

			// Answer AAAA records mapping "<hostname>.local." to IPv6 address
			mdns_record_t answer = service->record_aaaa;

			mdns_record_t additional[5] = {0};
			size_t additional_count = 0;
			mdns_string_t addrstr;

			// AAAA record mapping "<hostname>.local." to IPv6 addresses
			if (intf->ipv6_addr.sin6_family == AF_INET6) {
				service->record_aaaa.data.aaaa.addr = intf->ipv6_addr;
				additional[additional_count++] = service->record_aaaa;
			}

			// Send the answer, unicast or multicast depending on flag in query
			addrstr =
				ip_address_to_string(addrbuffer, sizeof(addrbuffer),
									 (struct sockaddr*)&service->record_aaaa.data.aaaa.addr,
									 sizeof(service->record_aaaa.data.aaaa.addr));
			printf("  --> answer %.*s IPv6 %.*s (%s)\n",
				   MDNS_STRING_FORMAT(service->record_aaaa.name), MDNS_STRING_FORMAT(addrstr),
				   (unicast ? "unicast" : "multicast"));

			if (unicast) {
				mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
										  query_id, rtype, name.str, name.length, answer, 0, 0,
										  additional, additional_count);
			} else {
				mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0,
											additional, additional_count);
			}
		}
	}
	return 0;
}

// Open sockets for sending one-shot multicast queries from an ephemeral port
static int
open_client_sockets(service_t *service, int* sockets, int max_sockets, int port) {
	// When sending, each socket can only send to one network interface
	// Thus we need to open one socket for each interface and address family
	int num_sockets = 0;
	interface_t *new_intf;

#ifdef _WIN32

	PIP_ADAPTER_ADDRESSES adapter_address = 0;
	PIP_ADAPTER_ADDRESSES adapter;
	ULONG address_size = 8000;
	unsigned int ret;
	unsigned int num_retries = 4;
	do {
		adapter_address = (PIP_ADAPTER_ADDRESSES)malloc(address_size);
		ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, 0,
								   adapter_address, &address_size);
		if (ret == ERROR_BUFFER_OVERFLOW) {
			free(adapter_address);
			adapter_address = 0;
			address_size *= 2;
		} else {
			break;
		}
	} while (num_retries-- > 0);

	if (!adapter_address || (ret != NO_ERROR)) {
		free(adapter_address);
		printf("Failed to get network adapter addresses\n");
		return num_sockets;
	}

	for (adapter = adapter_address; adapter; adapter = adapter->Next) {
		IP_ADAPTER_UNICAST_ADDRESS* unicast;
		if (adapter->TunnelType == TUNNEL_TYPE_TEREDO)
			continue;
		if (adapter->OperStatus != IfOperStatusUp)
			continue;

		new_intf = (interface_t *)malloc(sizeof(*new_intf));
		if (NULL == new_intf) {
			continue;
		}
		memset((void *)new_intf, 0x00, sizeof(*new_intf));
		for (unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
			if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
				struct sockaddr_in* saddr = (struct sockaddr_in*)unicast->Address.lpSockaddr;
				int log_addr = 1;
				new_intf->ipv4_addr = *saddr;
				ConvertLengthToIpv4Mask(unicast->OnLinkPrefixLength, (PULONG)&new_intf->ipv4_mask);
				if (num_sockets < max_sockets) {
					int sock;
					saddr->sin_port = htons((unsigned short)port);
					sock = mdns_socket_open_ipv4(saddr);
					if (sock >= 0) {
						sockets[num_sockets++] = sock;
						log_addr = 1;
					} else {
						log_addr = 0;
					}
				}
				if (log_addr) {
					char buffer[128];
					mdns_string_t addr = ipv4_address_to_string(buffer, sizeof(buffer), saddr,
																sizeof(struct sockaddr_in));
					printf("Local IPv4 address: %.*s\n", MDNS_STRING_FORMAT(addr));
				}
			} else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
				struct sockaddr_in6* saddr = (struct sockaddr_in6*)unicast->Address.lpSockaddr;
				static const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0,
														  0, 0, 0, 0, 0, 0, 0, 1};
				static const unsigned char localhost_mapped[] = {0, 0, 0,	0,	0,	0, 0, 0,
																 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
				if ((unicast->DadState == NldsPreferred) &&
					memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
					memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
					int log_addr = 1;
					new_intf->ipv6_addr = *saddr;
					//ConvertLengthToIpv4Mask(unicast->OnLinkPrefixLength, &new_intf->ipv6_mask);
					if (num_sockets < max_sockets) {
						int sock;
						saddr->sin6_port = htons((unsigned short)port);
						sock = mdns_socket_open_ipv6(saddr);
						if (sock >= 0) {
							sockets[num_sockets++] = sock;
							log_addr = 1;
						} else {
							log_addr = 0;
						}
					}
					if (log_addr) {
						char buffer[128];
						mdns_string_t addr = ipv6_address_to_string(buffer, sizeof(buffer), saddr,
																	sizeof(struct sockaddr_in6));
						printf("Local IPv6 address: %.*s\n", MDNS_STRING_FORMAT(addr));
					}
				}
			}
		}

		mdns_intf_append(service, new_intf);
	}

	free(adapter_address);

#else

	struct ifaddrs* ifaddr = 0;
	struct ifaddrs* ifa = 0;

	if (getifaddrs(&ifaddr) < 0)
		printf("Unable to get interface addresses\n");

	int first_ipv4 = 1;
	int first_ipv6 = 1;
	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;

		new_intf = (interface_t *)malloc(*new_intf);
		if (NULL == new_intf) {
			continue;
		}
		memset((void *)new_intf, 0x00, sizeof(*new_intf));
		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in* saddr = (struct sockaddr_in*)ifa->ifa_addr;
			int log_addr = 1;
			new_intf->ipv4_addr = *saddr;
			//ConvertLengthToIpv4Mask(unicast->OnLinkPrefixLength, service_mask_ipv4 + count_ipv4);
			if (num_sockets < max_sockets) {
				int sock;
				saddr->sin_port = htons(port);
				sock = mdns_socket_open_ipv4(saddr);
				if (sock >= 0) {
					sockets[num_sockets++] = sock;
					log_addr = 1;
				} else {
					log_addr = 0;
				}
			}
			if (log_addr) {
				char buffer[128];
				mdns_string_t addr = ipv4_address_to_string(buffer, sizeof(buffer), saddr,
															sizeof(struct sockaddr_in));
				printf("Local IPv4 address: %.*s\n", MDNS_STRING_FORMAT(addr));
			}
		} else if (ifa->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6* saddr = (struct sockaddr_in6*)ifa->ifa_addr;
			static const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0,
													  0, 0, 0, 0, 0, 0, 0, 1};
			static const unsigned char localhost_mapped[] = {0, 0, 0,	0,	0,	0, 0, 0,
															 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
			if (memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
				memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
				int log_addr = 1;
				new_intf->ipv6_addr = *saddr;
				//ConvertLengthToIpv4Mask(unicast->OnLinkPrefixLength, service_mask_ipv6 + count_ipv6);
				if (num_sockets < max_sockets) {
					int sock;
					saddr->sin6_port = htons(port);
					sock = mdns_socket_open_ipv6(saddr);
					if (sock >= 0) {
						sockets[num_sockets++] = sock;
						log_addr = 1;
					} else {
						log_addr = 0;
					}
				}
				if (log_addr) {
					char buffer[128];
					mdns_string_t addr = ipv6_address_to_string(buffer, sizeof(buffer), saddr,
																sizeof(struct sockaddr_in6));
					printf("Local IPv6 address: %.*s\n", MDNS_STRING_FORMAT(addr));
				}
			}
		}
	}

	freeifaddrs(ifaddr);

#endif

	return num_sockets;
}

// Open sockets to listen to incoming mDNS queries on port 5353
static int
open_service_sockets(service_t *service, int* sockets, int max_sockets) {
	// When recieving, each socket can recieve data from all network interfaces
	// Thus we only need to open one socket for each address family
	int num_sockets = 0;
	int sock;

	// Call the client socket function to enumerate and get local addresses,
	// but not open the actual sockets
	open_client_sockets(service, 0, 0, 0);

	if (num_sockets < max_sockets) {
		struct sockaddr_in sock_addr;
		memset(&sock_addr, 0, sizeof(struct sockaddr_in));
		sock_addr.sin_family = AF_INET;
#ifdef _WIN32
		sock_addr.sin_addr = in4addr_any;
#else
		sock_addr.sin_addr.s_addr = INADDR_ANY;
#endif
		sock_addr.sin_port = htons(MDNS_PORT);
#ifdef __APPLE__
		sock_addr.sin_len = sizeof(struct sockaddr_in);
#endif
		sock = mdns_socket_open_ipv4(&sock_addr);
		if (sock >= 0)
			sockets[num_sockets++] = sock;
	}

	if (num_sockets < max_sockets) {
		struct sockaddr_in6 sock_addr;
		memset(&sock_addr, 0, sizeof(struct sockaddr_in6));
		sock_addr.sin6_family = AF_INET6;
		sock_addr.sin6_addr = in6addr_any;
		sock_addr.sin6_port = htons(MDNS_PORT);
#ifdef __APPLE__
		sock_addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
		sock = mdns_socket_open_ipv6(&sock_addr);
		if (sock >= 0)
			sockets[num_sockets++] = sock;
	}

	return num_sockets;
}

// Send a DNS-SD query
static int mdns_discover(service_t *service) {
	int sockets[32];
	int num_sockets;
	int isock;
	int res;
	size_t records;
	size_t capacity = 2048;
	void* user_data = 0;
	void* buffer;
	num_sockets = open_client_sockets(service, sockets, sizeof(sockets) / sizeof(sockets[0]), 0);
	if (num_sockets <= 0) {
		printf("Failed to open any client sockets\n");
		return -1;
	}
	printf("Opened %d socket%s for DNS-SD\n", num_sockets, num_sockets ? "s" : "");

	printf("Sending DNS-SD discovery\n");
	for (isock = 0; isock < num_sockets; ++isock) {
		if (mdns_discovery_send(sockets[isock]))
			printf("Failed to send DNS-DS discovery: %s\n", strerror(errno));
	}

	buffer = malloc(capacity);

	// This is a simple implementation that loops for 5 seconds or as long as we get replies
	printf("Reading DNS-SD replies\n");
	do {
		struct timeval timeout;
		int nfds = 0;
		fd_set readfs;

		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		FD_ZERO(&readfs);
		for (isock = 0; isock < num_sockets; ++isock) {
			if (sockets[isock] >= nfds)
				nfds = sockets[isock] + 1;
			FD_SET(sockets[isock], &readfs);
		}

		records = 0;
		res = select(nfds, &readfs, 0, 0, &timeout);
		if (res > 0) {
			for (isock = 0; isock < num_sockets; ++isock) {
				if (FD_ISSET(sockets[isock], &readfs)) {
					records += mdns_discovery_recv(sockets[isock], buffer, capacity, query_callback,
												   user_data);
				}
			}
		}
	} while (res > 0);

	free(buffer);

	for (isock = 0; isock < num_sockets; ++isock)
		mdns_socket_close(sockets[isock]);
	printf("Closed socket%s\n", num_sockets ? "s" : "");

	return 0;
}

// Send a mDNS query
static int mdns_query(service_t *service, const char* name, int record) {
	int sockets[32];
	int query_id[32];
	int num_sockets;
	size_t capacity = 2048;
	const char* record_name = "PTR";
	void* buffer;
	void* user_data = 0;
	size_t records;
	int isock;
	int res;

	num_sockets = open_client_sockets(service, sockets, sizeof(sockets) / sizeof(sockets[0]), 0);
	if (num_sockets <= 0) {
		printf("Failed to open any client sockets\n");
		return -1;
	}
	printf("Opened %d socket%s for mDNS query\n", num_sockets, num_sockets ? "s" : "");

	buffer = malloc(capacity);

	if (record == MDNS_RECORDTYPE_SRV)
		record_name = "SRV";
	else if (record == MDNS_RECORDTYPE_A)
		record_name = "A";
	else if (record == MDNS_RECORDTYPE_AAAA)
		record_name = "AAAA";
	else
		record = MDNS_RECORDTYPE_PTR;

	printf("Sending mDNS query: %s %s\n", name, record_name);
	for (isock = 0; isock < num_sockets; ++isock) {
		query_id[isock] =
			mdns_query_send(sockets[isock], record, name, strlen(name), buffer, capacity, 0);
		if (query_id[isock] < 0)
			printf("Failed to send mDNS query: %s\n", strerror(errno));
	}

	// This is a simple implementation that loops for 5 seconds or as long as we get replies
	printf("Reading mDNS query replies\n");
	do {
		struct timeval timeout;
		int nfds = 0;
		fd_set readfs;

		timeout.tv_sec = 10;
		timeout.tv_usec = 0;
		FD_ZERO(&readfs);
		for (isock = 0; isock < num_sockets; ++isock) {
			if (sockets[isock] >= nfds)
				nfds = sockets[isock] + 1;
			FD_SET(sockets[isock], &readfs);
		}

		records = 0;
		res = select(nfds, &readfs, 0, 0, &timeout);
		if (res > 0) {
			for (isock = 0; isock < num_sockets; ++isock) {
				if (FD_ISSET(sockets[isock], &readfs)) {
					records += mdns_query_recv(sockets[isock], buffer, capacity, query_callback,
											   user_data, query_id[isock]);
				}
				FD_SET(sockets[isock], &readfs);
			}
		}
	} while (res > 0);

	free(buffer);

	for (isock = 0; isock < num_sockets; ++isock)
		mdns_socket_close(sockets[isock]);
	printf("Closed socket%s\n", num_sockets ? "s" : "");

	return 0;
}

// Provide a mDNS service, answering incoming DNS-SD and mDNS queries
static void mdns_service(void* param) {
	service_t *service = (service_t *)param;
	void* buffer;
	size_t capacity = 2048;
	int sockets[32];
	int isock;
	char service_instance_buffer[256] = {0};
	char qualified_hostname_buffer[256] = {0};
	int num_sockets = open_service_sockets(service, sockets, sizeof(sockets) / sizeof(sockets[0]));
	if (num_sockets <= 0) {
		printf("Failed to open any client sockets\n");
		return;
	}
	printf("Opened %d socket%s for mDNS service\n", num_sockets, num_sockets ? "s" : "");

	printf("Service mDNS: %.*s:%d\n", MDNS_STRING_FORMAT(service->service), service->port);
	printf("Hostname: %.*s\n", MDNS_STRING_FORMAT(service->hostname));

	buffer = malloc(capacity);

	// Build the service instance "<hostname>.<_service-name>._tcp.local." string
	snprintf(service_instance_buffer, sizeof(service_instance_buffer) - 1, "%.*s.%.*s",
			 MDNS_STRING_FORMAT(service->hostname), MDNS_STRING_FORMAT(service->service));

	// Build the "<hostname>.local." string
	snprintf(qualified_hostname_buffer, sizeof(qualified_hostname_buffer) - 1, "%.*s.local.",
			 MDNS_STRING_FORMAT(service->hostname));

	service->service_instance.str = service_instance_buffer;
	service->service_instance.length = strlen(service_instance_buffer);
	service->hostname_qualified.str = qualified_hostname_buffer;
	service->hostname_qualified.length = strlen(qualified_hostname_buffer);

	// Setup our mDNS records

	// PTR record reverse mapping "<_service-name>._tcp.local." to
	// "<hostname>.<_service-name>._tcp.local."
	service->record_ptr.name = service->service;
	service->record_ptr.type = MDNS_RECORDTYPE_PTR;
	service->record_ptr.data.ptr.name = service->service_instance;

	// SRV record mapping "<hostname>.<_service-name>._tcp.local." to
	// "<hostname>.local." with port. Set weight & priority to 0.
	service->record_srv.name = service->service_instance;
	service->record_srv.type = MDNS_RECORDTYPE_SRV;
	service->record_srv.data.srv.name = service->hostname_qualified;
	service->record_srv.data.srv.port = service->port;
	service->record_srv.data.srv.priority = 0;
	service->record_srv.data.srv.weight = 0;

	// A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
	service->record_a.name = service->hostname_qualified;
	service->record_a.type = MDNS_RECORDTYPE_A;
	//service->record_a.data.a.addr = service->address_ipv4;

	service->record_aaaa.name = service->hostname_qualified;
	service->record_aaaa.type = MDNS_RECORDTYPE_AAAA;
	//service->record_aaaa.data.aaaa.addr = service->address_ipv6;

	// Send an announcement on startup of service
#if (0)
	{
		mdns_record_t additional[5] = {0};
		size_t additional_count = 0;
		additional[additional_count++] = service->record_srv;
		if (service->address_ipv4.sin_family == AF_INET)
			additional[additional_count++] = service->record_a;
		if (service->address_ipv6.sin6_family == AF_INET6)
			additional[additional_count++] = service->record_aaaa;

		for (int isock = 0; isock < num_sockets; ++isock)
			mdns_announce_multicast(sockets[isock], buffer, capacity, service->record_ptr, 0, 0,
									additional, additional_count);
	}
#endif
	// This is a crude implementation that checks for incoming queries
	while (1) {
		int nfds = 0;
		fd_set readfs;
		FD_ZERO(&readfs);
		for (isock = 0; isock < num_sockets; ++isock) {
			if (sockets[isock] >= nfds)
				nfds = sockets[isock] + 1;
			FD_SET(sockets[isock], &readfs);
		}

		if (select(nfds, &readfs, 0, 0, 0) >= 0) {
			for (isock = 0; isock < num_sockets; ++isock) {
				if (FD_ISSET(sockets[isock], &readfs)) {
					mdns_socket_listen(sockets[isock], buffer, capacity, service_callback,
									   service);
				}
				FD_SET(sockets[isock], &readfs);
			}
		} else {
			break;
		}
	}

	free(buffer);

	for (isock = 0; isock < num_sockets; ++isock)
		mdns_socket_close(sockets[isock]);
	printf("Closed socket%s\n", num_sockets ? "s" : "");

	return;
}

#if defined(_WIN32)
typedef HANDLE slim_thread;

#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO {
	DWORD  dwType;	 // Must be 0x1000.
	LPCSTR szName;	 // Pointer to name (in user addr space).
	DWORD  dwThreadID; // Thread ID (-1=caller thread).
	DWORD  dwFlags;	// Reserved for future use, must be zero.
} THREADNAME_INFO;
#pragma pack(pop)

typedef struct slim_thread_info {
	uint8_t	 priority;
	const char *name;
	void (*function)(void *);
	void	   *arg;
	void	   *stack_ptr;
	uint32_t	stack_size;
} slim_thread_info;

int slim_thread_create(slim_thread *thread, slim_thread_info *info) {
	HANDLE		  hThread;
	unsigned		threadID;
	THREADNAME_INFO nameInfo;
	const DWORD	 MS_VC_EXCEPTION = 0x406D1388;

	hThread = (HANDLE)_beginthreadex(NULL, info->stack_size, (unsigned(__stdcall *)(void *))info->function, info->arg, 0, &threadID);
	if (NULL == hThread) {
		printf("create thread failed\n");
		return -1;
	}

	*thread = hThread;

	nameInfo.dwType	 = 0x1000;
	nameInfo.szName	 = info->name;
	nameInfo.dwThreadID = threadID;
	nameInfo.dwFlags	= 0;
	__try {
		RaiseException(MS_VC_EXCEPTION, 0, sizeof(nameInfo) / sizeof(ULONG_PTR), (ULONG_PTR *)&nameInfo);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return 0;
}

int slim_thread_startup(slim_thread *thread) {
	return 0;
}

int slim_thread_msleep(uint32_t milliseconds) {
	Sleep(milliseconds);

	return 0;
}

#endif

int main(int argc, char *argv[]) {
	struct timeval tv;
	fd_set read_set;
	int timeout_ms = 1000;
	int length;
	char buf[256];
	slim_thread_info thread_info;
	slim_thread	  tid;
	int			  result;
	int iarg;
	int mode = 0;
	char *svcbuffer;
	const char* svcname = "iot.local.";
	const char* hostname = "product";
	char *ptr;
	int query_record = MDNS_RECORDTYPE_PTR;
	int service_port = 63636;
	service_t service;
#ifdef _WIN32
	WORD versionWanted = MAKEWORD(1, 1);
	WSADATA wsaData;
#endif

	for (iarg = 1; iarg < argc; ++iarg) {
		if (strcmp(argv[iarg], "--discovery") == 0) {
			mode = 0;
		} else if (strcmp(argv[iarg], "--query") == 0) {
			mode = 1;
			++iarg;
			if (iarg < argc)
				svcname = argv[iarg++];
			if (iarg < argc) {
				const char* record_name = svcname;
				svcname = argv[iarg++];
				if (strcmp(record_name, "PTR") == 0)
					query_record = MDNS_RECORDTYPE_PTR;
				else if (strcmp(record_name, "SRV") == 0)
					query_record = MDNS_RECORDTYPE_SRV;
				else if (strcmp(record_name, "A") == 0)
					query_record = MDNS_RECORDTYPE_A;
				else if (strcmp(record_name, "AAAA") == 0)
					query_record = MDNS_RECORDTYPE_AAAA;
			}
		} else if (strcmp(argv[iarg], "--service") == 0) {
			mode = 2;
			++iarg;
			if (iarg < argc)
				svcname = argv[iarg];
		} else if (strcmp(argv[iarg], "--hostname") == 0) {
			++iarg;
			if (iarg < argc)
				hostname = argv[iarg];
		} else if (strcmp(argv[iarg], "--port") == 0) {
			++iarg;
			if (iarg < argc)
				service_port = atoi(argv[iarg]);
		} else {
			printf("usage %s option [parameter ...]\n", argv[0]);
			printf("option:\n");
			printf("\t--help						 show usage info\n");
			printf("\t--discovery					send dns service discovery\n");
			printf("\t--query host [A|AAAA|SRV|PTR]  send dns query with type\n");
			printf("\t--service [name]			   start mdns service with name\n");
			printf("parameter:\n");
			printf("\t--hostname name				host name\n");
			printf("\t--port number				  port number\n");
			return 0;
		}
	}

#ifdef _WIN32
	if (WSAStartup(versionWanted, &wsaData)) {
		printf("Failed to initialize WinSock\n");
		return -1;
	}
#endif

	memset((void *)&service, 0x00, sizeof(service));
	service.service.length = strlen(svcname);
	if (!service.service.length) {
		printf("Invalid service name\n");
		return -1;
	}

	svcbuffer = malloc(service.service.length + 2);
	memcpy(svcbuffer, svcname, service.service.length);
	if (svcbuffer[service.service.length - 1] != '.')
		svcbuffer[service.service.length++] = '.';
	svcbuffer[service.service.length] = 0;
	service.service.str = svcbuffer;

	service.hostname.str = hostname;
	service.hostname.length = strlen(hostname);
	service.port = service_port;

	if (mode == 0) {
		mdns_discover(&service);
	} else if (mode == 1) {
		mdns_query(&service, svcname, query_record);
	} else {
		memset((void *)&thread_info, 0x0, sizeof(thread_info));
		thread_info.priority   = 1;
		thread_info.name	   = "mdns";
		thread_info.function   = mdns_service;
		thread_info.arg		= (void *)&service;
		thread_info.stack_ptr  = NULL;
		thread_info.stack_size = 4096;
		result = slim_thread_create(&tid, &thread_info);

		if (result >= 0) {
			slim_thread_startup(&tid);
		}
	}

	while (1) {
		tv.tv_sec = timeout_ms / 1000;
		tv.tv_usec = (timeout_ms - tv.tv_sec * 1000) * 1000;

		FD_ZERO(&read_set);
		FD_SET(STDIN_FILENO, &read_set);

		select(STDIN_FILENO + 1, &read_set, NULL, NULL, &tv);
		if (!FD_ISSET(STDIN_FILENO, &read_set)) {
			continue;
		}
		length = read(STDIN_FILENO, buf, sizeof(buf) - 1);
		if (length <= 0) {
			continue;
		}
		buf[length] = '\0';
		if (0 == memcmp(buf, "exit", 4)) {
			break;
		} else if (0 == memcmp(buf, "help", 4)) {
			printf("query host\n");
			if (mode == 2) {
				printf("add   host\n");
			}
			printf("exit\n");
		} else if (0 == memcmp(buf, "add ", 4)) {
			if (mode != 2) {
				continue;
			}
			svcname = buf + 4;
			while ((' ' == *svcname) || ('\t' == *svcname) || ('\r' == *svcname)) {
				svcname++;
			}
			ptr = strpbrk(svcname, " \t\r\n");
			if (NULL != ptr) {
				*ptr = '\0';
			}
			printf("TODO add '%s'\n", svcname);
		} else if (0 == memcmp(buf, "query ", 6)) {
			svcname = buf + 6;
			while ((' ' == *svcname) || ('\t' == *svcname) || ('\r' == *svcname)) {
				svcname++;
			}
			ptr = strpbrk(svcname, " \t\r\n");
			if (NULL != ptr) {
				*ptr = '\0';
			}
			mdns_query(&service, svcname, MDNS_RECORDTYPE_A);
		}
	}
	
#ifdef _WIN32
	WSACleanup();
#endif

	return 0;
}

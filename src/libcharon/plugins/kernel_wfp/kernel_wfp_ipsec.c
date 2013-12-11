/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/* Windows 7, for some fwpmu.h functionality */
#define _WIN32_WINNT 0x0601

#include "kernel_wfp_compat.h"
#include "kernel_wfp_ipsec.h"

#include <daemon.h>
#include <hydra.h>
#include <threading/mutex.h>
#include <collections/array.h>
#include <collections/hashtable.h>
#include <processing/jobs/callback_job.h>


typedef struct private_kernel_wfp_ipsec_t private_kernel_wfp_ipsec_t;

struct private_kernel_wfp_ipsec_t {

	/**
	 * Public interface
	 */
	kernel_wfp_ipsec_t public;

	/**
	 * Next SPI to allocate
	 */
	refcount_t nextspi;

	/**
	 * Temporary SAD/SPD entries referenced reqid, as uintptr_t => entry_t
	 */
	hashtable_t *tsas;

	/**
	 * SAD/SPD entries referenced by inbound SA, as sa_entry_t => entry_t
	 */
	hashtable_t *isas;

	/**
	 * SAD/SPD entries referenced by outbound SA, as sa_entry_t => entry_t
	 */
	hashtable_t *osas;

	/**
	 * Mutex for accessing entries
	 */
	mutex_t *mutex;

	/**
	 * WFP session handle
	 */
	HANDLE handle;

	/**
	 * Provider charon registers as
	 */
	FWPM_PROVIDER0 provider;
};

/**
 * Security association entry
 */
typedef struct {
	/** SPI for this SA */
	u_int32_t spi;
	/** protocol, IPPROTO_ESP/IPPROTO_AH */
	u_int8_t protocol;
	/** hard lifetime of SA */
	u_int32_t lifetime;
	/** destination host address for this SPI */
	host_t *dst;
	struct {
		/** algorithm */
		u_int16_t alg;
		/** key */
		chunk_t key;
	} integ, encr;
} sa_entry_t;

/**
 * Hash function for sas lookup table
 */
static u_int hash_sa(sa_entry_t *key)
{
	return chunk_hash_inc(chunk_from_thing(key->spi),
						  chunk_hash(key->dst->get_address(key->dst)));
}

/**
 * equals function for sas lookup table
 */
static bool equals_sa(sa_entry_t *a, sa_entry_t *b)
{
	return a->spi == b->spi && a->dst->ip_equals(a->dst, b->dst);
}

/**
 * Security policy entry
 */
typedef struct {
	/** policy source addresses */
	traffic_selector_t *src;
	/** policy destinaiton addresses */
	traffic_selector_t *dst;
} sp_entry_t;

/**
 * Destroy an SP entry
 */
static void sp_entry_destroy(sp_entry_t *sp)
{
	sp->src->destroy(sp->src);
	sp->dst->destroy(sp->dst);
	free(sp);
}

/**
 * Collection of SA/SP database entries for a reqid
 */
typedef struct {
	/** reqid of entry */
	u_int32_t reqid;
	/** outer address on local host */
	host_t *local;
	/** outer address on remote host */
	host_t *remote;
	/** inbound SA entry */
	sa_entry_t isa;
	/** outbound SA entry */
	sa_entry_t osa;
	/** associated (outbound) policies, as sp_entry_t* */
	array_t *sps;
	/** IPsec mode, tunnel|transport */
	ipsec_mode_t mode;
	/** UDP encapsulation */
	bool encap;
	/** WFP allocated LUID for inbound filter/tunnel policy ID */
	u_int64_t policy_in;
	/** WFP allocated LUID for outbound filter ID, unused for tunnel mode */
	u_int64_t policy_out;
	/** WFP allocated LUID for SA context */
	u_int64_t sa_id;
} entry_t;

/**
 * Remove a transport or tunnel policy from kernel
 */
static void cleanup_policy(private_kernel_wfp_ipsec_t *this, bool transport,
						   u_int64_t policy)
{
	if (transport)
	{
		FwpmFilterDeleteById0(this->handle, policy);
	}
	else
	{
		FWPM_PROVIDER_CONTEXT0 *ctx;

		if (FwpmProviderContextGetById0(this->handle, policy,
										&ctx) == ERROR_SUCCESS)
		{
			FwpmIPsecTunnelDeleteByKey0(this->handle, &ctx->providerContextKey);
			FwpmFreeMemory0((void**)&ctx);
		}
	}
}

/**
 * Remove policies associated to an entry from kernel
 */
static void cleanup_policies(private_kernel_wfp_ipsec_t *this, entry_t *entry)
{
	if (entry->policy_in)
	{
		cleanup_policy(this, entry->mode == MODE_TRANSPORT, entry->policy_in);
		entry->policy_in = 0;
	}
	if (entry->policy_out)
	{
		cleanup_policy(this, entry->mode == MODE_TRANSPORT, entry->policy_out);
		entry->policy_out = 0;
	}
}

/**
 * Destroy a SA/SP entry set
 */
static void entry_destroy(private_kernel_wfp_ipsec_t *this, entry_t *entry)
{
	if (entry->sa_id)
	{
		IPsecSaContextDeleteById0(this->handle, entry->sa_id);
	}
	cleanup_policies(this, entry);
	array_destroy_function(entry->sps, (void*)sp_entry_destroy, NULL);
	entry->local->destroy(entry->local);
	entry->remote->destroy(entry->remote);
	chunk_clear(&entry->isa.integ.key);
	chunk_clear(&entry->isa.encr.key);
	chunk_clear(&entry->osa.integ.key);
	chunk_clear(&entry->osa.encr.key);
	free(entry);
}

/**
 * Append/Realloc a filter condition to an existing condition set
 */
static FWPM_FILTER_CONDITION0 *append_condition(FWPM_FILTER_CONDITION0 *conds[],
												int *count)
{
	FWPM_FILTER_CONDITION0 *cond;

	(*count)++;
	*conds = realloc(*conds, *count * sizeof(*cond));
	cond = *conds + *count - 1;
	memset(cond, 0, sizeof(*cond));

	return cond;
}

/**
 * Convert an IPv4 prefix to a host order subnet mask
 */
static u_int32_t prefix2mask(u_int8_t prefix)
{
	u_int8_t netmask[4] = {};
	int i;

	for (i = 0; i < sizeof(netmask); i++)
	{
		if (prefix < 8)
		{
			netmask[i] = 0xFF << (8 - prefix);
			break;
		}
		netmask[i] = 0xFF;
		prefix -= 8;
	}
	return untoh32(netmask);
}

/**
 * Convert a 16-bit range to a WFP condition
 */
static void range2cond(FWPM_FILTER_CONDITION0 *cond,
					   u_int16_t from, u_int16_t to)
{
	if (from == to)
	{
		cond->matchType = FWP_MATCH_EQUAL;
		cond->conditionValue.type = FWP_UINT16;
		cond->conditionValue.uint16 = from;
	}
	else
	{
		cond->matchType = FWP_MATCH_RANGE;
		cond->conditionValue.type = FWP_RANGE_TYPE;
		cond->conditionValue.rangeValue = calloc(1, sizeof(FWP_RANGE0));
		cond->conditionValue.rangeValue->valueLow.type = FWP_UINT16;
		cond->conditionValue.rangeValue->valueLow.uint16 = from;
		cond->conditionValue.rangeValue->valueHigh.type = FWP_UINT16;
		cond->conditionValue.rangeValue->valueHigh.uint16 = to;
	}
}

/**
 * (Re-)allocate filter conditions for given local or remote traffic selector
 */
static bool ts2condition(traffic_selector_t *ts, bool local,
						 FWPM_FILTER_CONDITION0 *conds[], int *count)
{
	FWPM_FILTER_CONDITION0 *cond;
	FWP_BYTE_ARRAY16 *addr;
	FWP_RANGE0 *range;
	u_int16_t from_port, to_port;
	void *from, *to;
	u_int8_t proto;
	host_t *net;
	u_int8_t prefix;

	from = ts->get_from_address(ts).ptr;
	to = ts->get_to_address(ts).ptr;
	from_port = ts->get_from_port(ts);
	to_port = ts->get_to_port(ts);

	cond = append_condition(conds, count);
	if (local)
	{
		cond->fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
	}
	else
	{
		cond->fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	}
	if (ts->is_host(ts, NULL))
	{
		cond->matchType = FWP_MATCH_EQUAL;
		switch (ts->get_type(ts))
		{
			case TS_IPV4_ADDR_RANGE:
				cond->conditionValue.type = FWP_UINT32;
				cond->conditionValue.uint32 = untoh32(from);
				break;
			case TS_IPV6_ADDR_RANGE:
				cond->conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
				cond->conditionValue.byteArray16 = addr = malloc(sizeof(*addr));
				memcpy(addr, from, sizeof(*addr));
				break;
			default:
				return FALSE;
		}
	}
	else if (ts->to_subnet(ts, &net, &prefix))
	{
		FWP_V6_ADDR_AND_MASK *m6;
		FWP_V4_ADDR_AND_MASK *m4;

		cond->matchType = FWP_MATCH_EQUAL;
		switch (net->get_family(net))
		{
			case AF_INET:
				cond->conditionValue.type = FWP_V4_ADDR_MASK;
				cond->conditionValue.v4AddrMask = m4 = calloc(1, sizeof(*m4));
				m4->addr = untoh32(from);
				m4->mask = prefix2mask(prefix);
				break;
			case AF_INET6:
				cond->conditionValue.type = FWP_V6_ADDR_MASK;
				cond->conditionValue.v6AddrMask = m6 = calloc(1, sizeof(*m6));
				memcpy(m6->addr, from, sizeof(m6->addr));
				m6->prefixLength = prefix;
				break;
			default:
				net->destroy(net);
				return FALSE;
		}
		net->destroy(net);
	}
	else
	{
		cond->matchType = FWP_MATCH_RANGE;
		cond->conditionValue.type = FWP_RANGE_TYPE;
		cond->conditionValue.rangeValue = range = calloc(1, sizeof(*range));
		switch (ts->get_type(ts))
		{
			case TS_IPV4_ADDR_RANGE:
				range->valueLow.type = FWP_UINT32;
				range->valueLow.uint32 = untoh32(from);
				range->valueHigh.type = FWP_UINT32;
				range->valueHigh.uint32 = untoh32(to);
				break;
			case TS_IPV6_ADDR_RANGE:
				range->valueLow.type = FWP_BYTE_ARRAY16_TYPE;
				range->valueLow.byteArray16 = addr = malloc(sizeof(*addr));
				memcpy(addr, from, sizeof(*addr));
				range->valueHigh.type = FWP_BYTE_ARRAY16_TYPE;
				range->valueHigh.byteArray16 = addr = malloc(sizeof(*addr));
				memcpy(addr, to, sizeof(*addr));
				break;
			default:
				return FALSE;
		}
	}

	proto = ts->get_protocol(ts);
	if (proto && local)
	{
		cond = append_condition(conds, count);
		cond->fieldKey = FWPM_CONDITION_IP_PROTOCOL;
		cond->matchType = FWP_MATCH_EQUAL;
		cond->conditionValue.type = FWP_UINT8;
		cond->conditionValue.uint8 = proto;
	}

	if (proto == IPPROTO_ICMP)
	{
		if (local)
		{
			u_int8_t from_type, to_type, from_code, to_code;

			from_type = traffic_selector_icmp_type(from_port);
			to_type = traffic_selector_icmp_type(to_port);
			from_code = traffic_selector_icmp_code(from_port);
			to_code = traffic_selector_icmp_code(to_port);

			if (from_type != 0 || to_type != 0xFF)
			{
				cond = append_condition(conds, count);
				cond->fieldKey = FWPM_CONDITION_ICMP_TYPE;
				range2cond(cond, from_type, to_type);
			}
			if (from_code != 0 || to_code != 0xFF)
			{
				cond = append_condition(conds, count);
				cond->fieldKey = FWPM_CONDITION_ICMP_CODE;
				range2cond(cond, from_code, to_code);
			}
		}
	}
	else if (from_port != 0 || to_port != 0xFFFF)
	{
		cond = append_condition(conds, count);
		if (local)
		{
			cond->fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
		}
		else
		{
			cond->fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
		}
		range2cond(cond, from_port, to_port);
	}
	return TRUE;
}

/**
 * Free memory associated to a single condition
 */
static void free_condition(FWP_DATA_TYPE type, void *value)
{
	FWP_RANGE0 *range;

	switch (type)
	{
		case FWP_BYTE_ARRAY16_TYPE:
		case FWP_V4_ADDR_MASK:
		case FWP_V6_ADDR_MASK:
			free(value);
			break;
		case FWP_RANGE_TYPE:
			range = value;
			free_condition(range->valueLow.type, range->valueLow.sd);
			free_condition(range->valueHigh.type, range->valueHigh.sd);
			free(range);
			break;
		default:
			break;
	}
}

/**
 * Free memory used by a set of conditions
 */
static void free_conditions(FWPM_FILTER_CONDITION0 *conds, int count)
{
	int i;

	for (i = 0; i < count; i++)
	{
		free_condition(conds[i].conditionValue.type, conds[i].conditionValue.sd);
	}
	free(conds);
}

/**
 * Install transport mode SP to the kernel
 */
static bool install_transport_sp(private_kernel_wfp_ipsec_t *this,
								 entry_t *entry, bool inbound)
{
	FWPM_FILTER_CONDITION0 *conds = NULL;
	int count = 0;
	enumerator_t *enumerator;
	traffic_selector_t *local, *remote;
	sp_entry_t *sp;
	DWORD res;
	FWPM_FILTER0 filter = {
		.displayData = {
			.name = L"charon IPsec transport",
		},
		.action = {
			.type = FWP_ACTION_CALLOUT_TERMINATING,
			.calloutKey = inbound ? FWPM_CALLOUT_IPSEC_INBOUND_TRANSPORT_V4 :
									FWPM_CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V4,
		},
		.layerKey = inbound ? FWPM_LAYER_INBOUND_TRANSPORT_V4 :
							  FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
	};

	enumerator = array_create_enumerator(entry->sps);
	while (enumerator->enumerate(enumerator, &sp))
	{
		if (inbound)
		{
			local = sp->dst;
			remote = sp->src;
		}
		else
		{
			local = sp->src;
			remote = sp->dst;
		}

		if (!ts2condition(local, TRUE, &conds, &count) ||
			!ts2condition(remote, FALSE, &conds, &count))
		{
			free_conditions(conds, count);
			enumerator->destroy(enumerator);
			return FALSE;
		}
	}
	enumerator->destroy(enumerator);

	filter.numFilterConditions = count;
	filter.filterCondition = conds;

	if (inbound)
	{
		res = FwpmFilterAdd0(this->handle, &filter, NULL, &entry->policy_in);
	}
	else
	{
		res = FwpmFilterAdd0(this->handle, &filter, NULL, &entry->policy_out);
	}
	free_conditions(conds, count);
	if (res != ERROR_SUCCESS)
	{
		DBG1(DBG_KNL, "installing inbound FWP filter failed: 0x%08x", res);
		return FALSE;
	}
	return TRUE;
}

/**
 * Convert a chunk_t to a WFP FWP_BYTE_BLOB
 */
static inline FWP_BYTE_BLOB chunk2blob(chunk_t chunk)
{
	return (FWP_BYTE_BLOB){
		.size = chunk.len,
		.data = chunk.ptr,
	};
}

/**
 * Convert an integrity_algorithm_t to a WFP IPSEC_AUTH_TRANFORM_ID0
 */
static bool alg2auth(integrity_algorithm_t alg,
					 IPSEC_SA_AUTH_INFORMATION0 *info)
{
	struct {
		integrity_algorithm_t alg;
		IPSEC_AUTH_TRANSFORM_ID0 transform;
	} map[] = {
		{ AUTH_HMAC_MD5_96,			IPSEC_AUTH_TRANSFORM_ID_HMAC_MD5_96		},
		{ AUTH_HMAC_SHA1_96,		IPSEC_AUTH_TRANSFORM_ID_HMAC_SHA_1_96	},
		{ AUTH_HMAC_SHA2_256_128,	IPSEC_AUTH_TRANSFORM_ID_HMAC_SHA_256_128},
		{ AUTH_AES_128_GMAC,		IPSEC_AUTH_TRANSFORM_ID_GCM_AES_128		},
		{ AUTH_AES_192_GMAC,		IPSEC_AUTH_TRANSFORM_ID_GCM_AES_192		},
		{ AUTH_AES_256_GMAC,		IPSEC_AUTH_TRANSFORM_ID_GCM_AES_256		},
	};
	int i;

	for (i = 0; i < countof(map); i++)
	{
		if (map[i].alg == alg)
		{
			info->authTransform.authTransformId = map[i].transform;
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Convert an encryption_algorithm_t to a WFP IPSEC_CIPHER_TRANFORM_ID0
 */
static bool alg2cipher(encryption_algorithm_t alg, int keylen,
					   IPSEC_SA_CIPHER_INFORMATION0 *info)
{
	struct {
		encryption_algorithm_t alg;
		int keylen;
		IPSEC_CIPHER_TRANSFORM_ID0 transform;
	} map[] = {
		{ ENCR_DES,				 8, IPSEC_CIPHER_TRANSFORM_ID_CBC_DES		},
		{ ENCR_3DES,			24, IPSEC_CIPHER_TRANSFORM_ID_CBC_3DES		},
		{ ENCR_AES_CBC,			16, IPSEC_CIPHER_TRANSFORM_ID_AES_128		},
		{ ENCR_AES_CBC,			24, IPSEC_CIPHER_TRANSFORM_ID_AES_192		},
		{ ENCR_AES_CBC,			32, IPSEC_CIPHER_TRANSFORM_ID_AES_256		},
		{ ENCR_AES_GCM_ICV16,	20, IPSEC_CIPHER_TRANSFORM_ID_GCM_AES_128	},
		{ ENCR_AES_GCM_ICV16,	28, IPSEC_CIPHER_TRANSFORM_ID_GCM_AES_192	},
		{ ENCR_AES_GCM_ICV16,	36, IPSEC_CIPHER_TRANSFORM_ID_GCM_AES_256	},
	};
	int i;

	for (i = 0; i < countof(map); i++)
	{
		if (map[i].alg == alg && map[i].keylen == keylen)
		{
			info->cipherTransform.cipherTransformId = map[i].transform;
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Get the integrity algorithm used for an AEAD transform
 */
static integrity_algorithm_t encr2integ(encryption_algorithm_t encr, int keylen)
{
	struct {
		encryption_algorithm_t encr;
		int keylen;
		integrity_algorithm_t integ;
	} map[] = {
		{ ENCR_NULL_AUTH_AES_GMAC,		20, AUTH_AES_128_GMAC				},
		{ ENCR_NULL_AUTH_AES_GMAC,		28, AUTH_AES_192_GMAC				},
		{ ENCR_NULL_AUTH_AES_GMAC,		36, AUTH_AES_256_GMAC				},
		{ ENCR_AES_GCM_ICV16,			20, AUTH_AES_128_GMAC				},
		{ ENCR_AES_GCM_ICV16,			28, AUTH_AES_192_GMAC				},
		{ ENCR_AES_GCM_ICV16,			36, AUTH_AES_256_GMAC				},
	};
	int i;

	for (i = 0; i < countof(map); i++)
	{
		if (map[i].encr == encr && map[i].keylen == keylen)
		{
			return map[i].integ;
		}
	}
	return AUTH_UNDEFINED;
}

/**
 * Install a single SA
 */
static bool install_sa(private_kernel_wfp_ipsec_t *this, entry_t *entry,
					   bool inbound, sa_entry_t *sa, FWP_IP_VERSION version)
{
	IPSEC_SA_AUTH_AND_CIPHER_INFORMATION0 info = {};
	IPSEC_SA0 ipsec = {
		.spi = ntohl(sa->spi),
	};
	IPSEC_SA_BUNDLE0 bundle = {
		.lifetime = {
			.lifetimeSeconds = inbound ? entry->isa.lifetime
									   : entry->osa.lifetime,
		},
		.saList = &ipsec,
		.numSAs = 1,
		.ipVersion = version,
	};
	struct {
		u_int16_t alg;
		chunk_t key;
	} integ = {}, encr = {};
	DWORD res;

	switch (sa->protocol)
	{
		case IPPROTO_AH:
			ipsec.saTransformType = IPSEC_TRANSFORM_AH;
			ipsec.ahInformation = &info.saAuthInformation;
			integ.key = sa->integ.key;
			integ.alg = sa->integ.alg;
			break;
		case IPPROTO_ESP:
			if (sa->encr.alg == ENCR_NULL ||
				sa->encr.alg == ENCR_NULL_AUTH_AES_GMAC)
			{
				ipsec.saTransformType = IPSEC_TRANSFORM_ESP_AUTH;
				ipsec.espAuthInformation = &info.saAuthInformation;
			}
			else
			{
				ipsec.saTransformType = IPSEC_TRANSFORM_ESP_AUTH_AND_CIPHER;
				ipsec.espAuthAndCipherInformation = &info;
				encr.key = sa->encr.key;
				encr.alg = sa->encr.alg;
			}
			if (encryption_algorithm_is_aead(sa->encr.alg))
			{
				integ.alg = encr2integ(sa->encr.alg, sa->encr.key.len);
				integ.key = sa->encr.key;
			}
			else
			{
				integ.alg = sa->integ.alg;
				integ.key = sa->integ.key;
			}
			break;
		default:
			return FALSE;
	}

	if (integ.alg)
	{
		info.saAuthInformation.authKey = chunk2blob(integ.key);
		if (!alg2auth(integ.alg, &info.saAuthInformation))
		{
			DBG1(DBG_KNL, "integrity algorithm %N not supported by WFP",
				 integrity_algorithm_names, integ.alg);
			return FALSE;
		}
	}
	if (encr.alg)
	{
		info.saCipherInformation.cipherKey = chunk2blob(encr.key);
		if (!alg2cipher(encr.alg, encr.key.len, &info.saCipherInformation))
		{
			DBG1(DBG_KNL, "encryption algorithm %N not supported by WFP",
				 encryption_algorithm_names, encr.alg);
			return FALSE;
		}
	}

	if (inbound)
	{
		res = IPsecSaContextAddInbound0(this->handle, entry->sa_id, &bundle);
	}
	else
	{
		res = IPsecSaContextAddOutbound0(this->handle, entry->sa_id, &bundle);
	}
	if (res != ERROR_SUCCESS)
	{
		DBG1(DBG_KNL, "adding %sbound WFP SA failed: 0x%08x",
			 inbound ? "in" : "out", res);
		return FALSE;
	}
	return TRUE;
}

/**
 * Install SAs to the kernel
 */
static bool install_sas(private_kernel_wfp_ipsec_t *this, entry_t *entry,
						IPSEC_TRAFFIC_TYPE type)
{
	IPSEC_TRAFFIC0 traffic = {
		.trafficType = type,
	};
	IPSEC_GETSPI1 spi = {
		.inboundIpsecTraffic = {
			.trafficType = type,
		},
	};
	DWORD res;

	if (type == IPSEC_TRAFFIC_TYPE_TRANSPORT)
	{
		traffic.ipsecFilterId = entry->policy_out;
		spi.inboundIpsecTraffic.ipsecFilterId = entry->policy_in;
	}
	else
	{
		traffic.tunnelPolicyId = entry->policy_in;
		spi.inboundIpsecTraffic.tunnelPolicyId = entry->policy_in;
	}

	switch (entry->local->get_family(entry->local))
	{
		case AF_INET:
			traffic.ipVersion = FWP_IP_VERSION_V4;
			traffic.localV4Address =
						untoh32(entry->local->get_address(entry->local).ptr);
			traffic.remoteV4Address =
						untoh32(entry->remote->get_address(entry->remote).ptr);
			break;
		case AF_INET6:
			traffic.ipVersion = FWP_IP_VERSION_V6;
			memcpy(&traffic.localV6Address,
				   entry->local->get_address(entry->local).ptr, 16);
			memcpy(&traffic.remoteV6Address,
				   entry->remote->get_address(entry->remote).ptr, 16);
			break;
		default:
			return FALSE;
	}

	res = IPsecSaContextCreate0(this->handle, &traffic, NULL, &entry->sa_id);
	if (res != ERROR_SUCCESS)
	{
		DBG1(DBG_KNL, "creating WFP SA context failed: 0x%08x", res);
		return FALSE;
	}

	memcpy(spi.inboundIpsecTraffic.localV6Address, traffic.localV6Address,
		   sizeof(traffic.localV6Address));
	memcpy(spi.inboundIpsecTraffic.remoteV6Address, traffic.remoteV6Address,
		   sizeof(traffic.remoteV6Address));
	spi.ipVersion = traffic.ipVersion;

	res = IPsecSaContextSetSpi0(this->handle, entry->sa_id, &spi,
								ntohl(entry->isa.spi));
	if (res != ERROR_SUCCESS)
	{
		DBG1(DBG_KNL, "setting WFP SA SPI failed: 0x%08x", res);
		IPsecSaContextDeleteById0(this->handle, entry->sa_id);
		entry->sa_id = 0;
		return FALSE;
	}

	if (!install_sa(this, entry, TRUE, &entry->isa, spi.ipVersion) ||
		!install_sa(this, entry, FALSE, &entry->osa, spi.ipVersion))
	{
		IPsecSaContextDeleteById0(this->handle, entry->sa_id);
		entry->sa_id = 0;
		return FALSE;
	}

	return TRUE;
}

/**
 * Install a transport mode SA/SP set to the kernel
 */
static bool install_transport(private_kernel_wfp_ipsec_t *this, entry_t *entry)
{
	if (install_transport_sp(this, entry, TRUE) &&
		install_transport_sp(this, entry, FALSE) &&
		install_sas(this, entry, IPSEC_TRAFFIC_TYPE_TRANSPORT))
	{
		return TRUE;
	}
	cleanup_policies(this, entry);
	return FALSE;
}

/**
 * Generate a new GUID, random
 */
static bool generate_guid(private_kernel_wfp_ipsec_t *this, GUID *guid)
{
	bool ok;
	rng_t *rng;

	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		return FALSE;
	}
	ok = rng->get_bytes(rng, sizeof(GUID), (u_int8_t*)guid);
	rng->destroy(rng);
	return ok;
}

/**
 * Install tunnel mode SPs to the kernel
 */
static bool install_tunnel_sps(private_kernel_wfp_ipsec_t *this, entry_t *entry)
{
	FWPM_FILTER_CONDITION0 *conds = NULL;
	int count = 0;
	enumerator_t *enumerator;
	sp_entry_t *sp;
	DWORD res;

	IPSEC_AUTH_TRANSFORM0 transform = {
		/* Create any valid proposal. This is actually not used, as we
		 * don't create an SA from this information. */
		.authTransformId = IPSEC_AUTH_TRANSFORM_ID_HMAC_SHA_1_96,
	};
	IPSEC_SA_TRANSFORM0 transforms = {
		.ipsecTransformType = IPSEC_TRANSFORM_ESP_AUTH,
		.espAuthTransform = &transform,
	};
	IPSEC_PROPOSAL0 proposal = {
		.lifetime = {
			/* We need a valid lifetime, even if we don't create any SA
			 * from these values. Pick some values accepted. */
			.lifetimeSeconds = 0xFFFF,
			.lifetimeKilobytes = 0xFFFFFFFF,
			.lifetimePackets = 0xFFFFFFFF,
		},
		.numSaTransforms = 1,
		.saTransforms = &transforms,
	};
	IPSEC_TUNNEL_POLICY0 policy = {
		.numIpsecProposals = 1,
		.ipsecProposals = &proposal,
		.saIdleTimeout = {
			/* not used, set to lifetime for maximum */
			.idleTimeoutSeconds = proposal.lifetime.lifetimeSeconds,
			.idleTimeoutSecondsFailOver = proposal.lifetime.lifetimeSeconds,
		},
	};
	FWPM_PROVIDER_CONTEXT0 *ctx, qm = {
		.displayData = {
			.name = L"charon tunnel provider context",
		},
		.providerKey = (GUID*)&this->provider.providerKey,
		.type = FWPM_IPSEC_IKE_QM_TUNNEL_CONTEXT,
		.ikeQmTunnelPolicy = &policy,
	};

	switch (entry->local->get_family(entry->local))
	{
		case AF_INET:
			policy.tunnelEndpoints.ipVersion = FWP_IP_VERSION_V4;
			policy.tunnelEndpoints.localV4Address =
						untoh32(entry->local->get_address(entry->local).ptr);
			policy.tunnelEndpoints.remoteV4Address =
						untoh32(entry->remote->get_address(entry->remote).ptr);
			break;
		case AF_INET6:
			policy.tunnelEndpoints.ipVersion = FWP_IP_VERSION_V6;
			memcpy(&policy.tunnelEndpoints.localV6Address,
				   entry->local->get_address(entry->local).ptr, 16);
			memcpy(&policy.tunnelEndpoints.remoteV6Address,
				   entry->remote->get_address(entry->remote).ptr, 16);
			break;
		default:
			return FALSE;
	}

	if (!generate_guid(this, &qm.providerContextKey))
	{
		return FALSE;
	}

	enumerator = array_create_enumerator(entry->sps);
	while (enumerator->enumerate(enumerator, &sp))
	{
		if (!ts2condition(sp->src, TRUE, &conds, &count) ||
			!ts2condition(sp->dst, FALSE, &conds, &count))
		{
			free_conditions(conds, count);
			enumerator->destroy(enumerator);
			return FALSE;
		}
	}
	enumerator->destroy(enumerator);

	res = FwpmIPsecTunnelAdd0(this->handle, 0, NULL, &qm, count, conds, NULL);
	free_conditions(conds, count);
	if (res != ERROR_SUCCESS)
	{
		DBG1(DBG_KNL, "installing FWP tunnel policy failed: 0x%08x", res);
		return FALSE;
	}

	/* to get the tunnelPolicyId LUID we have to query the context */
	res = FwpmProviderContextGetByKey0(this->handle, &qm.providerContextKey,
									   &ctx);
	if (res != ERROR_SUCCESS)
	{
		DBG1(DBG_KNL, "getting FWP tunnel policy context failed: 0x%08x", res);
		return FALSE;
	}
	entry->policy_in = ctx->providerContextId;
	FwpmFreeMemory0((void**)&ctx);

	return TRUE;
}

/**
 * Install a tunnel mode SA/SP set to the kernel
 */
static bool install_tunnel(private_kernel_wfp_ipsec_t *this, entry_t *entry)
{
	if (install_tunnel_sps(this, entry) &&
		install_sas(this, entry, IPSEC_TRAFFIC_TYPE_TUNNEL))
	{
		return TRUE;
	}
	cleanup_policies(this, entry);
	return FALSE;
}

/**
 * Install a SA/SP set to the kernel
 */
static bool install(private_kernel_wfp_ipsec_t *this, entry_t *entry)
{
	switch (entry->mode)
	{
		case MODE_TRANSPORT:
			return install_transport(this, entry);
		case MODE_TUNNEL:
			return install_tunnel(this, entry);
		case MODE_BEET:
		default:
			return FALSE;
	}
}

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
	private_kernel_wfp_ipsec_t *this)
{
	return KERNEL_ESP_V3_TFC;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	u_int8_t protocol, u_int32_t reqid, u_int32_t *spi)
{
	*spi = ref_get(&this->nextspi);
	return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t reqid, u_int16_t *cpi)
{
	return NOT_SUPPORTED;
}

/**
 * Data for an expire callback job
 */
typedef struct {
	/* backref to kernel backend */
	private_kernel_wfp_ipsec_t *this;
	/* SPI of expiring SA */
	u_int32_t spi;
	/* destination address of expiring SA */
	host_t *dst;
	/* is this a hard expire, or a rekey request? */
	bool hard;
} expire_data_t;

/**
 * Clean up expire data
 */
static void expire_data_destroy(expire_data_t *data)
{
	data->dst->destroy(data->dst);
	free(data);
}

/**
 * Callback job for SA expiration
 */
static job_requeue_t expire_job(expire_data_t *data)
{
	private_kernel_wfp_ipsec_t *this = data->this;
	u_int32_t reqid = 0;
	u_int8_t protocol;
	entry_t *entry;
	sa_entry_t key = {
		.spi = data->spi,
		.dst = data->dst,
	};

	if (data->hard)
	{
		this->mutex->lock(this->mutex);
		entry = this->isas->remove(this->isas, &key);
		this->mutex->unlock(this->mutex);
		if (entry)
		{
			protocol = entry->isa.protocol;
			reqid = entry->reqid;
			if (entry->osa.dst)
			{
				key.dst = entry->osa.dst;
				key.spi = entry->osa.spi;
				this->osas->remove(this->osas, &key);
			}
			entry_destroy(this, entry);
		}
	}
	else
	{
		this->mutex->lock(this->mutex);
		entry = this->isas->get(this->isas, &key);
		if (entry)
		{
			protocol = entry->isa.protocol;
			reqid = entry->reqid;
		}
		this->mutex->unlock(this->mutex);
	}

	if (reqid)
	{
		hydra->kernel_interface->expire(hydra->kernel_interface,
										reqid, protocol, data->spi, data->hard);
	}

	return JOB_REQUEUE_NONE;
}

/**
 * Schedule an expire event for an SA
 */
static void schedule_expire(private_kernel_wfp_ipsec_t *this, u_int32_t spi,
							host_t *dst, u_int32_t lifetime, bool hard)
{
	expire_data_t *data;

	INIT(data,
		.this = this,
		.spi = spi,
		.dst = dst->clone(dst),
		.hard = hard,
	);

	lib->scheduler->schedule_job(lib->scheduler, (job_t*)
						callback_job_create((void*)expire_job, data,
											(void*)expire_data_destroy, NULL),
						lifetime);
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int32_t reqid, mark_t mark,
	u_int32_t tfc, lifetime_cfg_t *lifetime, u_int16_t enc_alg, chunk_t enc_key,
	u_int16_t int_alg, chunk_t int_key, ipsec_mode_t mode, u_int16_t ipcomp,
	u_int16_t cpi, bool initiator, bool encap, bool esn, bool inbound,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts)
{
	host_t *local, *remote;
	entry_t *entry;

	if (inbound)
	{
		/* comes first, create new entry */
		local = dst->clone(dst);
		remote = src->clone(src);

		INIT(entry,
			.reqid = reqid,
			.isa = {
				.spi = spi,
				.dst = local,
				.protocol = protocol,
				.lifetime = lifetime->time.life,
				.encr = {
					.alg = enc_alg,
					.key = chunk_clone(enc_key),
				},
				.integ = {
					.alg = int_alg,
					.key = chunk_clone(int_key),
				},
			},
			.sps = array_create(0, 0),
			.local = local,
			.remote = remote,
			.mode = mode,
			.encap = encap,
		);

		if (lifetime->time.life)
		{
			schedule_expire(this, spi, local, lifetime->time.life, TRUE);
		}
		if (lifetime->time.rekey && lifetime->time.rekey != lifetime->time.life)
		{
			schedule_expire(this, spi, local, lifetime->time.rekey, FALSE);
		}

		this->mutex->lock(this->mutex);
		this->tsas->put(this->tsas, (void*)(uintptr_t)reqid, entry);
		this->isas->put(this->isas, &entry->isa, entry);
		this->mutex->unlock(this->mutex);
	}
	else
	{
		/* comes after inbound, update entry */
		this->mutex->lock(this->mutex);
		entry = this->tsas->remove(this->tsas, (void*)(uintptr_t)reqid);
		this->mutex->unlock(this->mutex);

		if (!entry)
		{
			DBG1(DBG_KNL, "adding outbound SA failed, no inbound SA found "
				 "for reqid %u ", reqid);
			return NOT_FOUND;
		}
		/* TODO: should we check for local/remote, mode etc.? */

		entry->osa = (sa_entry_t){
			.spi = spi,
			.dst = entry->remote,
			.protocol = protocol,
			.lifetime = lifetime->time.life,
			.encr = {
				.alg = enc_alg,
				.key = chunk_clone(enc_key),
			},
			.integ = {
				.alg = int_alg,
				.key = chunk_clone(int_key),
			},
		};

		this->mutex->lock(this->mutex);
		this->osas->put(this->osas, &entry->osa, entry);
		this->mutex->unlock(this->mutex);
	}

	return SUCCESS;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_kernel_wfp_ipsec_t *this, u_int32_t spi, u_int8_t protocol,
	u_int16_t cpi, host_t *src, host_t *dst, host_t *new_src, host_t *new_dst,
	bool encap, bool new_encap, mark_t mark)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, mark_t mark, u_int64_t *bytes,
	u_int64_t *packets, time_t *time)
{
	/* It does not seem that WFP provides any means of getting per-SA traffic
	 * statistics. IPsecGetStatistics0/1() provides global stats, and
	 * IPsecSaContextEnum0/1() and IPsecSaEnum0/1() return the configured
	 * values only. */
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int16_t cpi, mark_t mark)
{
	entry_t *entry;
	sa_entry_t key = {
		.dst = dst,
		.spi = spi,
	};

	this->mutex->lock(this->mutex);
	entry = this->isas->remove(this->isas, &key);
	this->mutex->unlock(this->mutex);

	if (entry)
	{
		/* keep entry until removal of outbound */
		return SUCCESS;
	}

	this->mutex->lock(this->mutex);
	entry = this->osas->remove(this->osas, &key);
	this->mutex->unlock(this->mutex);

	if (entry)
	{
		entry_destroy(this, entry);
		return SUCCESS;
	}

	return NOT_FOUND;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
	private_kernel_wfp_ipsec_t *this)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	policy_dir_t direction, policy_type_t type, ipsec_sa_cfg_t *sa, mark_t mark,
	policy_priority_t priority)
{
	status_t status = SUCCESS;
	entry_t *entry;
	sp_entry_t *sp;
	sa_entry_t key = {
		.spi = sa->esp.use ? sa->esp.spi : sa->ah.spi,
		.dst = dst,
	};

	if (sa->esp.use && sa->ah.use)
	{
		return NOT_SUPPORTED;
	}

	switch (direction)
	{
		case POLICY_OUT:
			break;
		case POLICY_IN:
		case POLICY_FWD:
			/* not required */
			return SUCCESS;
		default:
			return NOT_SUPPORTED;
	}

	switch (priority)
	{
		case POLICY_PRIORITY_DEFAULT:
			break;
		case POLICY_PRIORITY_FALLBACK:
			/* TODO: install fallback policy? */
			return SUCCESS;
		case POLICY_PRIORITY_ROUTED:
			/* TODO: install trap policy with low prio */
		default:
			return NOT_SUPPORTED;
	}

	this->mutex->lock(this->mutex);
	entry = this->osas->get(this->osas, &key);
	if (entry)
	{
		if (array_count(entry->sps) == 0)
		{
			INIT(sp,
				.src = src_ts->clone(src_ts),
				.dst = dst_ts->clone(dst_ts),
			);
			array_insert(entry->sps, -1, sp);
			if (!install(this, entry))
			{
				status = FAILED;
			}
		}
		else
		{
			/* TODO: reinstall with a filter using multiple TS?
			 * Filters are ANDed for a match, but we could install a filter
			 * with the inverse TS set using NOT-matches... */
			status = NOT_SUPPORTED;
		}
	}
	else
	{
		DBG1(DBG_KNL, "adding SP failed, no SA found for SPI 0x%08x", key.spi);
		status = FAILED;
	}
	this->mutex->unlock(this->mutex);

	return status;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_kernel_wfp_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, mark_t mark,
	time_t *use_time)
{
	/* see query_sa() for some notes */
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_kernel_wfp_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, u_int32_t reqid,
	mark_t mark, policy_priority_t priority)
{
	/* not required, as we delete the whole SA/SP set during del_sa() */
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	private_kernel_wfp_ipsec_t *this)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_kernel_wfp_ipsec_t *this, int fd, int family)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
	private_kernel_wfp_ipsec_t *this, int fd, int family, u_int16_t port)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, destroy, void,
	private_kernel_wfp_ipsec_t *this)
{
	if (this->handle)
	{
		FwpmProviderDeleteByKey0(this->handle, &this->provider.providerKey);
		FwpmEngineClose0(this->handle);
	}
	this->tsas->destroy(this->tsas);
	this->isas->destroy(this->isas);
	this->osas->destroy(this->osas);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * Described in header.
 */
kernel_wfp_ipsec_t *kernel_wfp_ipsec_create()
{
	private_kernel_wfp_ipsec_t *this;
	DWORD res;
	FWPM_SESSION0 session = {
		.displayData = {
			.name = L"charon",
			.description = L"strongSwan IKE kernel-wfp backend",
		},
	};

	INIT(this,
		.public = {
			.interface = {
				.get_features = _get_features,
				.get_spi = _get_spi,
				.get_cpi = _get_cpi,
				.add_sa  = _add_sa,
				.update_sa = _update_sa,
				.query_sa = _query_sa,
				.del_sa = _del_sa,
				.flush_sas = _flush_sas,
				.add_policy = _add_policy,
				.query_policy = _query_policy,
				.del_policy = _del_policy,
				.flush_policies = _flush_policies,
				.bypass_socket = _bypass_socket,
				.enable_udp_decap = _enable_udp_decap,
				.destroy = _destroy,
			},
		},
		.provider = {
			.displayData = {
				.name = L"charon",
				.description = L"strongSwan IKE kernel-wfp backend",
			},
			.providerKey = { 0x59cdae2e, 0xf6bb, 0x4c09,
							{ 0xa9,0x59,0x9d,0x91,0xac,0xaf,0xf9,0x19 }},
		},
		.nextspi = htonl(0xc0000001),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.tsas = hashtable_create(hashtable_hash_ptr, hashtable_equals_ptr, 4),
		.isas = hashtable_create((void*)hash_sa, (void*)equals_sa, 4),
		.osas = hashtable_create((void*)hash_sa, (void*)equals_sa, 4),
	);

	res = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session,
						  &this->handle);
	if (res != ERROR_SUCCESS)
	{
		DBG1(DBG_KNL, "opening WFP engine failed: 0x%08x", res);
		destroy(this);
		return NULL;
	}

	res = FwpmProviderAdd0(this->handle, &this->provider, NULL);
	if (res != ERROR_SUCCESS && res != FWP_E_ALREADY_EXISTS)
	{
		DBG1(DBG_KNL, "registering WFP provider failed: 0x%08x", res);
		destroy(this);
		return NULL;
	}

	return &this->public;
}

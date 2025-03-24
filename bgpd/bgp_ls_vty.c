/***************************************************************************
*
* This is an implementation of BGP Link State as per RFC 7752
* Copyright (C) 2020 CTBRI
*
 ***************************************************************************/


#include <zebra.h>
#include "command.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_debug.h"

#include "bgp_ls_pub.h"
#include "bgpd/bgp_ls.h"
#include "bgpd/bgp_ls_vty.h"

DEFINE_MTYPE_STATIC(BGPD, BGPLS_STR, "bgp ls string ");
    
#define LS_STR_DEFAULT_LEN  1024

enum bgp_ls_str_fmt_t {
	BGP_LS_STR_DISPLAY = 0,
	BGP_LS_STR_CONVERT = 1,
	BGP_LS_STR_JSON = 2,
};

//#define BGPLS_DEBUG(...) 
//if (BGP_DEBUG(link_state, BGPLS)) zlog_debug(__FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)

/* Local Structures and variables declarations
 * This code block hosts the struct declared that host the link-state rules
 * as well as some structure used to convert to stringx
 */

/*Protocol-ID NLRI information source protocol*/
static const struct message bgp_ls_display_pro_id[] = {
	{BGP_LS_PROTO_ISIS_L1, "IS-IS Level 1"},
	{BGP_LS_PROTO_ISIS_L2, "IS-IS Level 2"},
	{BGP_LS_PROTO_OSPF2, "OSPFv2"},
	{BGP_LS_PROTO_DIRECT, "Direct"},
	{BGP_LS_PROTO_STATIC, "Static configuration"},
	{BGP_LS_PROTO_OSPF3, "OSPFv3"},
	{BGP_LS_PROTO_BGP, "BGP"},
	{BGP_LS_PROTO_RSVP_TE, "RSVP-TE"},
	{BGP_LS_PROTO_SR, "Segment Routing"},
    {0}
} ;

/*Node Descriptor, Link Descriptor, Prefix Descriptor, and Attribute TLVs*/
static const struct message bgp_ls_display_tlv[] = {

    /*0-255, Reserved"},[RFC7752]*/
    {BGP_LS_LOCAL_NODE_DESC, "Local Node Descriptors"},/*[RFC7752, Section 3.2.1.2]*/
    {BGP_LS_REMOTE_NODE_DESC, "Remote Node Descriptors"},/*[RFC7752, Section 3.2.1.3]*/
    {BGP_LS_LINK_LOCAL_OR_REMOTE_ID, "Link Local/Remote Identifiers"},/*[RFC5307, Section 1.1]*/
    {BGP_LS_IP4_INF_ADDR, "IPv4 interface address"},/*[RFC5305, Section 3.2]*/
    {BGP_LS_IP4_NEIGHBOR_ADDR, "IPv4 neighbor address"},/*[RFC5305, Section 3.3]*/
    {BGP_LS_IP6_INF_ADDR, "IPv6 interface address"},/*[RFC6119, Section 4.2]*/
    {BGP_LS_IP6_NEIGHBOR_ADDR, "IPv6 neighbor address"},/*[RFC6119, Section 4.3]*/
    {BGP_LS_MUL_TOP_ID, "Multi-Topology ID"},/*[RFC7752, Section 3.2.1.5]*/
    {BGP_LS_OSPF_ROUTE_TYPE, "OSPF Route Type"},/*[RFC7752, Section 3.2.3]*/
    {BGP_LS_IP_REACH_INFO, "IP Reachability Information"},/*[RFC7752, Section 3.2.3]*/
    {BGP_LS_NODE_MSD, "Node MSD"},/*(TEMPORARY) [draft-ietf-idr-bgp-ls-segment-routing-msd]*/
    {BGP_LS_LINK_MSD, "Link MSD"},/*(TEMPORARY) [draft-ietf-idr-bgp-ls-segment-routing-msd]*/
                
    /* 268-511, Unassigned, */
    {BGP_LS_AUTO_SYS, "Autonomous System"},/*[RFC7752, Section 3.2.1.4]*/
    {BGP_LS_ID, "BGP-LS Identifier"},/*[RFC7752, Section 3.2.1.4]*/
    {BGP_LS_OSPF_AREA_ID, "OSPF Area-ID"},/*[RFC7752, Section 3.2.1.4]*/
    {BGP_LS_IGP_ROUTE_ID, "IGP Router-ID"},/*[RFC7752, Section 3.2.1.4]*/
    {BGP_LS_BGP_ROUTER_ID, "BGP Router-ID"},/*[RFC-ietf-idr-bgpls-segment-routing-epe-19]*/
    {BGP_LS_BGP_CONFRE_MEM, "BGP Confederation Member"},/*[RFC-ietf-idr-bgpls-segment-routing-epe-19]*/
    {BGP_LS_SRv6_SID_INFO, "SRv6 SID Information TLV "},/*(TEMPORARY) [draft-ietf-idr-bgpls-srv6-ext]*/
                
    /* 519-549,  Unassigned*/
    {BGP_LS_TUNNEL_ID, "Tunnel ID TLV "},/*(TEMPORARY)[draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_LSP_ID, "LSP ID TLV "},/*(TEMPORARY)-[draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_IP46_TUNNEL_HEAD, "IPv4/6 Tunnel Head-end address TLV "},/*(TEMPORARY)[draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_IP46_TUNNEL_TAIL, "IPv4/6 Tunnel Tail-end address TLV "},/*(TEMPORARY)[draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_SR_POLICY_CP_DESC, "SR Policy CP Descriptor TLV "},/*(TEMPORARY)[draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_MPLS_LOCAL_CROSS, "MPLS Local Cross Connect TLV "},/*(TEMPORARY)[draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_MPLS_CROSS_INF, "MPLS Cross Connect Interface TLV "},/*(TEMPORARY)[draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_MPLS_CROSS_FEC, "MPLS Cross Connect FEC TLV "},/*(TEMPORARY)[draft-ietf-idr-te-lsp-distribution]*/
                
    /* 558-1023,  Unassigned*/
    {BGP_LS_NODE_FLAG, "Node Flag Bits"},/*[RFC7752, Section 3.3.1.1]*/
    {BGP_LS_OPAQUE_NODE_ATTRI, "Opaque Node Attribute"},/*[RFC7752, Section 3.3.1.5]*/
    {BGP_LS_NODE_NAME, "Node Name"},/*[RFC7752, Section 3.3.1.3]*/
    {BGP_LS_ISIS_AREA_ID, "IS-IS Area Identifier"},/*[RFC7752, Section 3.3.1.2]*/
    {BGP_LS_IP4_LOCAL_NODE_RT_ID, "IPv4 Router-ID of Local Node"},/*[RFC5305, Section 4.3]*/
    {BGP_LS_IP6_LOCAL_NODE_RT_ID, "IPv6 Router-ID of Local Node"},/*[RFC6119, Section 4.1]*/
    {BGP_LS_IP4_REMOTE_NODE_RT_ID, "IPv4 Router-ID of Remote Node"},/*[RFC5305, Section 4.3]*/
    {BGP_LS_IP6_REMOTE_NODE_RT_ID, "IPv6 Router-ID of Remote Node"},/*[RFC6119, Section 4.1]*/
    {BGP_LS_SBFD_DISCRI, "S-BFD Discriminators TLV "},/*(TEMPORARY)- 
                registered 2019-08-06, expires 2020-08-06)", [draft-ietf-idr-bgp-ls-sbfd-extensions]*/
                
    /* 1033,  Unassigned*/
    {BGP_LS_SR_CAP, "SR Capabilities"},/*[RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.1.2]*/
    {BGP_LS_SR_ALGO, "SR Algorithm"},/*[RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.1.3]*/
    {BGP_LS_SR_LOCAL_BLK, "SR Local Block"},/*[RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.1.4]*/
    {BGP_LS_SRMS_PREFRE, "SRMS Preference"},/*[RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.1.5]*/
    {BGP_LS_SR6_CAP, "SRv6 Capabilities TLV "},/*(TEMPORARY)[draft-ietf-idr-bgpls-srv6-ext]*/
    {BGP_LS_FLEX_ALGO, "Flex Algorithm Definition TLV "},/*(TEMPORARY)[draft-ietf-idr-bgp-ls-flex-algo]*/
    {BGP_LS_FLEX_ALGO_EX, "Flex Algo Exclude Any Affinity sub-TLV "},/*(TEMPORARY)[draft-ietf-idr-bgp-ls-flex-algo]*/
    {BGP_LS_FLEX_ALGO_IN, "Flex Algo Include Any Affinity sub-TLV "},/*(TEMPORARY)[draft-ietf-idr-bgp-ls-flex-algo]*/
    {BGP_LS_FLEX_ALGO_IN_ALL, "Flex Algo Include All Affinity sub-TLV "},/*(TEMPORARY)[draft-ietf-idr-bgp-ls-flex-algo
]*/
    {BGP_LS_FLEX_ALGO_FLAG, "Flex Algo Definition Flags sub-TLV "},/*(TEMPORARY)[draft-ietf-idr-bgp-ls-flex-algo]*/
    {BGP_LS_FLEX_ALGO_PRE_METRIC, "Flex Algorithm Prefix Metric TLV "},/*(TEMPORARY)[draft-ietf-idr-bgp-ls-flex-algo]*/
                
    /* 1045-1087,  Unassigned*/
    {BGP_LS_ADMIN_GROUP, "Administrative group (color)"},/*[RFC5305, Section 3.1]*/
    {BGP_LS_MAX_LINK_BW, "Maximum link bandwidth"},/*[RFC5305, Section 3.4]*/
    {BGP_LS_MAX_RESERV_LINK_BW, "Max. reservable link bandwidth"},/*[RFC5305, Section 3.5]*/
    {BGP_LS_UNRESERV_BW, "Unreserved bandwidth"},/*[RFC5305, Section 3.6]*/
    {BGP_LS_TE_DEFAUT_METRIC, "TE Default Metric"},/*[RFC7752, Section 3.3.2.3]*/
    {BGP_LS_LINK_PROTECT_TYPE, "Link Protection Type"},/*[RFC5307, Section 1.2]*/
    {BGP_LS_MPLS_PRO_MASK, "MPLS Protocol Mask"},/*[RFC7752, Section 3.3.2.2]*/
    {BGP_LS_IGP_METRIC, "IGP Metric"},/*[RFC7752, Section 3.3.2.4]*/
    {BGP_LS_SHARE_RISK_LINK_GROUP, "Shared Risk Link Group"},/*[RFC7752, Section 3.3.2.5]*/
    {BGP_LS_OPAQUE_LINK_ATTRI, "Opaque Link Attribute"},/*[RFC7752, Section 3.3.2.6]*/
    {BGP_LS_LINK_NAME, "Link Name"},/*[RFC7752, Section 3.3.2.7]*/
    {BGP_LS_ADJ_SID, "Adjacency SID"},/*[RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.2.1]*/
    {BGP_LS_LAN_ADJ_SID, "LAN Adjacency SID"},/*[RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.2.2]*/
    {BGP_LS_PEER_NODE_SID, "PeerNode SID"},/*[RFC-ietf-idr-bgpls-segment-routing-epe-19]*/
    {BGP_LS_PEER_ADJ_SID, "PeerAdj SID"},/*[RFC-ietf-idr-bgpls-segment-routing-epe-19]*/
    {BGP_LS_PEER_SET_SID, "PeerSet SID"},/*[RFC-ietf-idr-bgpls-segment-routing-epe-19]*/
    
    /* 1104,  Unassigned*/
    {BGP_LS_RTM_CAP, "RTM Capability"},/*[RFC8169]*/
    {BGP_LS_SR6_END_SID, "SRv6 End.X SID TLV "},/*(TEMPORARY)[draft-ietf-idr-bgpls-srv6-ext]*/
    {BGP_LS_ISIS_SR6_LAN_END_SID, "IS-IS SRv6 LAN End.X SID TLV "},/*(TEMPORARY)[draft-ietf-idr-bgpls-srv6-ext]*/
    {BGP_LS_OSPF3_SR6_LAN_END_SID, "OSPFv3 SRv6 LAN End.X SID TLV "},/*(TEMPORARY)[draft-ietf-idr-bgpls-srv6-ext]*/
                
    /* 1109-1113,  Unassigned*/
    {BGP_LS_UNIDIRECT_LINK_DELAY, "Unidirectional Link Delay"},/*[RFC8571]*/
    {BGP_LS_MINMAX_LINK_DELAY, "Min/Max Unidirectional Link Delay"},/*[RFC8571]*/
    {BGP_LS_UNIDIRECT_DELAY_VAR, "Unidirectional Delay Variation"},/*[RFC8571]*/
    {BGP_LS_UNIDIRECT_LINK_LOSS, "Unidirectional Link Loss"},/*[RFC8571]*/
    {BGP_LS_UNIDIRECT_RES_BW, "Unidirectional Residual Bandwidth"},/*[RFC8571]*/
    {BGP_LS_UNIDIRECT_AVAIL_BW, "Unidirectional Available Bandwidth"},/*[RFC8571]*/
    {BGP_LS_UNIDIRECT_UTIL_BW, "Unidirectional Utilized Bandwidth"},/*[RFC8571]*/
    {BGP_LS_GR_LINK_SHUTDOWN, "Graceful-Link-Shutdown TLV"},/*[RFC8379]*/
    {BGP_LS_APP_SPEC_LINK_ATTRI, "Application Specific Link Attributes TLV "},/*(TEMPORARY)[draft-ietf-idr-bgp-ls-app-specific-attr]*/
                
    /* 1123-1151,  Unassigned*/
    {BGP_LS_IGP_FLAG, "IGP Flags"},/*[RFC7752, Section 3.3.3.1]*/
    {BGP_LS_IGP_ROUTE_TAG, "IGP Route Tag"},/*[RFC5130]*/
    {BGP_LS_IGP_EXT_ROUTE_TAG , "IGP Extended Route Tag"},/*[RFC5130]*/
    {BGP_LS_PREFIX_METRIC, "Prefix Metric"},/*[RFC5305]*/
    {BGP_LS_OSPF_FWD_ADD, "OSPF Forwarding Address"},/*[RFC2328]*/
    {BGP_LS_OPAQUE_PREFIX_ATTRI, "Opaque Prefix Attribute"},/*[RFC7752, Section 3.3.3.6]*/
    {BGP_LS_PREFIX_SID, "Prefix SID"},/*[RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.3.1]*/
    {BGP_LS_RANGE, "Range"},/*[RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.3.4]*/
    
    /* 1160,  Unassigned*/
    {BGP_LS_SID_LABEL, "SID/Label"},/*[RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.1.1]*/
    {BGP_LS_SR6_LOCATER, "SRv6 Locator TLV "},/*(TEMPORARY)[draft-ietf-idr-bgpls-srv6-ext]*/
                
    /* 1163-1169,  Unassigned*/
    {BGP_LS_PREFIX_ATTRI_FLAG, "Prefix Attributes Flags"},/*[RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section2.3.2]*/
    {BGP_LS_SR_ROUTE_ID, "Source Router-ID"},/*[RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.3.3]*/
    {BGP_LS_L3_BOND_MEM_ATTRI, "L2 Bundle Member Attributes"},/*[RFC-ietf-idr-bgp-ls-segment-routing-ext-16,Section 2.2.3]*/
    {BGP_LS_EXT_ADMIN_GROUP, "Extended Administrative Group "},/*(TEMPORARY)[draft-ietf-idr-eag-distribution][RFC7308]*/
                
    /* 1174-1199,  Unassigned*/
    {BGP_LS_MPLS_TE_POLICY_STATE, "MPLS-TE Policy State TLV "},/*(TEMPORARY)- 
                 [draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_SR_BSID, "SR BSID TLV "},/*(TEMPORARY)- 
                 [draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_SR_CP_STATE, "SR CP State TLV "},/*(TEMPORARY)- 
                 [draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_SR_CP_NAME, "SR CP Name TLV "},/*(TEMPORARY)- 
                 [draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_SR_CP_CONST, "SR CP Constraints TLV "},/*(TEMPORARY)- 
                 [draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_SR_SEGMENT_LIST, "SR Segment List TLV "},/*(TEMPORARY)- 
                 [draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_SR_SEGMENT_SUB, "SR Segment sub-TLV "},/*(TEMPORARY)- 
                 [draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_SR_SEGMENT_LIST_METRIC, "SR Segment List Metric sub-TLV "},/*(TEMPORARY)- 
                 [draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_SR_AFFI_CONST, "SR Affinity Constraint sub-TLV "},/*(TEMPORARY)- 
                 [draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_SR_SRLG_CONST, "SR SRLG Constraint sub-TLV "},/*(TEMPORARY)- 
                 [draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_SR_BW_CONST, "SR Bandwidth Constraint sub-TLV "},/*(TEMPORARY)- 
                 [draft-ietf-idr-te-lsp-distribution]*/
    {BGP_LS_SR_DIS_GROUP_CONST, "SR Disjoint Group Constraint sub-TLV "},/*(TEMPORARY)- 
                 [draft-ietf-idr-te-lsp-distribution]*/
                
    /* 1212-1249,  Unassigned*/
    {BGP_LS_SR6_END_FUNC, "SRv6 Endpoint Function TLV "},/*(TEMPORARY)[draft-ietf-idr-bgpls-srv6-ext]*/
    {BGP_LS_SR6_BGP_PEER_NODE_SID, "SRv6 BGP Peer Node SID TLV "},/*(TEMPORARY)[draft-ietf-idr-bgpls-srv6-ext]*/
    {BGP_LS_SR6_SID_STRUCT, "SRv6 SID Structure TLV "},/*(TEMPORARY)[draft-ietf-idr-bgpls-srv6-ext]*/
    {0}
};

/*Definition of parameters related to float type and int32 data conversion*/
#define IEEE_INFINITY         0x7F800000
#define MINUS_INFINITY        (int32_t)0x80000000L
#define PLUS_INFINITY         0x7FFFFFFF
#define IEEE_NUMBER_WIDTH       32        /* bits in number */
#define IEEE_EXP_WIDTH          8         /* bits in exponent */
#define IEEE_MANTISSA_WIDTH     (IEEE_NUMBER_WIDTH - 1 - IEEE_EXP_WIDTH)
#define IEEE_SIGN_MASK          0x80000000
#define IEEE_EXPONENT_MASK      0x7F800000
#define IEEE_MANTISSA_MASK      0x007FFFFF
#define IEEE_IMPLIED_BIT        (1 << IEEE_MANTISSA_WIDTH)
#define IEEE_INFINITE           ((1 << IEEE_EXP_WIDTH) - 1)
#define IEEE_BIAS               ((1 << (IEEE_EXP_WIDTH - 1)) - 1)

/*The bandwidth data type of float in LS attribute is converted to the kbps type*/
static uint32_t float_to_kbps(int32_t float_val) 
{
    int32_t sign, exponent, mantissa;
    int64_t bits_value = 0;

    sign = float_val & IEEE_SIGN_MASK;
    exponent = float_val & IEEE_EXPONENT_MASK;
    mantissa = float_val & IEEE_MANTISSA_MASK;

    if ((float_val & ~IEEE_SIGN_MASK) == 0) {
        /* Number is zero, unnormalized, or not-a-float_val. */
        return 0;
    }

    if (IEEE_INFINITY == exponent) {
        /* Number is positive or negative infinity, or a special value. */
        return (sign ? MINUS_INFINITY : PLUS_INFINITY);
    }

    exponent = (exponent >> IEEE_MANTISSA_WIDTH) - IEEE_BIAS;
    if (exponent < 0) {
         /* Number is between zero and one. */
         return 0;
    }

    mantissa |= IEEE_IMPLIED_BIT;

    bits_value = mantissa;

    if (exponent <= IEEE_MANTISSA_WIDTH) {
       bits_value >>= IEEE_MANTISSA_WIDTH - exponent;
    } else {
       bits_value <<= exponent - IEEE_MANTISSA_WIDTH;
    }

    // Change sign
    if (sign)
        bits_value *= -1;

    bits_value *= 8;        // to bits
    bits_value /= 1000;     // to kbits

    return bits_value;
}

/*isis's ID type string conversion*/
#define LS_FORMAT_BUF_COUNT 4
#define LS_ISIS_FORMAT_ID_SIZE sizeof("0000.0000.0000")
const char *bgp_ls_isis_id_fmt(const uint8_t *id)
{    
	static char buf_ring[LS_FORMAT_BUF_COUNT][LS_ISIS_FORMAT_ID_SIZE];
    static size_t cur_buf = 0;
	char *rv;
	cur_buf++;
	if (cur_buf >= LS_FORMAT_BUF_COUNT)
		cur_buf = 0;
	rv = buf_ring[cur_buf];

	snprintf(rv, LS_ISIS_FORMAT_ID_SIZE, "%02x%02x.%02x%02x.%02x%02x", id[0], id[1],
		 id[2], id[3], id[4], id[5]);
    
	return rv;
}

/*conversion of uint32 type ID string related IPV4 */
#define LS_FORMAT_ID4_SIZE sizeof("255.255.255.255")
static const char *bgp_ls_router_id_fmt(const uint32_t router_id)
{    

	static char buf_ring[LS_FORMAT_BUF_COUNT][LS_FORMAT_ID4_SIZE];
	static size_t cur_buf = 0;
	char *rv;
	cur_buf++;
	if (cur_buf >= LS_FORMAT_BUF_COUNT)
		cur_buf = 0;
	rv = buf_ring[cur_buf];
    
	snprintf(rv, LS_FORMAT_ID4_SIZE, "%u.%u.%u.%u",
        (router_id>>24)&0xff, (router_id>>16)&0xff,
		 (router_id>>8)&0xff, (router_id)&0xff);
	return rv;
}

/*conversion of uint32 type ID string related IPV6*/
#define LS_FORMAT_ID6_SIZE sizeof("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
static const char *bgp_ls_router_id6_fmt(const uint32_t *router_id)
{    
   struct { 
        int32_t base;
        int32_t len; 
    } best, cur;
    uint32_t words[8];
    int32_t i;
	static char buf_ring[LS_FORMAT_BUF_COUNT][LS_FORMAT_ID6_SIZE];    
    static size_t cur_buf = 0;
	char *tp,*rv;
	cur_buf++;
	if (cur_buf >= LS_FORMAT_BUF_COUNT)
		cur_buf = 0;
	tp = buf_ring[cur_buf];
    rv = buf_ring[cur_buf];
    /*
     * Preprocess:
     *        Copy the input (bytewise) array into a wordwise array.
     *        Find the longest run of 0x00's in src[] for :: shorthanding.
     */
    memset(words, '\0', sizeof words);
    for (i = 0; i < 8; i += 2)
    {
        words[i] = (router_id[i/2] >> 16) & 0xffff;
        words[i+1] = router_id[i/2] & 0xffff;
    }
    
    best.base = -1;
    cur.base = -1;
    best.len = 0;
    cur.len = 0;
    for (i = 0; i < (8); i++)
    {
        if (words[i] == 0) 
        {
            if (cur.base == -1)
            cur.base = i, cur.len = 1;
            else
            cur.len++;
        }
        else
        {
            if (cur.base != -1)
            {
                if (best.base == -1 || cur.len > best.len)
                        best = cur;
                cur.base = -1;
            }
        }
    }
    if (cur.base != -1)
    {
        if (best.base == -1 || cur.len > best.len)
            best = cur;
    }
    if (best.base != -1 && best.len < 2)
            best.base = -1;
    /* Format the result. */
    for (i = 0; i < (8); i++)
    {
        /* Are we inside the best run of 0x00's? */
        if (best.base != -1 && i >= best.base && i < (best.base + best.len))
        {
            if (i == best.base)
                    *tp++ = ':';
            continue;
        }
        /* Are we following an initial run of 0x00s or any real hex? */
        if (i != 0)
            *tp++ = ':';
        tp += sprintf(tp, "%x", words[i]);
    }
    /* Was it a trailing run of 0x00's? */
    if (best.base != -1 && (best.base + best.len) == (8))
            *tp++ = ':';
    *tp++ = '\0';

	return rv;
}

/*print origin attribution buf information*/
static BGP_LS_RET_T bgp_ls_attr_vty_out(struct vty *vty,  struct list *list_attrs,uint32_t type)
{    
    uint32_t idx = 0;
    BGP_LS_ATTR *attrs;
    struct listnode *node, *nnode;
    if (NULL == list_attrs)
    {
        return BGP_LS_RET_OK;
    }

    for (ALL_LIST_ELEMENTS(list_attrs, node, nnode, attrs))
    {       
        vty_out(vty, "[attrs-type%u-%u]ref %llu origin buf\n%s\n", type, ++idx, attrs->refcnt, bgp_ls_attr_str(attrs));     
    }
    return BGP_LS_RET_OK;
}


 /*print NODE attribution information*/
static BGP_LS_RET_T bgp_ls_node_attr_vty_out(struct vty *vty, node_attribute *attrs_node, int32_t use_json)
{    
    uint32_t idx = 0;

    if (NULL == attrs_node)
    {
        return BGP_LS_RET_OK;
    }

    vty_out(vty, "   Node attribute:\n");

    if (attrs_node->mt_ID_b)
    { 
        vty_out(vty, "      Node attribute Multi-Topology ID Num:%u\n", attrs_node->mt_ID.length/2);
        for(idx = 0;idx < (attrs_node->mt_ID.length/2); idx++)
        {
            vty_out(vty, "        MT-ID[%u]: %u\n", idx, attrs_node->mt_ID.IDs[idx]);
        }
    }
    if (attrs_node->node_flag_bits_b)
    { 
        vty_out(vty, "      Node Flag Bits:(%s%s%s%s%s%s)\n"
                        ,attrs_node->node_flag_bits.Overload?"Overload ":""
                        ,attrs_node->node_flag_bits.Attached?"Attached ":""
                        ,attrs_node->node_flag_bits.External?"External ":""
                        ,attrs_node->node_flag_bits.ABR?"ABR ":""
                        ,attrs_node->node_flag_bits.Router?"Router ":""
                        ,attrs_node->node_flag_bits.V6?"V6":""); 
    }
    if (attrs_node->opaque_node_attr_b)
    { 
        vty_out(vty, "      Opaque Node Attribute Length:%u Content:\n", attrs_node->opaque_node_attr.length);
        for(idx = 0;idx < attrs_node->opaque_node_attr.length; idx++)
        {
            vty_out(vty, "%x", attrs_node->opaque_node_attr.Data[idx]);
        }
        vty_out(vty, "\n");
    }
    if (attrs_node->node_name_b)
    { 
        vty_out(vty, "      Node Name:%s\n", attrs_node->node_name.Name);
    }
    if (attrs_node->IsIs_area_ID_b)
    { 
        vty_out(vty, "      IS-IS Area Identifier:");
        for(idx = 0;idx < attrs_node->IsIs_area_ID.length; idx++)
        {
            vty_out(vty, "%x", attrs_node->IsIs_area_ID.AreaID[idx]);
        }
        vty_out(vty, "\n");    
    }
    if (attrs_node->IPv4_router_ID_b)
    { 
        vty_out(vty, "      IPv4 Router-ID of Local Node: %s\n",bgp_ls_router_id_fmt(attrs_node->IPv4_router_ID.Address));
    }
    if (attrs_node->IPv6_router_ID_b)
    { 
        vty_out(vty, "      IPv6 Router-ID of Local Node: %s\n",bgp_ls_router_id6_fmt(attrs_node->IPv6_router_ID.Address));                
    }
    
    if (attrs_node->SR_caps_b)
    {
        vty_out(vty, "      SR Capabilities:\n");
        if (attrs_node->SR_caps.mpls_IPv4)
        {           
            vty_out(vty, "        Flags: MPLS IPv4 flag\n");
        }
        else if (attrs_node->SR_caps.mpls_IPv6)
        {           
            vty_out(vty, "        Flags: MPLS IPv6 flag\n");
        }
        vty_out(vty, "        Range Size: %d\n", attrs_node->SR_caps.range_size);
        vty_out(vty, "        %s: %d\n",
            attrs_node->SR_caps.SID_label.length > 3 ? "SID" : "Label",
            attrs_node->SR_caps.SID_label.SID_or_label);
    }
    if (attrs_node->SR_algo_b)
    {
        vty_out(vty, "      SR_algo_b!(exclude rfc7752)\n");     
    }
    if (attrs_node->SR_local_block_b)
    {
        vty_out(vty, "      SR_local_block_b!(exclude rfc7752)\n");     
    }
    if (attrs_node->SRMS_pref_b)
    {
        vty_out(vty, "      SRMS_pref_b!(exclude rfc7752)\n");     
    }
    
    if(attrs_node->sid_label_b)
    {
        vty_out(vty, "      %s: %d\n",
            attrs_node->sid_label.length > 3 ? "SID" : "Label",
            attrs_node->sid_label.SID_or_label);    
    }

    return BGP_LS_RET_OK;
}

/*print LINK attribution information*/
static BGP_LS_RET_T bgp_ls_link_attr_vty_out(struct vty *vty, link_attribute *attrs_link, int32_t use_json)
{
    
    uint32_t idx = 0;

    if (NULL == attrs_link)
    {
        return BGP_LS_RET_OK;
    }

    vty_out(vty, "   Link attribute:\n");

    if (attrs_link->local_IP4_router_ID_b)
    { 
        vty_out(vty, "      IPv4 Router-ID of Local Node: %s\n",bgp_ls_router_id_fmt(attrs_link->local_IP4_router_ID.Address));                
    }
    if (attrs_link->local_IP6_router_ID_b)
    {
        vty_out(vty, "      IPv6 Router-ID of Local Node: %s\n",bgp_ls_router_id6_fmt(attrs_link->local_IP6_router_ID.Address));
    }
    if (attrs_link->remote_IP4_router_ID_b)
    {
        vty_out(vty, "      IPv4 Router-ID of Remote Node: %s\n",bgp_ls_router_id_fmt(attrs_link->remote_IP4_router_ID.Address));               
    }
    if (attrs_link->remote_IP6_router_ID_b)
    {
        vty_out(vty, "      IPv6 Router-ID of Remote Node: %s\n",bgp_ls_router_id6_fmt(attrs_link->remote_IP6_router_ID.Address));
    }
    
    if (attrs_link->admin_group_b)
    {

        vty_out(vty, "      Administrative group (color): 0x%x\n",attrs_link->admin_group.Group_bits); 
    }
    if (attrs_link->maxLink_bandwidth_b)
    {
        vty_out(vty, "      Maximum link bandwidth: %u kpbs\n",float_to_kbps(attrs_link->maxLink_bandwidth.bytes_per_second)); 
    }
    if (attrs_link->max_reservable_link_bandwidth_b)
    {
        vty_out(vty, "      Max reservable link bandwidth: %u kpbs\n",float_to_kbps(attrs_link->max_reservable_link_bandwidth.bytes_per_second)); 
    }
    if (attrs_link->unreserved_bandwidth_b)
    {
        vty_out(vty, "      Unreserved bandwidth: [0]:%u [1]:%u [2]:%u [3]:%u [4]:%u [5]:%u [6]:%u [7]:%u kpbs\n"
                    ,float_to_kbps(attrs_link->unreserved_bandwidth.bytes_per_second[0])
                    ,float_to_kbps(attrs_link->unreserved_bandwidth.bytes_per_second[1])
                    ,float_to_kbps(attrs_link->unreserved_bandwidth.bytes_per_second[2])
                    ,float_to_kbps(attrs_link->unreserved_bandwidth.bytes_per_second[3])
                    ,float_to_kbps(attrs_link->unreserved_bandwidth.bytes_per_second[4])
                    ,float_to_kbps(attrs_link->unreserved_bandwidth.bytes_per_second[5])
                    ,float_to_kbps(attrs_link->unreserved_bandwidth.bytes_per_second[6])
                    ,float_to_kbps(attrs_link->unreserved_bandwidth.bytes_per_second[7])); 
    }
    if (attrs_link->TE_default_metric_b)
    {
        vty_out(vty, "      TE Default Metric: %u\n",attrs_link->TE_default_metric.Metric); 
    }
    if (attrs_link->link_protection_type_b)
    {
        vty_out(vty, "      Link Protection Type:(%s %s %s %s %s %s)\n"
                    ,attrs_link->link_protection_type.ExtraTraffic?"ExtraTraffic":""
                    ,attrs_link->link_protection_type.Unprotected?"Unprotected":""
                    ,attrs_link->link_protection_type.Shared?"Shared":""
                    ,attrs_link->link_protection_type.DedicatedOneToOne?"DedicatedOneToOne":""
                    ,attrs_link->link_protection_type.DedicatedOnePlusOne?"DedicatedOnePlusOne":""
                    ,attrs_link->link_protection_type.Enhanced?"Enhanced":""); 
    }
    if (attrs_link->mpls_protocol_mask_b)
    {
        vty_out(vty, "      MPLS Protocol Mask: :(%s %s)\n"
                ,attrs_link->mpls_protocol_mask.LDP?"LDP":""
                ,attrs_link->mpls_protocol_mask.RsvpTE?"RSVP-TE":""); 
    }
    if (attrs_link->igp_metric_b)
    {
        vty_out(vty, "      IGP Metric: %u (type:%s)\n",attrs_link->igp_metric.Metric
                ,attrs_link->igp_metric.Type == LINK_ATTR_IGP_METRIC_ISIS_SMALL_TYPE?"1 octet":
                attrs_link->igp_metric.Type == LINK_ATTR_IGP_METRIC_OSPF_TYPE?"2 octets":
                attrs_link->igp_metric.Type == LINK_ATTR_IGP_METRIC_ISIS_WIDE_TYPE?"3 octets":"other"); 
    }
    if (attrs_link->shared_risk_link_group_b)
    {
        vty_out(vty, "      Shared Risk Link Group Num:%u\n",attrs_link->shared_risk_link_group.length/4); 
        for(idx = 0;idx < attrs_link->shared_risk_link_group.length/4; idx++)
        {
            vty_out(vty, "        [%u] %u\n", idx, attrs_link->shared_risk_link_group.Groups[idx]);
        }
    }
    if (attrs_link->opaque_link_attr_b)
    {
        vty_out(vty, "      Opaque Link Attribute Length:%u Content:\n", attrs_link->opaque_link_attr.length);
        for(idx = 0;idx < attrs_link->opaque_link_attr.length; idx++)
        {
            vty_out(vty, "%x", attrs_link->opaque_link_attr.Data[idx]);
        }
        vty_out(vty, "\n");
    }
    if (attrs_link->link_name_b)
    {
        vty_out(vty, "      Link Name:%s\n", attrs_link->link_name.Name);
    }
    
    if (attrs_link->adj_SID_b)
    {
        vty_out(vty, "      Adjacency SID: %d\n", attrs_link->adj_SID.SID_index_label);
    }
    if (attrs_link->lan_adj_SID_b)
    {
        vty_out(vty, "      LAN Adj SID: %d\n", attrs_link->lan_adj_SID.SID_index_label);
    }
    if (attrs_link->peer_node_SID_b)
    {
        vty_out(vty, "      Peer Node SID: %d\n", attrs_link->peer_node_SID.SID_index_label);
    }
    if (attrs_link->peer_adj_SID_b)
    {
        vty_out(vty, "      Peer Adj SID: %d\n", attrs_link->peer_adj_SID.SID_index_label);
    }
    if (attrs_link->peer_set_SID_b)
    {
        vty_out(vty, "      Peer Set SID: %d\n", attrs_link->peer_set_SID.SID_index_label);
    }
    if (attrs_link->uni_link_delay_b)
    {
        vty_out(vty, "      uni_link_delay: %d\n",attrs_link->uni_link_delay);     
    }
    if (attrs_link->min_max_uniLink_delay_b)
    {
        vty_out(vty, "      min_uniLink_delay: %d\n",attrs_link->min_max_uniLink_delay.MinDelay); 
		vty_out(vty, "      max_uniLink_delay: %d\n",attrs_link->min_max_uniLink_delay.MaxDelay); 
    }
    if (attrs_link->uni_delay_variation_b)
    {
        vty_out(vty, "      uni_delay_variation: %d\n",attrs_link->uni_delay_variation);     
    }
    if (attrs_link->uni_packet_loss_b)
    {
        vty_out(vty, "      uni_packet_loss: %d\n",attrs_link->uni_packet_loss);     
    }
    if (attrs_link->uni_residual_bandwidth_b)
    {
        vty_out(vty, "      uni_residual_bandwidth: %d\n",attrs_link->uni_residual_bandwidth);     
    }
    if (attrs_link->uni_available_bandwidth_b)
    {
        vty_out(vty, "      uni_available_bandwidth: %d\n",attrs_link->uni_available_bandwidth);     
    }
    if (attrs_link->uni_bandwidth_util_b)
    {
        vty_out(vty, "      uni_bandwidth_util: %d\n",attrs_link->uni_bandwidth_util);     
    }
    if (attrs_link->l2_bundle_member_b)
    {
        vty_out(vty, "      l2_bundle_member_b!(exclude rfc7752)\n");     
    }
    if (attrs_link->sr6_end_sid_b)
    {        
        vty_out(vty, "      SRv6 End.X Behavior: %d\n", attrs_link->sr6_end_sid.endpoint_behavior);
        vty_out(vty, "      SRv6 End.X SID: %s\n", bgp_ls_router_id6_fmt(attrs_link->sr6_end_sid.sid));
    }
    if (attrs_link->isis_sr6_lan_end_sid_b)
    {
        vty_out(vty, "      SRv6 LAN End.X Behavior: %d\n", attrs_link->isis_sr6_lan_end_sid.endpoint_behavior);
        vty_out(vty, "      SRv6 LAN End.X SID(ISIS): %s\n", bgp_ls_router_id6_fmt(attrs_link->isis_sr6_lan_end_sid.sid));
    }
    if (attrs_link->ospf3_sr6_lan_end_sid_b)
    {
        vty_out(vty, "      SRv6 LAN End.X Behavior: %d\n", attrs_link->ospf3_sr6_lan_end_sid.endpoint_behavior);
        vty_out(vty, "      SRv6 LAN End.X SID(OSPFv3): %s\n", bgp_ls_router_id6_fmt(attrs_link->ospf3_sr6_lan_end_sid.sid));
    }

    return BGP_LS_RET_OK;
}

/*print prefix attribution information*/
static BGP_LS_RET_T bgp_ls_prefix_attr_vty_out(struct vty *vty, prefix_attribute *prefix_node,bool_t isIPv4,int32_t use_json)
{
    
    uint32_t idx = 0;

    if (NULL == prefix_node)
    {
        return BGP_LS_RET_OK;
    }

    vty_out(vty, "   Prefix attribute:\n");        
    if (prefix_node->igp_flags_b)
    {
        vty_out(vty, "      IGP Flags:(%s%s%s%s)\n"
                    ,prefix_node->igp_flags.IsIs_down?"D ":""
                    ,prefix_node->igp_flags.ospf_no_unicast?"N ":""
                    ,prefix_node->igp_flags.ospf_local_address?"L ":""
                    ,prefix_node->igp_flags.ospf_propagate_nssa?"P":""); 
    }
    if (prefix_node->igp_route_tag_b)
    {
        vty_out(vty, "      IGP Route Tags Num:%u Content:\n", prefix_node->igp_route_tag.length/4);
        for(idx = 0;idx < prefix_node->igp_route_tag.length/4; idx++)
        {
            vty_out(vty, "        [%u] %u\n", idx, prefix_node->igp_route_tag.Tags[idx]);
        }
    }
    if (prefix_node->igp_extended_route_tag_b)
    {
        vty_out(vty, "      IGP Route Extended Tags Num:%u Content:\n", prefix_node->igp_extended_route_tag.length/8);
        for(idx = 0;idx < prefix_node->igp_extended_route_tag.length/8; idx++)
        {
            vty_out(vty, "        [%u] %"PRIu64"\n", idx, prefix_node->igp_extended_route_tag.Tags[idx]);
        }
    }    
    
    if (prefix_node->prefix_metric_b)
    {
        vty_out(vty, "      Prefix Metric: %u\n",prefix_node->prefix_metric.Metric); 
    }
    if (prefix_node->ospf_forwarding_address_b)
    {
        if (OSPF_FORWARDING_ADDRESS_IPV4 == prefix_node->ospf_forwarding_address.type)
        {
            vty_out(vty, "      OSPF Forwarding Address(IPv4):%s\n",bgp_ls_router_id_fmt(prefix_node->ospf_forwarding_address.Address[0])); 
        }
        else if (OSPF_FORWARDING_ADDRESS_IPV6 == prefix_node->ospf_forwarding_address.type)
        {
            vty_out(vty, "      OSPF Forwarding Address(IPv6): %s\n",bgp_ls_router_id6_fmt(prefix_node->ospf_forwarding_address.Address)); 
        }
    }
    if (prefix_node->opaque_prefix_attribute_b)
    {
        vty_out(vty, "      Opaque Prefix Attribute Length:%u Content:\n", prefix_node->opaque_prefix_attribute.length);
        for(idx = 0;idx < prefix_node->opaque_prefix_attribute.length; idx++)
        {
            vty_out(vty, "%x", prefix_node->opaque_prefix_attribute.Data[idx]);
        }
        vty_out(vty, "\n");
    }     

    if (prefix_node->prefix_SID_b)
    {
        vty_out(vty, "      Prefix SID: %d\n", prefix_node->prefix_SID.SID_index_label.SID);
    }
    if (prefix_node->range_b)
    {
        vty_out(vty, "      range_b!(exclude rfc7752)\n");     
    }
    if (prefix_node->attr_flags_b)
    {
        vty_out(vty, "      attr_flags_b!(exclude rfc7752)\n");     
    }
    if (prefix_node->source_router_ID_b)
    {
        vty_out(vty, "      source_router_ID_b!(exclude rfc7752)\n");     
    }
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T bgp_ls_sr6_sid_attr_vty_out(struct vty *vty, sr6_sid_attribute *sr6_sid_node,bool_t isIPv4,int32_t use_json)
{
    if (NULL == sr6_sid_node)
    {
        return BGP_LS_RET_OK;
    }

    vty_out(vty, "   SRv6 SID attribute:\n");        
    if (sr6_sid_node->endpoint_behavior_b)
    {
        vty_out(vty, "      Endpoint Behavior: %x\n", sr6_sid_node->endpoint_behavior.endpoint_behavior);
        /*+-------------+--------+-------------------------+------------------+
           | Value       |  Hex   |    Endpoint behavior    |    Reference     |
           +-------------+--------+-------------------------+------------------+
           | 0           | 0x0000 |         Reserved        |    Not to be     |
           |             |        |                         |    allocated     |
           | 1           | 0x0001 |           End           |    [This.ID]     |
           | 2           | 0x0002 |       End with PSP      |    [This.ID]     |
           | 3           | 0x0003 |       End with USP      |    [This.ID]     |
           | 4           | 0x0004 |     End with PSP&USP    |    [This.ID]     |
           | 5           | 0x0005 |          End.X          |    [This.ID]     |
           | 6           | 0x0006 |      End.X with PSP     |    [This.ID]     |        
           | 7           | 0x0007 |      End.X with USP     |    [This.ID]     |
           | 8           | 0x0008 |    End.X with PSP&USP   |    [This.ID]     |
           | 9           | 0x0009 |          End.T          |    [This.ID]     |
           | 10          | 0x000A |      End.T with PSP     |    [This.ID]     |
           | 11          | 0x000B |      End.T with USP     |    [This.ID]     |
           | 12          | 0x000C |    End.T with PSP&USP   |    [This.ID]     |
           | 14          | 0x000E |      End.B6.Encaps      |    [This.ID]     |
           | 15          | 0x000F |          End.BM         |    [This.ID]     |
           | 16          | 0x0010 |         End.DX6         |    [This.ID]     |
           | 17          | 0x0011 |         End.DX4         |    [This.ID]     |
           | 18          | 0x0012 |         End.DT6         |    [This.ID]     |
           | 19          | 0x0013 |         End.DT4         |    [This.ID]     |
           | 20          | 0x0014 |         End.DT46        |    [This.ID]     |
           | 21          | 0x0015 |         End.DX2         |    [This.ID]     |
           | 22          | 0x0016 |         End.DX2V        |    [This.ID]     |
           | 23          | 0x0017 |         End.DT2U        |    [This.ID]     |
           | 24          | 0x0018 |         End.DT2M        |    [This.ID]     |
           | 25          | 0x0019 |         Reserved        |    [This.ID]     |
           | 27          | 0x001B |    End.B6.Encaps.Red    |    [This.ID]     |
           | 28          | 0x001C |       End with USD      |    [This.ID]     |
           | 29          | 0x001D |     End with PSP&USD    |    [This.ID]     |
           | 30          | 0x001E |     End with USP&USD    |    [This.ID]     |
           | 31          | 0x001F | End with PSP, USP & USD |    [This.ID]     |
           | 32          | 0x0020 |      End.X with USD     |    [This.ID]     |
           | 33          | 0x0021 |    End.X with PSP&USD   |    [This.ID]     |
           | 34          | 0x0022 |    End.X with USP&USD   |    [This.ID]     |
           | 35          | 0x0023 |  End.X with PSP, USP &  |    [This.ID]     |
           |             |        |           USD           |                  |
           | 36          | 0x0024 |      End.T with USD     |    [This.ID]     |
           | 37          | 0x0025 |    End.T with PSP&USD   |    [This.ID]     |
           | 38          | 0x0026 |    End.T with USP&USD   |    [This.ID]     |
           | 39          | 0x0027 |  End.T with PSP, USP &  |    [This.ID]     |
           |             |        |           USD           |                  |
           | 40-32766    |        |        Unassigned       |                  |
           | 32767       | 0x7FFF |    The SID defined in   |    [This.ID]     |
           |             |        |         RFC8754         |    [RFC8754]     |
           | 32768-65534 |        |         Reserved        |                  |
           | 65535       | 0xFFFF |          Opaque         |    [This.ID]     |
           +-------------+--------+-------------------------+------------------+*/ 
    }
    return BGP_LS_RET_OK;
}


/*print NODE descriptor information*/
static BGP_LS_RET_T bgp_ls_node_descriptor_vty_out(struct vty *vty, node_descriptor *ls_node, int32_t use_json)
{    
    if (NULL == ls_node)
    {
        return BGP_LS_RET_OK;
    }
    if(LINK_STATE_NLRI_LOCAL_NODE_DESCRIPTORS_CODE == ls_node->Code)
    {
        vty_out(vty, "    Local Node Descriptors:\n");
    }
    else if(LINK_STATE_NLRI_REMOTE_NODE_DESCRIPTORS_CODE == ls_node->Code)
    {
        vty_out(vty, "    Remote Node Descriptors:\n");
    }
    else
    {
        vty_out(vty, "    Unknown(code:%u) Node Descriptors:\n",ls_node->Code);
    }

    if (ls_node->ASN_b)
    {
        vty_out(vty, "      Autonomous System: %u\n",ls_node->ASN.ASN);
    }
    if (ls_node->bgp_ls_ID_b)
    {
        vty_out(vty, "      BGP-LS Identifier: %s\n",bgp_ls_router_id_fmt(ls_node->bgp_ls_ID.ID)); 
    }
    if (ls_node->ospf_area_ID_b)
    {
        vty_out(vty, "      OSPF Area-ID: %s\n",bgp_ls_router_id_fmt(ls_node->ospf_area_ID.ID));     
    }

    if (ls_node->igp_router_ID_b)
    {
        switch (ls_node->igp_router_ID.type)
        {
            case NODE_DESCRIPTOR_IGP_ROUTER_ID_ISIS_NON_PSEUDO_TYPE:
                vty_out(vty, "      IGP Router-ID(ISIS system-ID): %s\n"
                            ,bgp_ls_isis_id_fmt(ls_node->igp_router_ID.igp_router_ID.IsIs_non_pseudo.IsoNodeID));  
                break;
            case NODE_DESCRIPTOR_IGP_ROUTER_ID_ISIS_PSEUDO_TYPE:
                vty_out(vty, "      IGP Router-ID(ISIS system-ID): %s (PSN ID): %u\n"
                            ,bgp_ls_isis_id_fmt(ls_node->igp_router_ID.igp_router_ID.IsIs_pseudo.IsoNodeID)
                            ,ls_node->igp_router_ID.igp_router_ID.IsIs_pseudo.PsnID);  
                break;
            case NODE_DESCRIPTOR_IGP_ROUTER_ID_OSPF_NON_PSEUDO_TYPE:
                vty_out(vty, "      IGP Router-ID(OSPF Router-ID): %s\n"
                            ,bgp_ls_router_id_fmt(ls_node->igp_router_ID.igp_router_ID.ospf_non_pseudo.RouterID));  
                break;
            case NODE_DESCRIPTOR_IGP_ROUTER_ID_OSPF_PSEUDO_TYPE:
                vty_out(vty, "      IGP Router-ID(OSPF DR Router-ID): %s (DR LAN): %s\n"
                            ,bgp_ls_router_id_fmt(ls_node->igp_router_ID.igp_router_ID.ospf_pseudo.DrRouterID)
                            ,bgp_ls_router_id_fmt(ls_node->igp_router_ID.igp_router_ID.ospf_pseudo.DrInterfaceToLAN));  
                break; 
            default: 
                break;
        }   
    }

    if (ls_node->bgp_router_ID_b)
    {
        vty_out(vty, "      BGP router ID(exclude rfc7752): %s\n",bgp_ls_router_id_fmt(ls_node->bgp_router_ID.RouterID));     
    }

    if (ls_node->member_ASN_b)
    {
        vty_out(vty, "      member_ASN_b(exclude rfc7752): %u\n",ls_node->member_ASN.ASN);   
    }
    return BGP_LS_RET_OK;
}


/*print te policy descriptor information*/
static BGP_LS_RET_T bgp_te_policy_descriptor_vty_out(struct vty *vty, te_policy_descriptor *te_policyt, int32_t use_json)
{   
    
    if (NULL == te_policyt)
    {
        return BGP_LS_RET_OK;
    }
    
    vty_out(vty, "    TE-POLICT Descriptors:\n");
    
    if(te_policyt->color)
    {
         vty_out(vty, "      Color:%u \n",te_policyt->color);
    }
	if(te_policyt->orignator_as)
    {
         vty_out(vty, "      Orignator as:%u \n",te_policyt->orignator_as);
    }
	if(te_policyt->discriminator)
    {
         vty_out(vty, "      Discriminator:%u \n",te_policyt->discriminator);
    }
	if(te_policyt->flags & E_FLAG)
	{ 
		vty_out(vty, "      Endpoint : %s\n", bgp_ls_router_id6_fmt(te_policyt->end_point.addr_v6)); 
	}
	else
	{
	    vty_out(vty, "      Endpoint : %s\n", bgp_ls_router_id_fmt(te_policyt->end_point.addr_v4));  
	}

	if(te_policyt->flags  & O_FLAG)
	{
		vty_out(vty, "      Orignator : %s\n", bgp_ls_router_id6_fmt(te_policyt->orignator_addr.addr_v6)); 
	}
	else
	{
	    vty_out(vty, "      Orignator : %s\n", bgp_ls_router_id_fmt(te_policyt->orignator_addr.addr_v4)); 
	}	  

    return BGP_LS_RET_OK;
}


/*print te policy attr information*/
static BGP_LS_RET_T bgp_te_policy_attr_vty_out(struct vty *vty, te_policy_attribute *te_policyt, int32_t use_json)
{   
    
    if (NULL == te_policyt)
    {
        return BGP_LS_RET_OK;
    }
    
    vty_out(vty, "    TE-POLICT attribute:\n");
    
    if(te_policyt->binding_sid_b)
    {
         if(D_FLAG & te_policyt->binding_sid.flags)
	     {
			vty_out(vty, "      Binding sid: %s\n", bgp_ls_router_id6_fmt(te_policyt->binding_sid.binding_sid.addr_v6));         
	     }
	     else
	     {
	        vty_out(vty, "      Binding sid: %s\n", bgp_ls_router_id_fmt(te_policyt->binding_sid.binding_sid.addr_v4)); 
	     }
    }
	if(te_policyt->preference_b)
    {
         vty_out(vty, "      Preference :%u \n",te_policyt->preference.preference);
    }
	te_policy_attr_sid_list *tmp = te_policyt->sid_list;

	while (tmp && tmp->head)
    {
	     struct te_policy_attr_segment *seg = tmp->head;
		 vty_out(vty, "      weight:%u \n",tmp->weight);
		 vty_out(vty, "      sid-list\n"); 
	     while(seg) {
		    vty_out(vty, "        %s\n", bgp_ls_router_id6_fmt(seg->sid)); 
		    seg = seg->next;			    
	     }
		 tmp = tmp->next;
    }
    return BGP_LS_RET_OK;
}




/*print as-path information*/
static BGP_LS_RET_T bgp_ls_as_path_vty_out(struct vty *vty, char *as_path)
{ 
	vty_out(vty, "    AS-PATH:\n");
	vty_out(vty, "      --%s\n",as_path);
	return BGP_LS_RET_OK;
}



/*print NODE NLRI information*/
static BGP_LS_RET_T bgp_ls_node_nlri_vty_out(struct vty *vty, struct list *list_node, int32_t use_json)
{
    NLRI_NODE *ls_nlri_node;
    BGP_LS_RET_T ret;
    struct listnode *node, *nnode;
    uint32_t idx = 0; 
	char zero[MAX_AS_PATH];
	memset(zero, 0, MAX_AS_PATH);

    for (ALL_LIST_ELEMENTS(list_node, node, nnode, ls_nlri_node))
    {
        vty_out(vty, "[NODE-%u] NLRI Node Descriptors:\n",++idx);
        
        vty_out(vty, "    Protocol-ID:%u(%s)\n ", ls_nlri_node->protocol_ID,
                        lookup_msg(bgp_ls_display_pro_id,ls_nlri_node->protocol_ID, "Unknown"));
        vty_out(vty, "   Identifier:%"PRIu64"\n", ls_nlri_node->ID);
		if(memcmp(ls_nlri_node->as_path , zero, MAX_AS_PATH))
		{
		    ret = bgp_ls_as_path_vty_out(vty,ls_nlri_node->as_path);
		}
        ret = bgp_ls_node_descriptor_vty_out(vty,&ls_nlri_node->local_node,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }
        ret = bgp_ls_node_attr_vty_out(vty,&ls_nlri_node->node_attr,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }
    }
 
    return ret;
}

/*print LINK descriptor information*/
static BGP_LS_RET_T bgp_ls_link_descriptor_vty_out(struct vty *vty, link_descriptor *ls_link, int32_t use_json)
{   
    uint32_t idx = 0;

    if (NULL == ls_link)
    {
        return BGP_LS_RET_OK;
    }

    vty_out(vty, "    Link Descriptors:\n");

    if (ls_link->link_IDs_b)
    {
        vty_out(vty, "      Link Local Identifiers: %u  Remote Identifiers: %u\n"
                        ,ls_link->link_IDs.LocalID,ls_link->link_IDs.RemoteID);  
    }

    if (ls_link->IPv4_interface_address_b)
    {
        vty_out(vty, "      IPv4 interface address: %s\n", bgp_ls_router_id_fmt(ls_link->IPv4_interface_address.Address));                
    }
    if (ls_link->IPv4_neighbor_address_b)
    { 
        vty_out(vty, "      IPv4 neighbor address: %s\n", bgp_ls_router_id_fmt(ls_link->IPv4_neighbor_address.Address));                
    }
    if (ls_link->IPv6_interface_address_b)
    { 
        vty_out(vty, "      IPv6 interface address: %s\n", bgp_ls_router_id6_fmt(ls_link->IPv6_interface_address.Address)); 
    }
    if (ls_link->IPv6_neighbor_address_b)
    { 
        vty_out(vty, "      IPv6 neighbor address: %s\n", bgp_ls_router_id6_fmt(ls_link->IPv6_neighbor_address.Address));  
    }
    if (ls_link->mt_ID_b)
    { 
        vty_out(vty, "      Link Multi-Topology ID Num:%u\n", ls_link->mt_ID.length/2);
        for(idx = 0;idx < (ls_link->mt_ID.length/2); idx++)
        {
            vty_out(vty, "        MT-ID[%u]: %u\n", idx, ls_link->mt_ID.IDs[idx]);
        }
    }  
    
    return BGP_LS_RET_OK;
}

/*print LINK NLRI information*/
static BGP_LS_RET_T bgp_ls_link_nlri_vty_out(struct vty *vty, struct list *list_link, int32_t use_json)
{
    NLRI_LINK *ls_nlri_link;
    BGP_LS_RET_T ret;
    struct listnode *node, *nnode;
    uint32_t idx = 0; 
	char zero[MAX_AS_PATH];
	memset(zero, 0, MAX_AS_PATH);
    
    for (ALL_LIST_ELEMENTS(list_link, node, nnode, ls_nlri_link))
    {       
        
        vty_out(vty, "[LINK-%u] NLRI Link Descriptors:\n",++idx);
        vty_out(vty, "    Protocol-ID:%u(%s) \n ", ls_nlri_link->protocol_ID,
                        lookup_msg(bgp_ls_display_pro_id,ls_nlri_link->protocol_ID, "Unknown"));
        vty_out(vty, "   Identifier:%"PRIu64"\n", ls_nlri_link->ID);
		if(memcmp(ls_nlri_link->as_path , zero, MAX_AS_PATH))
		{
		    ret = bgp_ls_as_path_vty_out(vty,ls_nlri_link->as_path);

		}
        ret = bgp_ls_node_descriptor_vty_out(vty,&ls_nlri_link->local_node,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }
        ret = bgp_ls_node_descriptor_vty_out(vty,&ls_nlri_link->remote_node,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }
        ret = bgp_ls_link_descriptor_vty_out(vty,&ls_nlri_link->link,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }
        ret = bgp_ls_link_attr_vty_out(vty,&ls_nlri_link->link_attr,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }

    }
   
    return ret;
}

/*print prefix descriptor information*/
static BGP_LS_RET_T bgp_ls_prefix_descriptor_vty_out(struct vty *vty, prefix_descriptor *ls_prefix,bool_t isIPv4,int32_t use_json)
{       
    uint32_t idx = 0;

    if (NULL == ls_prefix)
    {
        return BGP_LS_RET_OK;
    }

    vty_out(vty, "    Prefix Descriptors:\n");

    if (ls_prefix->ospf_route_type_b)
    { 
        vty_out(vty, "      Prefix Protection Type: %u(%s)\n"
               , ls_prefix->ospf_route_type.route_type
               , ls_prefix->ospf_route_type.route_type == OSPF_ROUTE_TYPE_INTRAAREA? "Intra-Area":
                    ls_prefix->ospf_route_type.route_type == OSPF_ROUTE_TYPE_INTERAREA? "Inter-Area":
                    ls_prefix->ospf_route_type.route_type == OSPF_ROUTE_TYPE_EXTERNAL1? "External 1":
                    ls_prefix->ospf_route_type.route_type == OSPF_ROUTE_TYPE_EXTERNAL2? "External 2":
                    ls_prefix->ospf_route_type.route_type == OSPF_ROUTE_TYPE_NSSA1? "NSSA 1" :
                    ls_prefix->ospf_route_type.route_type == OSPF_ROUTE_TYPE_NSSA2? "NSSA 2":"unknown");
    }

    if (ls_prefix->IP_reachability_info_b)
    {  
        vty_out(vty, "      IP Reachability Prefix Length: %u IP Prefix:",ls_prefix->IP_reachability_info.PrefixLength);
        char ip_char[46] = {0};
        if (isIPv4)
        {
            inet_ntop(AF_INET, ls_prefix->IP_reachability_info.Prefix, ip_char, INET_ADDRSTRLEN);
        }
        else
        {
            inet_ntop(AF_INET6, ls_prefix->IP_reachability_info.Prefix, ip_char, INET6_ADDRSTRLEN);
        }
        vty_out(vty, "%s/%u\n",ip_char,ls_prefix->IP_reachability_info.PrefixLength); 
    }
    if (ls_prefix->mt_ID_b)
     { 
        vty_out(vty, "      Prefix Multi-Topology ID Num:%u\n", ls_prefix->mt_ID.length/2);
        for(idx = 0;idx < (uint32_t)(ls_prefix->mt_ID.length/2); idx++)
        {
            vty_out(vty, "        MT-ID[%u]: %u\n", idx, ls_prefix->mt_ID.IDs[idx]);
        }
    }        
    return BGP_LS_RET_OK;
}

/*print prefix NLRI information*/
static BGP_LS_RET_T bgp_ls_ip4_prefix_nlri_vty_out(struct vty *vty, struct list *list_prefix, int32_t use_json)
{
    NLRI_PREFIX *ls_nlri_prefix;
    BGP_LS_RET_T ret;
    struct listnode *node, *nnode;
    uint32_t idx = 0; 

    for (ALL_LIST_ELEMENTS(list_prefix, node, nnode, ls_nlri_prefix))
    {       
        vty_out(vty, "[PREFIX4-%u] NLRI IPv4 Topology Prefix Descriptors:\n",++idx);
        vty_out(vty, "    Protocol-ID:%u(%s) \n ", ls_nlri_prefix->protocol_ID,
                        lookup_msg(bgp_ls_display_pro_id,ls_nlri_prefix->protocol_ID, "Unknown"));
        vty_out(vty, "   Identifier:%"PRIu64"\n", ls_nlri_prefix->ID);
        ret = bgp_ls_node_descriptor_vty_out(vty,&ls_nlri_prefix->local_node,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }
        ret = bgp_ls_prefix_descriptor_vty_out(vty,&ls_nlri_prefix->prefix,true,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }
        ret = bgp_ls_prefix_attr_vty_out(vty,&ls_nlri_prefix->prefix_attr,true,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }

    }
   
    return ret;
}

static BGP_LS_RET_T bgp_ls_te_policy_nlri_vty_out(struct vty *vty, struct list *list_te_policy, int32_t use_json)
{
    NLRI_TE_POLICY *ls_nlri_te_policy;
    BGP_LS_RET_T ret;
    struct listnode *node, *nnode;
    uint32_t idx = 0; 
	char zero[MAX_AS_PATH];
	memset(zero, 0, MAX_AS_PATH);
	
    for (ALL_LIST_ELEMENTS(list_te_policy, node, nnode, ls_nlri_te_policy))
    {   
        vty_out(vty, "[TE-POLICY-%u] NLRI IPv6 Te Policy Descriptors:\n",++idx);    
        vty_out(vty, "    Protocol-ID:%u(%s) \n ", ls_nlri_te_policy->protocol_ID,
                        lookup_msg(bgp_ls_display_pro_id,ls_nlri_te_policy->protocol_ID, "Unknown"));
        vty_out(vty, "   Identifier:%"PRIu64"\n", ls_nlri_te_policy->ID);

		if(memcmp(ls_nlri_te_policy->as_path , zero, MAX_AS_PATH))
		{
			ret = bgp_ls_as_path_vty_out(vty,ls_nlri_te_policy->as_path);
		}
		
        ret = bgp_ls_node_descriptor_vty_out(vty,&ls_nlri_te_policy->local_node,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }
		ret = bgp_te_policy_descriptor_vty_out(vty,&ls_nlri_te_policy->te_policy_desc,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }
		ret = bgp_te_policy_attr_vty_out(vty,&ls_nlri_te_policy->te_policy_attr,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }
    }
   
    return ret;
}


static BGP_LS_RET_T bgp_ls_ip6_prefix_nlri_vty_out(struct vty *vty, struct list *list_prefix, int32_t use_json)
{
    NLRI_PREFIX *ls_nlri_prefix;
    BGP_LS_RET_T ret;
    struct listnode *node, *nnode;
    uint32_t idx = 0; 
	char zero[MAX_AS_PATH];
	memset(zero, 0, MAX_AS_PATH);

    for (ALL_LIST_ELEMENTS(list_prefix, node, nnode, ls_nlri_prefix))
    {   
        vty_out(vty, "[PREFIX6-%u] NLRI IPv6 Topology Prefix Descriptors:\n",++idx);    
        vty_out(vty, "    Protocol-ID:%u(%s) \n ", ls_nlri_prefix->protocol_ID,
                        lookup_msg(bgp_ls_display_pro_id,ls_nlri_prefix->protocol_ID, "Unknown"));
        vty_out(vty, "   Identifier:%"PRIu64"\n", ls_nlri_prefix->ID);
		if(memcmp(ls_nlri_prefix->as_path , zero, MAX_AS_PATH))
		{
		    ret = bgp_ls_as_path_vty_out(vty,ls_nlri_prefix->as_path);

		}
        ret = bgp_ls_node_descriptor_vty_out(vty,&ls_nlri_prefix->local_node,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }
        ret = bgp_ls_prefix_descriptor_vty_out(vty,&ls_nlri_prefix->prefix,false,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }
        ret = bgp_ls_prefix_attr_vty_out(vty,&ls_nlri_prefix->prefix_attr,false,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }
    }
   
    return ret;
}

static BGP_LS_RET_T bgp_ls_sr6_sid_nlri_vty_out(struct vty *vty, struct list *list_prefix, int32_t use_json)
{
    NLRI_SR6_SID *ls_nlri_sr6_sid;
    BGP_LS_RET_T ret;
    struct listnode *node, *nnode;
    uint32_t idx = 0; 
	char zero[MAX_AS_PATH];
	memset(zero, 0, MAX_AS_PATH);

    for (ALL_LIST_ELEMENTS(list_prefix, node, nnode, ls_nlri_sr6_sid))
    {
        vty_out(vty, "[SRv6 SID-%u] NLRI SRv6 SID Descriptors:\n",++idx);
        vty_out(vty, "    Protocol-ID:%u(%s) \n ", ls_nlri_sr6_sid->protocol_ID,
                        lookup_msg(bgp_ls_display_pro_id,ls_nlri_sr6_sid->protocol_ID, "Unknown"));
        vty_out(vty, "   Identifier:%"PRIu64"\n", ls_nlri_sr6_sid->ID);
		if(memcmp(ls_nlri_sr6_sid->as_path , zero, MAX_AS_PATH))
		{
		    ret = bgp_ls_as_path_vty_out(vty,ls_nlri_sr6_sid->as_path);

		}
        ret = bgp_ls_node_descriptor_vty_out(vty,&ls_nlri_sr6_sid->local_node,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }

        // bgp_ls_sr6_sid_descriptor_vty_out
        vty_out(vty, "    SRv6 SID Descriptors:\n");
        vty_out(vty, "      SRv6 SID: %s\n", bgp_ls_router_id6_fmt(ls_nlri_sr6_sid->sr6_sid_desc.sid));
                
        ret = bgp_ls_sr6_sid_attr_vty_out(vty,&ls_nlri_sr6_sid->sr6_sid_attr,false,use_json);
        if (BGP_LS_RET_OK != ret)
        {
            break;
        }        
    }
    return ret;
}


/*Display LS information received from neighbors*/
int bgp_ls_show_neighbor(struct vty *vty, struct peer *peer, afi_t afi, safi_t safi,
		    enum bgp_show_type type, enum bgp_ls_vty_enum subtype, int32_t use_json)
{
//	json_object *json_paths = NULL;
    BGP_LS_RET_T ret = BGP_LS_RET_OK;
    
    if ((type != bgp_show_type_ls_neighbor) ||  (NULL == peer))
    {
        return CMD_SUCCESS;
    }
    
	if ((0 == peer->afc[AFI_BGPLS][SAFI_BGP_LS])
          && (0 == peer->afc[AFI_BGPLS][SAFI_BGP_LS_VPN]))
    {
	
		vty_out(vty, "%% No such neighbor or address family\n");
		return CMD_WARNING;
	}

    vty_out(vty, "bgp link state reach nlri:\n");	
    if (BGP_LS_VTY_NLRI_NODE == subtype)
    {
        ret = bgp_ls_node_nlri_vty_out(vty, peer->lsdb_nei->reach_node,use_json);
    }
    else if (BGP_LS_VTY_NLRI_LINK == subtype)
    {
        ret = bgp_ls_link_nlri_vty_out(vty, peer->lsdb_nei->reach_link,use_json);
    }
    else if (BGP_LS_VTY_NLRI_IP4_PREFIX == subtype)
    {
        ret = bgp_ls_ip4_prefix_nlri_vty_out(vty, peer->lsdb_nei->reach_prefix_ip4,use_json);
    }
    else if (BGP_LS_VTY_NLRI_IP6_PREFIX == subtype)
    {
        ret = bgp_ls_ip6_prefix_nlri_vty_out(vty, peer->lsdb_nei->reach_prefix_ip6,use_json);
    }
	else if (BGP_LS_VTY_NLRI_TE_POLICY == subtype)
    {
        ret = bgp_ls_te_policy_nlri_vty_out(vty, peer->lsdb_nei->reach_te_policy,use_json);
    }
    else
    {
        ret = bgp_ls_node_nlri_vty_out(vty, peer->lsdb_nei->reach_node,use_json);
        ret |= bgp_ls_link_nlri_vty_out(vty, peer->lsdb_nei->reach_link,use_json);
        ret |= bgp_ls_ip4_prefix_nlri_vty_out(vty, peer->lsdb_nei->reach_prefix_ip4,use_json);
        ret |= bgp_ls_ip6_prefix_nlri_vty_out(vty, peer->lsdb_nei->reach_prefix_ip6,use_json);
        ret |= bgp_ls_sr6_sid_nlri_vty_out(vty, peer->lsdb_nei->reach_sr6_sid,use_json);
		ret |= bgp_ls_te_policy_nlri_vty_out(vty, peer->lsdb_nei->reach_te_policy,use_json);
    }    

	if (BGP_DEBUG(link_state,BGPLS))
    {
		vty_out(vty, "bgp link state withdraw nlri:\n");	
		if (BGP_LS_VTY_NLRI_NODE == subtype)
		{
			ret = bgp_ls_node_nlri_vty_out(vty, peer->lsdb_nei->withdraw_node,use_json);
		}
		else if (BGP_LS_VTY_NLRI_LINK == subtype)
		{
			ret = bgp_ls_link_nlri_vty_out(vty, peer->lsdb_nei->withdraw_link,use_json);
		}
		else if (BGP_LS_VTY_NLRI_IP4_PREFIX == subtype)
		{
			ret = bgp_ls_ip4_prefix_nlri_vty_out(vty, peer->lsdb_nei->withdraw_prefix_ip4,use_json);
		}
		else if (BGP_LS_VTY_NLRI_IP6_PREFIX == subtype)
		{
			ret = bgp_ls_ip6_prefix_nlri_vty_out(vty, peer->lsdb_nei->withdraw_prefix_ip6,use_json);
		}
		else
		{
			ret = bgp_ls_node_nlri_vty_out(vty, peer->lsdb_nei->withdraw_node,use_json);
			ret |= bgp_ls_link_nlri_vty_out(vty, peer->lsdb_nei->withdraw_link,use_json);
			ret |= bgp_ls_ip4_prefix_nlri_vty_out(vty, peer->lsdb_nei->withdraw_prefix_ip4,use_json);
			ret |= bgp_ls_ip6_prefix_nlri_vty_out(vty, peer->lsdb_nei->withdraw_prefix_ip6,use_json);
		}

	
        vty_out(vty, "bgp link state attribute:\n");
        ret |= bgp_ls_attr_vty_out(vty, peer->lsdb_nei->attri_node, BGP_LS_NLRI_TYPE_NODE);
        ret |= bgp_ls_attr_vty_out(vty, peer->lsdb_nei->attri_link, BGP_LS_NLRI_TYPE_LINK);
        ret |= bgp_ls_attr_vty_out(vty, peer->lsdb_nei->attri_prefix_ip4, BGP_LS_NLRI_TYPE_IP4_PREFIX);
        ret |= bgp_ls_attr_vty_out(vty, peer->lsdb_nei->attri_prefix_ip6, BGP_LS_NLRI_TYPE_IP6_PREFIX);
    }

	return CMD_SUCCESS;
}

#if 0
/*Display LS information received from ISIS/OSPF locally*/
int bgp_ls_show_local(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
            enum bgp_show_type type, enum bgp_ls_vty_enum subtype, int32_t use_json)
{
//    json_object *json_paths = NULL;
    BGP_LS_RET_T ret = BGP_LS_RET_OK;

    if ((type != bgp_show_type_ls_local) || (NULL == bgp))
    {
        return CMD_SUCCESS;
    }
    vty_out(vty, "bgp link state reach nlri:\n");	
    if (BGP_LS_VTY_NLRI_NODE == subtype)
    {
        ret = bgp_ls_node_nlri_vty_out(vty, bgp->lsdb_loc->reach_node,use_json);
    }
    else if (BGP_LS_VTY_NLRI_LINK == subtype)
    {
        ret = bgp_ls_link_nlri_vty_out(vty, bgp->lsdb_loc->reach_link,use_json);
    }
    else if (BGP_LS_VTY_NLRI_IP4_PREFIX == subtype)
    {
        ret = bgp_ls_ip4_prefix_nlri_vty_out(vty, bgp->lsdb_loc->reach_prefix_ip4,use_json);
    }
    else if (BGP_LS_VTY_NLRI_IP6_PREFIX == subtype)
    {
        ret = bgp_ls_ip6_prefix_nlri_vty_out(vty, bgp->lsdb_loc->reach_prefix_ip6,use_json);
    }
    else
    {
        ret = bgp_ls_node_nlri_vty_out(vty, bgp->lsdb_loc->reach_node,use_json);
        ret |= bgp_ls_link_nlri_vty_out(vty, bgp->lsdb_loc->reach_link,use_json);
        ret |= bgp_ls_ip4_prefix_nlri_vty_out(vty, bgp->lsdb_loc->reach_prefix_ip4,use_json); 
        ret |= bgp_ls_ip6_prefix_nlri_vty_out(vty, bgp->lsdb_loc->reach_prefix_ip6,use_json);
    }
    
    vty_out(vty, "bgp link state withdraw nlri:\n");	
    if (BGP_LS_VTY_NLRI_NODE == subtype)
    {
        ret = bgp_ls_node_nlri_vty_out(vty, bgp->lsdb_loc->withdraw_node,use_json);
    }
    else if (BGP_LS_VTY_NLRI_LINK == subtype)
    {
        ret = bgp_ls_link_nlri_vty_out(vty, bgp->lsdb_loc->withdraw_link,use_json);
    }
    else if (BGP_LS_VTY_NLRI_IP4_PREFIX == subtype)
    {
        ret = bgp_ls_ip4_prefix_nlri_vty_out(vty, bgp->lsdb_loc->withdraw_prefix_ip4,use_json);
    }
    else if (BGP_LS_VTY_NLRI_IP6_PREFIX == subtype)
    {
        ret = bgp_ls_ip6_prefix_nlri_vty_out(vty, bgp->lsdb_loc->withdraw_prefix_ip6,use_json);
    }
    else
    {
        ret = bgp_ls_node_nlri_vty_out(vty, bgp->lsdb_loc->withdraw_node,use_json);
        ret |= bgp_ls_link_nlri_vty_out(vty, bgp->lsdb_loc->withdraw_link,use_json);
        ret |= bgp_ls_ip4_prefix_nlri_vty_out(vty, bgp->lsdb_loc->withdraw_prefix_ip4,use_json);
        ret |= bgp_ls_ip6_prefix_nlri_vty_out(vty, bgp->lsdb_loc->withdraw_prefix_ip6,use_json);
    }

    if (BGP_DEBUG(link_state,BGPLS))
    {
        vty_out(vty, "bgp link state attribute:\n");
        ret |= bgp_ls_attr_vty_out(vty, bgp->lsdb_loc->attri_node, BGP_LS_NLRI_TYPE_NODE);
        ret |= bgp_ls_attr_vty_out(vty, bgp->lsdb_loc->attri_link, BGP_LS_NLRI_TYPE_LINK);
        ret |= bgp_ls_attr_vty_out(vty, bgp->lsdb_loc->attri_prefix_ip4, BGP_LS_NLRI_TYPE_IP4_PREFIX);
        ret |= bgp_ls_attr_vty_out(vty, bgp->lsdb_loc->attri_prefix_ip6, BGP_LS_NLRI_TYPE_IP6_PREFIX);
    }
    if (BGP_LS_RET_OK != ret)
    {
        vty_out(vty, "%% bgp link state address family error.\n");
	    return CMD_WARNING;
    }
           
    return CMD_SUCCESS;
}
#endif 

/*origin attr data buf convert into string format*/
static char *bgp_ls_buf_attr_2_str(int format, BGP_LS_TLV *origin_buf)
{    
    int idx;
 	uint16_t ls_tlv_type = 0;
	int16_t ls_tlv_len = 0;
	uint8_t *pnt; 
    uint8_t *tmp_pnt; 
    uint8_t *lim; 

    int str_size;
    int str_pnt;
    char *str_buf;
    int len_written = 0;
    char extra[3] = "";
    char pre_extra[3] = "";
    const struct message *bgp_ls_display;
    bgp_ls_display = bgp_ls_display_tlv;

    if (format == BGP_LS_STR_DISPLAY)
    {
        snprintf(pre_extra, sizeof(pre_extra), "\t");
        snprintf(extra, sizeof(extra), "\n");
    }
    
    /* Prepare buffer.  */
    str_buf = XMALLOC(MTYPE_BGPLS_STR, LS_STR_DEFAULT_LEN + 1);
    str_size = LS_STR_DEFAULT_LEN;
    memset(str_buf, 0, LS_STR_DEFAULT_LEN + 1);
    str_buf[0] = '\0';
    str_pnt = 0;    

    /*parse buf*/
    if ((NULL == origin_buf) || (NULL == origin_buf->value))
    {
        return str_buf;
    }    
    
    /*header*/
    len_written = snprintf(str_buf + str_pnt, (str_size - str_pnt), "%s attribute(length:%u) %s",
                           pre_extra,
                           origin_buf->length,
                           extra);
    str_pnt += len_written; 
    
    lim = origin_buf->value + origin_buf->length;    
    pnt = origin_buf->value;    
    for (; pnt < lim; pnt += ls_tlv_len)
    {
        /*parse Node Descriptor TLVs Type*/
        DECODE_UINT16(pnt,ls_tlv_type);
        
        /*parse Node length  */
        DECODE_UINT16(pnt,ls_tlv_len);
        
        /* Make it sure size is enough.  */
        if (str_pnt >= str_size)
        {
            break;
        }
        
        /*type | length*/
        len_written = snprintf(str_buf + str_pnt, (str_size - str_pnt), "%s type:%s length:%u %s",
                                pre_extra,
                                lookup_msg(bgp_ls_display,ls_tlv_type, "Unknown"),
                                ls_tlv_len,
                                extra);
        str_pnt += len_written; 

        /*value*/
        len_written = snprintf(str_buf + str_pnt, (str_size - str_pnt), "%s Content(Hex):",
                                pre_extra);
        str_pnt += len_written;

        tmp_pnt = pnt;
        for (idx = 0;idx < ls_tlv_len; idx++)
        {   
            if (idx%32 == 0)
            {
                len_written = snprintf(str_buf + str_pnt, (str_size - str_pnt), "%s%s",
                                    extra, pre_extra);
                str_pnt += len_written;
            }
            len_written = snprintf(str_buf + str_pnt, (str_size - str_pnt), "%02x", *tmp_pnt++);
            str_pnt += len_written;            
        }
        len_written = snprintf(str_buf + str_pnt, (str_size - str_pnt), "%s", extra);
        str_pnt += len_written; 
    }
        
    return str_buf;
}

char *bgp_ls_attr_str(BGP_LS_ATTR *ls_attr)
{
    char *tmp_str = NULL;
    tmp_str = bgp_ls_buf_attr_2_str(BGP_LS_STR_DISPLAY, &ls_attr->origin_buf);
    bgp_ls_str_alloc(&ls_attr->str,tmp_str);
    XFREE(MTYPE_BGPLS_STR, tmp_str);    
	return ls_attr->str;
}


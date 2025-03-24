/***************************************************************************
*
* This is an implementation of BGP Link State as per RFC 7752
* Copyright (C) 2020 CTBRI
*
 ***************************************************************************/
 

#ifndef _FRR_BGP_LS_PUB_H
#define _FRR_BGP_LS_PUB_H

//#include "bgpd.h"

/*
 *                        TLV Format define
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              Type             |             Length            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  //                       Value  (variable)                     //
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*TLV长度宏定义*/
#define BGP_LS_TLV_TL_LENGTH  4
#define BGP_LS_ATTR_TLV_TL_LENGTH  4      
#define BGP_LS_ATTR_TLV_L_LENGTH  2 
#define BGP_LS_ATTR_TLV_T_LENGTH  2 
#define BGP_LS_NLRI_TLV_TL_LENGTH 4
#define BGP_LS_NLRI_HEAD_LENGTH 9
#define BGP_LS_NLRI_RT_DIST_VALUE 0
#define BGP_LS_NLRI_DEF_L3_RT_TOP 0
#define BGP_LS_CLIENT_OP_LENGTH 4
#define BGP_LS_ATTR_BUF_LENGTH 512
#define BGP_LS_NLRI_BUF_LENGTH 512

#define BGPLS_ERR_LOG 
#ifdef BGPLS_ERR_LOG
#define BGPLS_ERR(fmt, ...) flog_err(EC_BGP_LS_ATTRI_INVALID, fmt, ##__VA_ARGS__);
#else
#define BGPLS_ERR(fmt, ...)
#endif

#ifndef bool_t
typedef unsigned char bool_t;
#endif

/*use 'int' type store 'float' type value*/
#ifndef float_int32_t
typedef int float_int32_t;
#endif

/*use 'unsigned long long' type store 'float' type value*/
#ifndef float_int64_t
typedef unsigned long long float_int64_t;
#endif


#define DECODE_UINT8(_p,_v)\
do{\
	_v = 0;\
    _v |= (uint8_t)(*_p++);\
}while(0);

#define ENCODE_UINT8(_p,_v)\
do{\
	*_p++ = (uint8_t)_v;\
}while(0);

#define DECODE_UINT16(_p,_v)\
do{\
	_v = 0;\
    _v |= (uint16_t)(*_p++ << 8);\
    _v |= (uint16_t)(*_p++);\
}while(0);

#define ENCODE_UINT16(_p,_v)\
do{\
    *_p++ = (uint8_t)(_v >> 8);\
    *_p++ = (uint8_t)_v;\
}while(0);

#define DECODE_U24_UINT32(_p,_v)\
do{\
	_v = 0;\
    _v |= (uint32_t)(*_p++ << 16);\
    _v |= (uint32_t)(*_p++ << 8);\
    _v |= (uint32_t)(*_p++);\
}while(0);

#define ENCODE_U24_UINT32(_p,_v)\
do{\
    *_p++ = (uint8_t)(_v >> 16);\
    *_p++ = (uint8_t)(_v >> 8);\
    *_p++ = (uint8_t)_v;\
}while(0);

#define DECODE_U16_UINT32(_p,_v)\
do{\
	_v = 0;\
    _v |= (uint32_t)(*_p++ << 8);\
    _v |= (uint32_t)(*_p++);\
}while(0);


#define DECODE_FLOAT32(_p,_v)\
do{\
	(_v) = 0;\
    (_v) |= (float_int32_t)(*_p++ << 24);\
    (_v) |= (float_int32_t)(*_p++ << 16);\
    (_v) |= (float_int32_t)(*_p++ << 8);\
    (_v) |= (float_int32_t)(*_p++);\
}while(0);

#define ENCODE_FLOAT32(_p,_v)\
do{\
    *_p++ = (float_int32_t)((_v) >> 24);\
    *_p++ = (float_int32_t)((_v) >> 16);\
    *_p++ = (float_int32_t)((_v) >> 8);\
    *_p++ = (float_int32_t)(_v);\
}while(0);

#define DECODE_UINT32(_p,_v)\
do{\
	(_v) = 0;\
    (_v) |= (uint32_t)(*_p++ << 24);\
    (_v) |= (uint32_t)(*_p++ << 16);\
    (_v) |= (uint32_t)(*_p++ << 8);\
    (_v) |= (uint32_t)(*_p++);\
}while(0);

#define ENCODE_UINT32(_p,_v)\
do{\
    *_p++ = (uint8_t)((_v) >> 24);\
    *_p++ = (uint8_t)((_v) >> 16);\
    *_p++ = (uint8_t)((_v) >> 8);\
    *_p++ = (uint8_t)(_v);\
}while(0);

#define DECODE_UINT64(_p,_v)\
do{\
	_v = 0;\
	_v |= ((uint64_t)*_p++ << 56);\
	_v |= ((uint64_t)*_p++ << 48);\
    _v |= ((uint64_t)*_p++ << 40);\
    _v |= ((uint64_t)*_p++ << 32);\
    _v |= ((uint64_t)*_p++ << 24);\
    _v |= ((uint64_t)*_p++ << 16);\
    _v |= ((uint64_t)*_p++ << 8);\
    _v |= ((uint64_t)*_p++);\
}while(0);

#define ENCODE_UINT64(_p,_v)\
do{\
    *_p++ = (uint8_t)(_v >> 56);\
    *_p++ = (uint8_t)(_v >> 48);\
    *_p++ = (uint8_t)(_v >> 40);\
    *_p++ = (uint8_t)(_v >> 32);\
    *_p++ = (uint8_t)(_v >> 24);\
    *_p++ = (uint8_t)(_v >> 16);\
    *_p++ = (uint8_t)(_v >> 8);\
    *_p++ = (uint8_t)_v;\
}while(0);

/*TLV general package operation macro definition*/
#define LS_SERIALIZE_TLV(_s, _bool, _type, _func, _value_st)\
 do\
 {\
     if(_bool)\
     {\
         ls_tlv.type = (_type);\
         ls_tlv.length = STREAM_WRITEABLE(_s) - 4;\
         ls_tlv.value = STREAM_DATA(_s) + stream_get_endp(_s) + 4;\
         if (BGP_LS_RET_OK == _func(&ls_tlv, (_value_st)))\
         {\
             stream_putw(_s, ls_tlv.type);\
             stream_putw(_s, ls_tlv.length);  \
             stream_forward_endp(_s, ls_tlv.length);  \
         } \
     }\
 }while(0);

/*TLV General Decapsulation Operation Macro Definition*/
#define LS_DESERIALIZE_TLV(_s, _bool, _type, _func, _value_st)\
  do\
  {\
      if(_bool)\
      {\
          ls_tlv.type = (_type);\
          ls_tlv.length = STREAM_WRITEABLE(_s) - 4;\
          ls_tlv.value = STREAM_DATA(_s) + stream_get_getp(_s) + 4;\
          if (BGP_LS_RET_OK == _func(&ls_tlv, (_value_st)))\
          {\
              stream_getw(_s, ls_tlv.type);\
              stream_getw(_s, ls_tlv.length);  \
              stream_forward_getp(_s, ls_tlv.length);  \
          } \
      }\
  }while(0);

  
#define LS_PARSE_TLV(_T , _L, _V, _bool, _func, _value_st)\
  do\
  {\
      ls_tlv.type = _T;\
      ls_tlv.length = _L;\
      ls_tlv.value = _V;\
      if (BGP_LS_RET_OK == _func(&ls_tlv, (_value_st)))\
      {\
          _bool = true;\
      } \
  }while(0);

/*BGP-LS general return value type*/
typedef enum {
	BGP_LS_RET_OK = 0,
	BGP_LS_RET_ERROR = -1,
	BGP_LS_RET_ERROR_MEM = -2,
} BGP_LS_RET_T;

/* ISIS/OSPF Client data operation type */
typedef enum {
    BGP_LS_OP_ADD = 0,/*add or update data*/
    BGP_LS_OP_DEL = 1,/*delete data*/
} BGP_LS_OP_ENUM;


typedef enum {
    RSVP_TE = 8,
    SEGMENT_ROUTING = 9,
} NLRI_TE_POLICY_ENUM;

typedef enum {
    TYPE_CANDIDATE_PATH = 554,
} TE_POLICY_TYPE_ENUM;

typedef enum {
    TYPE_SR_SEGMENT = 1206,
} SR_SEGMENT_TYPE_ENUM;

typedef enum {
    TYPE_SEGMENT = 2,
} SEGMENT_TYPE_ENUM;



typedef enum {
    D_FLAG = 0x8000,
} U16_FLAGS_TYPE_ENUM;



typedef enum {
    E_FLAG = 0x80,
	O_FLAG = 0x40,	
} TE_POLICY_FLAGS_ENUM;



/*BGP-LS address protocol stack type*/
typedef enum {
    BGP_LS_NO_VPN_TYPE = 0,
    BGP_LS_VPN_TYPE = 1,
} BGP_LS_VPN_TYPE_ENUM;

typedef struct bgp_ls_tlv {
    /*metadata*/
	uint16_t type;
	int16_t length;
	uint8_t *value; /* will be extended */
}BGP_LS_TLV;


/*  0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |            NLRI Type          |     Total NLRI Length         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     //                  Link-State NLRI (variable)                 //
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/*BGP-LS NLRI type*/
typedef enum {
    BGP_LS_NLRI_TYPE_NODE = 1, /*Node NLRI [RFC7752]*/
    BGP_LS_NLRI_TYPE_LINK = 2, /*Link NLRI [RFC7752]*/
    BGP_LS_NLRI_TYPE_IP4_PREFIX = 3, /*IPv4 Topology Prefix NLRI [RFC7752]*/
    BGP_LS_NLRI_TYPE_IP6_PREFIX = 4, /*IPv6 Topology Prefix NLRI [RFC7752]*/
    
    BGP_LS_NLRI_TYPE_TE_POLICY = 5, /*"TE Policy NLRI type 
            (TEMPORARY - registered 2019-09-17, expires 2020-09-17)" [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_NLRI_TYPE_SR6_SID = 6, /*"SRv6 SID 
            (TEMPORARY -registered 2019-08-06, expires 2020-08-06)" [draft-ietf-idr-bgpls-srv6-ext]*/      
} BGP_NLRI_TYPE_ENUM;


/*Protocol-ID NLRI information source protocol*/
typedef enum {
    BGP_LS_PROTO_ISIS_L1 = 1, /*IS-IS Level 1 [RFC7752]*/
    BGP_LS_PROTO_ISIS_L2 = 2, /*IS-IS Level 2 [RFC7752]*/
    BGP_LS_PROTO_OSPF2 = 3, /*OSPFv2 [RFC7752]*/
    BGP_LS_PROTO_DIRECT = 4, /*Direct [RFC7752]*/
    BGP_LS_PROTO_STATIC= 5, /*Static configuration [RFC7752]*/
    BGP_LS_PROTO_OSPF3 = 6, /*OSPFv3 [RFC7752]*/
    BGP_LS_PROTO_BGP = 7, /*BGP [RFC-ietf-idr-bgpls-segment-routing-epe-19]*/
    BGP_LS_PROTO_RSVP_TE = 8, /*"RSVP-TE 
            (TEMPORARY - registered 2019-09-17, expires 2020-09-17)" [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_PROTO_SR = 9, /*"Segment Routing 
            (TEMPORARY - registered 2019-09-17, expires 2020-09-17)" [draft-ietf-idr-te-lsp-distribution]*/
} BGP_PROTO_ID_TYPE_ENUM;

/*
 * +-----------+---------------------+---------------+-----------------+
   |  TLV Code | Description         |   IS-IS TLV   | Value defined   |
   |   Point   |                     |    /Sub-TLV   | in:             |
   +-----------+---------------------+---------------+-----------------+
   |   0-255   | Reserved            |      22/4     |    xxxxxxxxxx   |
   |           |                     |               |                 | 
   |    256    | Local node          |      22/6     |    xxxxxxxxxx   | 
   |           | Descriptors         |               |                 | 
   |    257    | Remote node         |      22/8     |    xxxxxxxxxx   | 
   |           | Descriptors         |               |                 |
 * +-----------+---------------------+---------------+-----------------+
 */
 
/*Node Descriptor, Link Descriptor, Prefix Descriptor, and Attribute TLVs*/    
typedef enum {

    /*0-255, Reserved, [RFC7752]*/
    BGP_LS_LOCAL_NODE_DESC = 256, /*Local Node Descriptors, [RFC7752, Section 3.2.1.2]*/
    BGP_LS_REMOTE_NODE_DESC = 257, /*Remote Node Descriptors, [RFC7752, Section 3.2.1.3]*/
    BGP_LS_LINK_LOCAL_OR_REMOTE_ID = 258, /*Link Local/Remote Identifiers, [RFC5307, Section 1.1]*/
    BGP_LS_IP4_INF_ADDR = 259, /*IPv4 interface address, [RFC5305, Section 3.2]*/
    BGP_LS_IP4_NEIGHBOR_ADDR = 260, /*IPv4 neighbor address, [RFC5305, Section 3.3]*/
    BGP_LS_IP6_INF_ADDR = 261, /*IPv6 interface address, [RFC6119, Section 4.2]*/
    BGP_LS_IP6_NEIGHBOR_ADDR = 262, /*IPv6 neighbor address, [RFC6119, Section 4.3]*/
    BGP_LS_MUL_TOP_ID = 263, /*Multi-Topology ID, [RFC7752, Section 3.2.1.5]*/
    BGP_LS_OSPF_ROUTE_TYPE = 264, /*OSPF Route Type, [RFC7752, Section 3.2.3]*/
    BGP_LS_IP_REACH_INFO = 265, /*IP Reachability Information, [RFC7752, Section 3.2.3]*/
    BGP_LS_NODE_MSD = 266, /*"Node MSD 
                (TEMPORARY - registered 2017-11-02, extension registered 2019-10-09, expires 2020-11-02)",
                [draft-ietf-idr-bgp-ls-segment-routing-msd]*/
    BGP_LS_LINK_MSD = 267, /*"Link MSD 
                (TEMPORARY - registered 2017-11-02, extension registered 2019-10-09, expires 2020-11-02)",
                [draft-ietf-idr-bgp-ls-segment-routing-msd]*/
                
    /* 268-511, Unassigned, */
    BGP_LS_AUTO_SYS = 512, /*Autonomous System, [RFC7752, Section 3.2.1.4]*/
    BGP_LS_ID = 513, /*BGP-LS Identifier, [RFC7752, Section 3.2.1.4]*/
    BGP_LS_OSPF_AREA_ID = 514, /*OSPF Area-ID, [RFC7752, Section 3.2.1.4]*/
    BGP_LS_IGP_ROUTE_ID = 515, /*IGP Router-ID, [RFC7752, Section 3.2.1.4]*/
    BGP_LS_BGP_ROUTER_ID = 516, /*BGP Router-ID, [RFC-ietf-idr-bgpls-segment-routing-epe-19]*/
    BGP_LS_BGP_CONFRE_MEM = 517, /*BGP Confederation Member, [RFC-ietf-idr-bgpls-segment-routing-epe-19]*/
    BGP_LS_SRv6_SID_INFO = 518, /*"SRv6 SID Information TLV 
                (TEMPORARY -registered 2019-08-06, expires 2020-08-06)", [draft-ietf-idr-bgpls-srv6-ext]*/
                
    /* 519-549,  Unassigned*/
    BGP_LS_TUNNEL_ID = 550, /*"Tunnel ID TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_LSP_ID = 551, /*"LSP ID TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_IP46_TUNNEL_HEAD = 552, /*"IPv4/6 Tunnel Head-end address TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_IP46_TUNNEL_TAIL  = 553, /*"IPv4/6 Tunnel Tail-end address TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_SR_POLICY_CP_DESC = 554, /*"SR Policy CP Descriptor TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_MPLS_LOCAL_CROSS= 555, /*"MPLS Local Cross Connect TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_MPLS_CROSS_INF = 556, /*"MPLS Cross Connect Interface TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_MPLS_CROSS_FEC  = 557, /*"MPLS Cross Connect FEC TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
                
    /* 558-1023,  Unassigned*/
    BGP_LS_NODE_FLAG = 1024, /*Node Flag Bits, [RFC7752, Section 3.3.1.1]*/
    BGP_LS_OPAQUE_NODE_ATTRI = 1025, /*Opaque Node Attribute, [RFC7752, Section 3.3.1.5]*/
    BGP_LS_NODE_NAME = 1026, /*Node Name, [RFC7752, Section 3.3.1.3]*/
    BGP_LS_ISIS_AREA_ID = 1027, /*IS-IS Area Identifier, [RFC7752, Section 3.3.1.2]*/
    BGP_LS_IP4_LOCAL_NODE_RT_ID = 1028, /*IPv4 Router-ID of Local Node, [RFC5305, Section 4.3]*/
    BGP_LS_IP6_LOCAL_NODE_RT_ID = 1029, /*IPv6 Router-ID of Local Node, [RFC6119, Section 4.1]*/
    BGP_LS_IP4_REMOTE_NODE_RT_ID = 1030, /*IPv4 Router-ID of Remote Node, [RFC5305, Section 4.3]*/
    BGP_LS_IP6_REMOTE_NODE_RT_ID = 1031, /*IPv6 Router-ID of Remote Node, [RFC6119, Section 4.1]*/
    BGP_LS_SBFD_DISCRI = 1032, /*"S-BFD Discriminators TLV (TEMPORARY - 
                registered 2019-08-06, expires 2020-08-06)", [draft-ietf-idr-bgp-ls-sbfd-extensions]*/
                
    /* 1033,  Unassigned*/
    BGP_LS_SR_CAP = 1034, /*SR Capabilities, [RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.1.2]*/
    BGP_LS_SR_ALGO = 1035, /*SR Algorithm, [RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.1.3]*/
    BGP_LS_SR_LOCAL_BLK = 1036, /*SR Local Block, [RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.1.4]*/
    BGP_LS_SRMS_PREFRE = 1037, /*SRMS Preference, [RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.1.5]*/
    BGP_LS_SR6_CAP = 1038, /*"SRv6 Capabilities TLV (TEMPORARY - 
                registered 2019-08-06, expires 2020-08-06)", [draft-ietf-idr-bgpls-srv6-ext]*/
    BGP_LS_FLEX_ALGO = 1039, /*"Flex Algorithm Definition TLV (TEMPORARY - 
                registered 2019-08-06, expires 2020-08-06)", [draft-ietf-idr-bgp-ls-flex-algo]*/
    BGP_LS_FLEX_ALGO_EX = 1040, /*"Flex Algo Exclude Any Affinity sub-TLV (TEMPORARY - 
                registered 2019-08-06, expires 2020-08-06)", [draft-ietf-idr-bgp-ls-flex-algo]*/
    BGP_LS_FLEX_ALGO_IN = 1041, /*"Flex Algo Include Any Affinity sub-TLV (TEMPORARY - 
                registered 2019-08-06, expires 2020-08-06)", [draft-ietf-idr-bgp-ls-flex-algo]*/
    BGP_LS_FLEX_ALGO_IN_ALL = 1042, /*"Flex Algo Include All Affinity sub-TLV (TEMPORARY - 
                registered 2019-08-06, expires 2020-08-06)", [draft-ietf-idr-bgp-ls-flex-algo]*/
    BGP_LS_FLEX_ALGO_FLAG = 1043, /*"Flex Algo Definition Flags sub-TLV (TEMPORARY - 
                registered 2019-08-19, expires 2020-08-19)", [draft-ietf-idr-bgp-ls-flex-algo]*/
    BGP_LS_FLEX_ALGO_PRE_METRIC = 1044, /*"Flex Algorithm Prefix Metric TLV (TEMPORARY - 
                registered 2019-08-19, expires 2020-08-19)", [draft-ietf-idr-bgp-ls-flex-algo]*/
                
    /* 1045-1087,  Unassigned*/
    BGP_LS_ADMIN_GROUP = 1088, /*Administrative group (color), [RFC5305, Section 3.1]*/
    BGP_LS_MAX_LINK_BW = 1089, /*Maximum link bandwidth, [RFC5305, Section 3.4]*/
    BGP_LS_MAX_RESERV_LINK_BW  = 1090, /*Max. reservable link bandwidth, [RFC5305, Section 3.5]*/
    BGP_LS_UNRESERV_BW = 1091, /*Unreserved bandwidth, [RFC5305, Section 3.6]*/
    BGP_LS_TE_DEFAUT_METRIC = 1092, /*TE Default Metric, [RFC7752, Section 3.3.2.3]*/
    BGP_LS_LINK_PROTECT_TYPE = 1093, /*Link Protection Type, [RFC5307, Section 1.2]*/
    BGP_LS_MPLS_PRO_MASK = 1094, /*MPLS Protocol Mask, [RFC7752, Section 3.3.2.2]*/
    BGP_LS_IGP_METRIC = 1095, /*IGP Metric, [RFC7752, Section 3.3.2.4]*/
    BGP_LS_SHARE_RISK_LINK_GROUP = 1096, /*Shared Risk Link Group, [RFC7752, Section 3.3.2.5]*/
    BGP_LS_OPAQUE_LINK_ATTRI = 1097, /*Opaque Link Attribute, [RFC7752, Section 3.3.2.6]*/
    BGP_LS_LINK_NAME = 1098, /*Link Name, [RFC7752, Section 3.3.2.7]*/
    BGP_LS_ADJ_SID = 1099, /*Adjacency SID, [RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.2.1]*/
    BGP_LS_LAN_ADJ_SID = 1100, /*LAN Adjacency SID, [RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.2.2]*/
    BGP_LS_PEER_NODE_SID = 1101, /*PeerNode SID, [RFC-ietf-idr-bgpls-segment-routing-epe-19]*/
    BGP_LS_PEER_ADJ_SID = 1102, /*PeerAdj SID, [RFC-ietf-idr-bgpls-segment-routing-epe-19]*/
    BGP_LS_PEER_SET_SID = 1103, /*PeerSet SID, [RFC-ietf-idr-bgpls-segment-routing-epe-19]*/
    
    /* 1104,  Unassigned*/
    BGP_LS_RTM_CAP = 1105, /*RTM Capability, [RFC8169]*/
    BGP_LS_SR6_END_SID = 1106, /*"SRv6 End.X SID TLV (TEMPORARY - 
                registered 2019-08-06, expires 2020-08-06)", [draft-ietf-idr-bgpls-srv6-ext]*/
    BGP_LS_ISIS_SR6_LAN_END_SID = 1107, /*"IS-IS SRv6 LAN End.X SID TLV (TEMPORARY - 
                registered 2019-08-06, expires 2020-08-06)", [draft-ietf-idr-bgpls-srv6-ext]*/
    BGP_LS_OSPF3_SR6_LAN_END_SID = 1108, /*"OSPFv3 SRv6 LAN End.X SID TLV (TEMPORARY - 
                registered 2019-08-06, expires 2020-08-06)", [draft-ietf-idr-bgpls-srv6-ext]*/
                
    /* 1109-1113,  Unassigned*/
    BGP_LS_UNIDIRECT_LINK_DELAY = 1114, /*Unidirectional Link Delay, [RFC8571]*/
    BGP_LS_MINMAX_LINK_DELAY = 1115, /*Min/Max Unidirectional Link Delay, [RFC8571]*/
    BGP_LS_UNIDIRECT_DELAY_VAR = 1116, /*Unidirectional Delay Variation, [RFC8571]*/
    BGP_LS_UNIDIRECT_LINK_LOSS = 1117, /*Unidirectional Link Loss, [RFC8571]*/
    BGP_LS_UNIDIRECT_RES_BW = 1118, /*Unidirectional Residual Bandwidth, [RFC8571]*/
    BGP_LS_UNIDIRECT_AVAIL_BW = 1119, /*Unidirectional Available Bandwidth, [RFC8571]*/
    BGP_LS_UNIDIRECT_UTIL_BW = 1120, /*Unidirectional Utilized Bandwidth, [RFC8571]*/
    BGP_LS_GR_LINK_SHUTDOWN = 1121, /*Graceful-Link-Shutdown TLV, [RFC8379]*/
    BGP_LS_APP_SPEC_LINK_ATTRI = 1122, /*"Application Specific Link Attributes TLV 
                        (TEMPORARY - registered 2019-08-06, expires 2020-08-06)",
                        [draft-ietf-idr-bgp-ls-app-specific-attr]*/
                
    /* 1123-1151,  Unassigned*/
    BGP_LS_IGP_FLAG = 1152, /*IGP Flags, [RFC7752, Section 3.3.3.1]*/
    BGP_LS_IGP_ROUTE_TAG = 1153, /*IGP Route Tag, [RFC5130]*/
    BGP_LS_IGP_EXT_ROUTE_TAG  = 1154, /*IGP Extended Route Tag, [RFC5130]*/
    BGP_LS_PREFIX_METRIC = 1155, /*Prefix Metric, [RFC5305]*/
    BGP_LS_OSPF_FWD_ADD = 1156, /*OSPF Forwarding Address, [RFC2328]*/
    BGP_LS_OPAQUE_PREFIX_ATTRI = 1157, /*Opaque Prefix Attribute, [RFC7752, Section 3.3.3.6]*/
    BGP_LS_PREFIX_SID = 1158, /*Prefix SID, [RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.3.1]*/
    BGP_LS_RANGE = 1159, /*Range, [RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.3.4]*/
    
    /* 1160,  Unassigned*/
    BGP_LS_SID_LABEL = 1161, /*SID/Label, [RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.1.1]*/
    BGP_LS_SR6_LOCATER = 1162, /*"SRv6 Locator TLV (TEMPORARY - registered 2019-08-06, expires 2020-08-06)",
                        [draft-ietf-idr-bgpls-srv6-ext]*/
                
    /* 1163-1169,  Unassigned*/
    BGP_LS_PREFIX_ATTRI_FLAG = 1170, /*Prefix Attributes Flags, [RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.3.2]*/
    BGP_LS_SR_ROUTE_ID = 1171, /*Source Router-ID, [RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.3.3]*/
    BGP_LS_L3_BOND_MEM_ATTRI= 1172, /*L2 Bundle Member Attributes, [RFC-ietf-idr-bgp-ls-segment-routing-ext-16, Section 2.2.3]*/
    BGP_LS_EXT_ADMIN_GROUP = 1173, /*"Extended Administrative Group 
                        (TEMPORARY - registered 2018-04-09, extension registered 2019-06-13, expires 2020-04-09)",
                        [draft-ietf-idr-eag-distribution][RFC7308]*/
                
    /* 1174-1199,  Unassigned*/
    BGP_LS_MPLS_TE_POLICY_STATE = 1200, /*"MPLS-TE Policy State TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_SR_BSID = 1201, /*"SR BSID TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_SR_CP_STATE = 1202, /*"SR CP State TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_SR_CP_NAME = 1203, /*"SR CP Name TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_SR_CP_CONST = 1204, /*"SR CP Constraints TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_SR_SEGMENT_LIST = 1205, /*"SR Segment List TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_SR_SEGMENT_SUB = 1206, /*"SR Segment sub-TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_SR_SEGMENT_LIST_METRIC = 1207, /*"SR Segment List Metric sub-TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_SR_AFFI_CONST = 1208, /*"SR Affinity Constraint sub-TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_SR_SRLG_CONST = 1209, /*"SR SRLG Constraint sub-TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_SR_BW_CONST = 1210, /*"SR Bandwidth Constraint sub-TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
    BGP_LS_SR_DIS_GROUP_CONST = 1211, /*"SR Disjoint Group Constraint sub-TLV (TEMPORARY - 
                registered 2019-09-17, expires 2020-09-17)", [draft-ietf-idr-te-lsp-distribution]*/
                
    /* 1212-1249,  Unassigned*/
    BGP_LS_SR6_END_FUNC = 1250, /*"SRv6 Endpoint Function TLV 
                (TEMPORARY - registered 2019-08-06, expires 2020-08-06)", [draft-ietf-idr-bgpls-srv6-ext]*/
    BGP_LS_SR6_BGP_PEER_NODE_SID = 1251, /*"SRv6 BGP Peer Node SID TLV (TEMPORARY - 
                registered 2019-08-06, expires 2020-08-06)", [draft-ietf-idr-bgpls-srv6-ext]*/
    BGP_LS_SR6_SID_STRUCT = 1252, /*"SRv6 SID Structure TLV 
                (TEMPORARY - registered 2019-08-19, expires 2020-08-19)", [draft-ietf-idr-bgpls-srv6-ext]*/
                  
    /* 1253-65535,  Unassigned*/
} BGP_LS_TLV_TYPE_ENUM;


typedef enum {
	MULTI_TOPOLOGY_ID_TYPE_LINK_DESC  = 0,  /*for nlri link descriptor*/
	MULTI_TOPOLOGY_ID_TYPE_PREFIX_DESC,     /*for nlri prefix descriptor*/
	MULTI_TOPOLOGY_ID_TYPE_NODE_ATTRI,      /*for path node attribute*/
}MULTI_TOPOLOGY_ID_TYPE_ENUM;

// link_descriptor_multi_topology_ID is a link descriptor contained in a bgp-ls link nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.5
typedef struct {
    MULTI_TOPOLOGY_ID_TYPE_ENUM type;/*link_descriptor or prefix_descriptor or node_attribute*/
    uint16_t length;
	uint16_t *IDs;
}multi_topology_ID;



/* node_attr_code_ describes the type of node attribute contained in a bgp-ls attribute
 * https://tools.ietf.org/html/rfc7752#section-3.3.1
 */
typedef enum {
	NODE_ATTR_CODE_MULTI_TOPOLOGY_ID    = BGP_LS_MUL_TOP_ID,
	NODE_ATTR_CODE_NODE_FLAG_BITS       = BGP_LS_NODE_FLAG,
	NODE_ATTR_CODE_OPAQUE_NODE_ATTR     = BGP_LS_OPAQUE_NODE_ATTRI,
	NODE_ATTR_CODE_NODE_NAME            = BGP_LS_NODE_NAME,
	NODE_ATTR_CODE_ISIS_AREA_ID         = BGP_LS_ISIS_AREA_ID,
	NODE_ATTR_CODE_LOCAL_IPV4_ROUTER_ID = BGP_LS_IP4_LOCAL_NODE_RT_ID,
	NODE_ATTR_CODE_LOCAL_IPV6_ROUTER_ID = BGP_LS_IP6_LOCAL_NODE_RT_ID,
	
	/*RFC7752 EXCLUDE....*/
	NODE_ATTR_CODE_SR_CAPS              = BGP_LS_SR_CAP,
	NODE_ATTR_CODE_SR_ALGO              = BGP_LS_SR_ALGO,
	NODE_ATTR_CODE_SR_LOCAL_BLOCK       = BGP_LS_SR_LOCAL_BLK,
	NODE_ATTR_CODE_SRMS_PREF            = BGP_LS_SRMS_PREFRE,
	NODE_ATTR_CODE_SR_SID_LABEL         = BGP_LS_SID_LABEL,
	NODE_ATTR_CODE_SR6_CAPS             = BGP_LS_SR6_CAP,	
	
	
}NODE_ATTR_CODE_ENUM;

/* BGP-LS Node flags : https://tools.ietf.org/html/rfc7752#section-3.3.1.1
 *
 * +-----------------+-------------------------+------------+
 * |        Bit       | Description             | Reference  |
 * +-----------------+-------------------------+------------+
 * |       'O'       | Overload Bit            | [ISO10589] |
 * |       'T'       | Attached Bit            | [ISO10589] |
 * |       'E'       | External Bit            | [RFC2328]  |
 * |       'B'       | ABR Bit                 | [RFC2328]  |
 * |       'R'       | Router Bit              | [RFC5340]  |
 * |       'V'       | V6 Bit                  | [RFC5340]  |
 * | Reserved (Rsvd) | Reserved for future use |            |
 * +-----------------+-------------------------+------------+
 *
* node_attr_node_flag_bits is a node attribute contained in a bgp-ls attribute.*/
typedef enum {
    NODE_ATTR_NODE_FLAG_OVERLOAD    = (1<<7),
    NODE_ATTR_NODE_FLAG_ATTACHED    = (1<<6),
    NODE_ATTR_NODE_FLAG_EXTERNAL    = (1<<5),
    NODE_ATTR_NODE_FLAG_ABR         = (1<<4),
    NODE_ATTR_NODE_FLAG_ROUTER      = (1<<3),
    NODE_ATTR_NODE_FLAG_V6          = (1<<2),

}NODE_ATTR_NODE_FLAG_BITS_ENUM;

typedef struct {
	uint8_t Overload;
	uint8_t Attached;
	uint8_t External;
	uint8_t ABR;
	uint8_t Router;
	uint8_t V6;
}node_attr_node_flag_bits;


// node_attr_opaque_node_attr is a node attribute contained a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.1.5
typedef struct  {
    uint16_t length;
	uint8_t *Data;
}node_attr_opaque_node_attr;


// node_attr_node_name is a node attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.1.3
typedef struct {
    uint16_t length;
	uint8_t *Name;
}node_attr_node_name;


// node_attr_IsIs_area_ID is a node attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.1.2
typedef struct   {
	uint16_t length;
	uint8_t *AreaID;
}node_attr_IsIs_area_ID;

// node_attr_local_IPv4_router_ID is a node attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc5305#section-4.3
typedef struct   {
	uint32_t Address; 
}local_IPv4_router_ID;

// node_attr_local_IPv6_router_ID is a node attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc5305#section-4.1
typedef struct   {
	uint32_t Address[4];
}local_IPv6_router_ID;


// SID_labelType values
typedef enum {
	SID_LABEL_TYPE_SID  = 0,
	SID_LABEL_TYPE_LABEL,
}SID_LABEL_TYPE_ENUM;

// SID_label is contained in the node_attr_SR_caps and node_attr_SR_local_block
//
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-04#section-2.1.1
typedef  struct {
	SID_LABEL_TYPE_ENUM Type;
    uint16_t length;
	uint32_t SID_or_label;/*Variable, 3 or 4 bytes*/
}SID_label;

// SID_labelType values
typedef enum {
	SR_CAP_FLAGS_MPLS_IPV4  = (1<<7),
	SR_CAP_FLAGS_MPLS_IPV6  = (1<<6),
}SR_CAP_FLAGS_ENUM;
// node_attr_SR_caps is a node attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-04#section-2.1.2
typedef struct {
	uint8_t mpls_IPv4;/*flags (I-Flag:1<<7)*/
	uint8_t mpls_IPv6;/*flags (V-Flag:1<<6)*/
    uint32_t range_size;/*3 bytes*/
	SID_label SID_label;
}node_attr_SR_caps;

/*capable of supporting SRH O-bit Flags*/
typedef enum {
	SR6_CAP_FLAGS_SRH_O_BIT  = (1<<14),
}SR6_CAP_FLAGS_ENUM;

typedef struct {
	uint16_t flags;/*flags (O-Flag:1<<14)*/
	uint16_t reserved;/*set to 0 and MUST be ignored on receipt*/
}node_attr_SR6_caps;


// node_attr_SR_algo is a node attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext#section-2.1.3
typedef  struct {
    uint16_t length;
	uint8_t *Algos;
}node_attr_SR_algo;

// node_attr_SR_local_block is a node attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-04#section-2.1.4
typedef  struct {
	uint8_t flags;
    uint32_t range_size;/*3 bytes*/
	SID_label SID_label;
}node_attr_SR_local_block;

// node_attr_SRMS_pref is a node attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-04#section-2.1.5
typedef  struct {
	uint8_t Preference;
}node_attr_SRMS_pref;


// node_attribute is a bgp-ls nlri node attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.1
typedef struct {

    /*attribute origin buf*/
    BGP_LS_TLV origin_buf;

    /*rfc7752 basic*/
    bool_t mt_ID_b;
    multi_topology_ID mt_ID;
    bool_t node_flag_bits_b;
    node_attr_node_flag_bits node_flag_bits;
    bool_t opaque_node_attr_b;
    node_attr_opaque_node_attr opaque_node_attr;
    bool_t node_name_b;
    node_attr_node_name node_name;
    bool_t IsIs_area_ID_b;
    node_attr_IsIs_area_ID IsIs_area_ID;
    bool_t IPv4_router_ID_b;
    local_IPv4_router_ID IPv4_router_ID;    
    bool_t IPv6_router_ID_b;
    local_IPv6_router_ID IPv6_router_ID;
    
    /*exclude rfc7752 */
    bool_t SR_caps_b;
    node_attr_SR_caps SR_caps;    
    bool_t SR_algo_b;
    node_attr_SR_algo SR_algo;    
    bool_t SR_local_block_b;
    node_attr_SR_local_block SR_local_block;
    bool_t SRMS_pref_b;
    node_attr_SRMS_pref SRMS_pref;
	bool_t sid_label_b;
    SID_label sid_label;
	bool_t SR6_caps_b;
    node_attr_SR6_caps SR6_caps;	
}node_attribute;



/*  link_attr_code_ describes the type of node attribute contained in a bgp-ls attribute.
 *  https://tools.ietf.org/html/rfc7752#section-3.3.2
 */
typedef enum {

	LINK_ATTR_CODE_LOCAL_IPV4_ROUTER_ID          = BGP_LS_IP4_LOCAL_NODE_RT_ID,
	LINK_ATTR_CODE_LOCAL_IPV6_ROUTER_ID          = BGP_LS_IP6_LOCAL_NODE_RT_ID,
	LINK_ATTR_CODE_REMOTEIPV4_ROUTER_ID          = BGP_LS_IP4_REMOTE_NODE_RT_ID,
	LINK_ATTR_CODE_REMOTEIPV6_ROUTER_ID          = BGP_LS_IP6_REMOTE_NODE_RT_ID,
	LINK_ATTR_CODE_ADMIN_GROUP                   = BGP_LS_ADMIN_GROUP,
	LINK_ATTR_CODE_MAXLINK_BANDWIDTH             = BGP_LS_MAX_LINK_BW,
	LINK_ATTR_CODE_MAX_RESERVABLE_LINK_BANDWIDTH = BGP_LS_MAX_RESERV_LINK_BW,
	LINK_ATTR_CODE_UNRESERVED_BANDWIDTH          = BGP_LS_UNRESERV_BW,
	LINK_ATTR_CODE_TE_DEFAULT_METRIC             = BGP_LS_TE_DEFAUT_METRIC,
	LINK_ATTR_CODE_LINK_PROTECTION_TYPE          = BGP_LS_LINK_PROTECT_TYPE,
	LINK_ATTR_CODE_MPLS_PROTOCOL_MASK            = BGP_LS_MPLS_PRO_MASK,
	LINK_ATTR_CODE_IGP_METRIC                    = BGP_LS_IGP_METRIC,
	LINK_ATTR_CODE_SHARED_RISK_LINK_GROUP        = BGP_LS_SHARE_RISK_LINK_GROUP,
	LINK_ATTR_CODE_OPAQUE_LINK_ATTR              = BGP_LS_OPAQUE_LINK_ATTRI,
	LINK_ATTR_CODE_LINK_NAME                     = BGP_LS_LINK_NAME,

    /*rfc7752 exclude....*/
	LINK_ATTR_CODE_ADJSID                        = BGP_LS_ADJ_SID,
	LINK_ATTR_CODE_LAN_ADJ_SID                   = BGP_LS_LAN_ADJ_SID,
	LINK_ATTR_CODE_PEER_NODE_SID                 = BGP_LS_PEER_NODE_SID,
	LINK_ATTR_CODE_PEER_ADJ_SID                  = BGP_LS_PEER_ADJ_SID,
	LINK_ATTR_CODE_PEER_SET_SID                  = BGP_LS_PEER_SET_SID,
	LINK_ATTR_CODE_UNI_LINK_DELAY                = BGP_LS_UNIDIRECT_LINK_DELAY,
	LINK_ATTR_CODE_MIN_MAX_UNILINK_DELAY         = BGP_LS_MINMAX_LINK_DELAY,
	LINK_ATTR_CODE_UNI_DELAY_VARIATION           = BGP_LS_UNIDIRECT_DELAY_VAR,
	LINK_ATTR_CODE_UNI_PACKET_LOSS               = BGP_LS_UNIDIRECT_LINK_LOSS,
	LINK_ATTR_CODE_UNI_RESIDUAL_BANDWIDTH        = BGP_LS_UNIDIRECT_RES_BW,
	LINK_ATTR_CODE_UNI_AVAILABLE_BANDWIDTH       = BGP_LS_UNIDIRECT_AVAIL_BW,
	LINK_ATTR_CODE_UNI_BANDWIDTH_UTIL            = BGP_LS_UNIDIRECT_UTIL_BW,
	LINK_ATTR_CODE_L2_BUNDLE_MEMBER              = BGP_LS_L3_BOND_MEM_ATTRI,
    LINK_ATTR_CODE_SR6_END_SID                   = BGP_LS_SR6_END_SID,
    LINK_ATTR_CODE_ISIS_SR6_LAN_END_SID          = BGP_LS_ISIS_SR6_LAN_END_SID,
    LINK_ATTR_CODE_OSPF3_SR6_LAN_END_SID         = BGP_LS_OSPF3_SR6_LAN_END_SID,
   
}LINK_ATTR_CODE_ENUM;

// link_attr_remote_IPv4_router_ID is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc5305#section-4.3
typedef  struct {
	uint32_t Address;
}remote_IPv4_router_ID;


// link_attr_remote_IPv6_router_ID is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc6119#section-4.1
typedef  struct {
	uint32_t Address[4];
}remote_IPv6_router_ID;

// link_attr_admin_group is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc5305#section-3.1
typedef  struct {
	uint32_t Group_bits;
}link_attr_admin_group;

// link_attr_maxLink_bandwidth is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc5305#section-3.4
typedef  struct {
	float_int32_t bytes_per_second;
}link_attr_maxLink_bandwidth;

// link_attr_max_reservable_link_bandwidth is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc5305#section-3.5
typedef  struct {
	float_int32_t bytes_per_second ;
}link_attr_max_reservable_link_bandwidth;

// link_attr_unreserved_bandwidth is a link attribute contained in a bgp-ls attribute.
// The index number represents the priority level.
//
// https://tools.ietf.org/html/rfc5305#section-3.6
typedef  struct {
	float_int32_t bytes_per_second[8];
}link_attr_unreserved_bandwidth;

// link_attr_TE_default_metric is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc5305#section-3.7
typedef  struct {
	uint32_t Metric;
}link_attr_TE_default_metric;

// link protectiontype values
typedef enum {
    LINK_PROTECTION_TYPE_EXTRATRAFFIC  = (1<<0),     
    LINK_PROTECTION_TYPE_UNPROTECTED  = (1<<1),
    LINK_PROTECTION_TYPE_SHARED  = (1<<2),
    LINK_PROTECTION_TYPE_DEDICATEDONETOONE  = (1<<3),
    LINK_PROTECTION_TYPE_DEDICATEDONEPLUSONE  = (1<<4),
    LINK_PROTECTION_TYPE_ENHANCED  = (1<<5),
}LINK_PROTECTION_TYPE_ENUM;

// link_attr_link_protection_type is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc5307#section-1.2
typedef  struct {
	bool_t ExtraTraffic;        
	bool_t Unprotected;
	bool_t Shared;
	bool_t DedicatedOneToOne;
	bool_t DedicatedOnePlusOne;
	bool_t Enhanced;
}link_attr_link_protection_type;

typedef enum {
    LINK_ATTR_MPLS_PROTOCOL_LDP = (1<<7),
    LINK_ATTR_MPLS_PROTOCOL_RSVP_TE =(1<<6),
}LINK_ATTR_MPLS_PROTOCOL;

// link_attr_mpls_protocol_mask is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.2.2
typedef  struct {
	bool_t LDP;
	bool_t RsvpTE;
}link_attr_mpls_protocol_mask;

// link_attr_igp_metricType values
typedef enum {
    LINK_ATTR_IGP_METRIC_ISIS_SMALL_TYPE  = 0,
    LINK_ATTR_IGP_METRIC_OSPF_TYPE,
    LINK_ATTR_IGP_METRIC_ISIS_WIDE_TYPE,
}LINK_ATTR_IGP_METRIC_ENUM;

// link_attr_igp_metric is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.2.4
typedef  struct {
	LINK_ATTR_IGP_METRIC_ENUM Type;
	uint32_t Metric; /*max 3 bytes;*/
}link_attr_igp_metric;


// link_attr_shared_risk_link_group is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.2.5
typedef struct {
    uint16_t length;
	uint32_t *Groups;
}link_attr_shared_risk_link_group;

// link_attr_opaque_link_attr is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.2.6
typedef  struct {
    uint16_t length;
	uint8_t *Data ;
}link_attr_opaque_link_attr;


// link_attr_link_name is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.2.7
typedef  struct {
    uint16_t length;
	uint8_t * Name;
}link_attr_link_name;


// link_attr_adj_SIDFlags values
typedef enum {
	LINK_ATTR_ADJ_SID_FLAGS_TYPE_ISIS  = 0,
	LINK_ATTR_ADJ_SID_FLAGS_TYPE_OSPF,
	LINK_ATTR_ADJ_SID_FLAGS_TYPE_OSPFV3,
}LINK_ATTR_ADJ_SID_FLAGS_TYPE_ENUM;
     
union SID_idx_label
{
    uint32_t SID;
    uint32_t Index;
    uint32_t Label;
    uint32_t Label_off;/*24 bits*/
    uint32_t IPv6_address[4];
};

// link_attr_adj_SID_flags_IsIs are contained in the link_attr_adj_SID link attribute.
//
// https://tools.ietf.org/html/draft-ietf-isis-segment-routing-extensions-15#section-2.2.1
typedef struct {
	bool_t AddressFamily;
	bool_t Backup       ;
	bool_t Value        ;
	bool_t Local        ;
	bool_t Set          ;
	bool_t Persistent   ;
}link_attr_adj_SID_flags_IsIs;

// link_attr_adj_SID_flags_ospf are contained in the link_attr_adj_SID link attribute.
//
// https://tools.ietf.org/html/draft-ietf-ospf-segment-routing-extensions-24#section-6.1
typedef struct {
	bool_t Backup     ;
	bool_t Value      ;
	bool_t Local      ;
	bool_t Group      ;
	bool_t Persistent ;
}link_attr_adj_SID_flags_ospf;

// link_attr_adj_SID is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-04#section-2.2.1
typedef struct {
    /*Network byte order data*/
    uint16_t type;
    uint16_t length;
    uint8_t *value;    

    /*local struct data*/
    LINK_ATTR_ADJ_SID_FLAGS_TYPE_ENUM adj_sid_flags_type;    
	uint8_t Flags;         
	uint8_t Weight;
    uint16_t Reserved;
    uint32_t SID_index_label;
	//union SID_idx_label SID_index_label;
}link_attr_adj_SID;

// link_attr_lan_adj_SID_proto_specific_ID_type values
typedef enum {
	LINK_ATTR_LAN_ADJ_SID_PROTO_SPECIFIC_ID_TYPE_ISIS  = 0,
	LINK_ATTR_LAN_ADJ_SID_PROTO_SPECIFIC_ID_TYPE_OSPF,
	LINK_ATTR_LAN_ADJ_SID_PROTO_SPECIFIC_ID_TYPE_OSPFV3,
}LINK_ATTR_LAN_ADJ_SID_PROTO_SPECIFIC_ID_TYPE_ENUM;


// link_attr_lan_adj_SID is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-04#section-2.2.2
typedef struct {
    /*Network byte order data*/
    uint16_t type;
    uint16_t length;
    uint8_t *value;    

    /*local struct data*/
    LINK_ATTR_ADJ_SID_FLAGS_TYPE_ENUM adj_sid_flags_type;
	uint8_t Flags ;
	uint8_t Weight;
    uint8_t Reserved;
	uint8_t Neighbor_ID_SystemID[6]; /*only use 6 bytes*/
	//union SID_idx_label SID_index_label; 
	uint32_t SID_index_label;
}link_attr_lan_adj_SID;

// link_attr_peer_node_SID is a link attribute contained a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-bgpls-segment-routing-epe-15#section-4.4
typedef struct {
    /*Network byte order data*/
    uint16_t type;
    uint16_t length;
    uint8_t *value;    

    /*local struct data*/
	uint8_t Flags;
    uint8_t Weight;
    uint16_t Reserved;
	uint32_t SID_index_label;
}link_attr_peer_node_SID;
/* 
1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Type            |              Length           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Flags         |     Weight    |             Reserved          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   SID/Label/Index (variable)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

// link_attr_peer_adj_SID is a link attribute contained a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-bgpls-segment-routing-epe-15#section-4.4
typedef struct {
    /*Network byte order data*/
    uint16_t type;
    uint16_t length;
    uint8_t *value;    

    /*local struct data*/
	/*bool_t Value;         
	bool_t Local;
	bool_t Backup;
	bool_t Persistent;*/
	uint8_t Flags;
    uint8_t Weight;
    uint16_t Reserved;
	uint32_t SID_index_label;
	//union SID_idx_label SID_index_label;
}link_attr_peer_adj_SID;

// link_attr_peer_set_SID is a link attributed contained a bgp-ls attribute
//
// https://tools.ietf.org/html/draft-ietf-idr-bgpls-segment-routing-epe-15#section-4.4
typedef struct {
    /*Network byte order data*/
    uint16_t type;
    uint16_t length;
    uint8_t *value;    

    /*local struct data*/
	uint8_t Flags;
    uint8_t Weight;
    uint16_t Reserved;
	uint32_t SID_index_label;
	//union SID_idx_label SID_index_label;
}link_attr_peer_set_SID;


// link_attr_uni_link_delay is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-te-pm-bgp-08#section-3.1
typedef struct {
	bool_t Anomalous;
	uint32_t Delay;
}link_attr_uni_link_delay;

// link_attr_min_max_uniLink_delay is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-te-pm-bgp-08#section-3.2
typedef struct {
	bool_t Anomalous;
	uint32_t MinDelay;
	uint32_t MaxDelay;
}link_attr_min_max_uniLink_delay;

// link_attr_uni_delay_variation is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-te-pm-bgp-08#section-3.3
typedef struct {
	uint32_t DelayVariation;
}link_attr_uni_delay_variation;

// link_attr_uni_packet_loss is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-te-pm-bgp-08#section-3.4
typedef struct {
	bool_t Anomalous;
	float_int32_t LossPercent;
}link_attr_uni_packet_loss;

// link_attr_uni_residual_bandwidth is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-te-pm-bgp-08#section-3.5
typedef struct {
	float_int32_t bytes_per_second;
}link_attr_uni_residual_bandwidth;

// link_attr_uni_available_bandwidth is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-te-pm-bgp-08#section-3.6
typedef struct {
	float_int32_t bytes_per_second;
}link_attr_uni_available_bandwidth;

// link_attr_uni_bandwidth_util is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-te-pm-bgp-08#section-3.7
typedef struct {
	float_int32_t bytes_per_second;
}link_attr_uni_bandwidth_util;

// link_attr_l2_bundle_member is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-04#section-2.2.3
typedef struct {
    /*Network byte order data*/
    uint16_t type;
    uint16_t length;
    uint8_t *value;    

    /*local struct data*/
	uint32_t member_descriptor; 
	uint8_t *LinkAttrs;
}link_attr_l2_bundle_member;

typedef struct {
	uint16_t type;
    uint16_t length;
	uint16_t endpoint_behavior;
	uint8_t flags;
	uint8_t algorithm;
	uint8_t weight;
	uint8_t reserved;
	uint32_t sid[4];
	uint8_t *sub_tlv;
} link_attr_sr6_end_sid;

typedef struct {
	uint16_t type;
    uint16_t length;
	uint16_t endpoint_behavior;
	uint8_t flags;
	uint8_t algorithm;
	uint8_t weight;
	uint8_t reserved;
	
	//ISIS System-ID (6 octets) or OSPFv3 Router-ID (4 octets)
	uint32_t neighbor_id[2];
	uint32_t sid[4];
	uint8_t *sub_tlv;
} link_attr_sr6_lan_end_x_sid;


// link_attribute is a bgp-ls nlri link attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.2
typedef struct {

    /*attribute origin buf*/
    BGP_LS_TLV origin_buf;

    /*rfc7752 basic*/
    bool_t local_IP4_router_ID_b;
    local_IPv4_router_ID local_IP4_router_ID ;
    bool_t local_IP6_router_ID_b;
    local_IPv6_router_ID local_IP6_router_ID ;
    bool_t remote_IP4_router_ID_b;
    remote_IPv4_router_ID  remote_IP4_router_ID ;
    bool_t remote_IP6_router_ID_b;
    remote_IPv6_router_ID remote_IP6_router_ID ;
    bool_t admin_group_b;
    link_attr_admin_group admin_group;
    bool_t maxLink_bandwidth_b;
    link_attr_maxLink_bandwidth maxLink_bandwidth;
    bool_t max_reservable_link_bandwidth_b;
    link_attr_max_reservable_link_bandwidth max_reservable_link_bandwidth;
    bool_t unreserved_bandwidth_b;
    link_attr_unreserved_bandwidth unreserved_bandwidth;
    bool_t TE_default_metric_b;
    link_attr_TE_default_metric TE_default_metric;
    bool_t link_protection_type_b;
    link_attr_link_protection_type link_protection_type;
    bool_t mpls_protocol_mask_b;
    link_attr_mpls_protocol_mask mpls_protocol_mask;
    bool_t igp_metric_b;
    link_attr_igp_metric igp_metric;
    bool_t shared_risk_link_group_b;
    link_attr_shared_risk_link_group shared_risk_link_group;
    bool_t opaque_link_attr_b;
    link_attr_opaque_link_attr opaque_link_attr;
    bool_t link_name_b;
    link_attr_link_name link_name;

    
    /*exclude rfc7752 */
    bool_t adj_SID_b;
    link_attr_adj_SID adj_SID;
    bool_t lan_adj_SID_b;
    link_attr_lan_adj_SID lan_adj_SID;
     bool_t peer_node_SID_b;
    link_attr_peer_node_SID peer_node_SID;    
    bool_t peer_adj_SID_b;
    link_attr_peer_adj_SID peer_adj_SID;
    bool_t peer_set_SID_b;
    link_attr_peer_set_SID peer_set_SID;
    bool_t uni_link_delay_b;
    link_attr_uni_link_delay uni_link_delay;
    bool_t min_max_uniLink_delay_b;
    link_attr_min_max_uniLink_delay min_max_uniLink_delay;
    bool_t uni_delay_variation_b;
    link_attr_uni_delay_variation uni_delay_variation;
    bool_t uni_packet_loss_b;
    link_attr_uni_packet_loss uni_packet_loss;
    bool_t uni_residual_bandwidth_b;
    link_attr_uni_residual_bandwidth uni_residual_bandwidth;
    bool_t uni_available_bandwidth_b;
    link_attr_uni_available_bandwidth uni_available_bandwidth;
    bool_t uni_bandwidth_util_b;
    link_attr_uni_bandwidth_util  uni_bandwidth_util;
    bool_t l2_bundle_member_b;
    link_attr_l2_bundle_member  l2_bundle_member;
	bool_t sr6_end_sid_b;
    link_attr_sr6_end_sid  sr6_end_sid;
	bool_t isis_sr6_lan_end_sid_b;
    link_attr_sr6_lan_end_x_sid  isis_sr6_lan_end_sid;
	bool_t ospf3_sr6_lan_end_sid_b;
    link_attr_sr6_lan_end_x_sid  ospf3_sr6_lan_end_sid;

}link_attribute;

/* prefix_attr_code_ describes the type of prefix attribute contained in a bgp-ls attribute.
 * https://tools.ietf.org/html/rfc7752#section-3.3.3
 */
typedef enum {
	PREFIX_ATTR_CODE_IGP_FLAGS                 = BGP_LS_IGP_FLAG,
	PREFIX_ATTR_CODE_IGP_ROUTE_TAG             = BGP_LS_IGP_ROUTE_TAG,
	PREFIX_ATTR_CODE_IGP_EXTENDED_ROUTE_TAG    = BGP_LS_IGP_EXT_ROUTE_TAG,
	PREFIX_ATTR_CODE_PREFIX_METRIC             = BGP_LS_PREFIX_METRIC,
	PREFIX_ATTR_CODE_OSPF_FORWARDING_ADDRESS   = BGP_LS_OSPF_FWD_ADD,
	PREFIX_ATTR_CODE_OPAQUE_PREFIX_ATTRIBUTE   = BGP_LS_OPAQUE_PREFIX_ATTRI,
	
	/*RFC7752 EXCLUDE....*/
	PREFIX_ATTR_CODE_PREFIX_SID               = BGP_LS_PREFIX_SID,
	PREFIX_ATTR_CODE_RANGE                    = BGP_LS_RANGE,
	PREFIX_ATTR_CODE_FLAGS                    = BGP_LS_PREFIX_ATTRI_FLAG,
	PREFIX_ATTR_CODE_SOURCE_ROUTER_ID         = BGP_LS_SR_ROUTE_ID,
	PREFIX_ATTR_CODE_SR6_LOCATER              = BGP_LS_SR6_LOCATER,
}PREFIX_ATTR_CODE_ENUM;
 
typedef enum {	
	/*RFC7752 EXCLUDE....*/
    SR6_SID_ATTR_CODE_END_BEHAVIOR             = BGP_LS_SR6_END_FUNC,
	SR6_SID_ATTR_CODE_BGP_PEER_NODE_SID        = BGP_LS_SR6_BGP_PEER_NODE_SID,
	SR6_SID_ATTR_CODE_SID_STRUCT               = BGP_LS_SR6_SID_STRUCT,	
}SR6_SID_ATTR_CODE_ENUM;


typedef enum {	
	/*RFC7752 EXCLUDE....*/
    TE_POLICY_ATTR_CODE_BINDING_SID             = BGP_LS_SR_BSID,
	TE_POLICY_ATTR_CODE_SR_CANDIDATE_PATH_STATE = BGP_LS_SR_CP_STATE,
	TE_POLICY_ATTR_CODE_SEGMENT_LIST            = BGP_LS_SR_SEGMENT_LIST,	
}TE_POLICY_ATTR_CODE_ENUM;


// prefix igp flags values
typedef enum {
    IGP_FLAGS_D  = (1<<7),     
    IGP_FLAGS_N  = (1<<6),
    IGP_FLAGS_L  = (1<<5),
    IGP_FLAGS_P  = (1<<4),
}IGP_FLAGS_ENUM;
// prefix_attr_igp_flags is a prefix attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.3.1
typedef struct {
	bool_t IsIs_down;
	bool_t ospf_no_unicast;
	bool_t ospf_local_address;
	bool_t ospf_propagate_nssa;
}prefix_attr_igp_flags;

// prefix_attr_igp_route_tag is a prefix attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.3.2
typedef struct {
    uint16_t length;
	uint32_t *Tags;
}prefix_attr_igp_route_tag;

// prefix_attr_igp_extended_route_tag is a prefix attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.3.3
typedef struct {
    uint16_t length;
	uint64_t *Tags;
}prefix_attr_igp_extended_route_tag;

// prefix_attr_prefix_metric is a prefix attributed contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.3.4
typedef struct {
	uint32_t Metric;
}prefix_attr_prefix_metric;

// ospf_forwarding_address_type values
typedef enum {
	OSPF_FORWARDING_ADDRESS_IPV4  = 0,
	OSPF_FORWARDING_ADDRESS_IPV6,
}OSPF_FORWARDING_ADDRESS_TYPE_ENUM;

// prefix_attr_ospf_forwarding_address is a prefix attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.3.5
typedef struct {
    OSPF_FORWARDING_ADDRESS_TYPE_ENUM type;
	uint32_t Address[4];
}prefix_attr_ospf_forwarding_address;

// prefix_attr_opaque_prefix_attribute is a prefix attribute contained in a bgp-ls attribute.
typedef struct {
    uint16_t length;
	uint8_t *Data;
}prefix_attr_opaque_prefix_attribute;

// prefix_attr_prefix_SID_flags_type values
typedef enum {
	PREFIX_ATTR_PREFIX_SID_FLAGS_TYPE_ISIS  = 0,
	PREFIX_ATTR_PREFIX_SID_FLAGS_TYPE_OSPF,
	PREFIX_ATTR_PREFIX_SID_FLAGS_TYPE_OSPFV3,
}PREFIX_ATTR_PREFIX_SID_FLAGS_TYPE_ENUM;

// prefix_attr_prefix_SID_flags_IsIs are contained in a prefix_attr_prefix_SID prefix
// attribute.
//
// https://tools.ietf.org/html/draft-ietf-isis-segment-routing-extensions-15#section-2.1
typedef struct {
	bool_t Readvertisement ;
	bool_t NodeSID         ;
	bool_t NoPHP           ;
	bool_t ExplicitNull    ;
	bool_t Value           ;
	bool_t Local           ;
}prefix_attr_prefix_SID_flags_IsIs;

// prefix_attr_prefix_SID_flags_ospf are contained in a prefix_attr_prefix_SID prefix
// attribute.
//
// https://tools.ietf.org/html/draft-ietf-ospf-segment-routing-extensions-24#section-5
typedef struct {
	bool_t NoPHP         ;
	bool_t MappingServer ;
	bool_t ExplicitNull  ;
	bool_t Value         ;
	bool_t Local         ;
}prefix_attr_prefix_SID_flags_ospf;

// prefix_attr_prefix_SID is a prefix attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-04#section-2.3.1
typedef struct {
    /*Network byte order data*/
    uint16_t type;
    uint16_t length;
    uint8_t *value;    

    /*local struct data*/
	uint8_t Flags;
	uint8_t Algorithm;
	union SID_idx_label SID_index_label;
}prefix_attr_prefix_SID;


// prefix_attr_range_flags_type values
typedef enum {
	PREFIX_ATTR_RANGE_FLAGS_TYPE_ISIS  = 0,
	PREFIX_ATTR_RANGE_FLAGS_TYPE_OSPF,
	PREFIX_ATTR_RANGE_FLAGS_TYPE_OSPFV3,
}PREFIX_ATTR_RANGE_FLAGS_TYPE_ENUM;


// prefix_attr_range_flags_IsIs are contained in a prefix_attr_range prefix attribute.
typedef struct {
	bool_t AddressFamily ;
	bool_t Mirror        ;
	bool_t SFlag         ;
	bool_t DFlag         ;
	bool_t Attached      ;
}prefix_attr_range_flags_IsIs;

// prefix_attr_range_flags_ospf are contained in a prefix_attr_range prefix attribute.
//
// https://tools.ietf.org/html/draft-ietf-ospf-segment-routing-extensions-24#section-4
typedef struct {
	bool_t InterArea;
}prefix_attr_range_flags_ospf;

// prefix_attr_range is a prefix attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-04#section-2.3.4
typedef struct {
    /*Network byte order data*/
    uint16_t type;
    uint16_t length;
    uint8_t *value;    

    /*local struct data*/
	uint8_t Flags;     
	uint16_t range_size;
	uint8_t *prefix_subTLVs;
}prefix_attr_range;

// prefix_attr_flags_OSPFv2 is a prefix attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-04#section-2.3.2
//
// https://tools.ietf.org/html/rfc7684#section-2.1
typedef struct {
	bool_t Attach;
	bool_t Node  ;
}prefix_attr_flags_OSPFv2;


// prefix_attr_flags_OSPFv3 is a prefix attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-04#section-2.3.2
//
// https://tools.ietf.org/html/rfc5340#appendix-A.4.1.1
typedef struct {
	bool_t DN           ;
	bool_t Propagate    ;
	bool_t LocalAddress ;
	bool_t NoUnicast    ;
}prefix_attr_flags_OSPFv3;

// prefix_attr_flags_IsIs is a prefix attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-04#section-2.3.2
//
// https://tools.ietf.org/html/rfc7794#section-2.1
typedef struct {
	bool_t External        ;
	bool_t Readvertisement ;
	bool_t Node            ;
}prefix_attr_flags_IsIs;

// prefix_attr_flags is a prefix attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-04#section-2.3.2
typedef struct {
    /*Network byte order data*/
    uint16_t type;
    uint16_t length;
    uint8_t *value;    

    /*local struct data*/
	uint8_t *Flags;     
	uint8_t type_flag;
}prefix_attr_flags;


// ospf_forwarding_address_type values
typedef enum {
	SOURCE_ROUTER_ADDRESS_IPV4  = 0,
	SOURCE_ROUTER_ADDRESS_IPV6,
}SOURCE_ROUTER_ADDRESS_TYPE_ENUM;

// prefix_attr_source_router_ID is a prefix attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-04#section-2.3.3
typedef  struct {
    SOURCE_ROUTER_ADDRESS_TYPE_ENUM type;
	uint32_t Address[4];
}prefix_attr_source_router_ID;


// prefix_attribute is a bgp-ls nlri prefix attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.3
typedef struct {
    /*attribute origin buf*/
    BGP_LS_TLV origin_buf;

    /*rfc7752 basic*/
    bool_t igp_flags_b;
    prefix_attr_igp_flags igp_flags;
    bool_t igp_route_tag_b;
    prefix_attr_igp_route_tag igp_route_tag;
    bool_t igp_extended_route_tag_b;
    prefix_attr_igp_extended_route_tag igp_extended_route_tag;
    bool_t prefix_metric_b;
    prefix_attr_prefix_metric prefix_metric;
    bool_t ospf_forwarding_address_b;
    prefix_attr_ospf_forwarding_address ospf_forwarding_address;
    bool_t opaque_prefix_attribute_b;
    prefix_attr_opaque_prefix_attribute opaque_prefix_attribute;
    
    /*exclude rfc7752 */
    bool_t prefix_SID_b;
    prefix_attr_prefix_SID prefix_SID;
    bool_t range_b;
    prefix_attr_range range;
    bool_t attr_flags_b;
    prefix_attr_flags attr_flags;
    bool_t source_router_ID_b;
    prefix_attr_source_router_ID source_router_ID;
}prefix_attribute;


typedef struct {
    uint16_t type;
    uint16_t length;
    uint16_t endpoint_behavior;
    uint8_t flags;
    uint8_t algorithm;
}sr6_sid_attr_endpoint_behavior;

typedef struct {
    uint16_t type;
    uint16_t length;
    uint8_t flags;
    uint8_t weight;
    uint16_t reserved;
    uint32_t peer_as_number;
    uint32_t peer_bgp_id;
}sr6_sid_attr_sr6_bgp_peer_node_sid;

typedef struct {
    uint16_t type;
    uint16_t length;
    uint8_t lb_len;    
    uint8_t ln_len;
    uint8_t fun_len;
    uint8_t arg_len;
}sr6_sid_attr_sr6_sid_struct;

typedef struct {
    /*attribute origin buf*/
    BGP_LS_TLV origin_buf;

    /*exclude rfc7752 */
    bool_t endpoint_behavior_b;
    sr6_sid_attr_endpoint_behavior endpoint_behavior;
    bool_t sr6_bgp_peer_node_sid_b;
    sr6_sid_attr_sr6_bgp_peer_node_sid sr6_bgp_peer_node_sid;
    bool_t sr6_sid_struct_b;
    sr6_sid_attr_sr6_sid_struct sr6_sid_struct;
}sr6_sid_attribute;

typedef struct {
    uint16_t type;
    uint16_t length;
	uint16_t flags;
    union{
      uint32_t  addr_v4; 
	  uint32_t addr_v6[4];
	} binding_sid;
}te_policy_attr_binding_sid;

typedef struct {
    uint16_t type;
    uint16_t length;
	uint8_t priority;
	uint16_t flags;
    uint32_t preference;
}te_policy_attr_preference;

struct te_policy_attr_segment{
	struct te_policy_attr_segment *next;
    uint16_t type;
    uint16_t length;
	uint8_t seg_type;
	uint16_t flags;
	uint32_t sid[4];
};


typedef struct {
    uint16_t type;
    uint16_t length;
    uint16_t flags;
	uint32_t weight;
	struct te_policy_attr_segment *head;
	struct te_policy_attr_segment *tail;
	struct te_policy_attr_sid_list *next;
}te_policy_attr_sid_list;

typedef struct {
    /*attribute origin buf*/
    BGP_LS_TLV origin_buf;

    /*exclude rfc7752 */
    bool_t binding_sid_b;
    te_policy_attr_binding_sid binding_sid;
    bool_t preference_b;
    te_policy_attr_preference preference;
    bool_t sid_list_b;
    te_policy_attr_sid_list *sid_list;
}te_policy_attribute;




/*  node_descriptor_code_ describes the type of node descriptor.
*  https://tools.ietf.org/html/rfc7752#section-3.2.1.4
*/
typedef enum {
	NODE_DESCRIPTOR_CODE_ASN          = BGP_LS_AUTO_SYS,
	NODE_DESCRIPTOR_CODE_BGP_LS_ID      = BGP_LS_ID,
	NODE_DESCRIPTOR_CODE_OSPF_AREA_ID   = BGP_LS_OSPF_AREA_ID,
	NODE_DESCRIPTOR_CODE_IGP_ROUTER_ID  = BGP_LS_IGP_ROUTE_ID,

    /*exclude rfc7752 */
	NODE_DESCRIPTOR_CODE_BGP_ROUTER_ID  = BGP_LS_BGP_ROUTER_ID,
	NODE_DESCRIPTOR_CODE_MEMBER_ASN    = BGP_LS_BGP_CONFRE_MEM,
}NODE_DESCRIPTOR_CODE_ENUM;
    
// node_descriptor_ASN is a node descriptor contained in a bgp-ls node nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
typedef struct {
    uint32_t ASN ;
}node_descriptor_ASN;


// node_descriptor_bgp_ls_ID is a node descriptor contained in a bgp-ls node nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
typedef struct {
	uint32_t ID ;
}node_descriptor_bgp_ls_ID;

// node_descriptor_ospf_area_ID is a node descriptor contained in a bgp-ls node nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
typedef struct {
	uint32_t ID ;
}node_descriptor_ospf_area_ID;

// node_descriptor_igp_router_ID_type values
typedef enum {
	NODE_DESCRIPTOR_IGP_ROUTER_ID_ISIS_NON_PSEUDO_TYPE  = 0,
	NODE_DESCRIPTOR_IGP_ROUTER_ID_ISIS_PSEUDO_TYPE,
	NODE_DESCRIPTOR_IGP_ROUTER_ID_OSPF_NON_PSEUDO_TYPE,
	NODE_DESCRIPTOR_IGP_ROUTER_ID_OSPF_PSEUDO_TYPE,
}NODE_DESCRIPTOR_IGP_ROUTER_ID_TYPE_ENUM;

// node_descriptor_igp_router_ID_IsIs_non_pseudo is a node descriptor contained in a bgp-ls node nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
typedef struct {
	uint8_t IsoNodeID[6];
}node_descriptor_igp_router_ID_IsIs_non_pseudo;

// node_descriptor_igp_router_ID_IsIs_pseudo is a node descriptor contained in a bgp-ls node nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
typedef struct {
	uint8_t IsoNodeID[6];
	uint8_t PsnID ;
}node_descriptor_igp_router_ID_IsIs_pseudo;

// node_descriptor_igp_router_ID_ospf_non_pseudo is a node descriptor contained in a bgp-ls node nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
typedef struct {
	uint32_t RouterID ;
}node_descriptor_igp_router_ID_ospf_non_pseudo;


// node_descriptor_igp_router_ID_ospf_pseudo is a node descriptor contained in a bgp-ls node nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
typedef struct {  
	uint32_t DrRouterID       ;    
	uint32_t DrInterfaceToLAN ;  
}node_descriptor_igp_router_ID_ospf_pseudo;


// node_descriptor_igp_router_ID_ospf_pseudo is a node descriptor contained in a bgp-ls node nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
struct igp_router_id {
    node_descriptor_igp_router_ID_IsIs_non_pseudo IsIs_non_pseudo;
    node_descriptor_igp_router_ID_IsIs_pseudo IsIs_pseudo;
    node_descriptor_igp_router_ID_ospf_non_pseudo ospf_non_pseudo;
    node_descriptor_igp_router_ID_ospf_pseudo ospf_pseudo;
};

typedef struct {
    NODE_DESCRIPTOR_IGP_ROUTER_ID_TYPE_ENUM type;
    struct igp_router_id igp_router_ID;
}node_descriptor_igp_router_ID;



// node_descriptor_bgp_router_ID is a node descriptor contained in a bgp-ls node nlri
//
// https://tools.ietf.org/html/draft-ietf-idr-bgpls-segment-routing-epe-15#section-4.1
typedef struct {
	uint32_t RouterID ;
}node_descriptor_bgp_router_ID;


// node_descriptor_member_ASN is a node descriptor contained in a bgp-ls node nlri
//
// https://tools.ietf.org/html/draft-ietf-idr-bgpls-segment-routing-epe-15#section-4.1
typedef struct {
	uint32_t ASN ;
}node_descriptor_member_ASN;


// link_state_nlri_descriptorCode values
typedef enum {
	LINK_STATE_NLRI_LOCAL_NODE_DESCRIPTORS_CODE   = BGP_LS_LOCAL_NODE_DESC,
	LINK_STATE_NLRI_REMOTE_NODE_DESCRIPTORS_CODE  = BGP_LS_REMOTE_NODE_DESC,
}LINK_STATE_NLRI_DESCRIPTOR_CODE_ENUM;

// node_descriptor is a bgp-ls nlri node descriptor.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1
typedef struct {
	LINK_STATE_NLRI_DESCRIPTOR_CODE_ENUM Code;

    /*rfc7752 basic*/
    bool_t ASN_b;
    node_descriptor_ASN ASN;
    bool_t bgp_ls_ID_b;
    node_descriptor_bgp_ls_ID bgp_ls_ID;
    bool_t ospf_area_ID_b;
    node_descriptor_ospf_area_ID ospf_area_ID;
    bool_t igp_router_ID_b;
    node_descriptor_igp_router_ID igp_router_ID;

    /*exclude rfc7752 */
    bool_t bgp_router_ID_b;
    node_descriptor_bgp_router_ID bgp_router_ID;
    bool_t member_ASN_b;
    node_descriptor_member_ASN member_ASN;
}node_descriptor;

#define MAX_AS_PATH 200

// NLRI_NODE is a link state nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2 figure 7
typedef struct {   
    /*interal sync flags*/
    uint8_t  sync_flag;
    
    /*need send update packet*/
    uint8_t  ntt;

    /* origin nlri format.  */
    BGP_LS_TLV origin_nlri_buf;

    /*metadata*/
	uint8_t protocol_ID;
	uint64_t ID;
	node_descriptor local_node;

    /*attribute*/
    node_attribute node_attr;  
	
	char as_path[MAX_AS_PATH];
}NLRI_NODE;

typedef struct { 
	
    uint32_t  color;   
	uint8_t flags;
	uint8_t protocol;
	union{
      uint32_t  addr_v4; 
	  uint32_t addr_v6[4];
	} end_point;
	union{
      uint32_t  addr_v4; 
	  uint32_t addr_v6[4];
	} orignator_addr;
	uint32_t  orignator_as;
	uint32_t  discriminator;
}te_policy_descriptor;


typedef struct { 
	/* origin nlri format.*/
    BGP_LS_TLV origin_nlri_buf;
	/*metadata*/
	uint8_t protocol_ID;
	uint64_t ID;
	node_descriptor local_node;
	te_policy_descriptor te_policy_desc;
	
	/*attribute*/
    te_policy_attribute te_policy_attr;
	char as_path[MAX_AS_PATH];
    
}NLRI_TE_POLICY;


// link_descriptor_link_IDs is a link descriptor contained in a bgp-ls link nlri.
//
// https://tools.ietf.org/html/rfc5307#section-1.1
typedef struct {
	uint32_t LocalID ; 
	uint32_t RemoteID ;
}link_descriptor_link_IDs;

// link_descriptor_IPv4_interface_address is a link descriptor contained in a bgp-ls link nlri.
//
// https://tools.ietf.org/html/rfc5305#section-3.2
typedef struct {
	uint32_t Address;
}link_descriptor_IPv4_interface_address;

// link_descriptor_IPv4_neighbor_address is a link descriptor contained in a bgp-ls link nlri.
//
// https://tools.ietf.org/html/rfc5305#section-3.3
typedef struct {
	uint32_t Address;
}link_descriptor_IPv4_neighbor_address;

// link_descriptor_IPv6_interface_address is a link descriptor contained in a bgp-ls link nlri.
//
// https://tools.ietf.org/html/rfc6119#section-4.2
typedef struct {
	uint32_t Address[4];
}link_descriptor_IPv6_interface_address;

// link_descriptor_IPv6_neighbor_address is a link descriptor contained in a bgp-ls link nlri.
//
// https://tools.ietf.org/html/rfc6119#section-4.3
typedef struct {
	uint32_t Address[4];
}link_descriptor_IPv6_neighbor_address;


/*  link_descriptor_code_ describes the type of link descriptor.
*  https://tools.ietf.org/html/rfc7752#section-3.2.2 table 5
*/
typedef enum {
	LINK_DESCRIPTOR_CODE_LINK_IDS                = BGP_LS_LINK_LOCAL_OR_REMOTE_ID,
	LINK_DESCRIPTOR_CODE_IPV4_INTERFACE_ADDRESS  = BGP_LS_IP4_INF_ADDR,
	LINK_DESCRIPTOR_CODE_IPV4_NEIGHBOR_ADDRESS   = BGP_LS_IP4_NEIGHBOR_ADDR,
	LINK_DESCRIPTOR_CODE_IPV6_INTERFACE_ADDRESS  = BGP_LS_IP6_INF_ADDR,
	LINK_DESCRIPTOR_CODE_IPV6_NEIGHBOR_ADDRESS   = BGP_LS_IP6_NEIGHBOR_ADDR,
	LINK_DESCRIPTOR_CODE_MULTI_TOPOLOGY_ID       = BGP_LS_MUL_TOP_ID,
}LINK_DESCRIPTOR_CODE_ENUM;

// link_descriptor is a bgp-ls nlri.
typedef struct {
    /*rfc7752 basic*/
    bool_t link_IDs_b;
    link_descriptor_link_IDs link_IDs;
    bool_t IPv4_interface_address_b;
    link_descriptor_IPv4_interface_address IPv4_interface_address;
    bool_t IPv4_neighbor_address_b;
    link_descriptor_IPv4_neighbor_address IPv4_neighbor_address;
    bool_t IPv6_interface_address_b;
    link_descriptor_IPv6_interface_address IPv6_interface_address;
    bool_t IPv6_neighbor_address_b;
    link_descriptor_IPv6_neighbor_address IPv6_neighbor_address;
    bool_t mt_ID_b;
    multi_topology_ID mt_ID;    
}link_descriptor;

// NLRI_LINK is a link state nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2 figure 8
typedef struct {
    /*interal flags*/
    uint8_t  sync_flag;

    /*interal send flags*/
    uint8_t  send_flag;
    
    /*need send update packet*/
    uint8_t  ntt;

    /* origin nlri format.  */
    BGP_LS_TLV origin_nlri_buf;

    /*metadata*/
	uint8_t protocol_ID;
	uint64_t ID;
	node_descriptor local_node;
	node_descriptor remote_node;
	link_descriptor link;

    /*attribute*/
    link_attribute link_attr;

	char as_path[MAX_AS_PATH];
    
}NLRI_LINK;

// prefix_descriptor_ospf_route_type is a prefix descriptor contained in a bgp-ls nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.3.1
typedef struct {
	uint8_t route_type; 
}prefix_descriptor_ospf_route_type;

// ospf_route_type_ values
typedef enum {
	OSPF_ROUTE_TYPE_INTRAAREA = 1,
	OSPF_ROUTE_TYPE_INTERAREA,
	OSPF_ROUTE_TYPE_EXTERNAL1,
	OSPF_ROUTE_TYPE_EXTERNAL2,
	OSPF_ROUTE_TYPE_NSSA1,
	OSPF_ROUTE_TYPE_NSSA2,
}OSPF_ROUTE_TYPE_ENUM;

// prefix_descriptor_IP_reachability_info is a prefix descriptor contained in a bgp-ls nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.3.2
typedef struct {
	uint8_t PrefixLength;
	uint8_t Prefix[16];
}prefix_descriptor_IP_reachability_info;


/*  prefix_descriptor_code_ describes the type of prefix descriptor.
*  https://tools.ietf.org/html/rfc7752#section-3.2.3
*/
typedef enum {
	PREFIX_DESCRIPTOR_CODE_MULTI_TOPOLOGY_ID     = BGP_LS_MUL_TOP_ID,
	PREFIX_DESCRIPTOR_CODE_OSPF_ROUTE_TYPE       = BGP_LS_OSPF_ROUTE_TYPE,
	PREFIX_DESCRIPTOR_CODE_IP_REACHABILITY_INFO  = BGP_LS_IP_REACH_INFO,
}PREFIX_DESCRIPTOR_CODE_ENUM;

// prefix_descriptor is a bgp-ls prefix descriptor.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.3
typedef struct {
    /*rfc7752 basic*/    
    bool_t mt_ID_b;
    multi_topology_ID mt_ID;     
    bool_t ospf_route_type_b;
    prefix_descriptor_ospf_route_type ospf_route_type;
    bool_t IP_reachability_info_b; 
    prefix_descriptor_IP_reachability_info IP_reachability_info; 
}prefix_descriptor;

// NLRI_PREFIX is a link state nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2 figure 9
typedef struct {
    /*interal flags*/
    uint8_t  sync_flag;
    
    /*need send update packet*/
    uint8_t  ntt;

    /* origin nlri format.  */
    BGP_LS_TLV origin_nlri_buf;

    /*metadata*/
	uint8_t protocol_ID;
	uint64_t ID;
	node_descriptor local_node;
	prefix_descriptor prefix;

    /*attribute*/
    prefix_attribute prefix_attr;

	char as_path[MAX_AS_PATH];
    
}NLRI_PREFIX;


typedef struct {
	uint32_t sid[4];    
}sr6_sid_descriptor;

typedef struct {
    /*interal flags*/
    uint8_t  sync_flag;
    
    /*need send update packet*/
    uint8_t  ntt;

    /* origin nlri format.  */
    BGP_LS_TLV origin_nlri_buf;

    /*metadata*/
	uint8_t protocol_ID;
	uint64_t ID;
	node_descriptor local_node;
	sr6_sid_descriptor sr6_sid_desc;

    /*attribute*/
    sr6_sid_attribute sr6_sid_attr;

	char as_path[MAX_AS_PATH];
    
}NLRI_SR6_SID;




// BGP_LS_NLRI is a bgp link-state NLRI attribute
//
// https://tools.ietf.org/html/rfc7752#section-3.2
typedef struct bgp_ls_nlri {

    /*nlri Node.*/
    NLRI_NODE nlri_node;

    /*nlri Link.*/
    NLRI_LINK nlri_link;

    /*nlri ipv4 Prefix.*/
	NLRI_PREFIX nlri_prefix_ip4;

    /*nlri ipv6 Prefix.*/
    NLRI_PREFIX nlri_prefix_ip6;
    
    /* tlv human readable format string.  */
    char *str;
    BGP_LS_TLV origin_buf;

}BGP_LS_NLRI;

// https://tools.ietf.org/html/rfc7752#section-3.3
typedef struct bgp_ls_attr{

	/* Reference count of this attribute. */
	uint64_t refcnt;
    
    /*need send update packet*/
    uint8_t  ntt;

    /*attr has send flag*/
    uint8_t  send;

	node_attribute attrs_node;
	link_attribute attrs_link;
	prefix_attribute attrs_prefix;
    sr6_sid_attribute attrs_sr6_sid;
	te_policy_attribute attrs_te_policy;

    /* Human readable format string.  */
    char *str;
    BGP_LS_TLV origin_buf;
}BGP_LS_ATTR;


typedef struct bgp_ls_db{
 //    nlri reach; 
    struct list *reach_node;/* (struct NLRI_NODE) */
    struct list *reach_link;/* (struct NLRI_LINK) */
    struct list *reach_prefix_ip4;/* (struct NLRI_PREFIX) */
    struct list *reach_prefix_ip6;/* (struct NLRI_PREFIX) */
	/*added by wangqian for links psrse NLRI_TE-POLICY*/
	struct list *reach_te_policy;  /* (struct NLRI_TE_POLICY) */
    struct list *reach_sr6_sid;/* (struct NLRI_SR6_SID) */

 //    nlri unreach;  
    struct list *withdraw_node;/* (struct NLRI_NODE) */
    struct list *withdraw_link;/* (struct NLRI_LINK) */
    struct list *withdraw_prefix_ip4;/* (struct NLRI_PREFIX) */
    struct list *withdraw_prefix_ip6;/* (struct NLRI_PREFIX) */
    struct list *withdraw_sr6_sid;/* (struct NLRI_SR6_SID) */

//    link state attribute; 
    struct list *attri_node;/* (struct BGP_LS_ATTR) */
    struct list *attri_link;/* (struct BGP_LS_ATTR) */
    struct list *attri_prefix_ip4;/* (struct BGP_LS_ATTR) */
    struct list *attri_prefix_ip6;/* (struct BGP_LS_ATTR) */
    struct list *attri_sr6_sid;/* (struct BGP_LS_ATTR) */
	
    /*vpn type*/
    BGP_LS_VPN_TYPE_ENUM  type;
    uint64_t  route_distinguisher;
    
}BGP_LS_DB;



/*public serialize or parser function*/
extern void bgp_ls_nlri_node_desc_serialize
    (struct stream *s, node_descriptor *ls_node_nlri);
extern void bgp_ls_nlri_link_desc_serialize
    (struct stream *s, link_descriptor *ls_link_nlri);
extern  void bgp_ls_nlri_prefix_desc_serialize
    (struct stream *s, prefix_descriptor *ls_prefix_nlri);

    
extern  int32_t bgp_ls_nlri_node_parse
    (NLRI_NODE *nlri_node_head, uint8_t *pnt, uint16_t nlri_parse_len);
extern int32_t bgp_ls_nlri_link_parse
    (NLRI_LINK *nlri_link_head, uint8_t *pnt, uint16_t nlri_parse_len);
extern int32_t bgp_ls_nlri_ip4_prefix_parse
    (NLRI_PREFIX *nlri_prefix_head, uint8_t *pnt, uint16_t nlri_parse_len);
extern int32_t bgp_ls_nlri_ip6_prefix_parse
    (NLRI_PREFIX *nlri_prefix_head, uint8_t *pnt, uint16_t nlri_parse_len);
extern int32_t bgp_ls_nlri_sr6_sid_parse
    (NLRI_SR6_SID *nlri_prefix_head, uint8_t *pnt, uint16_t nlri_parse_len);


extern void bgp_ls_attr_node_serialize
    (struct stream *s, node_attribute *ls_node_attr);
extern void bgp_ls_attr_link_serialize
    (struct stream *s, link_attribute *ls_link_attr);
extern void bgp_ls_attr_prefix_serialize
    (struct stream *s, prefix_attribute *ls_prefix_attr);

extern int32_t bgp_ls_attr_node_parse
(
    uint16_t attr_type,
    uint16_t attr_length,
    uint8_t *pnt,
    node_attribute *ls_node_attr
);
extern int32_t bgp_ls_attr_link_parse
(
    uint16_t attr_type,
    uint16_t attr_length,
    uint8_t *pnt,
    link_attribute *ls_link_attr
);
extern int32_t bgp_ls_attr_prefix_parse
(
    uint16_t attr_type,
    uint16_t attr_length,
    uint8_t *pnt,
    prefix_attribute *ls_prefix_attr
);
extern int32_t bgp_ls_attr_sr6_sid_parse
(
    uint16_t attr_type,
    uint16_t attr_length,
    uint8_t *pnt,
    sr6_sid_attribute *ls_sr6_sid_attr
);

extern  void bgp_ls_str_alloc(char **str_buf,char *str);

extern  void bgp_ls_origin_buf_alloc
    (BGP_LS_TLV *origin_buf,uint8_t *data ,uint16_t type, int16_t length);

extern void bgp_ls_free_nlri_node(NLRI_NODE *ls_nlri_node);
extern void bgp_ls_free_nlri_link(NLRI_LINK *ls_nlri_link);
extern void bgp_ls_free_nlri_prefix(NLRI_PREFIX *ls_nlri_prefix);
extern void bgp_ls_free_nlri_sr6_sid(NLRI_SR6_SID *ls_nlri_sr6_sid);
extern void bgp_ls_free_attr(BGP_LS_ATTR *ls_attr);
extern int32_t bgp_ls_nlri_te_policy_parse(NLRI_TE_POLICY *nlri_te_policy_head,
								  uint8_t *pnt, uint16_t nlri_parse_len);
extern void bgp_ls_free_nlri_te_policy(NLRI_TE_POLICY *ls_nlri_te_policy);
extern int32_t bgp_ls_attr_te_policy_parse(uint16_t attr_type, uint16_t attr_length, uint8_t *pnt,te_policy_attribute *te_policy_attr);
extern int32_t bgp_ls_nlri_te_policy_desc_parse(te_policy_descriptor *te_policy_desc,
								uint8_t *pnt, uint16_t nlri_parse_len);


extern void bgp_ls_dup_nlri_node(NLRI_NODE *ls_nlri_node, NLRI_NODE *ls_nlri_node_new);
extern void bgp_ls_dup_nlri_link(NLRI_LINK *ls_nlri_link, NLRI_LINK *ls_nlri_link_new);
extern void bgp_ls_dup_nlri_prefix(NLRI_PREFIX *ls_nlri_prefix,NLRI_PREFIX *ls_nlri_prefix_new);


#endif /* _FRR_BGP_LS_H */

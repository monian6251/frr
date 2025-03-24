/***************************************************************************
*
* This is an implementation of BGP Link State as per RFC 7752
* Copyright (C) 2020 CTBRI
*
 ***************************************************************************/


#include <zebra.h>

#include "command.h"
#include "filter.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"
#include "hash.h"
#include "jhash.h"
#include "zclient.h"

#include "bgpd/bgp_errors.h"
#include "bgp_ls_pub.h"

DEFINE_MGROUP(BGPLS, "bgp link state");

DEFINE_MTYPE_STATIC(BGPLS, BGPLS_DECODE, "bgp ls decode ");

/*
 * Encapsulation and decapsulation functions defined in RFC   
 */

static BGP_LS_RET_T  node_descriptor_ASN_decode(BGP_LS_TLV *ls_tlv, node_descriptor_ASN* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("node descriptor Autonomous System length decode error");
        return BGP_LS_RET_ERROR;
    }
    
    DECODE_UINT32(ls_tlv->value, value_st->ASN);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_descriptor_ASN_encode(BGP_LS_TLV * ls_tlv, node_descriptor_ASN* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("node descriptor Autonomous System length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_UINT32(ls_tlv->value, value_st->ASN);
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_descriptor_bgp_ls_ID_decode(BGP_LS_TLV *ls_tlv, node_descriptor_bgp_ls_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("node descriptor BGP-LS Identifier length decode error");
        return BGP_LS_RET_ERROR;
    }
    
    DECODE_UINT32(ls_tlv->value, value_st->ID);
    return BGP_LS_RET_OK;

}

static BGP_LS_RET_T node_descriptor_bgp_ls_ID_encode(BGP_LS_TLV * ls_tlv, node_descriptor_bgp_ls_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("node descriptor OSPF Area-ID length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_UINT32(ls_tlv->value, value_st->ID);
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_descriptor_ospf_area_ID_decode(BGP_LS_TLV* ls_tlv, node_descriptor_ospf_area_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("node descriptor OSPF Area-ID length decode error");
        return BGP_LS_RET_ERROR;
    }
    
    DECODE_UINT32(ls_tlv->value, value_st->ID);    
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_descriptor_ospf_area_ID_encode(BGP_LS_TLV * ls_tlv, node_descriptor_ospf_area_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("node descriptor OSPF Area-ID length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_UINT32(ls_tlv->value, value_st->ID);
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_descriptor_igp_router_ID_decode(BGP_LS_TLV* ls_tlv, node_descriptor_igp_router_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (ls_tlv->length == 4)
    {        
        value_st->type = NODE_DESCRIPTOR_IGP_ROUTER_ID_OSPF_NON_PSEUDO_TYPE;
        DECODE_UINT32(ls_tlv->value, value_st->igp_router_ID.ospf_non_pseudo.RouterID);
    }
    else if (ls_tlv->length == 6)
    {
        value_st->type = NODE_DESCRIPTOR_IGP_ROUTER_ID_ISIS_NON_PSEUDO_TYPE;
        memcpy(value_st->igp_router_ID.IsIs_non_pseudo.IsoNodeID, ls_tlv->value, 6);  
    }
    else if (ls_tlv->length == 7)
    {
        value_st->type = NODE_DESCRIPTOR_IGP_ROUTER_ID_ISIS_PSEUDO_TYPE;
        memcpy(value_st->igp_router_ID.IsIs_pseudo.IsoNodeID, ls_tlv->value, 6);
        ls_tlv->value += 6;
        DECODE_UINT8(ls_tlv->value, value_st->igp_router_ID.IsIs_pseudo.PsnID);
    }
    else if (ls_tlv->length == 8)
    {
        value_st->type = NODE_DESCRIPTOR_IGP_ROUTER_ID_OSPF_PSEUDO_TYPE;
        DECODE_UINT32(ls_tlv->value, value_st->igp_router_ID.ospf_pseudo.DrRouterID);
        DECODE_UINT32(ls_tlv->value, value_st->igp_router_ID.ospf_pseudo.DrInterfaceToLAN);
    }
    else
    {
        BGPLS_ERR("node descriptor IGP Router-ID length decode error");
        return BGP_LS_RET_ERROR;
    }

    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T node_descriptor_igp_router_ID_encode(BGP_LS_TLV* ls_tlv, node_descriptor_igp_router_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }

    if (value_st->type == NODE_DESCRIPTOR_IGP_ROUTER_ID_OSPF_NON_PSEUDO_TYPE)
    {        
        ls_tlv->length = 4;
        ENCODE_UINT32(ls_tlv->value, value_st->igp_router_ID.ospf_non_pseudo.RouterID);
    }
    else if (value_st->type == NODE_DESCRIPTOR_IGP_ROUTER_ID_ISIS_NON_PSEUDO_TYPE)
    {
        ls_tlv->length = 6;
        memcpy(ls_tlv->value, value_st->igp_router_ID.IsIs_non_pseudo.IsoNodeID, 6);  
        ls_tlv->value += 6;
    }
    else if (value_st->type == NODE_DESCRIPTOR_IGP_ROUTER_ID_ISIS_PSEUDO_TYPE)
    {
        ls_tlv->length = 7;
        memcpy(ls_tlv->value,value_st->igp_router_ID.IsIs_pseudo.IsoNodeID, 6);  
        ls_tlv->value += 6;
        ENCODE_UINT8(ls_tlv->value, value_st->igp_router_ID.IsIs_pseudo.PsnID);
    }
    else if (value_st->type == NODE_DESCRIPTOR_IGP_ROUTER_ID_OSPF_PSEUDO_TYPE)
    {
        ls_tlv->length = 8;
        ENCODE_UINT32(ls_tlv->value, value_st->igp_router_ID.ospf_pseudo.DrRouterID);
        ENCODE_UINT32(ls_tlv->value, value_st->igp_router_ID.ospf_pseudo.DrInterfaceToLAN);
    }
    else
    {
        BGPLS_ERR("node descriptor IGP Router-ID length encode error");
        return BGP_LS_RET_ERROR;
    }
    
    return BGP_LS_RET_OK;
}

/*exclude rfc7752 */

static BGP_LS_RET_T node_descriptor_bgp_router_ID_decode(BGP_LS_TLV* ls_tlv, node_descriptor_bgp_router_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("node descriptor BGP Router-ID length decode error");
        return BGP_LS_RET_ERROR;
    }
    
    DECODE_UINT32(ls_tlv->value, value_st->RouterID);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_descriptor_bgp_router_ID_encode(BGP_LS_TLV* ls_tlv, node_descriptor_bgp_router_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("node descriptor BGP Router-ID length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_UINT32(ls_tlv->value, value_st->RouterID);
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_descriptor_member_ASN_decode(BGP_LS_TLV* ls_tlv, node_descriptor_member_ASN* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("node descriptor Member-ASN length decode error");
        return BGP_LS_RET_ERROR;
    }
    
    DECODE_UINT32(ls_tlv->value, value_st->ASN);
    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T node_descriptor_member_ASN_encode(BGP_LS_TLV* ls_tlv, node_descriptor_member_ASN* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("node descriptor Member-ASN length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_UINT32(ls_tlv->value, value_st->ASN);
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}



static BGP_LS_RET_T link_descriptor_link_IDs_decode(BGP_LS_TLV* ls_tlv, link_descriptor_link_IDs* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 8)
    {
        BGPLS_ERR("node descriptor Link Local/Remote Identifiers length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_UINT32(ls_tlv->value, value_st->LocalID);
    DECODE_UINT32(ls_tlv->value, value_st->RemoteID);
    return BGP_LS_RET_OK;

}

static BGP_LS_RET_T link_descriptor_link_IDs_encode(BGP_LS_TLV* ls_tlv, link_descriptor_link_IDs* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 8)
    {
        BGPLS_ERR("node descriptor Link Local/Remote Identifiers length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_UINT32(ls_tlv->value, value_st->LocalID);
    ENCODE_UINT32(ls_tlv->value, value_st->RemoteID);
    ls_tlv->length = 8;
    return BGP_LS_RET_OK;

}

static BGP_LS_RET_T link_descriptor_IPv4_interface_address_decode(BGP_LS_TLV* ls_tlv, link_descriptor_IPv4_interface_address* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("node descriptor Link IPv4 interface address length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_UINT32(ls_tlv->value, value_st->Address);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_descriptor_IPv4_interface_address_encode(BGP_LS_TLV* ls_tlv, link_descriptor_IPv4_interface_address* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("node descriptor Link IPv4 interface address length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_UINT32(ls_tlv->value, value_st->Address);
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T link_descriptor_IPv4_neighbor_address_decode(BGP_LS_TLV* ls_tlv, link_descriptor_IPv4_neighbor_address* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("node descriptor Link IPv4 neighbor address length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_UINT32(ls_tlv->value, value_st->Address);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_descriptor_IPv4_neighbor_address_encode(BGP_LS_TLV* ls_tlv, link_descriptor_IPv4_neighbor_address* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("node descriptor Link IPv4 neighbor address length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_UINT32(ls_tlv->value, value_st->Address);
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}



static BGP_LS_RET_T link_descriptor_IPv6_interface_address_decode(BGP_LS_TLV* ls_tlv, link_descriptor_IPv6_interface_address* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 16)
    {
        BGPLS_ERR("node descriptor Link IPv6 interface address length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_UINT32(ls_tlv->value, value_st->Address[0]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[1]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[2]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[3]);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_descriptor_IPv6_interface_address_encode(BGP_LS_TLV* ls_tlv, link_descriptor_IPv6_interface_address* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 16)
    {
        BGPLS_ERR("node descriptor Link IPv6 interface address length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_UINT32(ls_tlv->value, value_st->Address[0]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[1]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[2]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[3]);
    ls_tlv->length = 16;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_descriptor_IPv6_neighbor_address_decode(BGP_LS_TLV* ls_tlv, link_descriptor_IPv6_neighbor_address* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 16)
    {
        BGPLS_ERR("node descriptor Link IPv6 neighbor address length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_UINT32(ls_tlv->value, value_st->Address[0]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[1]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[2]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[3]);
    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T link_descriptor_IPv6_neighbor_address_encode(BGP_LS_TLV* ls_tlv, link_descriptor_IPv6_neighbor_address* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 16)
    {
        BGPLS_ERR("node descriptor Link IPv6 neighbor address length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_UINT32(ls_tlv->value, value_st->Address[0]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[1]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[2]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[3]);
    ls_tlv->length = 16;
    return BGP_LS_RET_OK;
}

/*  The format of the MT-ID TLV
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|              Type             |          Length=2*n           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|R R R R|  Multi-Topology ID 1  |             ....             //
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//             ....             |R R R R|  Multi-Topology ID n  |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static BGP_LS_RET_T multi_topology_IDs_decode(BGP_LS_TLV* ls_tlv, multi_topology_ID* value_st)
{
    uint32_t idx = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length%2 != 0)
    {
        BGPLS_ERR("Multi-Topology ID length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    if (NULL != value_st->IDs)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->IDs);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->IDs = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->IDs, ls_tlv->value, ls_tlv->length);
    }

    for(idx = 0;idx < (uint32_t)(ls_tlv->length/2);idx++)
    {
        DECODE_UINT16(ls_tlv->value, value_st->IDs[idx]);
    }
    value_st->length = ls_tlv->length;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T multi_topology_IDs_encode(BGP_LS_TLV* ls_tlv, multi_topology_ID* value_st)
{
    uint32_t idx = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (value_st->length%2 != 0)
    {
        BGPLS_ERR("Multi-Topology ID length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    for(idx = 0;idx < (uint32_t)(value_st->length/2);idx++)
    {
        ENCODE_UINT16(ls_tlv->value, value_st->IDs[idx]);
    }
    
    ls_tlv->length = value_st->length;

    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T prefix_descriptor_ospf_route_type_decode(BGP_LS_TLV* ls_tlv, prefix_descriptor_ospf_route_type* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 1)
    {
        BGPLS_ERR("prefix descriptor ospf route type length decode error");
        return BGP_LS_RET_ERROR;
    }
    
    DECODE_UINT8(ls_tlv->value, value_st->route_type);
    
	if ((value_st->route_type < OSPF_ROUTE_TYPE_INTRAAREA)
        || (value_st->route_type > OSPF_ROUTE_TYPE_NSSA2))
    {
		BGPLS_ERR("prefix descriptor invalid ospf route type prefix descriptor value");
        return BGP_LS_RET_ERROR;
	}

    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T prefix_descriptor_ospf_route_type_encode(BGP_LS_TLV* ls_tlv, prefix_descriptor_ospf_route_type* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 1)
    {
        BGPLS_ERR("prefix descriptor ospf route type length encode error");
        return BGP_LS_RET_ERROR;
    } 
    ls_tlv->length = 1;
    ENCODE_UINT8(ls_tlv->value, value_st->route_type);
    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T prefix_descriptor_IP_reachability_info_decode(BGP_LS_TLV* ls_tlv, prefix_descriptor_IP_reachability_info* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length > 17)
    {
        BGPLS_ERR("prefix descriptor ip reachability info length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_UINT8(ls_tlv->value, value_st->PrefixLength);  
    
    /* 
    * If length is greater than 1 then parse the prefix 
    * (default/zero prefix will not have prefix bytes)
    */               
    if (value_st->PrefixLength > 128)
    {
        BGPLS_ERR("prefix descriptor ip reachability info prefix length decode error");
        return BGP_LS_RET_ERROR;
    } 
    else if (value_st->PrefixLength == 0)
    {
        return BGP_LS_RET_OK;
    }

    memcpy(value_st->Prefix, ls_tlv->value, ls_tlv->length - 1);

    if ((ls_tlv->length - 1) < (((value_st->PrefixLength-1)/8) + 1))
    {
        BGPLS_ERR("prefix descriptor ip reachability info prefix length decode match error");
    }
    
    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T prefix_descriptor_IP_reachability_info_encode(BGP_LS_TLV* ls_tlv, prefix_descriptor_IP_reachability_info* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 17)
    {
        BGPLS_ERR("prefix descriptor ip reachability info prefix pre length encode error");
        return BGP_LS_RET_ERROR;
    } 

    ENCODE_UINT8(ls_tlv->value, value_st->PrefixLength);  
    
    if (value_st->PrefixLength > 128)
    {
        BGPLS_ERR("prefix descriptor ip reachability info prefix length encode error");
        return BGP_LS_RET_ERROR;
    } 
    else if (value_st->PrefixLength == 0)
    {        
        ls_tlv->length = 1;
        return BGP_LS_RET_OK;
    }

    memcpy( ls_tlv->value, value_st->Prefix, ((value_st->PrefixLength-1)/8)+1);    
    ls_tlv->length = 1 + ((value_st->PrefixLength-1)/8+1);

    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T node_attr_node_flag_bits_decode(BGP_LS_TLV* ls_tlv, node_attr_node_flag_bits* value_st)
{
    uint8_t node_attr_node_flag = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 1)
    {
        BGPLS_ERR("invalid length for node flag bits link state node attribute");
        return BGP_LS_RET_ERROR;
    }
    
    DECODE_UINT8(ls_tlv->value, node_attr_node_flag);

    value_st->Overload = (NODE_ATTR_NODE_FLAG_OVERLOAD & node_attr_node_flag);
    value_st->Attached = (NODE_ATTR_NODE_FLAG_ATTACHED & node_attr_node_flag);
    value_st->External = (NODE_ATTR_NODE_FLAG_EXTERNAL & node_attr_node_flag);
    value_st->ABR = (NODE_ATTR_NODE_FLAG_ABR & node_attr_node_flag);
    value_st->Router = (NODE_ATTR_NODE_FLAG_ROUTER & node_attr_node_flag);
    value_st->V6 = (NODE_ATTR_NODE_FLAG_V6 & node_attr_node_flag);
    
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_attr_node_flag_bits_encode(BGP_LS_TLV* ls_tlv, node_attr_node_flag_bits* value_st)
{
    uint8_t node_attr_node_flag = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 1)
    {
        BGPLS_ERR("node attribute flag bits length encode error");
        return BGP_LS_RET_ERROR;
    } 

    if(value_st->Overload)
        node_attr_node_flag |=NODE_ATTR_NODE_FLAG_OVERLOAD;
    if(value_st->Attached)
        node_attr_node_flag |=NODE_ATTR_NODE_FLAG_ATTACHED;
    if(value_st->External) 
        node_attr_node_flag |= NODE_ATTR_NODE_FLAG_EXTERNAL;
    if(value_st->ABR)
        node_attr_node_flag |=NODE_ATTR_NODE_FLAG_ABR;
    if(value_st->Router)
        node_attr_node_flag |=NODE_ATTR_NODE_FLAG_ROUTER;
    if(value_st->V6)
        node_attr_node_flag |=NODE_ATTR_NODE_FLAG_V6;

    ls_tlv->length = 1;
    ENCODE_UINT8(ls_tlv->value, node_attr_node_flag);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_attr_opaque_node_attr_decode(BGP_LS_TLV* ls_tlv, node_attr_opaque_node_attr* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (NULL != value_st->Data)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->Data);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->Data = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->Data, ls_tlv->value, ls_tlv->length);
    }
    value_st->length = ls_tlv->length; 
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_attr_opaque_node_attr_encode(BGP_LS_TLV* ls_tlv, node_attr_opaque_node_attr* value_st)
{
    if (value_st->length != 0)
    {
        memcpy(ls_tlv->value, value_st->Data, value_st->length);
    }
    ls_tlv->length = value_st->length;
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_attr_node_name_decode(BGP_LS_TLV* ls_tlv, node_attr_node_name* value_st)
{   
    if (NULL != value_st->Name)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->Name);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->Name = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->Name, ls_tlv->value, ls_tlv->length);
    }
    value_st->length = ls_tlv->length; 
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_attr_node_name_encode(BGP_LS_TLV* ls_tlv, node_attr_node_name* value_st)
{
    if (value_st->length != 0)
    {
        memcpy(ls_tlv->value, value_st->Name, value_st->length);
    }
    ls_tlv->length = value_st->length;
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_attr_IsIs_area_ID_decode(BGP_LS_TLV* ls_tlv, node_attr_IsIs_area_ID* value_st)
{    
    if (NULL != value_st->AreaID)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->AreaID);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->AreaID = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->AreaID, ls_tlv->value, ls_tlv->length);
    }
    value_st->length = ls_tlv->length; 

    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_attr_IsIs_area_ID_encode(BGP_LS_TLV* ls_tlv, node_attr_IsIs_area_ID* value_st)
{
    if (value_st->length != 0)
    {
        memcpy(ls_tlv->value, value_st->AreaID, value_st->length);
    }
    ls_tlv->length = value_st->length;
    return  BGP_LS_RET_OK;
}


static BGP_LS_RET_T local_IPv4_router_ID_decode(BGP_LS_TLV* ls_tlv, local_IPv4_router_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("local IPv4 router ID length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_UINT32(ls_tlv->value, value_st->Address);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T local_IPv4_router_ID_encode(BGP_LS_TLV* ls_tlv, local_IPv4_router_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("local IPv4 router ID length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_UINT32(ls_tlv->value, value_st->Address);
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T local_IPv6_router_ID_decode(BGP_LS_TLV* ls_tlv, local_IPv6_router_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 16)
    {
        BGPLS_ERR("local IPv6 router ID length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_UINT32(ls_tlv->value, value_st->Address[0]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[1]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[2]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[3]);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T local_IPv6_router_ID_encode(BGP_LS_TLV* ls_tlv, local_IPv6_router_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 16)
    {
        BGPLS_ERR("local IPv6 router ID length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_UINT32(ls_tlv->value, value_st->Address[0]);
    ENCODE_UINT32(ls_tlv->value, value_st->Address[1]);
    ENCODE_UINT32(ls_tlv->value, value_st->Address[2]);
    ENCODE_UINT32(ls_tlv->value, value_st->Address[3]);
    ls_tlv->length = 16;
    return BGP_LS_RET_OK;
}


/*exclude rfc7752 */
static BGP_LS_RET_T node_attr_SR_caps_decode(BGP_LS_TLV* ls_tlv, node_attr_SR_caps* value_st)
{    
    
    uint8_t node_attr_SR_caps_flag = 0;
    uint8_t node_attr_SR_caps_reserved = 0;
    if (ls_tlv->length < 8)
    {
        BGPLS_ERR("invalid length for node_attr_SR_caps");
        return BGP_LS_RET_ERROR;
    } 
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    DECODE_UINT8(ls_tlv->value, node_attr_SR_caps_flag);
    value_st->mpls_IPv4 = (SR_CAP_FLAGS_MPLS_IPV4 & node_attr_SR_caps_flag);
    value_st->mpls_IPv6 = (SR_CAP_FLAGS_MPLS_IPV6 & node_attr_SR_caps_flag);
    
    /*skip RESERVED 1 byte*/
    DECODE_UINT8(ls_tlv->value, node_attr_SR_caps_reserved);

    DECODE_U24_UINT32(ls_tlv->value, value_st->range_size);

    DECODE_UINT16(ls_tlv->value, value_st->SID_label.Type);
    DECODE_UINT16(ls_tlv->value, value_st->SID_label.length);

    if(value_st->SID_label.length == 3)
    {
        DECODE_U24_UINT32(ls_tlv->value, value_st->SID_label.SID_or_label);
    }
    else if(value_st->SID_label.length == 4)
    {
        DECODE_UINT32(ls_tlv->value, value_st->SID_label.SID_or_label);
    }
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_attr_SR_caps_encode(BGP_LS_TLV* ls_tlv, node_attr_SR_caps* value_st)
{
    uint8_t node_attr_SR_caps_flag = 0;
    uint8_t node_attr_SR_caps_reserved = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 13)
    {
        BGPLS_ERR("node SR caps pre length decode error");
        return BGP_LS_RET_ERROR;
    }

    if(value_st->mpls_IPv4)
        node_attr_SR_caps_flag |=SR_CAP_FLAGS_MPLS_IPV4;
    if(value_st->mpls_IPv6)
        node_attr_SR_caps_flag |=SR_CAP_FLAGS_MPLS_IPV6;
    
    ENCODE_UINT8(ls_tlv->value, node_attr_SR_caps_flag);
    /*skip RESERVED 1 byte*/
    ENCODE_UINT8(ls_tlv->value, node_attr_SR_caps_reserved);

    ENCODE_U24_UINT32(ls_tlv->value, value_st->range_size);

    ENCODE_UINT16(ls_tlv->value, value_st->SID_label.Type);
    
    ENCODE_UINT16(ls_tlv->value, value_st->SID_label.length);

    if(value_st->SID_label.length == 3)
    {
        ENCODE_U24_UINT32(ls_tlv->value, value_st->SID_label.SID_or_label);
        ls_tlv->length = 7 + 5;
    }
    else if(value_st->SID_label.length == 4)
    {
        ENCODE_UINT32(ls_tlv->value, value_st->SID_label.SID_or_label);
        ls_tlv->length = 8 + 5;
    }
    return BGP_LS_RET_OK;

}


static BGP_LS_RET_T node_attr_SR_algo_decode(BGP_LS_TLV* ls_tlv, node_attr_SR_algo* value_st)
{
    if (NULL != value_st->Algos)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->Algos);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->Algos = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->Algos, ls_tlv->value, ls_tlv->length);
    }
    value_st->length = ls_tlv->length; 

    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_attr_SR_algo_encode(BGP_LS_TLV* ls_tlv, node_attr_SR_algo* value_st)
{
    if (value_st->length != 0)
    {
        memcpy(ls_tlv->value, value_st->Algos, value_st->length);
    }
    ls_tlv->length = value_st->length;
    return  BGP_LS_RET_OK;
}


static BGP_LS_RET_T node_attr_SR_local_block_decode(BGP_LS_TLV* ls_tlv, node_attr_SR_local_block* value_st)
{    
    
    uint8_t node_attr_SR_local_block_reserved = 0;
    if (ls_tlv->length < 8)
    {
        BGPLS_ERR("invalid length for node_attr_SR_caps");
        return BGP_LS_RET_ERROR;
    } 
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    DECODE_UINT8(ls_tlv->value, value_st->flags);
    
    /*skip RESERVED 1 byte*/
    DECODE_UINT8(ls_tlv->value, node_attr_SR_local_block_reserved);

    DECODE_U24_UINT32(ls_tlv->value, value_st->range_size);

    DECODE_UINT16(ls_tlv->value, value_st->SID_label.Type);
    DECODE_UINT16(ls_tlv->value, value_st->SID_label.length);

    if(value_st->SID_label.length == 3)
    {
        DECODE_U24_UINT32(ls_tlv->value, value_st->SID_label.SID_or_label);
    }
    else if(value_st->SID_label.length == 4)
    {
        DECODE_UINT32(ls_tlv->value, value_st->SID_label.SID_or_label);
    }
    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T node_attr_SR_local_block_encode(BGP_LS_TLV* ls_tlv, node_attr_SR_local_block* value_st)
{
    uint8_t node_attr_SR_local_block_reserved = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (ls_tlv->length < 13)
    {
        BGPLS_ERR("node SR local block pre length decode error");
        return BGP_LS_RET_ERROR;
    }
    
    ENCODE_UINT8(ls_tlv->value, value_st->flags);
    /*skip RESERVED 1 byte*/
    ENCODE_UINT8(ls_tlv->value, node_attr_SR_local_block_reserved);

    ENCODE_U24_UINT32(ls_tlv->value, value_st->range_size);

    ENCODE_UINT16(ls_tlv->value, value_st->SID_label.Type);
    
    ENCODE_UINT16(ls_tlv->value, value_st->SID_label.length);

    if(value_st->SID_label.length == 3)
    {
        ENCODE_U24_UINT32(ls_tlv->value, value_st->SID_label.SID_or_label);
        ls_tlv->length = 7 + 5;
    }
    else if(value_st->SID_label.length == 4)
    {
        ENCODE_UINT32(ls_tlv->value, value_st->SID_label.SID_or_label);
        ls_tlv->length = 8 + 5;
    }
    return BGP_LS_RET_OK;

}


static BGP_LS_RET_T node_attr_SRMS_pref_decode(BGP_LS_TLV* ls_tlv, node_attr_SRMS_pref* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 1)
    {
        BGPLS_ERR("invalid length for node flag bits link state node attribute");
        return BGP_LS_RET_ERROR;
    }
    
    DECODE_UINT8(ls_tlv->value, value_st->Preference);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_attr_SRMS_pref_encode(BGP_LS_TLV* ls_tlv, node_attr_SRMS_pref* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 1)
    {
        BGPLS_ERR("node attribute flag bits length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ls_tlv->length = 1;
    ENCODE_UINT8(ls_tlv->value, value_st->Preference);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_attr_SID_label_decode(BGP_LS_TLV* ls_tlv, SID_label* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 7)
    {
        BGPLS_ERR("invalid length for SID/Label link state node attribute");
        return BGP_LS_RET_ERROR;
    }
 
	DECODE_UINT16(ls_tlv->value, value_st->Type);
    DECODE_UINT16(ls_tlv->value, value_st->length);

    if(value_st->length == 3)
    {
        DECODE_U24_UINT32(ls_tlv->value, value_st->SID_or_label);
    }
    else if(value_st->length == 4)
    {
        DECODE_UINT32(ls_tlv->value, value_st->SID_or_label);
    }
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_attr_SID_label_encode(BGP_LS_TLV* ls_tlv, SID_label* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 7)
    {
        BGPLS_ERR("invalid length for SID/Label link state node attribute");
        return BGP_LS_RET_ERROR;
    }
    
    ENCODE_UINT16(ls_tlv->value, value_st->Type);
    
    ENCODE_UINT16(ls_tlv->value, value_st->length);

    if(value_st->length == 3)
    {
        ENCODE_U24_UINT32(ls_tlv->value, value_st->SID_or_label);
        ls_tlv->length = 7;
    }
    else if(value_st->length == 4)
    {
        ENCODE_UINT32(ls_tlv->value, value_st->SID_or_label);
        ls_tlv->length = 8;
    }
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T node_attr_SR6_caps_decode(BGP_LS_TLV* ls_tlv, node_attr_SR6_caps* value_st)
{    
    
    uint16_t node_attr_SR6_caps_flag = 0;
    uint16_t node_attr_SR6_caps_reserved = 0;
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("invalid length for node_attr_SR6_caps");
        return BGP_LS_RET_ERROR;
    } 
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    DECODE_UINT16(ls_tlv->value, node_attr_SR6_caps_flag);
    value_st->flags = (SR6_CAP_FLAGS_SRH_O_BIT & node_attr_SR6_caps_flag);
    
    /*skip RESERVED 2 bytes*/
    DECODE_UINT16(ls_tlv->value, node_attr_SR6_caps_reserved);
    
    return BGP_LS_RET_OK;
}

#if 0
static BGP_LS_RET_T node_attr_SR6_caps_encode(BGP_LS_TLV* ls_tlv, node_attr_SR6_caps* value_st)
{
    uint16_t node_attr_SR6_caps_flag = 0;
    uint16_t node_attr_SR6_caps_reserved = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("node SRV6 caps pre length decode error");
        return BGP_LS_RET_ERROR;
    }

    if(value_st->flags)
        node_attr_SR6_caps_flag |= SR6_CAP_FLAGS_SRH_O_BIT;
    
    ENCODE_UINT16(ls_tlv->value, node_attr_SR6_caps_flag);
    /*skip RESERVED 2 bytes*/
    ENCODE_UINT16(ls_tlv->value, node_attr_SR6_caps_reserved);
    
    return BGP_LS_RET_OK;

}
#endif


static BGP_LS_RET_T remote_IPv4_router_ID_decode(BGP_LS_TLV* ls_tlv, remote_IPv4_router_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("remote IPv4 router ID length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_UINT32(ls_tlv->value, value_st->Address);
    return BGP_LS_RET_OK;

}

static BGP_LS_RET_T remote_IPv4_router_ID_encode(BGP_LS_TLV* ls_tlv, remote_IPv4_router_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("remote IPv4 router ID length decode error");
        return BGP_LS_RET_ERROR;
    } 
    ls_tlv->length = 4;
    DECODE_UINT32(ls_tlv->value, value_st->Address);
    return BGP_LS_RET_OK;

}


static BGP_LS_RET_T remote_IPv6_router_ID_decode(BGP_LS_TLV* ls_tlv, remote_IPv6_router_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 16)
    {
        BGPLS_ERR("remote IPv6 router ID length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_UINT32(ls_tlv->value, value_st->Address[0]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[1]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[2]);
    DECODE_UINT32(ls_tlv->value, value_st->Address[3]);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T remote_IPv6_router_ID_encode(BGP_LS_TLV* ls_tlv, remote_IPv6_router_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 16)
    {
        BGPLS_ERR("remote IPv6 router ID length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_UINT32(ls_tlv->value, value_st->Address[0]);
    ENCODE_UINT32(ls_tlv->value, value_st->Address[1]);
    ENCODE_UINT32(ls_tlv->value, value_st->Address[2]);
    ENCODE_UINT32(ls_tlv->value, value_st->Address[3]);
    ls_tlv->length = 16;
    return BGP_LS_RET_OK;
}

/*
	The administrative group sub-TLV contains a 4-octet bit mask assigned
	by the network administrator.  Each set bit corresponds to one
	administrative group assigned to the interface.

	By convention, the least significant bit is referred to as 'group 0',
	and the most significant bit is referred to as 'group 31'.
*/
static BGP_LS_RET_T link_attr_admin_group_decode(BGP_LS_TLV* ls_tlv, link_attr_admin_group* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("link attr admin group length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_UINT32(ls_tlv->value, value_st->Group_bits);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_admin_group_encode(BGP_LS_TLV* ls_tlv, link_attr_admin_group* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("link attr admin group length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_UINT32(ls_tlv->value, value_st->Group_bits);
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_maxLink_bandwidth_decode(BGP_LS_TLV* ls_tlv, link_attr_maxLink_bandwidth* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("link attr maxLink bandwidth length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_maxLink_bandwidth_encode(BGP_LS_TLV* ls_tlv, link_attr_maxLink_bandwidth* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("link attr maxLink bandwidth length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second);
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}



static BGP_LS_RET_T link_attr_max_reservable_link_bandwidth_decode(BGP_LS_TLV* ls_tlv, link_attr_max_reservable_link_bandwidth* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("link attr max reservable link bandwidth length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_max_reservable_link_bandwidth_encode(BGP_LS_TLV* ls_tlv, link_attr_max_reservable_link_bandwidth* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("link attr max reservable link bandwidth length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second);
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T link_attr_unreserved_bandwidth_decode(BGP_LS_TLV* ls_tlv, link_attr_unreserved_bandwidth* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 32)
    {
        BGPLS_ERR("link attr unreserved bandwidth length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second[0]);
    DECODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second[1]);
    DECODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second[2]);
    DECODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second[3]);
    DECODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second[4]);
    DECODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second[5]);
    DECODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second[6]);
    DECODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second[7]);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_unreserved_bandwidth_encode(BGP_LS_TLV* ls_tlv, link_attr_unreserved_bandwidth* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 32)
    {
        BGPLS_ERR("link attr unreserved bandwidth length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second[0]);
    ENCODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second[1]);
    ENCODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second[2]);
    ENCODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second[3]);
    ENCODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second[4]);
    ENCODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second[5]);
    ENCODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second[6]);
    ENCODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second[7]);
    ls_tlv->length = 32;
    return BGP_LS_RET_OK;

}

static BGP_LS_RET_T link_attr_TE_default_metric_decode(BGP_LS_TLV* ls_tlv, link_attr_TE_default_metric* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("link attr TE default metric length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_UINT32(ls_tlv->value, value_st->Metric);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_TE_default_metric_encode(BGP_LS_TLV* ls_tlv, link_attr_TE_default_metric* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("link attr TE default metric length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_UINT32(ls_tlv->value, value_st->Metric);
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_link_protection_type_decode(BGP_LS_TLV* ls_tlv, link_attr_link_protection_type* value_st)
{
    uint8_t link_protection_type = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 2)
    {
        BGPLS_ERR("invalid length for link protection typedef link attribute");
        return BGP_LS_RET_ERROR;
    } 
    
    /*decode the first octet (Protection Cap) */
    DECODE_UINT8(ls_tlv->value, link_protection_type);
    value_st->ExtraTraffic = (LINK_PROTECTION_TYPE_EXTRATRAFFIC & link_protection_type);
    value_st->Unprotected = (LINK_PROTECTION_TYPE_UNPROTECTED & link_protection_type);
    value_st->Shared = (LINK_PROTECTION_TYPE_SHARED & link_protection_type);
    value_st->DedicatedOneToOne = (LINK_PROTECTION_TYPE_DEDICATEDONETOONE & link_protection_type);
    value_st->DedicatedOnePlusOne = (LINK_PROTECTION_TYPE_DEDICATEDONEPLUSONE & link_protection_type);
    value_st->Enhanced = (LINK_PROTECTION_TYPE_ENHANCED & link_protection_type);  
    ls_tlv->length = 2;
    return BGP_LS_RET_OK;
    
}

static BGP_LS_RET_T link_attr_link_protection_type_encode(BGP_LS_TLV* ls_tlv, link_attr_link_protection_type* value_st)
{
    uint8_t link_protection_type = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (ls_tlv->length < 2)
    {
        BGPLS_ERR("invalid length for link protection typedef link attribute");
        return BGP_LS_RET_ERROR;
    } 

    if(value_st->ExtraTraffic)
        link_protection_type |=LINK_PROTECTION_TYPE_EXTRATRAFFIC;
    if(value_st->Unprotected)
        link_protection_type |=LINK_PROTECTION_TYPE_UNPROTECTED;
    if(value_st->Shared) 
        link_protection_type |=LINK_PROTECTION_TYPE_SHARED;
    if(value_st->DedicatedOneToOne)
        link_protection_type |=LINK_PROTECTION_TYPE_DEDICATEDONETOONE;
    if(value_st->DedicatedOnePlusOne)
        link_protection_type |=LINK_PROTECTION_TYPE_DEDICATEDONEPLUSONE;
    if(value_st->Enhanced)
        link_protection_type |=LINK_PROTECTION_TYPE_ENHANCED;
    
    /*encode the first octet (Protection Cap) */
    ENCODE_UINT8(ls_tlv->value, link_protection_type);

    /*encode Reserved */
    ENCODE_UINT8(ls_tlv->value, 0);
    ls_tlv->length = 2;
    return BGP_LS_RET_OK;

}

static BGP_LS_RET_T link_attr_mpls_protocol_mask_decode(BGP_LS_TLV* ls_tlv, link_attr_mpls_protocol_mask* value_st)
{
    uint8_t mpls_protocol_mask = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 1)
    {
        BGPLS_ERR("invalid length for mpls protocol mask link attribute");
        return BGP_LS_RET_ERROR;
    } 
    /*decode the first octet (Protection Cap) */
    DECODE_UINT8(ls_tlv->value, mpls_protocol_mask);
    value_st->LDP = LINK_ATTR_MPLS_PROTOCOL_LDP & mpls_protocol_mask;
    value_st->RsvpTE = LINK_ATTR_MPLS_PROTOCOL_RSVP_TE & mpls_protocol_mask;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_mpls_protocol_mask_encode(BGP_LS_TLV* ls_tlv, link_attr_mpls_protocol_mask* value_st)
{
    uint8_t mpls_protocol_mask = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 1)
    {
        BGPLS_ERR("invalid length for mpls protocol mask link attribute");
        return BGP_LS_RET_ERROR;
    }

    if(value_st->LDP)
        mpls_protocol_mask |=LINK_ATTR_MPLS_PROTOCOL_LDP;
    if(value_st->RsvpTE)
        mpls_protocol_mask |=LINK_ATTR_MPLS_PROTOCOL_RSVP_TE;
    
    /*encode the first octet (Protection Cap) */
    ENCODE_UINT8(ls_tlv->value, mpls_protocol_mask);
    ls_tlv->length = 1;
    return BGP_LS_RET_OK;
}

/*
	The IGP Metric TLV carries the metric for this link.  The length of
	this TLV is variable, depending on the metric width of the underlying
	protocol.  IS-IS small metrics have a length of 1 octet (the two most
	significant bits are ignored).  OSPF link metrics have a length of 2
	octets.  IS-IS wide metrics have a length of 3 octets.

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|              Type             |             Length            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//      IGP Link Metric (variable length)      //
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static BGP_LS_RET_T link_attr_igp_metric_decode(BGP_LS_TLV* ls_tlv, link_attr_igp_metric* value_st)
{    
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    switch (ls_tlv->length)
    {
        case 1:
            value_st->Type = LINK_ATTR_IGP_METRIC_ISIS_SMALL_TYPE;
            DECODE_UINT8(ls_tlv->value, value_st->Metric);
            break;
        case 2:
            value_st->Type = LINK_ATTR_IGP_METRIC_OSPF_TYPE;
            DECODE_UINT16(ls_tlv->value, value_st->Metric);
            break;
        case 3:
            value_st->Type = LINK_ATTR_IGP_METRIC_ISIS_WIDE_TYPE;
            DECODE_U24_UINT32(ls_tlv->value, value_st->Metric);
            break;
        default:
            BGPLS_ERR("invalid length for igp metric link attribute");
            return BGP_LS_RET_ERROR;
    }
   
   return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_igp_metric_encode(BGP_LS_TLV* ls_tlv, link_attr_igp_metric* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (ls_tlv->length < 3)
    {
        BGPLS_ERR("pre invalid length for igp metric link attribute");
        return BGP_LS_RET_ERROR;
    }

    switch (value_st->Type)
    {
        case LINK_ATTR_IGP_METRIC_ISIS_SMALL_TYPE:
            ls_tlv->length = 1;
            ENCODE_UINT8(ls_tlv->value, value_st->Metric);
            break;
        case LINK_ATTR_IGP_METRIC_OSPF_TYPE:
            ls_tlv->length = 2;
            ENCODE_UINT16(ls_tlv->value, value_st->Metric);
            break;
        case LINK_ATTR_IGP_METRIC_ISIS_WIDE_TYPE:
            ls_tlv->length = 3;
            ENCODE_U24_UINT32(ls_tlv->value, value_st->Metric);
            break;
        default:
            BGPLS_ERR("invalid length for igp metric link attribute");
            
    }
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_shared_risk_link_group_decode(BGP_LS_TLV* ls_tlv, link_attr_shared_risk_link_group* value_st)
{
    uint16_t idx = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }

    if ((ls_tlv->length%4 != 0) || (ls_tlv->length < 4))
    {
        BGPLS_ERR("invalid length for shared risk link group link attribute");
        return BGP_LS_RET_ERROR;
    }

    if (NULL != value_st->Groups)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->Groups);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->Groups = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->Groups, ls_tlv->value, ls_tlv->length);
    }
    
    for(idx = 0; idx < (((ls_tlv->length-1)/4) + 1); idx++)
    {
        DECODE_UINT32(ls_tlv->value, value_st->Groups[idx]);
    }
    
    value_st->length = ls_tlv->length;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_shared_risk_link_group_encode(BGP_LS_TLV* ls_tlv, link_attr_shared_risk_link_group* value_st)
{
    uint16_t idx = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (ls_tlv->length < value_st->length)
    {
        BGPLS_ERR("pre invalid length for shared risk link group link attribute");
        return BGP_LS_RET_ERROR;
    }

    if ((value_st->length%4 != 0) || (value_st->length < 4))
    {
        BGPLS_ERR("invalid length for encode shared risk link group link attribute");
        return BGP_LS_RET_ERROR;
    }
    for(idx = 0; idx < (((value_st->length-1)/4) + 1); idx++)
    {
        ENCODE_UINT32(ls_tlv->value, value_st->Groups[idx]);
    }
    
    ls_tlv->length = idx*4;
    return BGP_LS_RET_OK;

}


static BGP_LS_RET_T link_attr_opaque_link_attr_decode(BGP_LS_TLV* ls_tlv, link_attr_opaque_link_attr* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (NULL != value_st->Data)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->Data);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->Data = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->Data, ls_tlv->value, ls_tlv->length);
    }

    value_st->length = ls_tlv->length;    
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_opaque_link_attr_encode(BGP_LS_TLV* ls_tlv, link_attr_opaque_link_attr* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }

    if (ls_tlv->length < value_st->length)
    {
        BGPLS_ERR("pre invalid length for opaque link attribute");
        return BGP_LS_RET_ERROR;
    }
     
    if (value_st->length != 0)
    {
        memcpy(ls_tlv->value, value_st->Data, value_st->length);
    }
    ls_tlv->length = value_st->length;    
    return  BGP_LS_RET_OK;
}


static BGP_LS_RET_T link_attr_link_name_decode(BGP_LS_TLV* ls_tlv, link_attr_link_name* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (NULL != value_st->Name)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->Name);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->Name = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->Name, ls_tlv->value, ls_tlv->length);
    }
    value_st->length = ls_tlv->length; 
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_link_name_encode(BGP_LS_TLV* ls_tlv, link_attr_link_name* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (ls_tlv->length < value_st->length)
    {
        BGPLS_ERR("pre invalid length for link name attribute");
        return BGP_LS_RET_ERROR;
    }

    if (value_st->length != 0)
    {
        memcpy(ls_tlv->value, value_st->Name, value_st->length);
    }
    ls_tlv->length = value_st->length;    
    return  BGP_LS_RET_OK;
}

/*exclude rfc7752 */
static BGP_LS_RET_T link_attr_adj_SID_decode(BGP_LS_TLV* ls_tlv, link_attr_adj_SID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (NULL != value_st->value)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->value);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->value = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->value, ls_tlv->value, ls_tlv->length);
    }

    value_st->length = ls_tlv->length;  
    value_st->type = ls_tlv->type; 

    DECODE_UINT8(ls_tlv->value, value_st->Flags);
    DECODE_UINT8(ls_tlv->value, value_st->Weight);
    DECODE_UINT16(ls_tlv->value, value_st->Reserved);

    if(value_st->length == 7)
    {
        DECODE_U24_UINT32(ls_tlv->value, value_st->SID_index_label);
    }
    else if(value_st->length == 8)
    {
        DECODE_UINT32(ls_tlv->value, value_st->SID_index_label);
    }
    
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_adj_SID_encode(BGP_LS_TLV* ls_tlv, link_attr_adj_SID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < value_st->length)
    {
        BGPLS_ERR("pre invalid length for adj SID attribute");
        return BGP_LS_RET_ERROR;
    }

    /*need packet data*/    
    /*...................*/
    
    if (value_st->length != 0)
    {
        memcpy(ls_tlv->value, value_st->value, value_st->length);
    }
    ls_tlv->length = value_st->length;    
    ls_tlv->type = value_st->type;     
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_lan_adj_SID_decode(BGP_LS_TLV* ls_tlv, link_attr_lan_adj_SID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }

    if (NULL != value_st->value)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->value);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->value = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->value, ls_tlv->value, ls_tlv->length);
    }
    
    value_st->length = ls_tlv->length;  
    value_st->type = ls_tlv->type; 

    DECODE_UINT8(ls_tlv->value, value_st->Flags);
    DECODE_UINT8(ls_tlv->value, value_st->Weight);
    DECODE_UINT16(ls_tlv->value, value_st->Reserved);

    DECODE_UINT8(ls_tlv->value, value_st->Neighbor_ID_SystemID[0]);
    DECODE_UINT8(ls_tlv->value, value_st->Neighbor_ID_SystemID[1]);
    DECODE_UINT8(ls_tlv->value, value_st->Neighbor_ID_SystemID[2]);
    DECODE_UINT8(ls_tlv->value, value_st->Neighbor_ID_SystemID[3]);
    DECODE_UINT8(ls_tlv->value, value_st->Neighbor_ID_SystemID[4]);
    DECODE_UINT8(ls_tlv->value, value_st->Neighbor_ID_SystemID[5]);

    if(value_st->length == 13)
    {
        DECODE_U24_UINT32(ls_tlv->value, value_st->SID_index_label);
    }
    else if(value_st->length == 14)
    {
        DECODE_UINT32(ls_tlv->value, value_st->SID_index_label);
    }
    
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_lan_adj_SID_encode(BGP_LS_TLV* ls_tlv, link_attr_lan_adj_SID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (ls_tlv->length < value_st->length)
    {
        BGPLS_ERR("pre invalid length for lan adj SID attribute");
        return BGP_LS_RET_ERROR;
    }

    /*need packet data*/    
    /*...................*/
    
    if (value_st->length != 0)
    {
        memcpy(ls_tlv->value, value_st->value, value_st->length);
    }
    ls_tlv->length = value_st->length;    
    ls_tlv->type = value_st->type;     
    return  BGP_LS_RET_OK;
}


static BGP_LS_RET_T link_attr_peer_node_SID_decode(BGP_LS_TLV* ls_tlv, link_attr_peer_node_SID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (NULL != value_st->value)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->value);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->value = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->value, ls_tlv->value, ls_tlv->length);
    }

    value_st->length = ls_tlv->length;  
    value_st->type = ls_tlv->type; 

    DECODE_UINT8(ls_tlv->value, value_st->Flags);
    DECODE_UINT8(ls_tlv->value, value_st->Weight);
    DECODE_UINT16(ls_tlv->value, value_st->Reserved);

    if(value_st->length == 7)
    {
        DECODE_U24_UINT32(ls_tlv->value, value_st->SID_index_label);
    }
    else if(value_st->length == 8)
    {
        DECODE_UINT32(ls_tlv->value, value_st->SID_index_label);
    }
    
    
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_peer_node_SID_encode(BGP_LS_TLV* ls_tlv, link_attr_peer_node_SID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (ls_tlv->length < value_st->length)
    {
        BGPLS_ERR("pre invalid length for peer node SID attribute");
        return BGP_LS_RET_ERROR;
    }

    /*need packet data*/    
    /*...................*/
    
    if (NULL != value_st->value)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->value);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->value = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->value, ls_tlv->value, ls_tlv->length);
    }

    ls_tlv->length = value_st->length;    
    ls_tlv->type = value_st->type;     
    return  BGP_LS_RET_OK;
}


static BGP_LS_RET_T link_attr_peer_adj_SID_decode(BGP_LS_TLV* ls_tlv, link_attr_peer_adj_SID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (NULL != value_st->value)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->value);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->value = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->value, ls_tlv->value, ls_tlv->length);
    }

    value_st->length = ls_tlv->length;  
    value_st->type = ls_tlv->type; 

    DECODE_UINT8(ls_tlv->value, value_st->Flags);
    DECODE_UINT8(ls_tlv->value, value_st->Weight);
    DECODE_UINT16(ls_tlv->value, value_st->Reserved);

    if(value_st->length == 7)
    {
        DECODE_U24_UINT32(ls_tlv->value, value_st->SID_index_label);
    }
    else if(value_st->length == 8)
    {
        DECODE_UINT32(ls_tlv->value, value_st->SID_index_label);
    }
    
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_peer_adj_SID_encode(BGP_LS_TLV* ls_tlv, link_attr_peer_adj_SID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (ls_tlv->length < value_st->length)
    {
        BGPLS_ERR("pre invalid length for peer adj SID attribute");
        return BGP_LS_RET_ERROR;
    }

    /*need packet data*/    
    /*...................*/
    
    if (value_st->length != 0)
    {
        memcpy(ls_tlv->value, value_st->value, value_st->length);
    }
    ls_tlv->length = value_st->length;    
    ls_tlv->type = value_st->type;     
    return  BGP_LS_RET_OK;
}


static BGP_LS_RET_T link_attr_peer_set_SID_decode(BGP_LS_TLV* ls_tlv, link_attr_peer_set_SID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (NULL != value_st->value)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->value);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->value = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->value, ls_tlv->value, ls_tlv->length);
    }

    value_st->length = ls_tlv->length;  
    value_st->type = ls_tlv->type; 

    DECODE_UINT8(ls_tlv->value, value_st->Flags);
    DECODE_UINT8(ls_tlv->value, value_st->Weight);
    DECODE_UINT16(ls_tlv->value, value_st->Reserved);

    if(value_st->length == 7)
    {
        DECODE_U24_UINT32(ls_tlv->value, value_st->SID_index_label);
    }
    else if(value_st->length == 8)
    {
        DECODE_UINT32(ls_tlv->value, value_st->SID_index_label);
    }
    
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_peer_set_SID_encode(BGP_LS_TLV* ls_tlv, link_attr_peer_set_SID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (ls_tlv->length < value_st->length)
    {
        BGPLS_ERR("pre invalid length for peer set SID attribute");
        return BGP_LS_RET_ERROR;
    }

    /*need packet data*/    
    /*...................*/
    
    if (value_st->length != 0)
    {
        memcpy(ls_tlv->value, value_st->value, value_st->length);
    }
    ls_tlv->length = value_st->length;    
    ls_tlv->type = value_st->type;     
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_uni_link_delay_decode(BGP_LS_TLV* ls_tlv, link_attr_uni_link_delay* value_st)
{
    uint8_t anomalous_reserved  = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("link attr unidirectional link delay length decode error");
        return BGP_LS_RET_ERROR;
    } 
    DECODE_UINT8(ls_tlv->value, anomalous_reserved);
    value_st->Anomalous = anomalous_reserved | (1<<7);
    DECODE_U24_UINT32(ls_tlv->value, value_st->Delay);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_uni_link_delay_encode(BGP_LS_TLV* ls_tlv, link_attr_uni_link_delay* value_st)
{
    uint8_t anomalous_reserved  = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("link attr unidirectional link delay length encode error");
        return BGP_LS_RET_ERROR;
    } 
    if (value_st->Anomalous)
        anomalous_reserved |= (1<<7);
    ENCODE_UINT8(ls_tlv->value, anomalous_reserved);
    ENCODE_U24_UINT32(ls_tlv->value, value_st->Delay); 
    ls_tlv->length = 4;
    
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_min_max_uniLink_delay_decode(BGP_LS_TLV* ls_tlv, link_attr_min_max_uniLink_delay* value_st)
{
    uint8_t anomalous_reserved  = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 8)
    {
        BGPLS_ERR("link attr Min Max Unidirectional Link Delay length decode error");
        return BGP_LS_RET_ERROR;
    } 
    DECODE_UINT8(ls_tlv->value, anomalous_reserved);
    value_st->Anomalous = anomalous_reserved | (1<<7);
    DECODE_U24_UINT32(ls_tlv->value, value_st->MinDelay);
    anomalous_reserved  = 0;
    DECODE_UINT8(ls_tlv->value, anomalous_reserved);
    DECODE_U24_UINT32(ls_tlv->value, value_st->MaxDelay);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_min_max_uniLink_delay_encode(BGP_LS_TLV* ls_tlv, link_attr_min_max_uniLink_delay* value_st)
{
    uint8_t anomalous_reserved  = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 8)
    {
        BGPLS_ERR("link attr Min Max Unidirectional Link Delay length encode error");
        return BGP_LS_RET_ERROR;
    } 
    if (value_st->Anomalous)
        anomalous_reserved |= (1<<7);
    ENCODE_UINT8(ls_tlv->value, anomalous_reserved);
    ENCODE_U24_UINT32(ls_tlv->value, value_st->MinDelay);    
    anomalous_reserved  = 0;
    ENCODE_UINT8(ls_tlv->value, anomalous_reserved);
    ENCODE_U24_UINT32(ls_tlv->value, value_st->MinDelay);   
    ls_tlv->length = 8;
    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T link_attr_uni_delay_variation_decode(BGP_LS_TLV* ls_tlv, link_attr_uni_delay_variation* value_st)
{
    uint8_t anomalous_reserved  = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("link attr unidirectional delay variation length decode error");
        return BGP_LS_RET_ERROR;
    } 
    DECODE_UINT8(ls_tlv->value, anomalous_reserved);
    DECODE_U24_UINT32(ls_tlv->value, value_st->DelayVariation);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_uni_delay_variation_encode(BGP_LS_TLV* ls_tlv, link_attr_uni_delay_variation* value_st)
{
    uint8_t anomalous_reserved  = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("link attr unidirectional delay variation length encode error");
        return BGP_LS_RET_ERROR;
    } 
    ENCODE_UINT8(ls_tlv->value, anomalous_reserved);
    ENCODE_U24_UINT32(ls_tlv->value, value_st->DelayVariation);    
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_uni_packet_loss_decode(BGP_LS_TLV* ls_tlv, link_attr_uni_packet_loss* value_st)
{
    uint8_t anomalous_reserved  = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("link attr Unidirectional Link Loss length decode error");
        return BGP_LS_RET_ERROR;
    } 
    DECODE_UINT8(ls_tlv->value, anomalous_reserved);
    value_st->Anomalous = anomalous_reserved | (1<<7);
    DECODE_U24_UINT32(ls_tlv->value, value_st->LossPercent);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_uni_packet_loss_encode(BGP_LS_TLV* ls_tlv, link_attr_uni_packet_loss* value_st)
{
    uint8_t anomalous_reserved  = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("link attr Unidirectional Link Loss length encode error");
        return BGP_LS_RET_ERROR;
    } 
    if (value_st->Anomalous)
        anomalous_reserved |= (1<<7);
    ENCODE_UINT8(ls_tlv->value, anomalous_reserved);
    ENCODE_U24_UINT32(ls_tlv->value, value_st->LossPercent);   
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_uni_residual_bandwidth_decode(BGP_LS_TLV* ls_tlv, link_attr_uni_residual_bandwidth* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("link attr Unidirectional Residual Bandwidth length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_uni_residual_bandwidth_encode(BGP_LS_TLV* ls_tlv, link_attr_uni_residual_bandwidth* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("link attr Unidirectional Residual Bandwidth length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second);
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T link_attr_uni_available_bandwidth_decode(BGP_LS_TLV* ls_tlv, link_attr_uni_available_bandwidth* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("link attr Unidirectional Available Bandwidth length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_uni_available_bandwidth_encode(BGP_LS_TLV* ls_tlv, link_attr_uni_available_bandwidth* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("link attr Unidirectional Available Bandwidth length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second);
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_uni_bandwidth_util_decode(BGP_LS_TLV* ls_tlv, link_attr_uni_bandwidth_util* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("link attr Unidirectional Available Bandwidth length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_uni_bandwidth_util_encode(BGP_LS_TLV* ls_tlv, link_attr_uni_bandwidth_util* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("link attr Unidirectional Available Bandwidth length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_FLOAT32(ls_tlv->value, value_st->bytes_per_second);
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_l2_bundle_member_decode(BGP_LS_TLV* ls_tlv, link_attr_l2_bundle_member* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (NULL != value_st->value)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->value);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->value = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->value, ls_tlv->value, ls_tlv->length);
    }

    value_st->length = ls_tlv->length;  
    value_st->type = ls_tlv->type; 

    /*need parse data Link attribute sub-TLVs*/    
    ENCODE_UINT32(ls_tlv->value, value_st->member_descriptor);
    /*...................*/
    
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_l2_bundle_member_encode(BGP_LS_TLV* ls_tlv, link_attr_l2_bundle_member* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < value_st->length)
    {
        BGPLS_ERR("link attr l2 bundle member length encode error");
        return BGP_LS_RET_ERROR;
    }

    /*need packet Link attribute sub-TLVs data*/    
    /*...................*/
    
    if (value_st->length != 0)
    {
        memcpy(ls_tlv->value, value_st->value, value_st->length);
    }
    ls_tlv->length = value_st->length;    
    ls_tlv->type = value_st->type;     
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T link_attr_sr6_end_sid_decode(BGP_LS_TLV* ls_tlv, link_attr_sr6_end_sid* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 22)
    {
        BGPLS_ERR("link attr SRv6 End.X SID TLV length decode error");
        return BGP_LS_RET_ERROR;
    } 

    value_st->type = ls_tlv->type; 
    value_st->length = ls_tlv->length;
    
    DECODE_UINT16(ls_tlv->value, value_st->endpoint_behavior);
    DECODE_UINT8(ls_tlv->value, value_st->flags);
    DECODE_UINT8(ls_tlv->value, value_st->algorithm);
    DECODE_UINT8(ls_tlv->value, value_st->weight);
    DECODE_UINT8(ls_tlv->value, value_st->reserved);

    DECODE_UINT32(ls_tlv->value, value_st->sid[0]);
    DECODE_UINT32(ls_tlv->value, value_st->sid[1]);
    DECODE_UINT32(ls_tlv->value, value_st->sid[2]);
    DECODE_UINT32(ls_tlv->value, value_st->sid[3]);

    /*if (ls_tlv->length > 22)
    {
        value_st->sub_tlv = XCALLOC(MTYPE_BGPLS_DECODE, (ls_tlv->length - 26));
        memcpy(value_st->sub_tlv, ls_tlv->value, (ls_tlv->length - 26));
    }*/
    return  BGP_LS_RET_OK;
    
}
static BGP_LS_RET_T link_attr_sr6_lan_end_x_sid_decode(BGP_LS_TLV* ls_tlv, link_attr_sr6_lan_end_x_sid* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 26)
    {
        BGPLS_ERR("link attr SRv6 LAN End.X SID TLV length decode error");
        return BGP_LS_RET_ERROR;
    } 

    value_st->type = ls_tlv->type; 
    value_st->length = ls_tlv->length;
    
    DECODE_UINT16(ls_tlv->value, value_st->endpoint_behavior);
    DECODE_UINT8(ls_tlv->value, value_st->flags);
    DECODE_UINT8(ls_tlv->value, value_st->algorithm);
    DECODE_UINT8(ls_tlv->value, value_st->weight);
    DECODE_UINT8(ls_tlv->value, value_st->reserved);
    if (BGP_LS_ISIS_SR6_LAN_END_SID == value_st->type)
    {
        DECODE_UINT32(ls_tlv->value, value_st->neighbor_id[0]);
        DECODE_U16_UINT32(ls_tlv->value, value_st->neighbor_id[1]);
    }
    else if (BGP_LS_OSPF3_SR6_LAN_END_SID == value_st->type)
    {
        DECODE_UINT32(ls_tlv->value, value_st->neighbor_id[0]);
    }
    
    DECODE_UINT32(ls_tlv->value, value_st->sid[0]);
    DECODE_UINT32(ls_tlv->value, value_st->sid[1]);
    DECODE_UINT32(ls_tlv->value, value_st->sid[2]);
    DECODE_UINT32(ls_tlv->value, value_st->sid[3]);

    /*if (ls_tlv->length > 26)
    {
        value_st->sub_tlv = XCALLOC(MTYPE_BGPLS_DECODE, (ls_tlv->length - 26));
        memcpy(value_st->sub_tlv, ls_tlv->value, (ls_tlv->length - 26));
    }*/
    return  BGP_LS_RET_OK;
    
}

/*
	The IGP Flags TLV contains IS-IS and OSPF flags and bits originally
	assigned to the prefix.  The IGP Flags TLV is encoded as follows:

	  0                   1                   2                   3
	  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |              Type             |             Length            |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |D|N|L|P| Resvd.|
	 +-+-+-+-+-+-+-+-+
*/
static BGP_LS_RET_T prefix_attr_igp_flags_decode(BGP_LS_TLV* ls_tlv, prefix_attr_igp_flags* value_st)
{
    uint8_t prefix_igp_flags = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 1)
    {
        BGPLS_ERR("invalid length for IGP Flags prefix attribute");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_UINT8(ls_tlv->value, prefix_igp_flags);
    value_st->IsIs_down = (IGP_FLAGS_D & prefix_igp_flags);
    value_st->ospf_no_unicast = (IGP_FLAGS_N & prefix_igp_flags);
    value_st->ospf_local_address = (IGP_FLAGS_L & prefix_igp_flags);
    value_st->ospf_propagate_nssa = (IGP_FLAGS_P & prefix_igp_flags);
    return BGP_LS_RET_OK;

}

static BGP_LS_RET_T prefix_attr_igp_flags_encode(BGP_LS_TLV* ls_tlv, prefix_attr_igp_flags* value_st)
{
    uint8_t prefix_igp_flags = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (ls_tlv->length < 1)
    {
        BGPLS_ERR("invalid length for IGP Flags prefix attribute");
        return BGP_LS_RET_ERROR;
    }

    if(value_st->IsIs_down)
        prefix_igp_flags |=IGP_FLAGS_D;
    if(value_st->ospf_no_unicast)
        prefix_igp_flags |=IGP_FLAGS_N;
    if(value_st->ospf_local_address) 
        prefix_igp_flags |=IGP_FLAGS_L;
    if(value_st->ospf_propagate_nssa)
        prefix_igp_flags |=IGP_FLAGS_P;
    
    ENCODE_UINT8(ls_tlv->value, prefix_igp_flags);

    ls_tlv->length = 1;
    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T prefix_attr_igp_route_tag_decode(BGP_LS_TLV* ls_tlv, prefix_attr_igp_route_tag* value_st)
{
    uint16_t idx = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }

    if ((ls_tlv->length%4 != 0) || (ls_tlv->length < 4))
    {
        BGPLS_ERR("invalid length for IGP Route Tag prefix attribute");
        return BGP_LS_RET_ERROR;
    }
    
    if (NULL != value_st->Tags)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->Tags);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->Tags = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->Tags, ls_tlv->value, ls_tlv->length);
    }

    for(idx = 0; idx < (((ls_tlv->length-1)/4) + 1); idx++)
    {
        DECODE_UINT32(ls_tlv->value, value_st->Tags[idx]);
    }
    
    value_st->length = idx*4;
    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T prefix_attr_igp_route_tag_encode(BGP_LS_TLV* ls_tlv, prefix_attr_igp_route_tag* value_st)
{
    uint16_t idx = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < value_st->length)
    {
        BGPLS_ERR("invalid length for IGP Route Tag prefix attribute");
        return BGP_LS_RET_ERROR;
    }

    if ((value_st->length%4 != 0) || (value_st->length < 4))
    {
        BGPLS_ERR("invalid length for encode IGP Route Tag prefix attribute");
        return BGP_LS_RET_ERROR;
    }
    for(idx = 0; idx < (((value_st->length-1)/4) + 1); idx++)
    {
        ENCODE_UINT32(ls_tlv->value, value_st->Tags[idx]);
    }
    
    ls_tlv->length = idx*4;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T prefix_attr_igp_extended_route_tag_decode(BGP_LS_TLV* ls_tlv, prefix_attr_igp_extended_route_tag* value_st)
{
    uint16_t idx = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }  

    if ((ls_tlv->length%8 != 0) || (ls_tlv->length < 4))
    {
        BGPLS_ERR("invalid length for Extended IGP Route Tag prefix attribute");
        return BGP_LS_RET_ERROR;
    }
    
    if (NULL != value_st->Tags)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->Tags);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->Tags = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->Tags, ls_tlv->value, ls_tlv->length);
    }

    for(idx = 0; idx < (((ls_tlv->length-1)/8) + 1); idx++)
    {
        DECODE_UINT64(ls_tlv->value, value_st->Tags[idx]);
    }
    
    value_st->length = ls_tlv->length;
    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T prefix_attr_igp_extended_route_tag_encode(BGP_LS_TLV* ls_tlv, prefix_attr_igp_extended_route_tag* value_st)
{
    uint16_t idx = 0;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (ls_tlv->length < value_st->length)
    {
        BGPLS_ERR("invalid length for Extended IGP Route Tag prefix attribute");
        return BGP_LS_RET_ERROR;
    }

    if ((value_st->length%8 != 0) || (value_st->length < 8))
    {
        BGPLS_ERR("invalid length for encode Extended IGP Route Tag prefix attribute");
        return BGP_LS_RET_ERROR;
    }
    for(idx = 0; idx < (((value_st->length-1)/8) + 1); idx++)
    {
        ENCODE_UINT64(ls_tlv->value, value_st->Tags[idx]);
    }
    
    ls_tlv->length = idx*8;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T prefix_attr_prefix_metric_decode(BGP_LS_TLV* ls_tlv, prefix_attr_prefix_metric* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("prefix attr Prefix Metric length decode error");
        return BGP_LS_RET_ERROR;
    } 
    
    DECODE_UINT32(ls_tlv->value, value_st->Metric);
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T prefix_attr_prefix_metric_encode(BGP_LS_TLV* ls_tlv, prefix_attr_prefix_metric* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < 4)
    {
        BGPLS_ERR("prefix attr Prefix Metric length encode error");
        return BGP_LS_RET_ERROR;
    } 
    
    ENCODE_UINT32(ls_tlv->value, value_st->Metric);
    ls_tlv->length = 4;
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T prefix_attr_ospf_forwarding_address_decode(BGP_LS_TLV* ls_tlv, prefix_attr_ospf_forwarding_address* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length == 4)
    {
        DECODE_UINT32(ls_tlv->value, value_st->Address[0]);
        value_st->type = OSPF_FORWARDING_ADDRESS_IPV4;

    } 
    else if (ls_tlv->length == 16)
    {
        DECODE_UINT32(ls_tlv->value, value_st->Address[0]);
        DECODE_UINT32(ls_tlv->value, value_st->Address[1]);
        DECODE_UINT32(ls_tlv->value, value_st->Address[2]);
        DECODE_UINT32(ls_tlv->value, value_st->Address[3]);
        value_st->type = OSPF_FORWARDING_ADDRESS_IPV6;
    }
    else
    {
        BGPLS_ERR("prefix attr OSPF Forwarding Address length decode error");
        return BGP_LS_RET_ERROR;        
    }
    
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T prefix_attr_ospf_forwarding_address_encode(BGP_LS_TLV* ls_tlv, prefix_attr_ospf_forwarding_address* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (value_st->type == OSPF_FORWARDING_ADDRESS_IPV4)
    {
        if (ls_tlv->length < 4)
        {
            BGPLS_ERR("prefix attr ospf forwarding address length encode error");
            return BGP_LS_RET_ERROR;
        }

        ENCODE_UINT32(ls_tlv->value, value_st->Address[0]);
        ls_tlv->length = 4;
    } 
    else if (value_st->type == OSPF_FORWARDING_ADDRESS_IPV6)
    {
        if (ls_tlv->length < 16)
        {
            BGPLS_ERR("prefix attr ospf forwarding address length encode error");
            return BGP_LS_RET_ERROR;
        }

        ENCODE_UINT32(ls_tlv->value, value_st->Address[0]);
        ENCODE_UINT32(ls_tlv->value, value_st->Address[1]);
        ENCODE_UINT32(ls_tlv->value, value_st->Address[2]);
        ENCODE_UINT32(ls_tlv->value, value_st->Address[3]);
        ls_tlv->length = 16;
    }    

    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T prefix_attr_opaque_prefix_attr_decode(BGP_LS_TLV* ls_tlv, prefix_attr_opaque_prefix_attribute* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (NULL != value_st->Data)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->Data);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->Data = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->Data, ls_tlv->value, ls_tlv->length);
    }
    value_st->length = ls_tlv->length;    
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T prefix_attr_opaque_prefix_attr_encode(BGP_LS_TLV* ls_tlv, prefix_attr_opaque_prefix_attribute* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (ls_tlv->length < value_st->length)
    {
        BGPLS_ERR("invalid length for opaque prefix attribute");
        return BGP_LS_RET_ERROR;
    }

    if (value_st->length != 0)
    {
        memcpy(ls_tlv->value, value_st->Data, value_st->length);
    }
    ls_tlv->length = value_st->length;    
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T prefix_attr_prefix_SID_decode(BGP_LS_TLV* ls_tlv, prefix_attr_prefix_SID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (NULL != value_st->value)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->value);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->value = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->value, ls_tlv->value, ls_tlv->length);
    }

    value_st->length = ls_tlv->length;  
    value_st->type = ls_tlv->type; 

    /*need parse data*/    
    /*...................*/
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T prefix_attr_prefix_SID_encode(BGP_LS_TLV* ls_tlv, prefix_attr_prefix_SID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length < value_st->length)
    {
        BGPLS_ERR("invalid length for prefix SID attribute");
        return BGP_LS_RET_ERROR;
    }

    /*need packet flags range_size  data*/    
    /*...................*/
    
    if (value_st->length != 0)
    {
        memcpy(ls_tlv->value, value_st->value, value_st->length);
    }
    ls_tlv->length = value_st->length;    
    ls_tlv->type = value_st->type;     
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T prefix_attr_range_decode(BGP_LS_TLV* ls_tlv, prefix_attr_range* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (NULL != value_st->value)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->value);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->value = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->value, ls_tlv->value, ls_tlv->length);
    }

    value_st->length = ls_tlv->length;  
    value_st->type = ls_tlv->type; 

    /*need parse Flags range_size data*/    
    /*...................*/
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T prefix_attr_range_encode(BGP_LS_TLV* ls_tlv, prefix_attr_range* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (ls_tlv->length < value_st->length)
    {
        BGPLS_ERR("invalid length for prefix range attribute");
        return BGP_LS_RET_ERROR;
    }

    /*need packet data*/    
    /*...................*/
    
    if (value_st->length != 0)
    {
        memcpy(ls_tlv->value, value_st->value, value_st->length);
    }
    ls_tlv->length = value_st->length;    
    ls_tlv->type = value_st->type;     
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T prefix_attr_flags_decode(BGP_LS_TLV* ls_tlv, prefix_attr_flags* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (NULL != value_st->value)
    {
        XFREE(MTYPE_BGPLS_DECODE, value_st->value);
    }    
    
    if (ls_tlv->length != 0)
    {
        value_st->value = XCALLOC(MTYPE_BGPLS_DECODE, ls_tlv->length);
        memcpy(value_st->value, ls_tlv->value, ls_tlv->length);
    }

    value_st->length = ls_tlv->length;  
    value_st->type = ls_tlv->type; 

    /*need parse data*/    
    /*...................*/
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T prefix_attr_flags_encode(BGP_LS_TLV* ls_tlv, prefix_attr_flags* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    
    if (ls_tlv->length < value_st->length)
    {
        BGPLS_ERR("invalid length for prefix flags attribute");
        return BGP_LS_RET_ERROR;
    }

    /*need packet data*/    
    /*...................*/
    
    if (value_st->length != 0)
    {
        memcpy(ls_tlv->value, value_st->value, value_st->length);
    }
    ls_tlv->length = value_st->length;    
    ls_tlv->type = value_st->type;     
    return  BGP_LS_RET_OK;
}

static BGP_LS_RET_T prefix_attr_source_router_ID_decode(BGP_LS_TLV* ls_tlv, prefix_attr_source_router_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length == 4)
    {
        DECODE_UINT32(ls_tlv->value, value_st->Address[0]);
        value_st->type = SOURCE_ROUTER_ADDRESS_IPV4;

    } 
    else if (ls_tlv->length == 16)
    {
        DECODE_UINT32(ls_tlv->value, value_st->Address[0]);
        DECODE_UINT32(ls_tlv->value, value_st->Address[1]);
        DECODE_UINT32(ls_tlv->value, value_st->Address[2]);
        DECODE_UINT32(ls_tlv->value, value_st->Address[3]);
        value_st->type = SOURCE_ROUTER_ADDRESS_IPV6;
    }
    else
    {
        BGPLS_ERR("prefix attr Source Router Identifier length decode error");
        return BGP_LS_RET_ERROR;        
    }
    
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T prefix_attr_source_router_ID_encode(BGP_LS_TLV* ls_tlv, prefix_attr_source_router_ID* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (value_st->type == SOURCE_ROUTER_ADDRESS_IPV4)
    {
        if (ls_tlv->length < 4)
        {
            BGPLS_ERR("prefix attr source router ID length encode error");
            return BGP_LS_RET_ERROR;
        }

        ENCODE_UINT32(ls_tlv->value, value_st->Address[0]);
        ls_tlv->length = 4;
    } 
    else if (value_st->type == SOURCE_ROUTER_ADDRESS_IPV6)
    {
        if (ls_tlv->length < 16)
        {
            BGPLS_ERR("prefix attr source router ID length encode error");
            return BGP_LS_RET_ERROR;
        }

        ENCODE_UINT32(ls_tlv->value, value_st->Address[0]);
        ENCODE_UINT32(ls_tlv->value, value_st->Address[1]);
        ENCODE_UINT32(ls_tlv->value, value_st->Address[2]);
        ENCODE_UINT32(ls_tlv->value, value_st->Address[3]);
        ls_tlv->length = 16;
    }    

    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T te_policy_attr_binding_sid_decode(BGP_LS_TLV* ls_tlv, te_policy_attr_binding_sid* value_st)
{
    uint16_t reserved;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 12 && ls_tlv->length != 36)
    {
        BGPLS_ERR("TE POLICY attr binding sid length decode error");
        return BGP_LS_RET_ERROR;
    }
    value_st->type = ls_tlv->type; 
    value_st->length = ls_tlv->length;
	

	DECODE_UINT16(ls_tlv->value, value_st->flags);
	DECODE_UINT16(ls_tlv->value, reserved);
	if(D_FLAG & value_st->flags)
	{
	    DECODE_UINT32(ls_tlv->value, value_st->binding_sid.addr_v6[0]);
		DECODE_UINT32(ls_tlv->value, value_st->binding_sid.addr_v6[1]);
		DECODE_UINT32(ls_tlv->value, value_st->binding_sid.addr_v6[2]);
		DECODE_UINT32(ls_tlv->value, value_st->binding_sid.addr_v6[3]);	
	}
	else
	{
		DECODE_UINT32(ls_tlv->value, value_st->binding_sid.addr_v4);
	}
       
    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T te_policy_attr_perference_decode(BGP_LS_TLV* ls_tlv, te_policy_attr_preference* value_st)
{
    uint8_t reserved;
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 8)
    {
        BGPLS_ERR("TE POLICY attr perference length decode error");
        return BGP_LS_RET_ERROR;
    }
    value_st->type = ls_tlv->type; 
    value_st->length = ls_tlv->length;
	DECODE_UINT8(ls_tlv->value, value_st->priority);
	DECODE_UINT8(ls_tlv->value, reserved);
	DECODE_UINT16(ls_tlv->value, value_st->flags);
	DECODE_UINT32(ls_tlv->value, value_st->preference);
       
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T te_policy_attr_segment_add_list(te_policy_attr_sid_list *sids, struct te_policy_attr_segment *segment)
{
    if(sids == NULL || segment == NULL)
	{
		return BGP_LS_RET_ERROR;
	}
    if(sids->head)
	{
        sids->tail->next = segment;
	}
	else
	{
        sids->head = segment;		
	}   
	sids->tail = segment;
    return BGP_LS_RET_OK;
}


static BGP_LS_RET_T te_policy_attr_sid_list_decode(BGP_LS_TLV* ls_tlv, te_policy_attr_sid_list** value_st)
{
    uint8_t reserved1;
	uint8_t algorithm;
	uint16_t reserved2;
	uint16_t has_parse_length = 0;
	uint16_t seg_type;	
	uint16_t sid_list_type;
	uint16_t sid_list_len;
	uint16_t sid_len;
	uint16_t need_parse_len = 20;
	uint16_t mtid;
	struct te_policy_attr_segment *segment = NULL;
	te_policy_attr_sid_list *newlist;
	te_policy_attr_sid_list *tmp;

	newlist = malloc(sizeof(te_policy_attr_sid_list));
    memset(newlist, 0, sizeof(te_policy_attr_sid_list));
	
    if (NULL == ls_tlv)
    {
        return BGP_LS_RET_ERROR;
    }
    
    newlist->type = ls_tlv->type; 
    sid_list_len = newlist->length = ls_tlv->length;
    
	if(sid_list_len < 16)
	{
       return BGP_LS_RET_ERROR;
	}
	DECODE_UINT16(ls_tlv->value, newlist->flags);
	has_parse_length += 2;
	//parse srv6 sids only 
	if(!(newlist->flags & D_FLAG))
	{
       return BGP_LS_RET_ERROR;
	}
	DECODE_UINT16(ls_tlv->value, reserved2);
	has_parse_length += 2;
	DECODE_UINT16(ls_tlv->value, mtid);
	has_parse_length += 2;
	DECODE_UINT8(ls_tlv->value, algorithm);
	has_parse_length += 1;
	DECODE_UINT8(ls_tlv->value, reserved1);
	has_parse_length += 1;
	DECODE_UINT32(ls_tlv->value, newlist->weight);
	has_parse_length += 4;

	while(has_parse_length < sid_list_len)
	{	    
		DECODE_UINT16(ls_tlv->value, sid_list_type);
		has_parse_length += 2;       
	    if(sid_list_type != TYPE_SR_SEGMENT)
	    {
           return BGP_LS_RET_ERROR;
	    }						
		DECODE_UINT16(ls_tlv->value, sid_len);
		has_parse_length += 2;
		
		DECODE_UINT8(ls_tlv->value, seg_type);
		has_parse_length += 1;				
		//parse srv6 sids only 
		if(seg_type != TYPE_SEGMENT)
		{
			return BGP_LS_RET_ERROR;
		}
		segment = XCALLOC(MTYPE_BGPLS_DECODE, sizeof(struct te_policy_attr_segment));	        
        if (NULL == segment)
        {  
            return BGP_LS_RET_ERROR_MEM;
        }
		memset(segment, 0, sizeof(struct te_policy_attr_segment));
		segment->next = NULL;
        segment->type = sid_list_type;
		segment->length = sid_len;
		segment->seg_type = seg_type;
		DECODE_UINT8(ls_tlv->value, reserved1);
		has_parse_length += 1;
		DECODE_UINT16(ls_tlv->value, segment->flags);
		has_parse_length += 2;
		DECODE_UINT32(ls_tlv->value, segment->sid[0]);
		DECODE_UINT32(ls_tlv->value, segment->sid[1]);
		DECODE_UINT32(ls_tlv->value, segment->sid[2]);
		DECODE_UINT32(ls_tlv->value, segment->sid[3]);
	    has_parse_length += 16;
		//not need parse
		has_parse_length += (segment->length - need_parse_len);
		ls_tlv->value += (segment->length - need_parse_len);
		te_policy_attr_segment_add_list(newlist, segment);
	    if (sid_list_len - has_parse_length < need_parse_len) {
            break;
        }
    }
    tmp = *value_st;
    if (*value_st == NULL) {
        *value_st = newlist;
    } else if (tmp->head) {
        while (tmp->next) {
            tmp = tmp->next;
        }
        tmp->next = newlist;
    }

    return BGP_LS_RET_OK;
}




static BGP_LS_RET_T sr6_sid_attr_endpoint_behavior_decode(BGP_LS_TLV* ls_tlv, sr6_sid_attr_endpoint_behavior* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("SRv6 SID attr endpoint behavior length decode error");
        return BGP_LS_RET_ERROR;

    }
    value_st->type = ls_tlv->type; 
    value_st->length = ls_tlv->length;
    
    DECODE_UINT16(ls_tlv->value, value_st->endpoint_behavior);
    DECODE_UINT8(ls_tlv->value, value_st->flags);
    DECODE_UINT8(ls_tlv->value, value_st->algorithm);    
    
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T sr6_sid_attr_bgp_peer_node_sid_decode(BGP_LS_TLV* ls_tlv, sr6_sid_attr_sr6_bgp_peer_node_sid* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 12)
    {
        BGPLS_ERR("SRv6 SID attr bgp peer node sid length decode error");
        return BGP_LS_RET_ERROR;

    }
    value_st->type = ls_tlv->type; 
    value_st->length = ls_tlv->length;

    DECODE_UINT8(ls_tlv->value, value_st->flags);
    DECODE_UINT8(ls_tlv->value, value_st->weight);      
    DECODE_UINT16(ls_tlv->value, value_st->reserved);
    DECODE_UINT32(ls_tlv->value, value_st->peer_as_number);
    DECODE_UINT32(ls_tlv->value, value_st->peer_bgp_id);    
    
    return BGP_LS_RET_OK;
}

static BGP_LS_RET_T sr6_sid_attr_sid_struct_decode(BGP_LS_TLV* ls_tlv, sr6_sid_attr_sr6_sid_struct* value_st)
{
    if ((NULL == value_st) || (NULL == ls_tlv))
    {
        return BGP_LS_RET_ERROR;
    }
    if (ls_tlv->length != 4)
    {
        BGPLS_ERR("SRv6 SID attr sid struct length decode error");
        return BGP_LS_RET_ERROR;

    }
    value_st->type = ls_tlv->type; 
    value_st->length = ls_tlv->length;
    
    DECODE_UINT8(ls_tlv->value, value_st->lb_len);
    DECODE_UINT8(ls_tlv->value, value_st->ln_len);
    DECODE_UINT8(ls_tlv->value, value_st->fun_len);
    DECODE_UINT8(ls_tlv->value, value_st->arg_len);    
    
    return BGP_LS_RET_OK;
}


/*BGP-LS packet encapsulation and decapsulation function definition*/

void bgp_ls_nlri_node_desc_serialize(struct stream *s, node_descriptor *ls_node_nlri)
{
    uint16_t node_nlri_len_pos;
    BGP_LS_TLV ls_tlv;

    if (NULL == ls_node_nlri)
    {
        return;
    }

    stream_putw(s, ls_node_nlri->Code);
    node_nlri_len_pos = stream_get_endp(s);
    stream_putw(s, 0);

    LS_SERIALIZE_TLV(s,
            ls_node_nlri->ASN_b,
            NODE_DESCRIPTOR_CODE_ASN,
            node_descriptor_ASN_encode,
            &ls_node_nlri->ASN);

    LS_SERIALIZE_TLV(s,
            ls_node_nlri->bgp_ls_ID_b,
            NODE_DESCRIPTOR_CODE_BGP_LS_ID,
            node_descriptor_bgp_ls_ID_encode,
            &ls_node_nlri->bgp_ls_ID);

    LS_SERIALIZE_TLV(s,
            ls_node_nlri->ospf_area_ID_b,
            NODE_DESCRIPTOR_CODE_OSPF_AREA_ID,
            node_descriptor_ospf_area_ID_encode,
            &ls_node_nlri->ospf_area_ID);
    
    LS_SERIALIZE_TLV(s,
            ls_node_nlri->igp_router_ID_b,
            NODE_DESCRIPTOR_CODE_IGP_ROUTER_ID,
            node_descriptor_igp_router_ID_encode,
            &ls_node_nlri->igp_router_ID);
    
    LS_SERIALIZE_TLV(s,
            ls_node_nlri->bgp_router_ID_b,
            NODE_DESCRIPTOR_CODE_BGP_ROUTER_ID,
            node_descriptor_bgp_router_ID_encode,
            &ls_node_nlri->bgp_router_ID);
    
    LS_SERIALIZE_TLV(s,
            ls_node_nlri->member_ASN_b,
            NODE_DESCRIPTOR_CODE_MEMBER_ASN,
            node_descriptor_member_ASN_encode,
            &ls_node_nlri->member_ASN); 

    /* Set total node length (2 bytes) */
    stream_putw_at(s, node_nlri_len_pos, (stream_get_endp(s) - node_nlri_len_pos) - 2);
    return;
}


void bgp_ls_nlri_link_desc_serialize(struct stream *s, link_descriptor *ls_link_nlri)
{
    BGP_LS_TLV ls_tlv;

    if (NULL == ls_link_nlri)
    {
        return;
    }
    
    LS_SERIALIZE_TLV(s,
            ls_link_nlri->link_IDs_b,
            LINK_DESCRIPTOR_CODE_LINK_IDS,
            link_descriptor_link_IDs_encode,
            &ls_link_nlri->link_IDs); 

    LS_SERIALIZE_TLV(s,
            ls_link_nlri->IPv4_interface_address_b,
            LINK_DESCRIPTOR_CODE_IPV4_INTERFACE_ADDRESS,
            link_descriptor_IPv4_interface_address_encode,
            &ls_link_nlri->IPv4_interface_address); 

    LS_SERIALIZE_TLV(s,
            ls_link_nlri->IPv4_neighbor_address_b,
            LINK_DESCRIPTOR_CODE_IPV4_NEIGHBOR_ADDRESS,
            link_descriptor_IPv4_neighbor_address_encode,
            &ls_link_nlri->IPv4_neighbor_address); 
    
    LS_SERIALIZE_TLV(s,
            ls_link_nlri->IPv6_interface_address_b,
            LINK_DESCRIPTOR_CODE_IPV6_INTERFACE_ADDRESS,
            link_descriptor_IPv6_interface_address_encode,
            &ls_link_nlri->IPv6_interface_address); 
    
    LS_SERIALIZE_TLV(s,
            ls_link_nlri->IPv6_neighbor_address_b,
            LINK_DESCRIPTOR_CODE_IPV6_NEIGHBOR_ADDRESS,
            link_descriptor_IPv6_neighbor_address_encode,
            &ls_link_nlri->IPv6_neighbor_address);   

    LS_SERIALIZE_TLV(s,
            ls_link_nlri->mt_ID_b,
            LINK_DESCRIPTOR_CODE_MULTI_TOPOLOGY_ID,
            multi_topology_IDs_encode,
            &ls_link_nlri->mt_ID);    
    return;
}


void bgp_ls_nlri_prefix_desc_serialize(struct stream *s, prefix_descriptor *ls_prefix_nlri)
{
    BGP_LS_TLV ls_tlv;
    if (NULL == ls_prefix_nlri)
    {
        return;
    }

    LS_SERIALIZE_TLV(s,
            ls_prefix_nlri->mt_ID_b,
            PREFIX_DESCRIPTOR_CODE_MULTI_TOPOLOGY_ID,
            multi_topology_IDs_encode,
            &ls_prefix_nlri->mt_ID);

    LS_SERIALIZE_TLV(s,
            ls_prefix_nlri->ospf_route_type_b,
            PREFIX_DESCRIPTOR_CODE_OSPF_ROUTE_TYPE,
            prefix_descriptor_ospf_route_type_encode,
            &ls_prefix_nlri->ospf_route_type);

    LS_SERIALIZE_TLV(s,
            ls_prefix_nlri->IP_reachability_info_b,
            PREFIX_DESCRIPTOR_CODE_IP_REACHABILITY_INFO,
            prefix_descriptor_IP_reachability_info_encode,
            &ls_prefix_nlri->IP_reachability_info);
    
    return;
}

static int32_t bgp_ls_nlri_node_desc_parse(node_descriptor *local_node,
                                uint8_t *pnt, uint16_t nlri_parse_len)
{

    /************************The Link NLRI Format**************************
         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |              Type             |             Length            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        //              Node Descriptor Sub-TLVs (variable)            //
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    uint16_t nlri_node_type = 0;
    uint16_t nlri_node_len = 0;
    uint16_t nlri_has_parse_len = 0;
    uint8_t *lim;    
    BGP_LS_TLV ls_tlv;


    /* Start processing the NLRI - there may be multiple in the MP_REACH */
    lim = pnt + nlri_parse_len;

    for (; pnt < lim; pnt += nlri_node_len)
    {   
        /*parse Node Descriptor TLVs Type*/
        DECODE_UINT16(pnt,nlri_node_type);
        nlri_has_parse_len += 2;

        /*parse Node length  */
        DECODE_UINT16(pnt,nlri_node_len);
        nlri_has_parse_len += 2;

        /* When packet overflow occur return immediately. */
        if ((nlri_has_parse_len + nlri_node_len) > nlri_parse_len)
            return BGP_LS_RET_ERROR;

        ls_tlv.length = nlri_node_len;
        ls_tlv.value = pnt;

        switch (nlri_node_type)
        {
            case NODE_DESCRIPTOR_CODE_ASN:
                LS_PARSE_TLV(nlri_node_type, nlri_node_len, pnt,
                       local_node->ASN_b,
                       node_descriptor_ASN_decode,
                       &local_node->ASN);
                break;
            case NODE_DESCRIPTOR_CODE_BGP_LS_ID:
                LS_PARSE_TLV(nlri_node_type, nlri_node_len, pnt,
                       local_node->bgp_ls_ID_b,
                       node_descriptor_bgp_ls_ID_decode,
                       &local_node->bgp_ls_ID);
                break;
            case NODE_DESCRIPTOR_CODE_OSPF_AREA_ID:
                LS_PARSE_TLV(nlri_node_type, nlri_node_len, pnt,
                       local_node->ospf_area_ID_b,
                       node_descriptor_ospf_area_ID_decode,
                       &local_node->ospf_area_ID);
                break; 
            case NODE_DESCRIPTOR_CODE_IGP_ROUTER_ID:
                LS_PARSE_TLV(nlri_node_type, nlri_node_len, pnt,
                       local_node->igp_router_ID_b,
                       node_descriptor_igp_router_ID_decode,
                       &local_node->igp_router_ID);
                break;
            /*exclude rfc7752 */  
            case NODE_DESCRIPTOR_CODE_BGP_ROUTER_ID:
                LS_PARSE_TLV(nlri_node_type, nlri_node_len, pnt,
                       local_node->bgp_router_ID_b,
                       node_descriptor_bgp_router_ID_decode,
                       &local_node->bgp_router_ID);
                break;
            case NODE_DESCRIPTOR_CODE_MEMBER_ASN:
                LS_PARSE_TLV(nlri_node_type, nlri_node_len, pnt,
                       local_node->member_ASN_b,
                       node_descriptor_member_ASN_decode,
                       &local_node->member_ASN);
                break;
            default:
                break;
        }
    }

    return BGP_LS_RET_OK;
}

static int32_t bgp_ls_nlri_link_desc_parse(link_descriptor *local_link,
                                uint8_t *pnt, uint16_t nlri_parse_len)
{

    uint16_t nlri_link_type = 0;
    uint16_t nlri_link_len = 0;
    uint16_t nlri_has_parse_len = 0;
    uint8_t *lim;
    BGP_LS_TLV ls_tlv;

    /* Start processing the NLRI - there may be multiple in the MP_REACH */
    lim = pnt + nlri_parse_len;
    for (; pnt < lim; pnt += nlri_link_len)
    {
        /*parse Link Descriptor TLVs Type*/
        DECODE_UINT16(pnt,nlri_link_type);
        nlri_has_parse_len += 2;

        /*parse Node length  */
        DECODE_UINT16(pnt,nlri_link_len);
        nlri_has_parse_len += 2;
        
        ls_tlv.length = nlri_link_type;
        ls_tlv.value = pnt;

        /* When packet overflow occur return immediately. */
        if ((nlri_has_parse_len + nlri_link_len) > nlri_parse_len)
            return BGP_LS_RET_ERROR;

        switch (nlri_link_type)
        {
            case LINK_DESCRIPTOR_CODE_LINK_IDS:
                LS_PARSE_TLV(nlri_link_type, nlri_link_len, pnt,
                    local_link->link_IDs_b,
                    link_descriptor_link_IDs_decode,
                    &local_link->link_IDs);
                break; 
            case LINK_DESCRIPTOR_CODE_IPV4_INTERFACE_ADDRESS:
                LS_PARSE_TLV(nlri_link_type, nlri_link_len, pnt,
                    local_link->IPv4_interface_address_b,
                    link_descriptor_IPv4_interface_address_decode,
                    &local_link->IPv4_interface_address);
                break; 
            case LINK_DESCRIPTOR_CODE_IPV4_NEIGHBOR_ADDRESS:
                LS_PARSE_TLV(nlri_link_type, nlri_link_len, pnt,
                    local_link->IPv4_neighbor_address_b,
                    link_descriptor_IPv4_neighbor_address_decode,
                    &local_link->IPv4_neighbor_address);
                break; 
            case LINK_DESCRIPTOR_CODE_IPV6_INTERFACE_ADDRESS:
                LS_PARSE_TLV(nlri_link_type, nlri_link_len, pnt,
                    local_link->IPv6_interface_address_b,
                    link_descriptor_IPv6_interface_address_decode,
                    &local_link->IPv6_interface_address);
                break; 
            case LINK_DESCRIPTOR_CODE_IPV6_NEIGHBOR_ADDRESS:
                LS_PARSE_TLV(nlri_link_type, nlri_link_len, pnt,
                    local_link->IPv6_neighbor_address_b,
                    link_descriptor_IPv6_neighbor_address_decode,
                    &local_link->IPv6_neighbor_address);
                break; 
            case LINK_DESCRIPTOR_CODE_MULTI_TOPOLOGY_ID:
                LS_PARSE_TLV(nlri_link_type, nlri_link_len, pnt,
                    local_link->mt_ID_b,
                    multi_topology_IDs_decode,
                    &local_link->mt_ID);
                break; 
            default:
                break;
        }
    }

    return BGP_LS_RET_OK;
}


static int32_t bgp_ls_nlri_prefix_desc_parse(prefix_descriptor *local_prefix,
                                uint8_t *pnt, uint16_t nlri_parse_len)
{
    uint16_t nlri_prefix_type = 0;
    uint16_t nlri_prefix_len = 0;
    uint16_t nlri_has_parse_len = 0;
    uint8_t *lim;
    BGP_LS_TLV ls_tlv;

    /* Start processing the NLRI - there may be multiple in the MP_REACH */
    lim = pnt + nlri_parse_len;
    for (; pnt < lim; pnt += nlri_prefix_len)
    {
        /*parse Link Descriptor TLVs Type*/
        DECODE_UINT16(pnt,nlri_prefix_type);
        nlri_has_parse_len += 2;

        /*parse Node length  */
        DECODE_UINT16(pnt,nlri_prefix_len);
        nlri_has_parse_len += 2;
        
        ls_tlv.length = nlri_prefix_len;
        ls_tlv.value = pnt;

        /* When packet overflow occur return immediately. */
        if ((nlri_has_parse_len + nlri_prefix_len) > nlri_parse_len)
            return BGP_LS_RET_ERROR;

        switch (nlri_prefix_type)
        {
            case PREFIX_DESCRIPTOR_CODE_MULTI_TOPOLOGY_ID:        
                LS_PARSE_TLV(nlri_prefix_type, nlri_prefix_len, pnt,
                    local_prefix->mt_ID_b,
                    multi_topology_IDs_decode,
                    &local_prefix->mt_ID);
                break;
            case PREFIX_DESCRIPTOR_CODE_OSPF_ROUTE_TYPE:          
                LS_PARSE_TLV(nlri_prefix_type, nlri_prefix_len, pnt,
                    local_prefix->ospf_route_type_b,
                    prefix_descriptor_ospf_route_type_decode,
                    &local_prefix->ospf_route_type);
                break;
            case PREFIX_DESCRIPTOR_CODE_IP_REACHABILITY_INFO:
                LS_PARSE_TLV(nlri_prefix_type, nlri_prefix_len, pnt,
                    local_prefix->IP_reachability_info_b,
                    prefix_descriptor_IP_reachability_info_decode,
                    &local_prefix->IP_reachability_info);
                break;
            default:
                break;
        }
    }

    return BGP_LS_RET_OK;
}

static int32_t bgp_ls_nlri_sr6_sid_desc_parse(sr6_sid_descriptor *sr6_sid_desc,
                                uint8_t *pnt, uint16_t nlri_parse_len)
{
    uint16_t nlri_sr6_sid_type = 0;
    uint16_t nlri_sr6_sid_len = 0;
    uint16_t nlri_has_parse_len = 0;
    uint8_t *lim;
    BGP_LS_TLV ls_tlv;
    /* Start processing the NLRI - there may be multiple in the MP_REACH */
    lim = pnt + nlri_parse_len;

    for (; pnt < lim; pnt += nlri_sr6_sid_len)
    {   
        /*parse Node Descriptor TLVs Type*/
        DECODE_UINT16(pnt,nlri_sr6_sid_type);
        nlri_has_parse_len += 2;

        /*parse Node length  */
        DECODE_UINT16(pnt,nlri_sr6_sid_len);
        nlri_has_parse_len += 2;

        /* When packet overflow occur return immediately. */
        if ((nlri_has_parse_len + nlri_sr6_sid_len) > nlri_parse_len)
            return BGP_LS_RET_ERROR;

        ls_tlv.length = nlri_sr6_sid_len;                
        ls_tlv.value = pnt;
        
        switch (nlri_sr6_sid_type)
        {
            case BGP_LS_SRv6_SID_INFO:
                if (ls_tlv.length != 16)
                {
                    BGPLS_ERR("SRv6 SID descriptor SID length decode error");
                    return BGP_LS_RET_ERROR;
                } 
                DECODE_UINT32(ls_tlv.value, sr6_sid_desc->sid[0]);
                DECODE_UINT32(ls_tlv.value, sr6_sid_desc->sid[1]);
                DECODE_UINT32(ls_tlv.value, sr6_sid_desc->sid[2]);
                DECODE_UINT32(ls_tlv.value, sr6_sid_desc->sid[3]);
                break;
            default:
                break;
        }
    }
    
    return BGP_LS_RET_OK;
}								

int32_t bgp_ls_nlri_te_policy_desc_parse(te_policy_descriptor *te_policy_desc,
								uint8_t *pnt, uint16_t nlri_parse_len)
{
	uint16_t nlri_te_policy_type = 0;
	uint16_t nlri_te_policy_len = 0;	
	uint16_t reserved = 0;
	uint16_t nlri_has_parse_len = 0;

	while(nlri_has_parse_len <  nlri_parse_len)
	{
	    DECODE_UINT16(pnt,nlri_te_policy_type);  
		nlri_has_parse_len += 2;
        /*parse Node length  */
        DECODE_UINT16(pnt,nlri_te_policy_len);
		nlri_has_parse_len += 2;
        if(TYPE_CANDIDATE_PATH ==  nlri_te_policy_type )
		{
			DECODE_UINT8(pnt,te_policy_desc->protocol);
			nlri_has_parse_len += 1;
			DECODE_UINT8(pnt,te_policy_desc->flags);
			nlri_has_parse_len += 1;
			DECODE_UINT16(pnt,reserved);
			nlri_has_parse_len += 2;
		
			if(te_policy_desc->flags & E_FLAG)
			{
				DECODE_UINT32(pnt,te_policy_desc->end_point.addr_v6[0]);
				DECODE_UINT32(pnt,te_policy_desc->end_point.addr_v6[1]);
				DECODE_UINT32(pnt,te_policy_desc->end_point.addr_v6[2]);
				DECODE_UINT32(pnt,te_policy_desc->end_point.addr_v6[3]);
				nlri_has_parse_len += 16;
			}
			else
			{
				DECODE_UINT32(pnt,te_policy_desc->end_point.addr_v4);
				nlri_has_parse_len += 4;
			}
			DECODE_UINT32(pnt,te_policy_desc->color);
			nlri_has_parse_len += 4;
			DECODE_UINT32(pnt,te_policy_desc->orignator_as);
			nlri_has_parse_len += 4;
			if(te_policy_desc->flags & O_FLAG)
			{
			    
				DECODE_UINT32(pnt,te_policy_desc->orignator_addr.addr_v6[0]);
				DECODE_UINT32(pnt,te_policy_desc->orignator_addr.addr_v6[1]);
				DECODE_UINT32(pnt,te_policy_desc->orignator_addr.addr_v6[2]);
				DECODE_UINT32(pnt,te_policy_desc->orignator_addr.addr_v6[3]);
				nlri_has_parse_len += 16;
			}
			else
			{
				DECODE_UINT32(pnt,te_policy_desc->orignator_addr.addr_v4);	
				nlri_has_parse_len += 4;
			}
			DECODE_UINT32(pnt,te_policy_desc->discriminator);
			nlri_has_parse_len += 4;
			break;
		}
		else
		{
			pnt += nlri_te_policy_len;
			nlri_has_parse_len += nlri_te_policy_len;
		}
	}		

	return BGP_LS_RET_OK;
}
                                
int32_t bgp_ls_nlri_node_parse(NLRI_NODE *nlri_node_head,
                           uint8_t *pnt, uint16_t nlri_parse_len)
{
    /************************The Node NLRI Format**************************
        The Node NLRI (NLRI Type = 1) is shown in the following figure.

           0                   1                   2                   3
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
          +-+-+-+-+-+-+-+-+
          |  Protocol-ID  |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                           Identifier                          |
          |                            (64 bits)                          |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          //                Local Node Descriptors (variable)            //
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */

    uint8_t nlri_proto_id = 0;
    uint64_t nlri_identifier = 0;
    uint16_t nlri_node_type = 0;
    uint16_t nlri_node_len = 0;
    uint16_t nlri_has_parse_len = 0;
    int32_t ret;

    if (NULL == nlri_node_head)
    {
        return BGP_LS_RET_ERROR;
    }
    
    /*save origin nlri buf*/
    nlri_node_head->origin_nlri_buf.type = BGP_LS_NLRI_TYPE_NODE;
    nlri_node_head->origin_nlri_buf.length = nlri_parse_len;
    nlri_node_head->origin_nlri_buf.value = XCALLOC(MTYPE_BGPLS_DECODE, nlri_parse_len);
    memcpy(nlri_node_head->origin_nlri_buf.value,pnt,nlri_parse_len);

    /*parse Protocol-ID */
    DECODE_UINT8(pnt,nlri_proto_id);    
    nlri_has_parse_len += 1;

    /*Protocol-ID NLRI information source protocol*/
    switch (nlri_proto_id)
    {
        case BGP_LS_PROTO_ISIS_L1:
        case BGP_LS_PROTO_ISIS_L2:
        case BGP_LS_PROTO_OSPF2:
        case BGP_LS_PROTO_DIRECT:
        case BGP_LS_PROTO_STATIC:
        case BGP_LS_PROTO_OSPF3:
         
        case BGP_LS_PROTO_BGP:
        case BGP_LS_PROTO_RSVP_TE:
        case BGP_LS_PROTO_SR:
            break;
        default:
            return BGP_LS_RET_ERROR;
    }

    /*parse Identifier */
    DECODE_UINT64(pnt,nlri_identifier);
    nlri_has_parse_len += 8;

    nlri_node_head->protocol_ID = nlri_proto_id;
    nlri_node_head->ID = nlri_identifier;
    /*parse Local Node Descriptors */

    /*parse Node Type  */
    DECODE_UINT16(pnt,nlri_node_type);
    nlri_has_parse_len += 2;

    if (BGP_LS_LOCAL_NODE_DESC == nlri_node_type)
    {
        /*parse Node length  */
        DECODE_UINT16(pnt,nlri_node_len);
        nlri_has_parse_len += 2;

        /* When packet overflow occur return immediately. */
        if ((nlri_has_parse_len + nlri_node_len) > nlri_parse_len)
            return BGP_LS_RET_ERROR;
        nlri_node_head->local_node.Code = LINK_STATE_NLRI_LOCAL_NODE_DESCRIPTORS_CODE;
        ret = bgp_ls_nlri_node_desc_parse(&(nlri_node_head->local_node)
                                          , pnt, nlri_node_len);
        if (BGP_LS_RET_OK != ret)
        {
            return BGP_LS_RET_ERROR;
        }
        nlri_has_parse_len += nlri_node_len;
        pnt += nlri_node_len;
    }
    else
    {
        /*back has parse type*/
        pnt -=2 ;
        nlri_has_parse_len -= 2;
    }

    return BGP_LS_RET_OK;
}


int32_t bgp_ls_nlri_link_parse(NLRI_LINK *nlri_link_head,
                           uint8_t *pnt, uint16_t nlri_parse_len)
{

    /************************The Link NLRI Format**************************
        The Link NLRI (NLRI Type = 2) is shown in the following figure.

           0                   1                   2                   3
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
          +-+-+-+-+-+-+-+-+
          |  Protocol-ID  |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                           Identifier                          |
          |                            (64 bits)                          |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          //               Local Node Descriptors (variable)             //
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          //               Remote Node Descriptors (variable)            //
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          //                  Link Descriptors (variable)                //
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */

    uint8_t nlri_proto_id = 0;
    uint64_t nlri_identifier = 0;
    uint16_t nlri_node_type = 0;
    uint16_t nlri_node_len = 0;
    uint16_t nlri_has_parse_len = 0;
    int32_t ret;

    if (NULL == nlri_link_head)
    {
        return BGP_LS_RET_ERROR;
    }
    
    /*save origin nlri buf*/
    nlri_link_head->origin_nlri_buf.type = BGP_LS_NLRI_TYPE_LINK;
    nlri_link_head->origin_nlri_buf.length = nlri_parse_len;
    nlri_link_head->origin_nlri_buf.value = XCALLOC(MTYPE_BGPLS_DECODE, nlri_parse_len);
    memcpy(nlri_link_head->origin_nlri_buf.value,pnt,nlri_parse_len);

    /*parse Protocol-ID */
    DECODE_UINT8(pnt,nlri_proto_id);
    nlri_has_parse_len += 1;

    /*Protocol-ID NLRI information source protocol*/
    switch (nlri_proto_id)
    {
        case BGP_LS_PROTO_ISIS_L1:
        case BGP_LS_PROTO_ISIS_L2:
        case BGP_LS_PROTO_OSPF2:
        case BGP_LS_PROTO_DIRECT:
        case BGP_LS_PROTO_STATIC:
        case BGP_LS_PROTO_OSPF3:
            
        /*Protocol-ID exclude rfc7752 */  
        case BGP_LS_PROTO_BGP:
        case BGP_LS_PROTO_RSVP_TE:
        case BGP_LS_PROTO_SR:            
            break;
        default:
            return BGP_LS_RET_ERROR;
    }
    
    /*parse Identifier */
    DECODE_UINT64(pnt,nlri_identifier);
    nlri_has_parse_len += 8;

    nlri_link_head->protocol_ID = nlri_proto_id;
    nlri_link_head->ID = nlri_identifier;
    /*parse Local Node Descriptors */

    /*parse Node Type  */
    DECODE_UINT16(pnt,nlri_node_type);
    nlri_has_parse_len += 2;

    if (BGP_LS_LOCAL_NODE_DESC == nlri_node_type)
    {
        /*parse Node length  */
        DECODE_UINT16(pnt,nlri_node_len);
        nlri_has_parse_len += 2;

        /* When packet overflow occur return immediately. */
        if ((nlri_has_parse_len + nlri_node_len) > nlri_parse_len)
            return BGP_LS_RET_ERROR;

        nlri_link_head->local_node.Code = LINK_STATE_NLRI_LOCAL_NODE_DESCRIPTORS_CODE;
        ret = bgp_ls_nlri_node_desc_parse(&(nlri_link_head->local_node)
                                          , pnt, nlri_node_len);
        if (BGP_LS_RET_OK != ret)
        {
            return BGP_LS_RET_ERROR;
        }
        nlri_has_parse_len += nlri_node_len;
        pnt += nlri_node_len;
    }
    else
    {
        /*back has parse type*/
        pnt -=2 ;
        nlri_has_parse_len -= 2;
    }
    
    /*parse Remote Node Descriptors Type*/
    DECODE_UINT16(pnt,nlri_node_type);
    nlri_has_parse_len += 2;

    if (BGP_LS_REMOTE_NODE_DESC == nlri_node_type)
    {
        /*parse Node length  */
        DECODE_UINT16(pnt,nlri_node_len);
        nlri_has_parse_len += 2;

        /* When packet overflow occur return immediately. */
        if ((nlri_has_parse_len + nlri_node_len) > nlri_parse_len)
            return BGP_LS_RET_ERROR;
        
        nlri_link_head->remote_node.Code = LINK_STATE_NLRI_REMOTE_NODE_DESCRIPTORS_CODE;
        ret = bgp_ls_nlri_node_desc_parse(&(nlri_link_head->remote_node)
                                          , pnt, nlri_node_len);
        if (BGP_LS_RET_OK != ret)
        {
            return BGP_LS_RET_ERROR;
        }
        nlri_has_parse_len += nlri_node_len;
        pnt += nlri_node_len;
    }
    else
    {
        /*back has parse type*/
        pnt -=2 ;
        nlri_has_parse_len -= 2;
    }

    ret = bgp_ls_nlri_link_desc_parse(&(nlri_link_head->link)
                                      , pnt, nlri_parse_len - nlri_has_parse_len);
    if (BGP_LS_RET_OK != ret)
    {
        return BGP_LS_RET_ERROR;
    }

    return BGP_LS_RET_OK;
}

int32_t bgp_ls_nlri_ip4_prefix_parse(NLRI_PREFIX *nlri_prefix_head,
                                 uint8_t *pnt, uint16_t nlri_parse_len)
{
    /***************The IPv4/IPv6 Topology Prefix NLRI Format**************

        The IPv4 and IPv6 Prefix NLRIs (NLRI Type = 3 and Type = 4) use the
        same format, as shown in the following figure.

           0                   1                   2                   3
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
          +-+-+-+-+-+-+-+-+
          |  Protocol-ID  |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                           Identifier                          |
          |                            (64 bits)                          |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          //              Local Node Descriptors (variable)              //
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          //                Prefix Descriptors (variable)                //
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */

    uint8_t nlri_proto_id = 0;
    uint64_t nlri_identifier = 0;
    uint16_t nlri_node_type = 0;
    uint16_t nlri_node_len = 0;
    uint16_t nlri_has_parse_len = 0;
    int32_t ret;

    if (NULL == nlri_prefix_head)
    {
        return BGP_LS_RET_ERROR;
    }
    /*save origin nlri buf*/
    nlri_prefix_head->origin_nlri_buf.type = BGP_LS_NLRI_TYPE_IP4_PREFIX;
    nlri_prefix_head->origin_nlri_buf.length = nlri_parse_len;
    nlri_prefix_head->origin_nlri_buf.value = XCALLOC(MTYPE_BGPLS_DECODE, nlri_parse_len);
    memcpy(nlri_prefix_head->origin_nlri_buf.value,pnt,nlri_parse_len);

    /*parse Protocol-ID */
    DECODE_UINT8(pnt,nlri_proto_id);
    nlri_has_parse_len += 1;

    /*Protocol-ID NLRI information source protocol*/
    switch (nlri_proto_id)
    {
        case BGP_LS_PROTO_ISIS_L1:
        case BGP_LS_PROTO_ISIS_L2:
        case BGP_LS_PROTO_OSPF2:
        case BGP_LS_PROTO_DIRECT:
        case BGP_LS_PROTO_STATIC:
        case BGP_LS_PROTO_OSPF3:
            /*
            case BGP_LS_PROTO_BGP:
            case BGP_LS_PROTO_RSVP_TE:
            case BGP_LS_PROTO_SR:
            */
            break;
        default:
            return BGP_LS_RET_ERROR;
    }

    /*parse Identifier */
    DECODE_UINT64(pnt,nlri_identifier);
    nlri_has_parse_len += 8;

    nlri_prefix_head->protocol_ID = nlri_proto_id;
    nlri_prefix_head->ID = nlri_identifier;

    /*parse Local Node Descriptors */

    /*parse Node Type  */
    DECODE_UINT16(pnt,nlri_node_type);
    nlri_has_parse_len += 2;

    if (BGP_LS_LOCAL_NODE_DESC == nlri_node_type)
    {
        /*parse Node length  */
        DECODE_UINT16(pnt,nlri_node_len);
        nlri_has_parse_len += 2;

        /* When packet overflow occur return immediately. */
        if ((nlri_has_parse_len + nlri_node_len) > nlri_parse_len)
            return BGP_LS_RET_ERROR;
        
        nlri_prefix_head->local_node.Code = LINK_STATE_NLRI_LOCAL_NODE_DESCRIPTORS_CODE;
        ret = bgp_ls_nlri_node_desc_parse(&(nlri_prefix_head->local_node)
                                          , pnt, nlri_node_len);
        if (BGP_LS_RET_OK != ret)
        {
            return BGP_LS_RET_ERROR;
        }
        nlri_has_parse_len += nlri_node_len;
        pnt += nlri_node_len;
    }
    else
    {
        /*back has parse type*/
        pnt -=2 ;
        nlri_has_parse_len -= 2;
    }

    ret = bgp_ls_nlri_prefix_desc_parse(&(nlri_prefix_head->prefix)
                                      , pnt, nlri_parse_len-nlri_has_parse_len);
    if (BGP_LS_RET_OK != ret)
    {
        return BGP_LS_RET_ERROR;
    }

    return BGP_LS_RET_OK;
}
int32_t bgp_ls_nlri_ip6_prefix_parse(NLRI_PREFIX *nlri_prefix_head,
                                 uint8_t *pnt, uint16_t nlri_parse_len)
{
    /***************The IPv4/IPv6 Topology Prefix NLRI Format**************

        The IPv4 and IPv6 Prefix NLRIs (NLRI Type = 3 and Type = 4) use the
        same format, as shown in the following figure.

           0                   1                   2                   3
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
          +-+-+-+-+-+-+-+-+
          |  Protocol-ID  |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |                           Identifier                          |
          |                            (64 bits)                          |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          //              Local Node Descriptors (variable)              //
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          //                Prefix Descriptors (variable)                //
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */

    uint8_t nlri_proto_id = 0;
    uint64_t nlri_identifier = 0;
    uint16_t nlri_node_type = 0;
    uint16_t nlri_node_len = 0;
    uint16_t nlri_has_parse_len = 0;
    int32_t ret;
    
    if (NULL == nlri_prefix_head)
    {
        return BGP_LS_RET_ERROR;
    }

    /*save origin nlri buf*/
    nlri_prefix_head->origin_nlri_buf.type = BGP_LS_NLRI_TYPE_IP6_PREFIX;
    nlri_prefix_head->origin_nlri_buf.length = nlri_parse_len;
    nlri_prefix_head->origin_nlri_buf.value = XCALLOC(MTYPE_BGPLS_DECODE, nlri_parse_len);
    memcpy(nlri_prefix_head->origin_nlri_buf.value,pnt,nlri_parse_len);

    /*parse Protocol-ID */
    DECODE_UINT8(pnt,nlri_proto_id);
    nlri_has_parse_len += 1;

    /*Protocol-ID NLRI information source protocol*/
    switch (nlri_proto_id)
    {
        case BGP_LS_PROTO_ISIS_L1:
        case BGP_LS_PROTO_ISIS_L2:
        case BGP_LS_PROTO_OSPF2:
        case BGP_LS_PROTO_DIRECT:
        case BGP_LS_PROTO_STATIC:
        case BGP_LS_PROTO_OSPF3:
            /*
            case BGP_LS_PROTO_BGP:
            case BGP_LS_PROTO_RSVP_TE:
            case BGP_LS_PROTO_SR:
            */
            break;
        default:
            return BGP_LS_RET_ERROR;
    }

    /*parse Identifier */
    DECODE_UINT64(pnt,nlri_identifier);
    nlri_has_parse_len += 8;
    
    nlri_prefix_head->protocol_ID = nlri_proto_id;
    nlri_prefix_head->ID = nlri_identifier;
    /*parse Local Node Descriptors */

    /*parse Node Type  */
    DECODE_UINT16(pnt,nlri_node_type);
    nlri_has_parse_len += 2;

    if (BGP_LS_LOCAL_NODE_DESC == nlri_node_type)
    {
        /*parse Node length  */
        DECODE_UINT16(pnt,nlri_node_len);
        nlri_has_parse_len += 2;

        /* When packet overflow occur return immediately. */
        if ((nlri_has_parse_len + nlri_node_len) > nlri_parse_len)
            return BGP_LS_RET_ERROR;

        nlri_prefix_head->local_node.Code = LINK_STATE_NLRI_LOCAL_NODE_DESCRIPTORS_CODE;
        ret = bgp_ls_nlri_node_desc_parse(&(nlri_prefix_head->local_node)
                                          , pnt, nlri_node_len);
        if (BGP_LS_RET_OK != ret)
        {
            return BGP_LS_RET_ERROR;
        }
        nlri_has_parse_len += nlri_node_len; 
        pnt += nlri_node_len;
    }
    else
    {
        /*back has parse type*/
        pnt -=2 ;
        nlri_has_parse_len -= 2;
    }

    ret = bgp_ls_nlri_prefix_desc_parse(&(nlri_prefix_head->prefix)
                                      , pnt, nlri_parse_len-nlri_has_parse_len);
    if (BGP_LS_RET_OK != ret)
    {
        return BGP_LS_RET_ERROR;
    }    

    return BGP_LS_RET_OK;
}

int32_t bgp_ls_nlri_sr6_sid_parse(NLRI_SR6_SID *nlri_sr6_sid_head,
                                 uint8_t *pnt, uint16_t nlri_parse_len)
{
    /************Link-State NLRI Type: SRv6 SID NLRI (value 6).**********    
       The format of this new NLRI type is as shown in the following figure:
    
         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+
        |  Protocol-ID  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        Identifier                             |
        |                        (64 bits)                              |
        ++-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
        |               Local Node Descriptors (variable)              //
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |               SRv6 SID Descriptors (variable)                //
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    
                          Figure 9: SRv6 SID NLRI Format                
    */
    uint8_t nlri_proto_id = 0;
    uint64_t nlri_identifier = 0;
    uint16_t nlri_node_type = 0;
    uint16_t nlri_node_len = 0;
    uint16_t nlri_has_parse_len = 0;
    int32_t ret;

    if (NULL == nlri_sr6_sid_head)
    {
        return BGP_LS_RET_ERROR;
    }

    /*save origin nlri buf*/
    nlri_sr6_sid_head->origin_nlri_buf.type = BGP_LS_NLRI_TYPE_SR6_SID;
    nlri_sr6_sid_head->origin_nlri_buf.length = nlri_parse_len;
    nlri_sr6_sid_head->origin_nlri_buf.value = XCALLOC(MTYPE_BGPLS_DECODE, nlri_parse_len);
    memcpy(nlri_sr6_sid_head->origin_nlri_buf.value,pnt,nlri_parse_len);

    /*parse Protocol-ID */
    DECODE_UINT8(pnt,nlri_proto_id);
    nlri_has_parse_len += 1;

    /*Protocol-ID NLRI information source protocol*/
    switch (nlri_proto_id)
    {
        case BGP_LS_PROTO_ISIS_L1:
        case BGP_LS_PROTO_ISIS_L2:
        case BGP_LS_PROTO_OSPF2:
        case BGP_LS_PROTO_DIRECT:
        case BGP_LS_PROTO_STATIC:
        case BGP_LS_PROTO_OSPF3:        
        case BGP_LS_PROTO_BGP:
        case BGP_LS_PROTO_RSVP_TE:
        case BGP_LS_PROTO_SR:

            break;
        default:
            return BGP_LS_RET_ERROR;
    }

    /*parse Identifier */
    DECODE_UINT64(pnt,nlri_identifier);
    nlri_has_parse_len += 8;
    
    nlri_sr6_sid_head->protocol_ID = nlri_proto_id;
    nlri_sr6_sid_head->ID = nlri_identifier;
    /*parse Local Node Descriptors */

    /*parse Node Type  */
    DECODE_UINT16(pnt,nlri_node_type);
    nlri_has_parse_len += 2;

    if (BGP_LS_LOCAL_NODE_DESC == nlri_node_type)
    {
        /*parse Node length  */
        DECODE_UINT16(pnt,nlri_node_len);
        nlri_has_parse_len += 2;

        /* When packet overflow occur return immediately. */
        if ((nlri_has_parse_len + nlri_node_len) > nlri_parse_len)
            return BGP_LS_RET_ERROR;

        nlri_sr6_sid_head->local_node.Code = LINK_STATE_NLRI_LOCAL_NODE_DESCRIPTORS_CODE;
        ret = bgp_ls_nlri_node_desc_parse(&(nlri_sr6_sid_head->local_node)
                                          , pnt, nlri_node_len);
        if (BGP_LS_RET_OK != ret)
        {
            return BGP_LS_RET_ERROR;
        }
        nlri_has_parse_len += nlri_node_len; 
        pnt += nlri_node_len;
    }
    else
    {
        /*back has parse type*/
        pnt -=2 ;
        nlri_has_parse_len -= 2;
    }

    ret = bgp_ls_nlri_sr6_sid_desc_parse(&(nlri_sr6_sid_head->sr6_sid_desc)
                                      , pnt, nlri_parse_len-nlri_has_parse_len);
    if (BGP_LS_RET_OK != ret)
    {
        return BGP_LS_RET_ERROR;
    }    

    return BGP_LS_RET_OK;  

}


 void bgp_ls_attr_node_serialize(struct stream *s, node_attribute *ls_node_attr)
{
    BGP_LS_TLV ls_tlv;
    
    if (NULL == ls_node_attr)
    {
        return;
    }

    LS_SERIALIZE_TLV(s,
            ls_node_attr->mt_ID_b,
            NODE_ATTR_CODE_MULTI_TOPOLOGY_ID,
            multi_topology_IDs_encode,
            &ls_node_attr->mt_ID);

    LS_SERIALIZE_TLV(s,
            ls_node_attr->node_flag_bits_b,
            NODE_ATTR_CODE_NODE_FLAG_BITS,
            node_attr_node_flag_bits_encode,
            &ls_node_attr->node_flag_bits);
            
    LS_SERIALIZE_TLV(s,
            ls_node_attr->opaque_node_attr_b,
            NODE_ATTR_CODE_OPAQUE_NODE_ATTR,
            node_attr_opaque_node_attr_encode,
            &ls_node_attr->opaque_node_attr);    

    LS_SERIALIZE_TLV(s,
            ls_node_attr->node_name_b,
            NODE_ATTR_CODE_NODE_NAME,
            node_attr_node_name_encode,
            &ls_node_attr->node_name);    

    LS_SERIALIZE_TLV(s,
            ls_node_attr->IsIs_area_ID_b,
            NODE_ATTR_CODE_ISIS_AREA_ID,
            node_attr_IsIs_area_ID_encode,
            &ls_node_attr->IsIs_area_ID);


    LS_SERIALIZE_TLV(s,
            ls_node_attr->IPv4_router_ID_b,
            NODE_ATTR_CODE_LOCAL_IPV4_ROUTER_ID,
            local_IPv4_router_ID_encode,
            &ls_node_attr->IPv4_router_ID);

    LS_SERIALIZE_TLV(s,
            ls_node_attr->IPv6_router_ID_b,
            NODE_ATTR_CODE_LOCAL_IPV6_ROUTER_ID,
            local_IPv6_router_ID_encode,
            &ls_node_attr->IPv6_router_ID);

    /*exclude rfc7752 */   
    LS_SERIALIZE_TLV(s,
            ls_node_attr->SR_caps_b,
            NODE_ATTR_CODE_SR_CAPS,
            node_attr_SR_caps_encode,
            &ls_node_attr->SR_caps);
    
    LS_SERIALIZE_TLV(s,
            ls_node_attr->SR_algo_b,
            NODE_ATTR_CODE_SR_ALGO,
            node_attr_SR_algo_encode,
            &ls_node_attr->SR_algo);
    
    LS_SERIALIZE_TLV(s,
            ls_node_attr->SR_local_block_b,
            NODE_ATTR_CODE_SR_LOCAL_BLOCK,
            node_attr_SR_local_block_encode,
            &ls_node_attr->SR_local_block);
    
    LS_SERIALIZE_TLV(s,
            ls_node_attr->SRMS_pref_b,
            NODE_ATTR_CODE_SRMS_PREF,
            node_attr_SRMS_pref_encode,
            &ls_node_attr->SRMS_pref);

	LS_SERIALIZE_TLV(s,
            ls_node_attr->sid_label_b,
            NODE_ATTR_CODE_SR_SID_LABEL,
            node_attr_SID_label_encode,
            &ls_node_attr->sid_label);
    return;
}


 int32_t bgp_ls_nlri_te_policy_parse(NLRI_TE_POLICY *nlri_te_policy_head,
								  uint8_t *pnt, uint16_t nlri_parse_len)
 {
	
	 uint8_t nlri_proto_id = 0;
	 uint64_t nlri_identifier = 0;
	 uint16_t nlri_node_type = 0;
	 uint16_t nlri_node_len = 0;
	 uint16_t nlri_has_parse_len = 0;
	 int32_t ret;
 
	 if (NULL == nlri_te_policy_head)
	 {
		 return BGP_LS_RET_ERROR;
	 }
 
	 /*save origin nlri buf*/
	 nlri_te_policy_head->origin_nlri_buf.type = BGP_LS_NLRI_TYPE_TE_POLICY;
	 nlri_te_policy_head->origin_nlri_buf.length = nlri_parse_len;
	 nlri_te_policy_head->origin_nlri_buf.value = XCALLOC(MTYPE_BGPLS_DECODE, nlri_parse_len);
	 memcpy(nlri_te_policy_head->origin_nlri_buf.value,pnt,nlri_parse_len);
 
	 /*parse Protocol-ID */
	 DECODE_UINT8(pnt,nlri_proto_id);
	 nlri_has_parse_len += 1;
 
	 /*Protocol-ID NLRI information source protocol*/
	 if(SEGMENT_ROUTING != nlri_proto_id)
	 {	
		return BGP_LS_RET_ERROR;
	 }
 
	 /*parse Identifier */
	 DECODE_UINT64(pnt,nlri_identifier);
	 nlri_has_parse_len += 8;
	 
	 nlri_te_policy_head->protocol_ID = nlri_proto_id;
	 nlri_te_policy_head->ID = nlri_identifier;
	 /*parse Local Node Descriptors */
	 DECODE_UINT16(pnt,nlri_node_type);
	 nlri_has_parse_len += 2;
 
	 if (BGP_LS_LOCAL_NODE_DESC == nlri_node_type)
	 {
		 /*parse Node length  */
		 DECODE_UINT16(pnt,nlri_node_len);
		 nlri_has_parse_len += 2;
 
		 /* When packet overflow occur return immediately. */
		 if ((nlri_has_parse_len + nlri_node_len) > nlri_parse_len)
			 return BGP_LS_RET_ERROR;
 
		 nlri_te_policy_head->local_node.Code = LINK_STATE_NLRI_LOCAL_NODE_DESCRIPTORS_CODE;
		 ret = bgp_ls_nlri_node_desc_parse(&(nlri_te_policy_head->local_node)
										   , pnt, nlri_node_len);
		 if (BGP_LS_RET_OK != ret)
		 {
			 return BGP_LS_RET_ERROR;
		 }
		 nlri_has_parse_len += nlri_node_len; 
		 pnt += nlri_node_len;
	 }
	 else
	 {
		 /*back has parse type*/
		 pnt -=2 ;
		 nlri_has_parse_len -= 2;
	 }
 
	 ret = bgp_ls_nlri_te_policy_desc_parse(&(nlri_te_policy_head->te_policy_desc)
									   , pnt, nlri_parse_len-nlri_has_parse_len);
	 if (BGP_LS_RET_OK != ret)
	 {
		 return BGP_LS_RET_ERROR;
	 }	  
 
	 return BGP_LS_RET_OK;	
 
 }

 void bgp_ls_attr_link_serialize(struct stream *s, link_attribute *ls_link_attr)
{
    BGP_LS_TLV ls_tlv;

    if (NULL == ls_link_attr)
    {
        return;
    }
    LS_SERIALIZE_TLV(s,
            ls_link_attr->local_IP4_router_ID_b,
            LINK_ATTR_CODE_LOCAL_IPV4_ROUTER_ID,
            local_IPv4_router_ID_encode,
            &ls_link_attr->local_IP4_router_ID);

    LS_SERIALIZE_TLV(s,
            ls_link_attr->local_IP6_router_ID_b,
            LINK_ATTR_CODE_LOCAL_IPV6_ROUTER_ID,
            local_IPv6_router_ID_encode,
            &ls_link_attr->local_IP6_router_ID);    

    LS_SERIALIZE_TLV(s,
            ls_link_attr->remote_IP4_router_ID_b,
            LINK_ATTR_CODE_REMOTEIPV4_ROUTER_ID,
            remote_IPv4_router_ID_encode,
            &ls_link_attr->remote_IP4_router_ID);


    LS_SERIALIZE_TLV(s,
            ls_link_attr->remote_IP6_router_ID_b,
            LINK_ATTR_CODE_REMOTEIPV6_ROUTER_ID,
            remote_IPv6_router_ID_encode,
            &ls_link_attr->remote_IP6_router_ID);    

    LS_SERIALIZE_TLV(s,
            ls_link_attr->admin_group_b,
            LINK_ATTR_CODE_ADMIN_GROUP,
            link_attr_admin_group_encode,
            &ls_link_attr->admin_group);


    LS_SERIALIZE_TLV(s,
            ls_link_attr->maxLink_bandwidth_b,
            LINK_ATTR_CODE_MAXLINK_BANDWIDTH,
            link_attr_maxLink_bandwidth_encode,
            &ls_link_attr->maxLink_bandwidth);


    LS_SERIALIZE_TLV(s,
            ls_link_attr->max_reservable_link_bandwidth_b,
            LINK_ATTR_CODE_MAX_RESERVABLE_LINK_BANDWIDTH,
            link_attr_max_reservable_link_bandwidth_encode,
            &ls_link_attr->max_reservable_link_bandwidth);


    LS_SERIALIZE_TLV(s,
            ls_link_attr->unreserved_bandwidth_b,
            LINK_ATTR_CODE_UNRESERVED_BANDWIDTH,
            link_attr_unreserved_bandwidth_encode,
            &ls_link_attr->unreserved_bandwidth);

    LS_SERIALIZE_TLV(s,
            ls_link_attr->TE_default_metric_b,
            LINK_ATTR_CODE_TE_DEFAULT_METRIC,
            link_attr_TE_default_metric_encode,
            &ls_link_attr->TE_default_metric);

    LS_SERIALIZE_TLV(s,
            ls_link_attr->link_protection_type_b,
            LINK_ATTR_CODE_LINK_PROTECTION_TYPE,
            link_attr_link_protection_type_encode,
            &ls_link_attr->link_protection_type);


    LS_SERIALIZE_TLV(s,
            ls_link_attr->mpls_protocol_mask_b,
            LINK_ATTR_CODE_MPLS_PROTOCOL_MASK,
            link_attr_mpls_protocol_mask_encode,
            &ls_link_attr->mpls_protocol_mask);

    LS_SERIALIZE_TLV(s,
            ls_link_attr->igp_metric_b,
            LINK_ATTR_CODE_IGP_METRIC,
            link_attr_igp_metric_encode,
            &ls_link_attr->igp_metric);   

    LS_SERIALIZE_TLV(s,
            ls_link_attr->shared_risk_link_group_b,
            LINK_ATTR_CODE_SHARED_RISK_LINK_GROUP,
            link_attr_shared_risk_link_group_encode,
            &ls_link_attr->shared_risk_link_group);
    
    LS_SERIALIZE_TLV(s,
            ls_link_attr->opaque_link_attr_b,
            LINK_ATTR_CODE_OPAQUE_LINK_ATTR,
            link_attr_opaque_link_attr_encode,
            &ls_link_attr->opaque_link_attr);

    LS_SERIALIZE_TLV(s,
            ls_link_attr->link_name_b,
            LINK_ATTR_CODE_LINK_NAME,
            link_attr_link_name_encode,
            &ls_link_attr->link_name);
    
    /*exclude rfc7752 */    
    LS_SERIALIZE_TLV(s,
            ls_link_attr->adj_SID_b,
            LINK_ATTR_CODE_ADJSID,
            link_attr_adj_SID_encode,
            &ls_link_attr->adj_SID);

    LS_SERIALIZE_TLV(s,
            ls_link_attr->lan_adj_SID_b,
            LINK_ATTR_CODE_LAN_ADJ_SID,
            link_attr_lan_adj_SID_encode,
            &ls_link_attr->lan_adj_SID);

    
    LS_SERIALIZE_TLV(s,
            ls_link_attr->peer_set_SID_b,
            LINK_ATTR_CODE_PEER_SET_SID,
            link_attr_peer_set_SID_encode,
            &ls_link_attr->peer_set_SID);
      
    LS_SERIALIZE_TLV(s,
            ls_link_attr->peer_node_SID_b,
            LINK_ATTR_CODE_PEER_NODE_SID,
            link_attr_peer_node_SID_encode,
            &ls_link_attr->peer_node_SID);


    LS_SERIALIZE_TLV(s,
            ls_link_attr->peer_adj_SID_b,
            LINK_ATTR_CODE_PEER_ADJ_SID,
            link_attr_peer_adj_SID_encode,
            &ls_link_attr->peer_adj_SID);

    LS_SERIALIZE_TLV(s,
            ls_link_attr->peer_set_SID_b,
            LINK_ATTR_CODE_PEER_SET_SID,
            link_attr_peer_set_SID_encode,
            &ls_link_attr->peer_set_SID);



    LS_SERIALIZE_TLV(s,
            ls_link_attr->uni_link_delay_b,
            LINK_ATTR_CODE_UNI_LINK_DELAY,
            link_attr_uni_link_delay_encode,
            &ls_link_attr->uni_link_delay);


    LS_SERIALIZE_TLV(s,
            ls_link_attr->min_max_uniLink_delay_b,
            LINK_ATTR_CODE_MIN_MAX_UNILINK_DELAY,
            link_attr_min_max_uniLink_delay_encode,
            &ls_link_attr->min_max_uniLink_delay);


    LS_SERIALIZE_TLV(s,
            ls_link_attr->uni_delay_variation_b,
            LINK_ATTR_CODE_UNI_DELAY_VARIATION,
            link_attr_uni_delay_variation_encode,
            &ls_link_attr->uni_delay_variation);

    
    LS_SERIALIZE_TLV(s,
            ls_link_attr->uni_packet_loss_b,
            LINK_ATTR_CODE_UNI_PACKET_LOSS,
            link_attr_uni_packet_loss_encode,
            &ls_link_attr->uni_packet_loss);

    LS_SERIALIZE_TLV(s,
            ls_link_attr->uni_residual_bandwidth_b,
            LINK_ATTR_CODE_UNI_RESIDUAL_BANDWIDTH,
            link_attr_uni_residual_bandwidth_encode,
            &ls_link_attr->uni_residual_bandwidth);


    LS_SERIALIZE_TLV(s,
            ls_link_attr->uni_available_bandwidth_b,
            LINK_ATTR_CODE_UNI_AVAILABLE_BANDWIDTH,
            link_attr_uni_available_bandwidth_encode,
            &ls_link_attr->uni_available_bandwidth);


    LS_SERIALIZE_TLV(s,
            ls_link_attr->uni_bandwidth_util_b,
            LINK_ATTR_CODE_UNI_BANDWIDTH_UTIL,
            link_attr_uni_bandwidth_util_encode,
            &ls_link_attr->uni_bandwidth_util);


    LS_SERIALIZE_TLV(s,
            ls_link_attr->l2_bundle_member_b,
            LINK_ATTR_CODE_L2_BUNDLE_MEMBER,
            link_attr_l2_bundle_member_encode,
            &ls_link_attr->l2_bundle_member); 
    
    return;
}


 void bgp_ls_attr_prefix_serialize(struct stream *s, prefix_attribute *ls_prefix_attr)
{    
    BGP_LS_TLV ls_tlv;

    if (NULL == ls_prefix_attr)
    {
        return;
    }

    LS_SERIALIZE_TLV(s,
            ls_prefix_attr->igp_flags_b,
            PREFIX_ATTR_CODE_IGP_FLAGS,
            prefix_attr_igp_flags_encode,
            &ls_prefix_attr->igp_flags); 

    LS_SERIALIZE_TLV(s,
            ls_prefix_attr->igp_route_tag_b,
            PREFIX_ATTR_CODE_IGP_ROUTE_TAG,
            prefix_attr_igp_route_tag_encode,
            &ls_prefix_attr->igp_route_tag); 

    LS_SERIALIZE_TLV(s,
            ls_prefix_attr->igp_extended_route_tag_b,
            PREFIX_ATTR_CODE_IGP_EXTENDED_ROUTE_TAG,
            prefix_attr_igp_extended_route_tag_encode,
            &ls_prefix_attr->igp_extended_route_tag);     

    LS_SERIALIZE_TLV(s,
            ls_prefix_attr->prefix_metric_b,
            PREFIX_ATTR_CODE_PREFIX_METRIC,
            prefix_attr_prefix_metric_encode,
            &ls_prefix_attr->prefix_metric); 
    
    LS_SERIALIZE_TLV(s,
            ls_prefix_attr->ospf_forwarding_address_b,
            PREFIX_ATTR_CODE_OSPF_FORWARDING_ADDRESS,
            prefix_attr_ospf_forwarding_address_encode,
            &ls_prefix_attr->ospf_forwarding_address);      
  
    LS_SERIALIZE_TLV(s,
            ls_prefix_attr->opaque_prefix_attribute_b,
            PREFIX_ATTR_CODE_OPAQUE_PREFIX_ATTRIBUTE,
            prefix_attr_opaque_prefix_attr_encode,
            &ls_prefix_attr->opaque_prefix_attribute);

    LS_SERIALIZE_TLV(s,
            ls_prefix_attr->prefix_SID_b,
            PREFIX_ATTR_CODE_PREFIX_SID,
            prefix_attr_prefix_SID_encode,
            &ls_prefix_attr->prefix_SID);

    LS_SERIALIZE_TLV(s,
            ls_prefix_attr->range_b,
            PREFIX_ATTR_CODE_RANGE,
            prefix_attr_range_encode,
            &ls_prefix_attr->range);
    
    LS_SERIALIZE_TLV(s,
            ls_prefix_attr->attr_flags_b,
            PREFIX_ATTR_CODE_FLAGS,
            prefix_attr_flags_encode,
            &ls_prefix_attr->attr_flags);
    
    LS_SERIALIZE_TLV(s,
            ls_prefix_attr->source_router_ID_b,
            PREFIX_ATTR_CODE_SOURCE_ROUTER_ID,
            prefix_attr_source_router_ID_encode,
            &ls_prefix_attr->source_router_ID);
    return;
}


 int32_t bgp_ls_attr_node_parse
(
    uint16_t attr_type,
    uint16_t attr_length,
    uint8_t *pnt,
    node_attribute *ls_node_attr
)
{    
    BGP_LS_TLV ls_tlv;
    switch (attr_type)
    {
        case NODE_ATTR_CODE_MULTI_TOPOLOGY_ID:        
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                    ls_node_attr->mt_ID_b,
                    multi_topology_IDs_decode,
                    &ls_node_attr->mt_ID);
            break;
        case NODE_ATTR_CODE_NODE_FLAG_BITS:        
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                    ls_node_attr->node_flag_bits_b,
                    node_attr_node_flag_bits_decode,
                    &ls_node_attr->node_flag_bits);
            break;
        case NODE_ATTR_CODE_OPAQUE_NODE_ATTR:        
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                    ls_node_attr->opaque_node_attr_b,
                    node_attr_opaque_node_attr_decode,
                    &ls_node_attr->opaque_node_attr);    
            break;
        case NODE_ATTR_CODE_NODE_NAME:        
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                    ls_node_attr->node_name_b,
                    node_attr_node_name_decode,
                    &ls_node_attr->node_name);    
            break;
        case NODE_ATTR_CODE_ISIS_AREA_ID:        
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                    ls_node_attr->IsIs_area_ID_b,
                    node_attr_IsIs_area_ID_decode,
                    &ls_node_attr->IsIs_area_ID);
            break;        
        case NODE_ATTR_CODE_LOCAL_IPV4_ROUTER_ID:        
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_node_attr->IPv4_router_ID_b,
                local_IPv4_router_ID_decode,
                &ls_node_attr->IPv4_router_ID);
            break;
        case NODE_ATTR_CODE_LOCAL_IPV6_ROUTER_ID:
        
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_node_attr->IPv6_router_ID_b,
                local_IPv6_router_ID_decode,
                &ls_node_attr->IPv6_router_ID);
            break;
            
        /*exclude rfc7752 */ 
        case NODE_ATTR_CODE_SR_CAPS:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_node_attr->SR_caps_b,
                node_attr_SR_caps_decode,
                &ls_node_attr->SR_caps);
            break;
        case NODE_ATTR_CODE_SR_ALGO:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_node_attr->SR_algo_b,
                node_attr_SR_algo_decode,
                &ls_node_attr->SR_algo);
            break;
        case NODE_ATTR_CODE_SR_LOCAL_BLOCK:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_node_attr->SR_local_block_b,
                node_attr_SR_local_block_decode,
                &ls_node_attr->SR_local_block);
            break;
        case NODE_ATTR_CODE_SRMS_PREF:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_node_attr->SRMS_pref_b,
                node_attr_SRMS_pref_decode,
                &ls_node_attr->SRMS_pref);
            break;
		case NODE_ATTR_CODE_SR_SID_LABEL:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_node_attr->sid_label_b,
                node_attr_SID_label_decode,
                &ls_node_attr->sid_label);
            break;
		case NODE_ATTR_CODE_SR6_CAPS:
			LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_node_attr->SR6_caps_b,
                node_attr_SR6_caps_decode,
                &ls_node_attr->SR6_caps);
            break;
        default:
            return BGP_LS_RET_ERROR;
    }
 
    return BGP_LS_RET_OK;
};

int32_t bgp_ls_attr_link_parse
(
    uint16_t attr_type,
    uint16_t attr_length,
    uint8_t *pnt,
    link_attribute *ls_link_attr
)
{
    
    BGP_LS_TLV ls_tlv;
    switch (attr_type)
    {        
        case LINK_ATTR_CODE_LOCAL_IPV4_ROUTER_ID:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->local_IP4_router_ID_b,
                local_IPv4_router_ID_decode,
                &ls_link_attr->local_IP4_router_ID);
            break;
        case LINK_ATTR_CODE_LOCAL_IPV6_ROUTER_ID:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->local_IP6_router_ID_b,
                local_IPv6_router_ID_decode,
                &ls_link_attr->local_IP6_router_ID);    
            break;
        case LINK_ATTR_CODE_REMOTEIPV4_ROUTER_ID:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->remote_IP4_router_ID_b,
                remote_IPv4_router_ID_decode,
                &ls_link_attr->remote_IP4_router_ID);
            break;
        case LINK_ATTR_CODE_REMOTEIPV6_ROUTER_ID:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->remote_IP6_router_ID_b,
                remote_IPv6_router_ID_decode,
                &ls_link_attr->remote_IP6_router_ID);    
            break;
        case LINK_ATTR_CODE_ADMIN_GROUP:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->admin_group_b,
                link_attr_admin_group_decode,
                &ls_link_attr->admin_group);
            break;
        case LINK_ATTR_CODE_MAXLINK_BANDWIDTH:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->maxLink_bandwidth_b,
                link_attr_maxLink_bandwidth_decode,
                &ls_link_attr->maxLink_bandwidth);
            break;
        case LINK_ATTR_CODE_MAX_RESERVABLE_LINK_BANDWIDTH:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->max_reservable_link_bandwidth_b,
                link_attr_max_reservable_link_bandwidth_decode,
                &ls_link_attr->max_reservable_link_bandwidth);
            break;
        case LINK_ATTR_CODE_UNRESERVED_BANDWIDTH:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->unreserved_bandwidth_b,
                link_attr_unreserved_bandwidth_decode,
                &ls_link_attr->unreserved_bandwidth);
            break;
        case LINK_ATTR_CODE_TE_DEFAULT_METRIC:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->TE_default_metric_b,
                link_attr_TE_default_metric_decode,
                &ls_link_attr->TE_default_metric);
            break;
        case LINK_ATTR_CODE_LINK_PROTECTION_TYPE:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->link_protection_type_b,
                link_attr_link_protection_type_decode,
                &ls_link_attr->link_protection_type);
            break;
        case LINK_ATTR_CODE_MPLS_PROTOCOL_MASK:

            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->mpls_protocol_mask_b,
                link_attr_mpls_protocol_mask_decode,
                &ls_link_attr->mpls_protocol_mask);
            break;
        case LINK_ATTR_CODE_IGP_METRIC:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->igp_metric_b,
                link_attr_igp_metric_decode,
                &ls_link_attr->igp_metric);   
            break;
        case LINK_ATTR_CODE_SHARED_RISK_LINK_GROUP:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->shared_risk_link_group_b,
                link_attr_shared_risk_link_group_decode,
                &ls_link_attr->shared_risk_link_group);
            break;
        case LINK_ATTR_CODE_OPAQUE_LINK_ATTR:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->opaque_link_attr_b,
                link_attr_opaque_link_attr_decode,
                &ls_link_attr->opaque_link_attr);
            break;
        case LINK_ATTR_CODE_LINK_NAME:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->link_name_b,
                link_attr_link_name_decode,
                &ls_link_attr->link_name);
            break;
        /*exclude rfc7752 */    

        case LINK_ATTR_CODE_ADJSID:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->adj_SID_b,
                link_attr_adj_SID_decode,
                &ls_link_attr->adj_SID);
            break;
        case LINK_ATTR_CODE_LAN_ADJ_SID:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->lan_adj_SID_b,
                link_attr_lan_adj_SID_decode,
                &ls_link_attr->lan_adj_SID);

            break;
        case LINK_ATTR_CODE_PEER_NODE_SID:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->peer_node_SID_b,
                link_attr_peer_node_SID_decode,
                &ls_link_attr->peer_node_SID);

            break;
        case LINK_ATTR_CODE_PEER_ADJ_SID:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->peer_adj_SID_b,
                link_attr_peer_adj_SID_decode,
                &ls_link_attr->peer_adj_SID);
            break;
        case LINK_ATTR_CODE_PEER_SET_SID:
        LS_PARSE_TLV(attr_type, attr_length, pnt,
            ls_link_attr->peer_set_SID_b,
            link_attr_peer_set_SID_decode,
            &ls_link_attr->peer_set_SID);
            break;

        case LINK_ATTR_CODE_UNI_LINK_DELAY:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->uni_link_delay_b,
                link_attr_uni_link_delay_decode,
                &ls_link_attr->uni_link_delay);
            break;

        case LINK_ATTR_CODE_MIN_MAX_UNILINK_DELAY:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->min_max_uniLink_delay_b,
                link_attr_min_max_uniLink_delay_decode,
                &ls_link_attr->min_max_uniLink_delay);
            break;
        case LINK_ATTR_CODE_UNI_DELAY_VARIATION:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->uni_delay_variation_b,
                link_attr_uni_delay_variation_decode,
                &ls_link_attr->uni_delay_variation);
            break;

        case LINK_ATTR_CODE_UNI_PACKET_LOSS:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->uni_packet_loss_b,
                link_attr_uni_packet_loss_decode,
                &ls_link_attr->uni_packet_loss);
            break;
        case LINK_ATTR_CODE_UNI_RESIDUAL_BANDWIDTH:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->uni_residual_bandwidth_b,
                link_attr_uni_residual_bandwidth_decode,
                &ls_link_attr->uni_residual_bandwidth);
            break;
        case LINK_ATTR_CODE_UNI_AVAILABLE_BANDWIDTH:

            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->uni_available_bandwidth_b,
                link_attr_uni_available_bandwidth_decode,
                &ls_link_attr->uni_available_bandwidth);
            break;
        case LINK_ATTR_CODE_UNI_BANDWIDTH_UTIL:

            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->uni_bandwidth_util_b,
                link_attr_uni_bandwidth_util_decode,
                &ls_link_attr->uni_bandwidth_util);
            break;
        case LINK_ATTR_CODE_L2_BUNDLE_MEMBER:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->l2_bundle_member_b,
                link_attr_l2_bundle_member_decode,
                &ls_link_attr->l2_bundle_member);             
            break;
		case LINK_ATTR_CODE_SR6_END_SID:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->sr6_end_sid_b,
                link_attr_sr6_end_sid_decode,
                &ls_link_attr->sr6_end_sid);             
            break;
		case LINK_ATTR_CODE_ISIS_SR6_LAN_END_SID:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->isis_sr6_lan_end_sid_b,
                link_attr_sr6_lan_end_x_sid_decode,
                &ls_link_attr->isis_sr6_lan_end_sid); 
            break;
		case LINK_ATTR_CODE_OSPF3_SR6_LAN_END_SID:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_link_attr->ospf3_sr6_lan_end_sid_b,
                link_attr_sr6_lan_end_x_sid_decode,
                &ls_link_attr->ospf3_sr6_lan_end_sid);
            break;
			
        default:
            return BGP_LS_RET_ERROR;
    }
 
    return BGP_LS_RET_OK;
};

int32_t bgp_ls_attr_prefix_parse
(
    uint16_t attr_type,
    uint16_t attr_length,
    uint8_t *pnt,
    prefix_attribute *ls_prefix_attr
)
{
    BGP_LS_TLV ls_tlv;
    switch (attr_type)
    {        
        case PREFIX_ATTR_CODE_IGP_FLAGS:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_prefix_attr->igp_flags_b,
                prefix_attr_igp_flags_decode,
                &ls_prefix_attr->igp_flags); 
            break;
        case PREFIX_ATTR_CODE_IGP_ROUTE_TAG:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_prefix_attr->igp_route_tag_b,
                prefix_attr_igp_route_tag_decode,
                &ls_prefix_attr->igp_route_tag); 
            break;
        case PREFIX_ATTR_CODE_IGP_EXTENDED_ROUTE_TAG:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_prefix_attr->igp_extended_route_tag_b,
                prefix_attr_igp_extended_route_tag_decode,
                &ls_prefix_attr->igp_extended_route_tag);     
            break;

        case PREFIX_ATTR_CODE_PREFIX_METRIC:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_prefix_attr->prefix_metric_b,
                prefix_attr_prefix_metric_decode,
                &ls_prefix_attr->prefix_metric); 
            break;
        case PREFIX_ATTR_CODE_OSPF_FORWARDING_ADDRESS:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_prefix_attr->ospf_forwarding_address_b,
                prefix_attr_ospf_forwarding_address_decode,
                &ls_prefix_attr->ospf_forwarding_address);      
            break;
        case PREFIX_ATTR_CODE_OPAQUE_PREFIX_ATTRIBUTE:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_prefix_attr->opaque_prefix_attribute_b,
                prefix_attr_opaque_prefix_attr_decode,
                &ls_prefix_attr->opaque_prefix_attribute);
            break;

        case PREFIX_ATTR_CODE_PREFIX_SID:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_prefix_attr->prefix_SID_b,
                prefix_attr_prefix_SID_decode,
                &ls_prefix_attr->prefix_SID);
            break;

        case PREFIX_ATTR_CODE_RANGE:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_prefix_attr->range_b,
                prefix_attr_range_decode,
                &ls_prefix_attr->range);
            break;
        case PREFIX_ATTR_CODE_FLAGS:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_prefix_attr->attr_flags_b,
                prefix_attr_flags_decode,
                &ls_prefix_attr->attr_flags);
            break;
        case PREFIX_ATTR_CODE_SOURCE_ROUTER_ID:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_prefix_attr->source_router_ID_b,
                prefix_attr_source_router_ID_decode,
                &ls_prefix_attr->source_router_ID);
            break;
        default:
            return BGP_LS_RET_ERROR;
    }
 
    return BGP_LS_RET_OK;
}

int32_t bgp_ls_attr_sr6_sid_parse
(
    uint16_t attr_type,
    uint16_t attr_length,
    uint8_t *pnt,
    sr6_sid_attribute *ls_sr6_sid_attr
)
{
    BGP_LS_TLV ls_tlv;
    switch (attr_type)
    {        
        case SR6_SID_ATTR_CODE_END_BEHAVIOR:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_sr6_sid_attr->endpoint_behavior_b,
                sr6_sid_attr_endpoint_behavior_decode,
                &ls_sr6_sid_attr->endpoint_behavior); 
            break;
        case SR6_SID_ATTR_CODE_BGP_PEER_NODE_SID:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_sr6_sid_attr->sr6_bgp_peer_node_sid_b,
                sr6_sid_attr_bgp_peer_node_sid_decode,
                &ls_sr6_sid_attr->sr6_bgp_peer_node_sid); 
            break;
        case SR6_SID_ATTR_CODE_SID_STRUCT:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                ls_sr6_sid_attr->sr6_sid_struct_b,
                sr6_sid_attr_sid_struct_decode,
                &ls_sr6_sid_attr->sr6_sid_struct); 
            break;
        default:
            return BGP_LS_RET_ERROR;
    }
 
    return BGP_LS_RET_OK;
}


int32_t bgp_ls_attr_te_policy_parse
(
    uint16_t attr_type,
    uint16_t attr_length,
    uint8_t *pnt,
    te_policy_attribute *te_policy_attr
)
{
    BGP_LS_TLV ls_tlv;
    switch (attr_type)
    {        
        case TE_POLICY_ATTR_CODE_BINDING_SID:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                te_policy_attr->binding_sid_b,
                te_policy_attr_binding_sid_decode,
                &te_policy_attr->binding_sid); 
            break;
        case TE_POLICY_ATTR_CODE_SR_CANDIDATE_PATH_STATE:
            LS_PARSE_TLV(attr_type, attr_length, pnt,
                te_policy_attr->preference_b,
                te_policy_attr_perference_decode,
                &te_policy_attr->preference); 
            break;
        case TE_POLICY_ATTR_CODE_SEGMENT_LIST:
            {
	            LS_PARSE_TLV(attr_type, attr_length, pnt,
	                te_policy_attr->sid_list_b,
	                te_policy_attr_sid_list_decode,
	                &(te_policy_attr->sid_list)); 
	            break;
        	}
        default:
            return BGP_LS_RET_ERROR;
    }
 
    return BGP_LS_RET_OK;
}



/*BGP-LS memory malloc funcitons*/
void bgp_ls_origin_buf_alloc(BGP_LS_TLV *origin_buf,uint8_t *data ,uint16_t type, int16_t length)
{
    if ((NULL == origin_buf)||(NULL == data))
    {
        return;
    }
    origin_buf->type = type;
    origin_buf->length = length;
    if (NULL != origin_buf->value)
    {
        XFREE(MTYPE_BGPLS_DECODE, origin_buf->value);
    }   
    origin_buf->value = XCALLOC(MTYPE_BGPLS_DECODE, length);
    memcpy(origin_buf->value, data, length);
    return;
}

void bgp_ls_str_alloc(char **str_buf,char *str)
{
    if (NULL == str)
    {
        return;
    }

    if (NULL != *str_buf)
    {
        XFREE(MTYPE_BGPLS_DECODE, *str_buf);
    }
    
    *str_buf = XCALLOC(MTYPE_BGPLS_DECODE, strlen(str)+1);
    memset(*str_buf, 0, strlen(str)+1);
    memcpy(*str_buf, str, strlen(str));
    return;
}

void bgp_ls_free_nlri_node(NLRI_NODE *ls_nlri_node)
{        
    if (ls_nlri_node->origin_nlri_buf.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_node->origin_nlri_buf.value);
        ls_nlri_node->origin_nlri_buf.value = NULL;
    }
    
    if (ls_nlri_node->node_attr.origin_buf.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_node->node_attr.origin_buf.value);
        ls_nlri_node->node_attr.origin_buf.value = NULL;
    }

    if (ls_nlri_node->node_attr.mt_ID.IDs)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_node->node_attr.mt_ID.IDs);
        ls_nlri_node->node_attr.mt_ID.IDs = NULL;
    }
    
    if (ls_nlri_node->node_attr.opaque_node_attr.Data)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_node->node_attr.opaque_node_attr.Data);
        ls_nlri_node->node_attr.opaque_node_attr.Data = NULL;
    }
    if (ls_nlri_node->node_attr.node_name.Name)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_node->node_attr.node_name.Name);
        ls_nlri_node->node_attr.node_name.Name = NULL;
    }
    if (ls_nlri_node->node_attr.IsIs_area_ID.AreaID)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_node->node_attr.IsIs_area_ID.AreaID);
        ls_nlri_node->node_attr.IsIs_area_ID.AreaID = NULL;
    }
    if (ls_nlri_node->node_attr.SR_algo.Algos)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_node->node_attr.SR_algo.Algos);
        ls_nlri_node->node_attr.SR_algo.Algos = NULL;
    }

    return;
}


void bgp_ls_free_nlri_link(NLRI_LINK *ls_nlri_link)
{
    
    if (ls_nlri_link->origin_nlri_buf.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_link->origin_nlri_buf.value);
        ls_nlri_link->origin_nlri_buf.value = NULL;
    }
    
    if (ls_nlri_link->link_attr.origin_buf.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.origin_buf.value);
        ls_nlri_link->link_attr.origin_buf.value = NULL;
    }

    if (ls_nlri_link->link.mt_ID.IDs)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_link->link.mt_ID.IDs);
        ls_nlri_link->link.mt_ID.IDs = NULL;
    }
    
    if (ls_nlri_link->link_attr.shared_risk_link_group.Groups)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.shared_risk_link_group.Groups);
        ls_nlri_link->link_attr.shared_risk_link_group.Groups = NULL;
    }

    if (ls_nlri_link->link_attr.opaque_link_attr.Data)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.opaque_link_attr.Data);
        ls_nlri_link->link_attr.opaque_link_attr.Data = NULL;
    }
    if (ls_nlri_link->link_attr.link_name.Name)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.link_name.Name);
        ls_nlri_link->link_attr.link_name.Name = NULL;
    }
    if (ls_nlri_link->link_attr.adj_SID.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.adj_SID.value);
        ls_nlri_link->link_attr.adj_SID.value = NULL;
    }
    if (ls_nlri_link->link_attr.lan_adj_SID.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.lan_adj_SID.value);
        ls_nlri_link->link_attr.lan_adj_SID.value = NULL;
    }
    if (ls_nlri_link->link_attr.peer_node_SID.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.peer_node_SID.value);
        ls_nlri_link->link_attr.peer_node_SID.value = NULL;
    }
    if (ls_nlri_link->link_attr.peer_adj_SID.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.peer_adj_SID.value);
        ls_nlri_link->link_attr.peer_adj_SID.value = NULL;
    }
    if (ls_nlri_link->link_attr.peer_set_SID.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.peer_set_SID.value);
        ls_nlri_link->link_attr.peer_set_SID.value = NULL;
    }
    if (ls_nlri_link->link_attr.l2_bundle_member.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.l2_bundle_member.value);
        ls_nlri_link->link_attr.l2_bundle_member.value = NULL;
    }
   
    return;
}


void bgp_ls_free_nlri_prefix(NLRI_PREFIX *ls_nlri_prefix)
{
    if (ls_nlri_prefix->origin_nlri_buf.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_prefix->origin_nlri_buf.value);
        ls_nlri_prefix->origin_nlri_buf.value = NULL;
    }
    
    if (ls_nlri_prefix->prefix_attr.origin_buf.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix_attr.origin_buf.value);
        ls_nlri_prefix->prefix_attr.origin_buf.value = NULL;
    }

    if (ls_nlri_prefix->prefix.mt_ID.IDs)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix.mt_ID.IDs);
        ls_nlri_prefix->prefix.mt_ID.IDs = NULL;
    }

    if (ls_nlri_prefix->prefix_attr.igp_route_tag.Tags)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix_attr.igp_route_tag.Tags);
        ls_nlri_prefix->prefix_attr.igp_route_tag.Tags = NULL;
    }
    
    if (ls_nlri_prefix->prefix_attr.igp_extended_route_tag.Tags)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix_attr.igp_extended_route_tag.Tags);
        ls_nlri_prefix->prefix_attr.igp_extended_route_tag.Tags = NULL;
    }
    
    if (ls_nlri_prefix->prefix_attr.igp_extended_route_tag.Tags)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix_attr.igp_extended_route_tag.Tags);
        ls_nlri_prefix->prefix_attr.igp_extended_route_tag.Tags = NULL;
    }
    if (ls_nlri_prefix->prefix_attr.opaque_prefix_attribute.Data)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix_attr.opaque_prefix_attribute.Data);
        ls_nlri_prefix->prefix_attr.opaque_prefix_attribute.Data = NULL;
    }
    if (ls_nlri_prefix->prefix_attr.prefix_SID.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix_attr.prefix_SID.value);
        ls_nlri_prefix->prefix_attr.prefix_SID.value = NULL;
    }
    if (ls_nlri_prefix->prefix_attr.range.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix_attr.range.value);
        ls_nlri_prefix->prefix_attr.range.value = NULL;
    }
    if (ls_nlri_prefix->prefix_attr.attr_flags.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix_attr.attr_flags.value);
        ls_nlri_prefix->prefix_attr.attr_flags.value = NULL;
    }

    return;
}

void bgp_ls_free_nlri_sr6_sid(NLRI_SR6_SID *ls_nlri_sr6_sid)
{        
    if (ls_nlri_sr6_sid->origin_nlri_buf.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_sr6_sid->origin_nlri_buf.value);
        ls_nlri_sr6_sid->origin_nlri_buf.value = NULL;
    }
    
    if (ls_nlri_sr6_sid->sr6_sid_attr.origin_buf.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_sr6_sid->sr6_sid_attr.origin_buf.value);
        ls_nlri_sr6_sid->sr6_sid_attr.origin_buf.value = NULL;
    }

    return;
}


void bgp_ls_free_nlri_te_policy(NLRI_TE_POLICY *ls_nlri_te_policy)
{        
    if (ls_nlri_te_policy && ls_nlri_te_policy->origin_nlri_buf.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_nlri_te_policy->origin_nlri_buf.value);
        ls_nlri_te_policy->origin_nlri_buf.value = NULL;
    }

    return;
}

static void sid_list_free_attr(te_policy_attr_sid_list *sid_list)
{
    te_policy_attr_sid_list *tmp = sid_list;
    struct te_policy_attr_segment *prev;
	te_policy_attr_sid_list *prev_sid_node;
	struct te_policy_attr_segment *seg;
    while (tmp) {
        seg = tmp->head;
	    while(seg) {
		    prev = seg;
		    seg = seg->next;
		    XFREE(MTYPE_BGPLS_DECODE, prev);
	    }
	    tmp->head = NULL;
	    tmp->tail = NULL;
		prev_sid_node = tmp;
		tmp = tmp->next;
		XFREE(MTYPE_BGPLS_DECODE, prev_sid_node);
    }
	return;
}

void bgp_ls_free_attr(BGP_LS_ATTR *ls_attr)
{

    if (ls_attr->str)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->str);
        ls_attr->str = NULL;
    }
    
    if (ls_attr->origin_buf.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->origin_buf.value);
        ls_attr->origin_buf.value = NULL;
    }

	if (ls_attr->attrs_node.origin_buf.value)
	{
		XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_node.origin_buf.value);
		ls_attr->attrs_node.origin_buf.value = NULL;
	}

    if (ls_attr->attrs_node.mt_ID.IDs)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_node.mt_ID.IDs);
        ls_attr->attrs_node.mt_ID.IDs = NULL;
    }
    
    if (ls_attr->attrs_node.opaque_node_attr.Data)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_node.opaque_node_attr.Data);
        ls_attr->attrs_node.opaque_node_attr.Data = NULL;
    }
    if (ls_attr->attrs_node.node_name.Name)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_node.node_name.Name);
        ls_attr->attrs_node.node_name.Name = NULL;
    }
    if (ls_attr->attrs_node.IsIs_area_ID.AreaID)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_node.IsIs_area_ID.AreaID);
        ls_attr->attrs_node.IsIs_area_ID.AreaID = NULL;
    }
    if (ls_attr->attrs_node.SR_algo.Algos)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_node.SR_algo.Algos);
        ls_attr->attrs_node.SR_algo.Algos = NULL;
    }

	if (ls_attr->attrs_link.origin_buf.value)
	{
		XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_link.origin_buf.value);
		ls_attr->attrs_link.origin_buf.value = NULL;
	}
	if (ls_attr->attrs_link.sr6_end_sid.sub_tlv)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_link.sr6_end_sid.sub_tlv);
        ls_attr->attrs_link.sr6_end_sid.sub_tlv = NULL;
    }
	if (ls_attr->attrs_link.isis_sr6_lan_end_sid.sub_tlv)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_link.isis_sr6_lan_end_sid.sub_tlv);
        ls_attr->attrs_link.isis_sr6_lan_end_sid.sub_tlv = NULL;
    }
	if (ls_attr->attrs_link.ospf3_sr6_lan_end_sid.sub_tlv)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_link.ospf3_sr6_lan_end_sid.sub_tlv);
        ls_attr->attrs_link.ospf3_sr6_lan_end_sid.sub_tlv = NULL;
    }

    if (ls_attr->attrs_link.shared_risk_link_group.Groups)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_link.shared_risk_link_group.Groups);
        ls_attr->attrs_link.shared_risk_link_group.Groups = NULL;
    }

    if (ls_attr->attrs_link.opaque_link_attr.Data)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_link.opaque_link_attr.Data);
        ls_attr->attrs_link.opaque_link_attr.Data = NULL;
    }
    if (ls_attr->attrs_link.link_name.Name)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_link.link_name.Name);
        ls_attr->attrs_link.link_name.Name = NULL;
    }
    if (ls_attr->attrs_link.adj_SID.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_link.adj_SID.value);
        ls_attr->attrs_link.adj_SID.value = NULL;
    }
    if (ls_attr->attrs_link.lan_adj_SID.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_link.lan_adj_SID.value);
        ls_attr->attrs_link.lan_adj_SID.value = NULL;
    }
    if (ls_attr->attrs_link.peer_node_SID.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_link.peer_node_SID.value);
        ls_attr->attrs_link.peer_node_SID.value = NULL;
    }
    if (ls_attr->attrs_link.peer_adj_SID.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_link.peer_adj_SID.value);
        ls_attr->attrs_link.peer_adj_SID.value = NULL;
    }
    if (ls_attr->attrs_link.peer_set_SID.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_link.peer_set_SID.value);
        ls_attr->attrs_link.peer_set_SID.value = NULL;
    }
    if (ls_attr->attrs_link.l2_bundle_member.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_link.l2_bundle_member.value);
        ls_attr->attrs_link.l2_bundle_member.value = NULL;
    }


	if (ls_attr->attrs_prefix.origin_buf.value)
	{
		XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_prefix.origin_buf.value);
		ls_attr->attrs_prefix.origin_buf.value = NULL;
	}
	if (ls_attr->attrs_prefix.range.prefix_subTLVs)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_prefix.range.prefix_subTLVs);
        ls_attr->attrs_prefix.range.prefix_subTLVs = NULL;
    }

	if (ls_attr->attrs_prefix.attr_flags.Flags)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_prefix.attr_flags.Flags);
        ls_attr->attrs_prefix.attr_flags.Flags = NULL;
    }

	if (ls_attr->attrs_sr6_sid.origin_buf.value)
	{
		XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_sr6_sid.origin_buf.value);
		ls_attr->attrs_sr6_sid.origin_buf.value = NULL;
	}

    if (ls_attr->attrs_prefix.igp_route_tag.Tags)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_prefix.igp_route_tag.Tags);
        ls_attr->attrs_prefix.igp_route_tag.Tags = NULL;
    }
    
    if (ls_attr->attrs_prefix.igp_extended_route_tag.Tags)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_prefix.igp_extended_route_tag.Tags);
        ls_attr->attrs_prefix.igp_extended_route_tag.Tags = NULL;
    }
    
    if (ls_attr->attrs_prefix.igp_extended_route_tag.Tags)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_prefix.igp_extended_route_tag.Tags);
        ls_attr->attrs_prefix.igp_extended_route_tag.Tags = NULL;
    }
    if (ls_attr->attrs_prefix.opaque_prefix_attribute.Data)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_prefix.opaque_prefix_attribute.Data);
        ls_attr->attrs_prefix.opaque_prefix_attribute.Data = NULL;
    }
    if (ls_attr->attrs_prefix.prefix_SID.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_prefix.prefix_SID.value);
        ls_attr->attrs_prefix.prefix_SID.value = NULL;
    }
    if (ls_attr->attrs_prefix.range.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_prefix.range.value);
        ls_attr->attrs_prefix.range.value = NULL;
    }
    if (ls_attr->attrs_prefix.attr_flags.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_prefix.attr_flags.value);
        ls_attr->attrs_prefix.attr_flags.value = NULL;
    }

	if (ls_attr->attrs_te_policy.origin_buf.value)
    {
        XFREE(MTYPE_BGPLS_DECODE, ls_attr->attrs_te_policy.origin_buf.value);
        ls_attr->attrs_te_policy.origin_buf.value = NULL;
    }

	if (ls_attr->attrs_te_policy.sid_list && ls_attr->attrs_te_policy.sid_list->head)
    {
        sid_list_free_attr(ls_attr->attrs_te_policy.sid_list);
    }

    return;
}


void bgp_ls_dup_nlri_node(NLRI_NODE *ls_nlri_node, NLRI_NODE *ls_nlri_node_new)
{        
    memcpy(ls_nlri_node_new , ls_nlri_node, sizeof(NLRI_NODE));
    
    if (ls_nlri_node->origin_nlri_buf.value)
    {
        ls_nlri_node_new->origin_nlri_buf.value = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_node->origin_nlri_buf.length);
        memcpy(ls_nlri_node_new->origin_nlri_buf.value, ls_nlri_node->origin_nlri_buf.value, ls_nlri_node->origin_nlri_buf.length);
    }
    
    if (ls_nlri_node->node_attr.origin_buf.value)
    {
        ls_nlri_node_new->node_attr.origin_buf.value = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_node->node_attr.origin_buf.length);
        memcpy(ls_nlri_node_new->node_attr.origin_buf.value, ls_nlri_node->node_attr.origin_buf.value, ls_nlri_node->node_attr.origin_buf.length);
    }

    if (ls_nlri_node->node_attr.mt_ID.IDs)
    {
        ls_nlri_node_new->node_attr.mt_ID.IDs = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_node->node_attr.mt_ID.length);
        memcpy(ls_nlri_node_new->node_attr.mt_ID.IDs, ls_nlri_node->node_attr.mt_ID.IDs, ls_nlri_node->node_attr.mt_ID.length);
    }
    
    if (ls_nlri_node->node_attr.opaque_node_attr.Data)
    {
        ls_nlri_node_new->node_attr.opaque_node_attr.Data = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_node->node_attr.opaque_node_attr.length);
        memcpy(ls_nlri_node_new->node_attr.opaque_node_attr.Data, ls_nlri_node->node_attr.opaque_node_attr.Data, ls_nlri_node->node_attr.opaque_node_attr.length);
    }
    if (ls_nlri_node->node_attr.node_name.Name)
    {
        ls_nlri_node_new->node_attr.node_name.Name = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_node->node_attr.node_name.length);
        memcpy(ls_nlri_node_new->node_attr.node_name.Name, ls_nlri_node->node_attr.node_name.Name, ls_nlri_node->node_attr.node_name.length);
    }
    if (ls_nlri_node->node_attr.IsIs_area_ID.AreaID)
    {
        ls_nlri_node_new->node_attr.IsIs_area_ID.AreaID = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_node->node_attr.IsIs_area_ID.length);
        memcpy(ls_nlri_node_new->node_attr.IsIs_area_ID.AreaID, ls_nlri_node->node_attr.IsIs_area_ID.AreaID, ls_nlri_node->node_attr.IsIs_area_ID.length);
    }
    if (ls_nlri_node->node_attr.SR_algo.Algos)
    {
        ls_nlri_node_new->node_attr.SR_algo.Algos = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_node->node_attr.SR_algo.length);
        memcpy(ls_nlri_node_new->node_attr.SR_algo.Algos, ls_nlri_node->node_attr.SR_algo.Algos, ls_nlri_node->node_attr.SR_algo.length);
    }

    return;
}


void bgp_ls_dup_nlri_link(NLRI_LINK *ls_nlri_link, NLRI_LINK *ls_nlri_link_new)
{   
    memcpy(ls_nlri_link_new , ls_nlri_link, sizeof(NLRI_LINK));

     if (ls_nlri_link->origin_nlri_buf.value)
    {
        ls_nlri_link_new->origin_nlri_buf.value = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_link->origin_nlri_buf.length);
        memcpy(ls_nlri_link_new->origin_nlri_buf.value, ls_nlri_link->origin_nlri_buf.value, ls_nlri_link->origin_nlri_buf.length);
    }
     
    if (ls_nlri_link->link_attr.origin_buf.value)
    {
        ls_nlri_link_new->link_attr.origin_buf.value = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.origin_buf.length);
        memcpy(ls_nlri_link_new->link_attr.origin_buf.value , ls_nlri_link->link_attr.origin_buf.value, ls_nlri_link->link_attr.origin_buf.length);
    }

    if (ls_nlri_link->link.mt_ID.IDs)
    {
        ls_nlri_link_new->link.mt_ID.IDs = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_link->link.mt_ID.length);
        memcpy(ls_nlri_link_new->link.mt_ID.IDs, ls_nlri_link->link.mt_ID.IDs, ls_nlri_link->link.mt_ID.length);
    }
   
    if (ls_nlri_link->link_attr.shared_risk_link_group.Groups)
    {
        ls_nlri_link_new->link_attr.shared_risk_link_group.Groups = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.shared_risk_link_group.length);
        memcpy(ls_nlri_link_new->link_attr.shared_risk_link_group.Groups, ls_nlri_link->link_attr.shared_risk_link_group.Groups, ls_nlri_link->link_attr.shared_risk_link_group.length);
    }

    if (ls_nlri_link->link_attr.opaque_link_attr.Data)
    {
        ls_nlri_link_new->link_attr.opaque_link_attr.Data = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.opaque_link_attr.length);
        memcpy(ls_nlri_link_new->link_attr.opaque_link_attr.Data, ls_nlri_link->link_attr.opaque_link_attr.Data, ls_nlri_link->link_attr.opaque_link_attr.length);
    }
    if (ls_nlri_link->link_attr.link_name.Name)
    {
        ls_nlri_link_new->link_attr.link_name.Name = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.link_name.length);
        memcpy(ls_nlri_link_new->link_attr.link_name.Name, ls_nlri_link->link_attr.link_name.Name, ls_nlri_link->link_attr.link_name.length);
    }
    if (ls_nlri_link->link_attr.adj_SID.value)
    {
        ls_nlri_link_new->link_attr.adj_SID.value = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.adj_SID.length);
        memcpy(ls_nlri_link_new->link_attr.adj_SID.value, ls_nlri_link->link_attr.adj_SID.value, ls_nlri_link->link_attr.adj_SID.length);
    }
    if (ls_nlri_link->link_attr.lan_adj_SID.value)
    {
        ls_nlri_link_new->link_attr.lan_adj_SID.value = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.lan_adj_SID.length);
        memcpy(ls_nlri_link_new->link_attr.lan_adj_SID.value, ls_nlri_link->link_attr.lan_adj_SID.value, ls_nlri_link->link_attr.lan_adj_SID.length);
    }
    if (ls_nlri_link->link_attr.peer_node_SID.value)
    {
        ls_nlri_link_new->link_attr.peer_node_SID.value = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.peer_node_SID.length);
        memcpy(ls_nlri_link_new->link_attr.peer_node_SID.value, ls_nlri_link->link_attr.peer_node_SID.value, ls_nlri_link->link_attr.peer_node_SID.length);
    }
    if (ls_nlri_link->link_attr.peer_adj_SID.value)
    {
        ls_nlri_link_new->link_attr.peer_adj_SID.value = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.peer_adj_SID.length);
        memcpy(ls_nlri_link_new->link_attr.peer_adj_SID.value, ls_nlri_link->link_attr.peer_adj_SID.value, ls_nlri_link->link_attr.peer_adj_SID.length);
    }
    if (ls_nlri_link->link_attr.peer_set_SID.value)
    {
        ls_nlri_link_new->link_attr.peer_set_SID.value = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.peer_set_SID.length);
        memcpy(ls_nlri_link_new->link_attr.peer_set_SID.value, ls_nlri_link->link_attr.peer_set_SID.value, ls_nlri_link->link_attr.peer_set_SID.length);
    }
    if (ls_nlri_link->link_attr.l2_bundle_member.value)
    {
        ls_nlri_link_new->link_attr.l2_bundle_member.value = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_link->link_attr.l2_bundle_member.length);
        memcpy(ls_nlri_link_new->link_attr.l2_bundle_member.value, ls_nlri_link->link_attr.l2_bundle_member.value, ls_nlri_link->link_attr.l2_bundle_member.length);
    }
   
    return;
}


void bgp_ls_dup_nlri_prefix(NLRI_PREFIX *ls_nlri_prefix,NLRI_PREFIX *ls_nlri_prefix_new)
{
    memcpy(ls_nlri_prefix_new , ls_nlri_prefix, sizeof(NLRI_PREFIX));
    
    if (ls_nlri_prefix->origin_nlri_buf.value)
    {
        ls_nlri_prefix_new->origin_nlri_buf.value = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_prefix->origin_nlri_buf.length);
        memcpy(ls_nlri_prefix_new->origin_nlri_buf.value, ls_nlri_prefix->origin_nlri_buf.value, ls_nlri_prefix->origin_nlri_buf.length);
    }
    
    if (ls_nlri_prefix->prefix_attr.origin_buf.value)
    {
        ls_nlri_prefix_new->prefix_attr.origin_buf.value = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix_attr.origin_buf.length);
        memcpy(ls_nlri_prefix_new->prefix_attr.origin_buf.value, ls_nlri_prefix->prefix_attr.origin_buf.value, ls_nlri_prefix->prefix_attr.origin_buf.length);
    }

    if (ls_nlri_prefix->prefix.mt_ID.IDs)
    {
        ls_nlri_prefix_new->prefix.mt_ID.IDs = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix.mt_ID.length);
        memcpy(ls_nlri_prefix_new->prefix.mt_ID.IDs, ls_nlri_prefix->prefix.mt_ID.IDs, ls_nlri_prefix->prefix.mt_ID.length);
    }

    if (ls_nlri_prefix->prefix_attr.igp_route_tag.Tags)
    {
        ls_nlri_prefix_new->prefix_attr.igp_route_tag.Tags = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix_attr.igp_route_tag.length);
        memcpy(ls_nlri_prefix_new->prefix_attr.igp_route_tag.Tags, ls_nlri_prefix->prefix_attr.igp_route_tag.Tags, ls_nlri_prefix->prefix_attr.igp_route_tag.length);
    }
    
    if (ls_nlri_prefix->prefix_attr.igp_extended_route_tag.Tags)
    {
        ls_nlri_prefix_new->prefix_attr.igp_extended_route_tag.Tags = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix_attr.igp_extended_route_tag.length);
        memcpy(ls_nlri_prefix_new->prefix_attr.igp_extended_route_tag.Tags, ls_nlri_prefix->prefix_attr.igp_extended_route_tag.Tags, ls_nlri_prefix->prefix_attr.igp_extended_route_tag.length);
    }
    
    if (ls_nlri_prefix->prefix_attr.igp_extended_route_tag.Tags)
    {
        ls_nlri_prefix_new->prefix_attr.igp_extended_route_tag.Tags = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix_attr.igp_extended_route_tag.length);
        memcpy(ls_nlri_prefix_new->prefix_attr.igp_extended_route_tag.Tags, ls_nlri_prefix->prefix_attr.igp_extended_route_tag.Tags, ls_nlri_prefix->prefix_attr.igp_extended_route_tag.length);
    }
    if (ls_nlri_prefix->prefix_attr.opaque_prefix_attribute.Data)
    {
        ls_nlri_prefix_new->prefix_attr.opaque_prefix_attribute.Data = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix_attr.opaque_prefix_attribute.length);
        memcpy(ls_nlri_prefix_new->prefix_attr.opaque_prefix_attribute.Data, ls_nlri_prefix->prefix_attr.opaque_prefix_attribute.Data, ls_nlri_prefix->prefix_attr.opaque_prefix_attribute.length);
    }
    if (ls_nlri_prefix->prefix_attr.prefix_SID.value)
    {
        ls_nlri_prefix_new->prefix_attr.prefix_SID.value = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix_attr.prefix_SID.length);
        memcpy(ls_nlri_prefix_new->prefix_attr.prefix_SID.value, ls_nlri_prefix->prefix_attr.prefix_SID.value, ls_nlri_prefix->prefix_attr.prefix_SID.length);
    }
    if (ls_nlri_prefix->prefix_attr.range.value)
    {
        ls_nlri_prefix_new->prefix_attr.range.value = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix_attr.range.length);
        memcpy(ls_nlri_prefix_new->prefix_attr.range.value, ls_nlri_prefix->prefix_attr.range.value, ls_nlri_prefix->prefix_attr.range.length);
    }
    if (ls_nlri_prefix->prefix_attr.attr_flags.value)
    {
        ls_nlri_prefix_new->prefix_attr.attr_flags.value = XCALLOC(MTYPE_BGPLS_DECODE, ls_nlri_prefix->prefix_attr.attr_flags.length);
        memcpy(ls_nlri_prefix_new->prefix_attr.attr_flags.value, ls_nlri_prefix->prefix_attr.attr_flags.value, ls_nlri_prefix->prefix_attr.attr_flags.length);
    }

    return;
}



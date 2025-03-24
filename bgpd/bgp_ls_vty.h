/***************************************************************************
*
* This is an implementation of BGP Link State as per RFC 7752
* Copyright (C) 2020 CTBRI
*
 ***************************************************************************/


#ifndef _FRR_BGP_LS_VTY_H
#define _FRR_BGP_LS_VTY_H

/*NLRI Type */
typedef enum bgp_ls_vty_enum{
    BGP_LS_VTY_ALL = 0,
	BGP_LS_VTY_NLRI_TE_POLICY = 3,
    BGP_LS_VTY_NLRI_NODE = 4,
    BGP_LS_VTY_NLRI_LINK = 5,
    BGP_LS_VTY_NLRI_IP4_PREFIX = 6,
    BGP_LS_VTY_NLRI_IP6_PREFIX = 7,
} BGP_LS_VTY_ENUM;

struct bgp_ls_attr;
extern int bgp_ls_show_neighbor(struct vty *vty, struct peer *peer, afi_t afi, safi_t safi,
		    enum bgp_show_type type, enum bgp_ls_vty_enum subtype, int32_t use_json);
/*extern int bgp_ls_show_local(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
            enum bgp_show_type type, enum bgp_ls_vty_enum subtype, int32_t use_json);*/
extern char *bgp_ls_attr_str(struct bgp_ls_attr *ls_attr);

#define BGPLS_DEBUG(fmt, ...) if (BGP_DEBUG(link_state,BGPLS)) { zlog_debug(fmt, ##__VA_ARGS__);}

#endif /* _FRR_BGP_LS_VTY_H */

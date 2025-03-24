/***************************************************************************
*
* This is an implementation of BGP Link State as per RFC 7752
* Copyright (C) 2020 CTBRI
*
 ***************************************************************************/
 

 #ifndef _FRR_BGP_LS_H
 #define _FRR_BGP_LS_H
 
 #include "bgp_ls_pub.h"
 
 typedef  struct bgp_attr_parser_args BGP_ATTR_PARSER_ARGS;
 
 #define ATTR_PACKET_NODE                        (1 << 0) /* send update packet nlri node */
 #define ATTR_PACKET_LINK                        (1 << 1)  /* send update packet nlri link */
 #define ATTR_PACKET_PREFIX_IP4                  (1 << 2) /* send update packet nlri prefix ipv4 */
 #define ATTR_PACKET_PREFIX_IP6                  (1 << 3)  /* send update packet nlri prefix ipv6 */
 #define PEER_ATTR_PACKET_NODE                   (1 << 4) /* send update packet nlri node */
 #define PEER_ATTR_PACKET_LINK                   (1 << 5)  /* send update packet nlri link */
 #define PEER_ATTR_PACKET_PREFIX_IP4             (1 << 6) /* send update packet nlri prefix ipv4 */
 #define PEER_ATTR_PACKET_PREFIX_IP6             (1 << 7)  /* send update packet nlri prefix ipv6 */
 
 #define LSDB_PEER_UPDATE_TE_POLICY              (1 << 15) /* send update packet nlri te policy */
 #define LSDB_PEER_UPDATE_NODE                   (1 << 16) /* send update packet nlri node */
 #define LSDB_PEER_UPDATE_LINK                   (1 << 17)  /* send update packet nlri link */
 #define LSDB_PEER_UPDATE_PREFIX_IP4             (1 << 18) /* send update packet nlri prefix ipv4 */
 #define LSDB_PEER_UPDATE_PREFIX_IP6             (1 << 19)  /* send update packet nlri prefix ipv6 */
 #define LSDB_PEER_UPDATE_NODE_WITHDRAW          (1 << 20) /* send update packet nlri node */
 #define LSDB_PEER_UPDATE_LINK_WITHDRAW          (1 << 21)  /* send update packet nlri link */
 #define LSDB_PEER_UPDATE_PREFIX_IP4_WITHDRAW    (1 << 22) /* send update packet nlri prefix ipv4 */
 #define LSDB_PEER_UPDATE_PREFIX_IP6_WITHDRAW    (1 << 23)  /* send update packet nlri prefix ipv6 */
 
 #define LSDB_PEER_UPDATE_ALL                    (1 << 27)  /* send update packet all nlri  */
 #define LSDB_SYNC                               (1 << 28) /* ls client sync link state data*/
 
 #define LSDB_PEER_UPDATE_SR6_SID             (1 << 29)  /* send update packet nlri srv6 sid */
 #define LSDB_PEER_UPDATE_SR6_SID_WITHDRAW          (1 << 30) /* send withdrawn packet nlri srv6 sid */
 
 /*****************************************************************************/
 extern void bgp_lsdb_init(struct bgp *bgp);
 extern void bgp_lsdb_exit(struct bgp *bgp);
 extern void bgp_ls_free_attr_all(BGP_LS_ATTR *ls_attr);
 
 extern void bgp_peer_lsdb_init(struct peer *peer);
 extern void bgp_peer_lsdb_clean(struct peer *peer);
 extern void bgp_peer_lsdb_delete(struct peer *peer);
 extern enum bgp_attr_parse_ret bgp_ls_attr_deserialize(struct bgp_attr_parser_args *args);
 extern int32_t bgp_nlri_parse_linkstate(struct peer *peer, struct attr *attr,
             struct bgp_nlri *packet, int32_t withdraw);
 extern void bgp_ls_db_list_update_add(BGP_LS_DB *lsdb, uint32_t *lsdb_flags,
                     void *ls_nlri, uint16_t nlri_type, uint32_t *actFlag);
 
 
 #endif /* _FRR_BGP_LS_H */
 
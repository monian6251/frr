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
 #include "bgp_ls_pub.h"
 
 #include "bgpd/bgpd.h"
 #include "bgpd/bgp_aspath.h"
 #include "bgpd/bgp_table.h"
 #include "bgpd/bgp_route.h"
 #include "bgpd/bgp_attr.h"
 #include "bgpd/bgp_debug.h"
 #include "bgpd/bgp_errors.h"
 #include "bgpd/bgp_zebra.h"
 #include "bgpd/bgp_packet.h"
 #include "bgpd/bgp_updgrp.h"
 #include "bgpd/bgp_vty.h"
 //#include "bgpd/api/bgp_apiserver.h"
 #include "bgpd/bgp_ls.h"
 #include "bgpd/bgp_ls_vty.h"
 #include "srv6.h"
 #include "time.h"
 
 
 /* Definitions and external declarations. */
 
 extern const char *bgp_ls_isis_id_fmt(const uint8_t *id);
 
 DEFINE_MTYPE_STATIC(BGPD, BGPLS_NLRI, "bgp ls nlri");
 
 static bool_t bgp_ls_tlv_cmp(BGP_LS_TLV *origin_buf_new,BGP_LS_TLV *origin_buf_old)
 {
 
     if ((origin_buf_new->length != origin_buf_old->length)
           || (memcmp(origin_buf_new->value,origin_buf_old->value, origin_buf_old->length)))
     {
         return true;
     }
     else
     {
         return false;
     }
 
 }
 
 static NLRI_NODE *bgp_ls_lookup_nlri_node(NLRI_NODE *ls_node, struct list *list_node)
 {
     NLRI_NODE *ls_nlri_node = NULL;
     struct listnode *node, *nnode;
 
     for (ALL_LIST_ELEMENTS(list_node, node, nnode, ls_nlri_node))
     {
         if ((ls_node->origin_nlri_buf.length == ls_nlri_node->origin_nlri_buf.length)
              &&(0 == memcmp(ls_node->origin_nlri_buf.value,ls_nlri_node->origin_nlri_buf.value, ls_node->origin_nlri_buf.length)))
         {
             return ls_nlri_node;
         }
     }
 
     return NULL;
 }
 
 static NLRI_LINK *bgp_ls_lookup_nlri_link(NLRI_LINK *ls_link, struct list *list_link)
 {
     NLRI_LINK *ls_nlri_link = NULL;
     struct listnode *node, *nnode;
 
     for (ALL_LIST_ELEMENTS(list_link, node, nnode, ls_nlri_link))
     {
         if ((ls_link->origin_nlri_buf.length == ls_nlri_link->origin_nlri_buf.length)
              &&(0 == memcmp(ls_link->origin_nlri_buf.value,ls_nlri_link->origin_nlri_buf.value, ls_link->origin_nlri_buf.length)))
         {
             return ls_nlri_link;
         }
     }
 
     return NULL;
 }
 
 static NLRI_PREFIX *bgp_ls_lookup_nlri_prefix(NLRI_PREFIX *ls_prefix, struct list *list_prefix)
 {
     NLRI_PREFIX *ls_nlri_prefix = NULL;
     struct listnode *node, *nnode;
 
     for (ALL_LIST_ELEMENTS(list_prefix, node, nnode, ls_nlri_prefix))
     {
         if ((ls_prefix->origin_nlri_buf.length == ls_nlri_prefix->origin_nlri_buf.length)
              &&(0 == memcmp(ls_prefix->origin_nlri_buf.value,ls_nlri_prefix->origin_nlri_buf.value, ls_prefix->origin_nlri_buf.length)))
         {
             return ls_nlri_prefix;
         }
     }
 
     return NULL;
 }
 
 static NLRI_SR6_SID *bgp_ls_lookup_nlri_sr6_sid(NLRI_SR6_SID *ls_sr6, struct list *list_node)
 {
     NLRI_SR6_SID *ls_nlri_sr6 = NULL;
     struct listnode *node, *nnode;
 
     for (ALL_LIST_ELEMENTS(list_node, node, nnode, ls_nlri_sr6))
     {
         if ((ls_sr6->origin_nlri_buf.length == ls_nlri_sr6->origin_nlri_buf.length)
              &&(0 == memcmp(ls_sr6->origin_nlri_buf.value,ls_nlri_sr6->origin_nlri_buf.value, ls_sr6->origin_nlri_buf.length)))
         {
             return ls_nlri_sr6;
         }
     }
 
     return NULL;
 }
 
 static NLRI_TE_POLICY *bgp_ls_lookup_nlri_te_policy(NLRI_TE_POLICY *ls_te_policy, struct list *list_te_policy)
 {
     NLRI_TE_POLICY *ls_nlri_te_policy = NULL;
     struct listnode *node, *nnode;
 
     for (ALL_LIST_ELEMENTS(list_te_policy, node, nnode, ls_nlri_te_policy))
     {
         if ((ls_te_policy->origin_nlri_buf.length == ls_nlri_te_policy->origin_nlri_buf.length)
              &&(0 == memcmp(ls_te_policy->origin_nlri_buf.value,ls_nlri_te_policy->origin_nlri_buf.value, ls_te_policy->origin_nlri_buf.length)))
         {
             return ls_nlri_te_policy;
         }
     }
 
     return NULL;
 }
 
 
 
 static void bgp_ls_add_attr_list(BGP_LS_TLV *origin_buf, struct list *list_attr)
 {
 
     BGP_LS_ATTR *ls_attr = NULL;
     struct listnode *node, *nnode;
 
     for (ALL_LIST_ELEMENTS(list_attr, node, nnode, ls_attr))
     {
         if ((origin_buf->length == ls_attr->origin_buf.length)
              &&(0 == memcmp(origin_buf->value,ls_attr->origin_buf.value, ls_attr->origin_buf.length)))
         {
             ls_attr->refcnt++;
             ls_attr->ntt++;
             return;
         }
     }
 
     ls_attr = XCALLOC(MTYPE_BGPLS_NLRI, sizeof(BGP_LS_ATTR));
     memset(ls_attr, 0, sizeof(BGP_LS_ATTR));
     bgp_ls_origin_buf_alloc(&ls_attr->origin_buf,origin_buf->value,origin_buf->type,origin_buf->length);
     listnode_add(list_attr, ls_attr);
     ls_attr->refcnt = 1;
     ls_attr->ntt = 1; 
     return;
 }
 
 static void bgp_ls_del_attr_list(BGP_LS_TLV *origin_buf, struct list *list_attr)
 {
 
     BGP_LS_ATTR *ls_attr = NULL;
     struct listnode *node, *nnode;
 
     for (ALL_LIST_ELEMENTS(list_attr, node, nnode, ls_attr))
     {
         if ((origin_buf->length == ls_attr->origin_buf.length)
              &&(0 == memcmp(origin_buf->value,ls_attr->origin_buf.value, ls_attr->origin_buf.length)))
         {
             if (ls_attr->refcnt <= 1)
             {
                 listnode_delete(list_attr, ls_attr);
                 bgp_ls_free_attr(ls_attr);
                 XFREE(MTYPE_BGPLS_NLRI, ls_attr);
                 return;
             }
             ls_attr->refcnt--;
         }
     }
 
     return ;
 }
 
 /*Clear all data under the node list*/
 static void bgp_ls_free_attr_list(struct list *list_attr)
 {
     BGP_LS_ATTR *ls_attr = NULL;
     struct listnode *node, *nnode;
 
     for (ALL_LIST_ELEMENTS(list_attr, node, nnode, ls_attr))
     {
         listnode_delete(list_attr, ls_attr);
         bgp_ls_free_attr(ls_attr);
         XFREE(MTYPE_BGPLS_NLRI, ls_attr);
     }
     return;
 }
 
 static void bgp_ls_free_nlri_sr6_sid_list(struct list *list_prefix)
 {
     NLRI_SR6_SID *ls_nlri_prefix = NULL;
     struct listnode *node, *nnode;
 
     for (ALL_LIST_ELEMENTS(list_prefix, node, nnode, ls_nlri_prefix))
     {
         listnode_delete(list_prefix, ls_nlri_prefix);
         bgp_ls_free_nlri_sr6_sid(ls_nlri_prefix);
         XFREE(MTYPE_BGPLS_NLRI, ls_nlri_prefix);
     }
     return;
 }
 
 
 static void bgp_ls_free_nlri_prefix_list(struct list *list_prefix)
 {
     NLRI_PREFIX *ls_nlri_prefix = NULL;
     struct listnode *node, *nnode;
 
     for (ALL_LIST_ELEMENTS(list_prefix, node, nnode, ls_nlri_prefix))
     {
         listnode_delete(list_prefix, ls_nlri_prefix);
         bgp_ls_free_nlri_prefix(ls_nlri_prefix);
         XFREE(MTYPE_BGPLS_NLRI, ls_nlri_prefix);
     }
     return;
 }
 static void bgp_ls_free_nlri_link_list(struct list *list_link)
 {
 
     NLRI_LINK *ls_nlri_link = NULL;
     struct listnode *node, *nnode;
 
     for (ALL_LIST_ELEMENTS(list_link, node, nnode, ls_nlri_link))
     {
         listnode_delete(list_link, ls_nlri_link);
         bgp_ls_free_nlri_link(ls_nlri_link);
         XFREE(MTYPE_BGPLS_NLRI, ls_nlri_link);
     }
     return;
 }
 
 static void bgp_ls_free_nlri_te_policy_list(struct list *list_te_policy)
 {
 
     NLRI_TE_POLICY *ls_nlri_te_policy = NULL;
     struct listnode *node, *nnode;
 
     for (ALL_LIST_ELEMENTS(list_te_policy, node, nnode, ls_nlri_te_policy))
     {
         listnode_delete(list_te_policy, ls_nlri_te_policy);
         bgp_ls_free_nlri_te_policy(ls_nlri_te_policy);
         XFREE(MTYPE_BGPLS_NLRI, ls_nlri_te_policy);
     }
     return;
 }
 
 static void bgp_ls_free_nlri_node_list(struct list *list_node)
 {
 
     NLRI_NODE *ls_nlri_node = NULL;
     struct listnode *node, *nnode;
 
     for (ALL_LIST_ELEMENTS(list_node, node, nnode, ls_nlri_node))
     {
         listnode_delete(list_node, ls_nlri_node);
         bgp_ls_free_nlri_node(ls_nlri_node);
         XFREE(MTYPE_BGPLS_NLRI, ls_nlri_node);
     }
     return;
 }
 
 void bgp_ls_db_list_update_add(BGP_LS_DB *lsdb, uint32_t *lsdb_flags,
                     void *ls_nlri, uint16_t nlri_type, uint32_t *actFlag)
 {
     struct list *insert_list_attr = NULL;
     struct list *insert_list_head = NULL;
     struct list *remove_list_head = NULL;
     NLRI_NODE * nlri_node_old = NULL;
     NLRI_NODE * nlri_node_new = (NLRI_NODE *)ls_nlri;
     NLRI_LINK * nlri_link_old = NULL;
     NLRI_LINK * nlri_link_new = (NLRI_LINK *)ls_nlri;
     NLRI_PREFIX * nlri_prefix_old = NULL;
     NLRI_PREFIX * nlri_prefix_new = (NLRI_PREFIX *)ls_nlri;
     NLRI_SR6_SID * nlri_sr6_sid_old = NULL;
     NLRI_SR6_SID * nlri_sr6_sid_new = (NLRI_SR6_SID *)ls_nlri;
     NLRI_TE_POLICY * nlri_te_policy_old = NULL;
     NLRI_TE_POLICY * nlri_te_policy_new = (NLRI_TE_POLICY *)ls_nlri;
     uint32_t set_lsdb_flags = 0;
 
     switch (nlri_type)
     {
         case BGP_LS_NLRI_TYPE_NODE:
 
             insert_list_head = lsdb->reach_node;
             remove_list_head = lsdb->withdraw_node;
             set_lsdb_flags = LSDB_PEER_UPDATE_NODE;
 
             /*delete corresponding node nlri in withdraw node list*/
             nlri_node_old = bgp_ls_lookup_nlri_node(nlri_node_new,remove_list_head);
             if (NULL != nlri_node_old)
             {
                 bgp_ls_free_nlri_node(nlri_node_old);
                 listnode_delete(remove_list_head, nlri_node_old);
                 XFREE(MTYPE_BGPLS_NLRI, nlri_node_old);
             }
 
             /*add corresponding node nlri in reach node list*/
             nlri_node_old = bgp_ls_lookup_nlri_node(nlri_node_new,insert_list_head);
             if (NULL != nlri_node_old)
             {
                 /*Determine if the attributes are the same*/
                if (bgp_ls_tlv_cmp(&nlri_node_new->node_attr.origin_buf,&nlri_node_old->node_attr.origin_buf))
                {
                     bgp_ls_del_attr_list(&nlri_node_old->node_attr.origin_buf, lsdb->attri_node);
                     bgp_ls_free_nlri_node(nlri_node_old);
                     listnode_delete(insert_list_head, nlri_node_old);
                     XFREE(MTYPE_BGPLS_NLRI, nlri_node_old);
 
                     bgp_ls_add_attr_list(&nlri_node_new->node_attr.origin_buf, lsdb->attri_node);
                     nlri_node_new->ntt = true;
                     listnode_add(insert_list_head, nlri_node_new);
                     SET_FLAG(*lsdb_flags, set_lsdb_flags);
                     *actFlag = 1;
                 }
                 else
                 {
                     bgp_ls_free_nlri_node(nlri_node_new);
                     XFREE(MTYPE_BGPLS_NLRI, nlri_node_new);
                 }
             }
             else
             {
                 bgp_ls_add_attr_list(&nlri_node_new->node_attr.origin_buf, lsdb->attri_node);             
                 nlri_node_new->ntt = true;
                 listnode_add(insert_list_head, nlri_node_new);
                 SET_FLAG(*lsdb_flags, set_lsdb_flags);
             }
 
             break;
         case BGP_LS_NLRI_TYPE_LINK:
 
             insert_list_head = lsdb->reach_link;
             remove_list_head = lsdb->withdraw_link;
             set_lsdb_flags = LSDB_PEER_UPDATE_LINK;
 
             /*delete corresponding node nlri in withdraw node list*/
             nlri_link_old = bgp_ls_lookup_nlri_link(nlri_link_new,remove_list_head);
             if (NULL != nlri_link_old)
             {
                 bgp_ls_free_nlri_link(nlri_link_old);
                 listnode_delete(remove_list_head, nlri_link_old);
                 XFREE(MTYPE_BGPLS_NLRI, nlri_link_old);
             }
 
             /*add corresponding node nlri in reach node list*/
             nlri_link_old = bgp_ls_lookup_nlri_link(nlri_link_new,insert_list_head);
             if (NULL != nlri_link_old)
             {
                 /*Determine if the attributes are the same*/
                if (bgp_ls_tlv_cmp(&nlri_link_old->link_attr.origin_buf,&nlri_link_new->link_attr.origin_buf))
                {
                     bgp_ls_del_attr_list(&nlri_link_old->link_attr.origin_buf, lsdb->attri_link);
                     bgp_ls_free_nlri_link(nlri_link_old);
                     listnode_delete(insert_list_head, nlri_link_old);
                     XFREE(MTYPE_BGPLS_NLRI, nlri_link_old);
 
                     bgp_ls_add_attr_list(&nlri_link_new->link_attr.origin_buf, lsdb->attri_link);
                     nlri_link_new->ntt = true;
                     listnode_add(insert_list_head, nlri_link_new);
                     SET_FLAG(*lsdb_flags, set_lsdb_flags);
                     *actFlag = 1;
                 }
                 else
                 {
                     bgp_ls_free_nlri_link(nlri_link_new);
                     XFREE(MTYPE_BGPLS_NLRI, nlri_link_new);
                 }
             }
             else
             {
                 bgp_ls_add_attr_list(&nlri_link_new->link_attr.origin_buf, lsdb->attri_link);           
                 nlri_link_new->ntt = true;
                 listnode_add(insert_list_head, nlri_link_new);
                 SET_FLAG(*lsdb_flags, set_lsdb_flags);
             }
             break;
         case BGP_LS_NLRI_TYPE_IP4_PREFIX:
         case BGP_LS_NLRI_TYPE_IP6_PREFIX:
 
             if (BGP_LS_NLRI_TYPE_IP4_PREFIX== nlri_type)
             {
                 insert_list_head = lsdb->reach_prefix_ip4;
                 remove_list_head = lsdb->withdraw_prefix_ip4;
                 insert_list_attr = lsdb->attri_prefix_ip4;
                 set_lsdb_flags = LSDB_PEER_UPDATE_PREFIX_IP4;
             }
             else
             {
                 insert_list_head = lsdb->reach_prefix_ip6;
                 remove_list_head = lsdb->withdraw_prefix_ip6;
                 insert_list_attr = lsdb->attri_prefix_ip6;
                 set_lsdb_flags = LSDB_PEER_UPDATE_PREFIX_IP6;
             }
 
             /*delete corresponding node nlri in withdraw node list*/
             nlri_prefix_old = bgp_ls_lookup_nlri_prefix(nlri_prefix_new,remove_list_head);
             if (NULL != nlri_prefix_old)
             {
                 bgp_ls_free_nlri_prefix(nlri_prefix_old);
                 listnode_delete(remove_list_head, nlri_prefix_old);
                 XFREE(MTYPE_BGPLS_NLRI, nlri_prefix_old);
             }
 
             /*add corresponding node nlri in reach node list*/
             nlri_prefix_old = bgp_ls_lookup_nlri_prefix(nlri_prefix_new,insert_list_head);
             if (NULL != nlri_prefix_old)
             {
                 /*Determine if the attributes are the same*/
                if (bgp_ls_tlv_cmp(&nlri_prefix_old->prefix_attr.origin_buf,&nlri_prefix_new->prefix_attr.origin_buf))
                {
                     bgp_ls_del_attr_list(&nlri_prefix_old->prefix_attr.origin_buf, insert_list_attr);
                     bgp_ls_free_nlri_prefix(nlri_prefix_old);
                     listnode_delete(insert_list_head, nlri_prefix_old);
                     XFREE(MTYPE_BGPLS_NLRI, nlri_prefix_old);
 
                     bgp_ls_add_attr_list(&nlri_prefix_new->prefix_attr.origin_buf, insert_list_attr);
                     nlri_prefix_new->ntt = true;
                     listnode_add(insert_list_head, nlri_prefix_new);
                     SET_FLAG(*lsdb_flags, set_lsdb_flags);
                     *actFlag = 1;
                 }
                 else
                 {
                     bgp_ls_free_nlri_prefix(nlri_prefix_new);
                     XFREE(MTYPE_BGPLS_NLRI, nlri_prefix_new);
                 }
             }
             else
             {
                 bgp_ls_add_attr_list(&nlri_prefix_new->prefix_attr.origin_buf, insert_list_attr);              
                 nlri_prefix_new->ntt = true;
                 listnode_add(insert_list_head, nlri_prefix_new);
                 SET_FLAG(*lsdb_flags, set_lsdb_flags);             
             }
             break;
         case BGP_LS_NLRI_TYPE_SR6_SID:
             insert_list_head = lsdb->reach_sr6_sid;
             remove_list_head = lsdb->withdraw_sr6_sid;
             set_lsdb_flags = LSDB_PEER_UPDATE_SR6_SID;			
 
             /*delete corresponding node nlri in withdraw node list*/
             nlri_sr6_sid_old = bgp_ls_lookup_nlri_sr6_sid(nlri_sr6_sid_new, remove_list_head);
             if (NULL != nlri_sr6_sid_old)
             {
                 bgp_ls_free_nlri_sr6_sid(nlri_sr6_sid_old);
                 listnode_delete(remove_list_head, nlri_sr6_sid_old);
                 XFREE(MTYPE_BGPLS_NLRI, nlri_sr6_sid_old);
             }
 
             /*add corresponding node nlri in reach node list*/
             nlri_sr6_sid_old = bgp_ls_lookup_nlri_sr6_sid(nlri_sr6_sid_new, insert_list_head);
             if (NULL != nlri_sr6_sid_old)
             {
                 /*Determine if the attributes are the same*/
                if (bgp_ls_tlv_cmp(&nlri_sr6_sid_new->sr6_sid_attr.origin_buf,&nlri_sr6_sid_old->sr6_sid_attr.origin_buf))
                {
                     bgp_ls_del_attr_list(&nlri_sr6_sid_old->sr6_sid_attr.origin_buf, lsdb->attri_sr6_sid);
                     bgp_ls_free_nlri_sr6_sid(nlri_sr6_sid_old);
                     listnode_delete(insert_list_head, nlri_sr6_sid_old);
                     XFREE(MTYPE_BGPLS_NLRI, nlri_sr6_sid_old);
 
                     bgp_ls_add_attr_list(&nlri_sr6_sid_new->sr6_sid_attr.origin_buf, lsdb->attri_sr6_sid);
                     nlri_sr6_sid_new->ntt = true;
                     listnode_add(insert_list_head, nlri_sr6_sid_new);
                     SET_FLAG(*lsdb_flags, set_lsdb_flags);
                     *actFlag = 1;
                 }
                 else
                 {
                     bgp_ls_free_nlri_sr6_sid(nlri_sr6_sid_new);
                     XFREE(MTYPE_BGPLS_NLRI, nlri_sr6_sid_new);
                 }
             }
             else
             {
                 bgp_ls_add_attr_list(&nlri_sr6_sid_new->sr6_sid_attr.origin_buf, lsdb->attri_sr6_sid);           
                 nlri_sr6_sid_new->ntt = true;
                 listnode_add(insert_list_head, nlri_sr6_sid_new);
                 SET_FLAG(*lsdb_flags, set_lsdb_flags);               
             }
             break;
         case BGP_LS_NLRI_TYPE_TE_POLICY:
             insert_list_head = lsdb->reach_te_policy;
             set_lsdb_flags = LSDB_PEER_UPDATE_TE_POLICY;		     
             /*add corresponding node nlri in reach node list*/
             nlri_te_policy_old = bgp_ls_lookup_nlri_te_policy(nlri_te_policy_new, insert_list_head);
             if (NULL != nlri_te_policy_old)
             {                 
                 bgp_ls_free_nlri_te_policy(nlri_te_policy_new);
                 XFREE(MTYPE_BGPLS_NLRI, nlri_te_policy_new);                
             }
             else
             {                       
                 listnode_add(insert_list_head, nlri_te_policy_new);
                 SET_FLAG(*lsdb_flags, set_lsdb_flags);               
             }
             break;
         default:
             break;
     }
 
     return;
 }
 
 static void bgp_ls_db_list_update_del(BGP_LS_DB *lsdb, uint32_t *lsdb_flags,
                         void *ls_nlri, uint16_t nlri_type)
 {
     struct list *insert_list_head = NULL;
     struct list *remove_list_head = NULL;
     struct list *insert_list_attr = NULL;
     NLRI_NODE * nlri_node_old = NULL;
     NLRI_NODE * nlri_node_new = (NLRI_NODE *)ls_nlri;
     NLRI_LINK * nlri_link_old = NULL;
     NLRI_LINK * nlri_link_new = (NLRI_LINK *)ls_nlri;
     NLRI_PREFIX * nlri_prefix_old = NULL;
     NLRI_PREFIX * nlri_prefix_new = (NLRI_PREFIX *)ls_nlri;
     NLRI_SR6_SID * nlri_sr6_sid_old = NULL;
     NLRI_SR6_SID * nlri_sr6_sid_new = (NLRI_SR6_SID *)ls_nlri;
     NLRI_TE_POLICY * nlri_te_policy_old = NULL;
     NLRI_TE_POLICY * nlri_te_policy_new = (NLRI_TE_POLICY *)ls_nlri;
     uint32_t set_lsdb_flags = 0;
 
     switch (nlri_type)
     {
         case BGP_LS_NLRI_TYPE_NODE:
 
             insert_list_head = lsdb->withdraw_node;
             remove_list_head = lsdb->reach_node;
             insert_list_attr = lsdb->attri_node;
             set_lsdb_flags = LSDB_PEER_UPDATE_NODE_WITHDRAW;
 
             /*delete corresponding node nlri in withdraw node list*/
             nlri_node_old = bgp_ls_lookup_nlri_node(nlri_node_new,remove_list_head);
             if (NULL != nlri_node_old)
             {
                 bgp_ls_del_attr_list(&nlri_node_old->node_attr.origin_buf, insert_list_attr);
                 bgp_ls_free_nlri_node(nlri_node_old);
                 listnode_delete(remove_list_head, nlri_node_old);
                 XFREE(MTYPE_BGPLS_NLRI, nlri_node_old);
             }
 
             /*add corresponding node nlri in reach node list*/
             nlri_node_old = bgp_ls_lookup_nlri_node(nlri_node_new,insert_list_head);
             if (NULL != nlri_node_old)
             {
                 nlri_node_old->ntt = true;
                 SET_FLAG(*lsdb_flags, set_lsdb_flags);
                 bgp_ls_free_nlri_node(nlri_node_new);
                 XFREE(MTYPE_BGPLS_NLRI, nlri_node_new);
             }
             else
             {
                 nlri_node_new->ntt = true;
                 listnode_add(insert_list_head, nlri_node_new);
                 SET_FLAG(*lsdb_flags, set_lsdb_flags);
             }
 
             break;
         case BGP_LS_NLRI_TYPE_LINK:
 
             insert_list_head = lsdb->withdraw_link;
             remove_list_head = lsdb->reach_link;
             insert_list_attr = lsdb->attri_link;
             set_lsdb_flags = LSDB_PEER_UPDATE_LINK_WITHDRAW;
 
             /*delete corresponding node nlri in withdraw node list*/
             nlri_link_old = bgp_ls_lookup_nlri_link(nlri_link_new,remove_list_head);
             if (NULL != nlri_link_old)
             {
                 bgp_ls_del_attr_list(&nlri_link_old->link_attr.origin_buf, insert_list_attr);
                 bgp_ls_free_nlri_link(nlri_link_old);
                 listnode_delete(remove_list_head, nlri_link_old);
                 XFREE(MTYPE_BGPLS_NLRI, nlri_link_old);
             }
 
             /*add corresponding node nlri in reach node liste*/
             nlri_link_old = bgp_ls_lookup_nlri_link(nlri_link_new,insert_list_head);
             if (NULL != nlri_link_old)
             {
                 nlri_link_old->ntt = true;
                 SET_FLAG(*lsdb_flags, set_lsdb_flags);
 
                 bgp_ls_free_nlri_link(nlri_link_new);
                 XFREE(MTYPE_BGPLS_NLRI, nlri_link_new);
             }
             else
             {
                 nlri_link_new->ntt = true;
                 listnode_add(insert_list_head, nlri_link_new);
                 SET_FLAG(*lsdb_flags, set_lsdb_flags);
             }
             break;
         case BGP_LS_NLRI_TYPE_IP4_PREFIX:
         case BGP_LS_NLRI_TYPE_IP6_PREFIX:
 
             if (BGP_LS_NLRI_TYPE_IP4_PREFIX== nlri_type)
             {
                 insert_list_head = lsdb->withdraw_prefix_ip4;
                 remove_list_head = lsdb->reach_prefix_ip4;
                 insert_list_attr = lsdb->attri_prefix_ip4;
                 set_lsdb_flags = LSDB_PEER_UPDATE_PREFIX_IP4_WITHDRAW;
             }
             else
             {
                 insert_list_head = lsdb->withdraw_prefix_ip6;
                 remove_list_head = lsdb->reach_prefix_ip6;
                 insert_list_attr = lsdb->attri_prefix_ip6;
                 set_lsdb_flags = LSDB_PEER_UPDATE_PREFIX_IP6_WITHDRAW;
             }
 
             /*delete corresponding node nlri in withdraw node list*/
             nlri_prefix_old = bgp_ls_lookup_nlri_prefix(nlri_prefix_new,remove_list_head);
             if (NULL != nlri_prefix_old)
             {
                 bgp_ls_del_attr_list(&nlri_prefix_old->prefix_attr.origin_buf, insert_list_attr);
                 bgp_ls_free_nlri_prefix(nlri_prefix_old);
                 listnode_delete(remove_list_head, nlri_prefix_old);
                 XFREE(MTYPE_BGPLS_NLRI, nlri_prefix_old);
             }
 
             /*add corresponding node nlri in reach node liste*/
             nlri_prefix_old = bgp_ls_lookup_nlri_prefix(nlri_prefix_new,insert_list_head);
             if (NULL != nlri_prefix_old)
             {
                 nlri_prefix_old->ntt = true;
                 SET_FLAG(*lsdb_flags, set_lsdb_flags);
 
                 bgp_ls_free_nlri_prefix(nlri_prefix_new);
                 XFREE(MTYPE_BGPLS_NLRI, nlri_prefix_new);
             }
             else
             {
                 nlri_prefix_new->ntt = true;
                 listnode_add(insert_list_head, nlri_prefix_new);
                 SET_FLAG(*lsdb_flags, set_lsdb_flags);
             }
             break;
         case BGP_LS_NLRI_TYPE_TE_POLICY:
             remove_list_head = lsdb->reach_te_policy;            
 
             /*delete corresponding node nlri in reach node list*/
             nlri_te_policy_old = bgp_ls_lookup_nlri_te_policy(nlri_te_policy_new,remove_list_head);
             if (NULL != nlri_te_policy_old)
             {
                 bgp_ls_free_nlri_te_policy(nlri_te_policy_old);
                 listnode_delete(remove_list_head, nlri_te_policy_old);
                 XFREE(MTYPE_BGPLS_NLRI, nlri_te_policy_old);
             }
             break;
           
         case BGP_LS_NLRI_TYPE_SR6_SID:
             insert_list_head = lsdb->withdraw_node;
             remove_list_head = lsdb->reach_node;
             insert_list_attr = lsdb->attri_sr6_sid;
             set_lsdb_flags = LSDB_PEER_UPDATE_SR6_SID_WITHDRAW;
 
             /*delete corresponding node nlri in reach node list*/
             nlri_sr6_sid_old = bgp_ls_lookup_nlri_sr6_sid(nlri_sr6_sid_new,remove_list_head);
             if (NULL != nlri_sr6_sid_old)
             {
                 bgp_ls_del_attr_list(&nlri_sr6_sid_old->sr6_sid_attr.origin_buf, insert_list_attr);
                 bgp_ls_free_nlri_sr6_sid(nlri_sr6_sid_old);
                 listnode_delete(remove_list_head, nlri_sr6_sid_old);
                 XFREE(MTYPE_BGPLS_NLRI, nlri_sr6_sid_old);
             }
 
             /*add corresponding node nlri in withdraw node list*/
             nlri_sr6_sid_old = bgp_ls_lookup_nlri_sr6_sid(nlri_sr6_sid_new,insert_list_head);
             if (NULL != nlri_sr6_sid_old)
             {
                 nlri_sr6_sid_old->ntt = true;
                 SET_FLAG(*lsdb_flags, set_lsdb_flags);
                 bgp_ls_free_nlri_sr6_sid(nlri_sr6_sid_new);
                 XFREE(MTYPE_BGPLS_NLRI, nlri_sr6_sid_new);
             }
             else
             {
                 nlri_sr6_sid_new->ntt = true;
                 listnode_add(insert_list_head, nlri_sr6_sid_new);
                 SET_FLAG(*lsdb_flags, set_lsdb_flags);
             }
 
             break;
         default:
             break;
     }
 
     return;
 }
 
 
 void bgp_ls_free_attr_all(BGP_LS_ATTR *ls_attr){
     bgp_ls_free_attr(ls_attr);
     XFREE(MTYPE_BGPLS_NLRI, ls_attr);
     return;
 }						
 
 /*BGP parse link-state attribute field in received update packet*/
 enum bgp_attr_parse_ret bgp_ls_attr_deserialize
 (
     struct bgp_attr_parser_args *args
 )
 {
     struct peer *const peer = args->peer;
     struct attr *const attri = args->attr;
     BGP_LS_RET_T ret = BGP_LS_RET_OK;
     bgp_size_t length = args->length;
     bgp_size_t has_parse_length = 0;
     struct stream *s = peer->curr;
     uint16_t attr_type = 0;
     uint16_t attr_length = 0;
 
     if (attri->ls_attr)
     {
         bgp_ls_free_attr(attri->ls_attr);
         memset(attri->ls_attr, 0, sizeof(struct bgp_ls_attr));
     }
     else
     {
         attri->ls_attr = XCALLOC(MTYPE_BGPLS_NLRI, sizeof(struct bgp_ls_attr));
         memset(attri->ls_attr, 0, sizeof(struct bgp_ls_attr));
     }
 
     bgp_ls_origin_buf_alloc(&attri->ls_attr->origin_buf, stream_pnt(s), args->type, length);
 
     for (; has_parse_length < length; has_parse_length += attr_length + BGP_LS_ATTR_TLV_TL_LENGTH)
     {
         attr_type = stream_getw(s);
         attr_length = stream_getw(s);
         if ((args->length-has_parse_length) < (attr_length + BGP_LS_ATTR_TLV_TL_LENGTH))
         {
             return BGP_ATTR_PARSE_ERROR;
         }
 
         switch (attr_type)
         {
             /*node_attr_code describes*/
             case NODE_ATTR_CODE_MULTI_TOPOLOGY_ID:
             case NODE_ATTR_CODE_NODE_FLAG_BITS:
             case NODE_ATTR_CODE_OPAQUE_NODE_ATTR:
             case NODE_ATTR_CODE_NODE_NAME:
             case NODE_ATTR_CODE_ISIS_AREA_ID:
             case NODE_ATTR_CODE_LOCAL_IPV4_ROUTER_ID:
             case NODE_ATTR_CODE_LOCAL_IPV6_ROUTER_ID:
             /*node_attr_code exclude rfc7752 */
             case NODE_ATTR_CODE_SR_CAPS:
             case NODE_ATTR_CODE_SR_ALGO:
             case NODE_ATTR_CODE_SR_LOCAL_BLOCK:
             case NODE_ATTR_CODE_SRMS_PREF:
             case NODE_ATTR_CODE_SR_SID_LABEL:
             case NODE_ATTR_CODE_SR6_CAPS:
                 ret = bgp_ls_attr_node_parse(attr_type, attr_length, stream_pnt(s), &attri->ls_attr->attrs_node);
                 stream_forward_getp(s, attr_length);
                 break;
 
             /*link_attr_code describes*/
             case LINK_ATTR_CODE_REMOTEIPV4_ROUTER_ID:
             case LINK_ATTR_CODE_REMOTEIPV6_ROUTER_ID:
             case LINK_ATTR_CODE_ADMIN_GROUP:
             case LINK_ATTR_CODE_MAXLINK_BANDWIDTH:
             case LINK_ATTR_CODE_MAX_RESERVABLE_LINK_BANDWIDTH:
             case LINK_ATTR_CODE_UNRESERVED_BANDWIDTH:
             case LINK_ATTR_CODE_TE_DEFAULT_METRIC:
             case LINK_ATTR_CODE_LINK_PROTECTION_TYPE:
             case LINK_ATTR_CODE_MPLS_PROTOCOL_MASK:
             case LINK_ATTR_CODE_IGP_METRIC:
             case LINK_ATTR_CODE_SHARED_RISK_LINK_GROUP:
             case LINK_ATTR_CODE_OPAQUE_LINK_ATTR:
             case LINK_ATTR_CODE_LINK_NAME:
             /*link_attr_code exclude rfc7752 */
             case LINK_ATTR_CODE_ADJSID:
             case LINK_ATTR_CODE_LAN_ADJ_SID:
             case LINK_ATTR_CODE_PEER_NODE_SID:
             case LINK_ATTR_CODE_PEER_ADJ_SID:
             case LINK_ATTR_CODE_PEER_SET_SID:
             case LINK_ATTR_CODE_UNI_LINK_DELAY:
             case LINK_ATTR_CODE_MIN_MAX_UNILINK_DELAY:
             case LINK_ATTR_CODE_UNI_DELAY_VARIATION:
             case LINK_ATTR_CODE_UNI_PACKET_LOSS:
             case LINK_ATTR_CODE_UNI_RESIDUAL_BANDWIDTH:
             case LINK_ATTR_CODE_UNI_AVAILABLE_BANDWIDTH:
             case LINK_ATTR_CODE_UNI_BANDWIDTH_UTIL:
             case LINK_ATTR_CODE_L2_BUNDLE_MEMBER:
             case LINK_ATTR_CODE_SR6_END_SID:
             case LINK_ATTR_CODE_ISIS_SR6_LAN_END_SID:
             case LINK_ATTR_CODE_OSPF3_SR6_LAN_END_SID:
                 ret = bgp_ls_attr_link_parse(attr_type, attr_length, stream_pnt(s), &attri->ls_attr->attrs_link);
                 stream_forward_getp(s, attr_length);
                 break;
 
             /*prefix_attr_code describes*/
             case PREFIX_ATTR_CODE_IGP_FLAGS:
             case PREFIX_ATTR_CODE_IGP_ROUTE_TAG:
             case PREFIX_ATTR_CODE_IGP_EXTENDED_ROUTE_TAG:
             case PREFIX_ATTR_CODE_PREFIX_METRIC:
             case PREFIX_ATTR_CODE_OSPF_FORWARDING_ADDRESS:
             case PREFIX_ATTR_CODE_OPAQUE_PREFIX_ATTRIBUTE:
             /*prefix_attr_code exclude rfc7752 */
             case PREFIX_ATTR_CODE_PREFIX_SID:
             case PREFIX_ATTR_CODE_RANGE:
             case PREFIX_ATTR_CODE_FLAGS:
             case PREFIX_ATTR_CODE_SOURCE_ROUTER_ID:
                 ret = bgp_ls_attr_prefix_parse(attr_type, attr_length, stream_pnt(s), &attri->ls_attr->attrs_prefix);
                 stream_forward_getp(s, attr_length);
                 break;
             case SR6_SID_ATTR_CODE_END_BEHAVIOR:
             case SR6_SID_ATTR_CODE_BGP_PEER_NODE_SID:
             case SR6_SID_ATTR_CODE_SID_STRUCT:
                 ret = bgp_ls_attr_sr6_sid_parse(attr_type, attr_length, stream_pnt(s), &attri->ls_attr->attrs_sr6_sid);
                 stream_forward_getp(s, attr_length);
                 break;
 
             case TE_POLICY_ATTR_CODE_BINDING_SID:
             case TE_POLICY_ATTR_CODE_SR_CANDIDATE_PATH_STATE:
             case TE_POLICY_ATTR_CODE_SEGMENT_LIST:
                 ret = bgp_ls_attr_te_policy_parse(attr_type, attr_length, stream_pnt(s), &attri->ls_attr->attrs_te_policy);
                 stream_forward_getp(s, attr_length);
                 break;
                 
             default:
                 stream_forward_getp(s, attr_length);
                 flog_warn(EC_BGP_LS_ATTRI_INVALID, "unknown link state attribute type %d", attr_type);
                 break;
         }
     }
     if (BGP_LS_RET_OK != ret)
     {
         return BGP_ATTR_PARSE_ERROR;
     }
     return BGP_ATTR_PARSE_PROCEED;
 };
 
 static void bgp_ls_nlri_as_path(char *nlri_as_path, struct aspath *aspath)
 {
     char *nlri_as_path_loc = nlri_as_path;
     if(aspath == NULL)
     {	
         return;
     }
     if(aspath->str != NULL)
     {
         if((strlen(aspath->str)+1) < MAX_AS_PATH){
             memcpy(nlri_as_path_loc,aspath->str, strlen(aspath->str)+1);
         }
         else{
             memcpy(nlri_as_path_loc,aspath->str, MAX_AS_PATH);
         }
         
     }
     return;
 }
 
 
 
 /*Fill the attribute field information of the received update message into the data structure corresponding to the nrli node*/
 static void bgp_ls_attr_fill_nlri(void *ls_nlri, struct attr *attr, uint16_t nlri_type)
 {
     /*parse attribute*/
     uint16_t attr_type = 0;
     uint16_t attr_length = 0;
     uint16_t attr_length_all = 0;
     uint16_t has_parse_length = 0;
     uint8_t *pnt;
     int32_t ret = BGP_LS_RET_ERROR;
 
     NLRI_NODE *nlri_node_head = (NLRI_NODE *)ls_nlri;
     NLRI_LINK *nlri_link_head = (NLRI_LINK *)ls_nlri;
     NLRI_PREFIX *nlri_prefix_ip4_head = (NLRI_PREFIX *)ls_nlri;
     NLRI_PREFIX *nlri_prefix_ip6_head = (NLRI_PREFIX *)ls_nlri;
     NLRI_SR6_SID *nlri_sr6_sid_head = (NLRI_SR6_SID *)ls_nlri;
     NLRI_TE_POLICY *nlri_te_policy_head = (NLRI_TE_POLICY *)ls_nlri;
 
     BGP_LS_TLV *origin_buf_tlv = NULL;
     if (NULL == attr)
     {
         return;
     }
     switch (nlri_type)
     {
         case BGP_LS_NLRI_TYPE_NODE:
             origin_buf_tlv = &nlri_node_head->node_attr.origin_buf;
             bgp_ls_nlri_as_path(nlri_node_head->as_path, attr->aspath);
             break;
         case BGP_LS_NLRI_TYPE_LINK:		
             origin_buf_tlv = &nlri_link_head->link_attr.origin_buf;
             bgp_ls_nlri_as_path(nlri_link_head->as_path, attr->aspath);
             break;
         case BGP_LS_NLRI_TYPE_IP4_PREFIX:
             origin_buf_tlv =  &nlri_prefix_ip4_head->prefix_attr.origin_buf;
             break;
         case BGP_LS_NLRI_TYPE_IP6_PREFIX:
             origin_buf_tlv = &nlri_prefix_ip6_head->prefix_attr.origin_buf;
             bgp_ls_nlri_as_path(nlri_prefix_ip6_head->as_path, attr->aspath);
             break;
         case BGP_LS_NLRI_TYPE_SR6_SID:
             origin_buf_tlv = &nlri_sr6_sid_head->sr6_sid_attr.origin_buf;
             bgp_ls_nlri_as_path(nlri_sr6_sid_head->as_path, attr->aspath);
             break;
         case BGP_LS_NLRI_TYPE_TE_POLICY:
             origin_buf_tlv = &nlri_te_policy_head->te_policy_attr.origin_buf;
             bgp_ls_nlri_as_path(nlri_te_policy_head->as_path, attr->aspath);
             break;
         default:
             return;
     }
     if (NULL == attr->ls_attr)
     {
         return;
     }
     if (!CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LINK_STATE_PATH)))
     {
         return;
     }
     /*parse ls path attribute Length*/
     attr_length_all = attr->ls_attr->origin_buf.length;
     pnt = attr->ls_attr->origin_buf.value;
     bgp_ls_origin_buf_alloc(origin_buf_tlv, attr->ls_attr->origin_buf.value,
                     attr->ls_attr->origin_buf.type, attr->ls_attr->origin_buf.length);
 
     for (; has_parse_length < attr_length_all; has_parse_length += attr_length + BGP_LS_ATTR_TLV_TL_LENGTH)
     {
         /*parse attribute Type*/
         DECODE_UINT16(pnt,attr_type);
 
         /*parse attribute Length*/
         DECODE_UINT16(pnt,attr_length);
 
         if ((attr_length_all - has_parse_length) < (uint16_t)(attr_length + BGP_LS_ATTR_TLV_TL_LENGTH))
         {
             return;
         }
 
         switch (nlri_type)
         {
             case BGP_LS_NLRI_TYPE_NODE:
                 ret = bgp_ls_attr_node_parse(attr_type, attr_length, pnt, &nlri_node_head->node_attr);
                 break;
             case BGP_LS_NLRI_TYPE_LINK:
                 ret = bgp_ls_attr_link_parse(attr_type, attr_length, pnt, &nlri_link_head->link_attr);
                 break;
             case BGP_LS_NLRI_TYPE_IP4_PREFIX:
                 ret = bgp_ls_attr_prefix_parse(attr_type, attr_length, pnt, &nlri_prefix_ip4_head->prefix_attr);
                 break;
             case BGP_LS_NLRI_TYPE_IP6_PREFIX:
                 ret = bgp_ls_attr_prefix_parse(attr_type, attr_length, pnt, &nlri_prefix_ip6_head->prefix_attr);
                 break;
             case BGP_LS_NLRI_TYPE_SR6_SID:
                 ret = bgp_ls_attr_sr6_sid_parse(attr_type, attr_length, pnt, &nlri_sr6_sid_head->sr6_sid_attr);
                 break;
             case BGP_LS_NLRI_TYPE_TE_POLICY:
                 ret = bgp_ls_attr_te_policy_parse(attr_type, attr_length, pnt, &nlri_te_policy_head->te_policy_attr);
                 break;
             default:
                 break;
         }
         if (BGP_LS_RET_OK != ret)
         {
              flog_warn(EC_BGP_LS_ATTRI_INVALID,
                       "Warning in processing NLRI type (%d), unsupport attribute type (%d)", nlri_type, attr_type);
              //return ; link-state解析应满足宽进的原则
         }
         pnt += attr_length;
     }
 
     return;
 }
 
 static NLRI_NODE *bgp_ls_nlri_node_dup(NLRI_NODE *nlri_node)
 {
     NLRI_NODE *new_node = NULL;
     new_node= XMALLOC(MTYPE_BGPLS_NLRI, sizeof(NLRI_NODE));
     memset(new_node, 0, sizeof(NLRI_NODE));
     bgp_ls_dup_nlri_node(nlri_node,new_node);
     return new_node;
 }
 
 static NLRI_LINK *bgp_ls_nlri_link_dup(NLRI_LINK *nlri_link)
 {
     NLRI_LINK *new_link = NULL;
     new_link = XMALLOC(MTYPE_BGPLS_NLRI, sizeof(NLRI_LINK));
     memset(new_link, 0, sizeof(NLRI_LINK));
     bgp_ls_dup_nlri_link(nlri_link,new_link);
     return new_link;
 }
 
 static NLRI_PREFIX *bgp_ls_nlri_prefix_dup(NLRI_PREFIX *nlri_prefix)
 {
     NLRI_PREFIX *new_prefix = NULL;
     new_prefix = XMALLOC(MTYPE_BGPLS_NLRI, sizeof(NLRI_PREFIX));
     memset(new_prefix, 0, sizeof(NLRI_PREFIX));
     bgp_ls_dup_nlri_prefix(nlri_prefix,new_prefix);
     return new_prefix;
 }
 
 
 /* Copy the relevant attributes and node data from neighbor lsdb to the local lsdb */
 static void bgp_local_lsdb_update(struct bgp *bgp, struct peer *peer)
 {
     return;//nothing to do
     NLRI_NODE *node_head = NULL;
     NLRI_LINK *link_head = NULL;
     NLRI_PREFIX *prefix_head = NULL;
 
     struct list *list_head = NULL;
     struct listnode *node, *nnode;
     NLRI_NODE *new_node = NULL;
     NLRI_LINK *new_link = NULL;
     NLRI_PREFIX *new_prefix = NULL;
 
     if ((NULL == peer->lsdb_nei) || (NULL == bgp->lsdb_loc))
     {
         return;
     }
 
     BGPLS_DEBUG("bgp_local_lsdb_update reach_node");
 
     /*mp reach*/
     if (CHECK_FLAG(peer->lsdb_nei_flags, LSDB_PEER_UPDATE_NODE))
     {
         list_head = peer->lsdb_nei->reach_node;
         for (ALL_LIST_ELEMENTS(list_head, node, nnode, node_head))
         {
             if (NULL == bgp_ls_lookup_nlri_node(node_head, bgp->lsdb_loc->reach_node))
             {
                 new_node = bgp_ls_nlri_node_dup(node_head);
                 listnode_add(bgp->lsdb_loc->reach_node, new_node);
             }
         }
         UNSET_FLAG(peer->lsdb_nei_flags, LSDB_PEER_UPDATE_NODE);
     }
     if (CHECK_FLAG(peer->lsdb_nei_flags, LSDB_PEER_UPDATE_LINK))
     {
 
         list_head = peer->lsdb_nei->reach_link;
         for (ALL_LIST_ELEMENTS(list_head, node, nnode, link_head))
         {
             if (NULL == bgp_ls_lookup_nlri_link(link_head, bgp->lsdb_loc->reach_link))
             {
                 new_link = bgp_ls_nlri_link_dup(link_head);
                 listnode_add(bgp->lsdb_loc->reach_link, new_link);
             }
         }
         UNSET_FLAG(peer->lsdb_nei_flags, LSDB_PEER_UPDATE_LINK);
     }
 
     if (CHECK_FLAG(peer->lsdb_nei_flags, LSDB_PEER_UPDATE_PREFIX_IP4))
     {
         list_head = peer->lsdb_nei->reach_prefix_ip4;
         for (ALL_LIST_ELEMENTS(list_head, node, nnode, prefix_head))
         {
             if (NULL == bgp_ls_lookup_nlri_prefix(prefix_head, bgp->lsdb_loc->reach_prefix_ip4))
             {
                 new_prefix = bgp_ls_nlri_prefix_dup(prefix_head);
                 listnode_add(bgp->lsdb_loc->reach_prefix_ip4, new_prefix);
             }
         }
         UNSET_FLAG(peer->lsdb_nei_flags, LSDB_PEER_UPDATE_PREFIX_IP4);
     }
 
     if (CHECK_FLAG(peer->lsdb_nei_flags, LSDB_PEER_UPDATE_PREFIX_IP6))
     {
         list_head = peer->lsdb_nei->reach_prefix_ip6;
         for (ALL_LIST_ELEMENTS(list_head, node, nnode, prefix_head))
         {
             if (NULL == bgp_ls_lookup_nlri_prefix(prefix_head, bgp->lsdb_loc->reach_prefix_ip6))
             {
                 new_prefix = bgp_ls_nlri_prefix_dup(prefix_head);
                 listnode_add(bgp->lsdb_loc->reach_prefix_ip6, new_prefix);
             }
         }
         UNSET_FLAG(peer->lsdb_nei_flags, LSDB_PEER_UPDATE_PREFIX_IP6);
     }
 
     /*mp unreach*/
     if (CHECK_FLAG(peer->lsdb_nei_flags, LSDB_PEER_UPDATE_NODE_WITHDRAW))
     {
         list_head = peer->lsdb_nei->withdraw_node;
         for (ALL_LIST_ELEMENTS(list_head, node, nnode, node_head))
         {
             if (NULL == bgp_ls_lookup_nlri_node(node_head, bgp->lsdb_loc->withdraw_node))
             {
                 new_node = bgp_ls_nlri_node_dup(node_head);
                 listnode_add(bgp->lsdb_loc->withdraw_node, new_node);
             }
         }
         UNSET_FLAG(peer->lsdb_nei_flags, LSDB_PEER_UPDATE_NODE_WITHDRAW);
     }
 
     if (CHECK_FLAG(peer->lsdb_nei_flags, LSDB_PEER_UPDATE_LINK_WITHDRAW))
     {
         list_head = peer->lsdb_nei->withdraw_link;
         for (ALL_LIST_ELEMENTS(list_head, node, nnode, link_head))
         {
             if (NULL == bgp_ls_lookup_nlri_link(link_head, bgp->lsdb_loc->withdraw_link))
             {
                 new_link = bgp_ls_nlri_link_dup(link_head);
                 listnode_add(bgp->lsdb_loc->withdraw_link, new_link);
             }
         }
         UNSET_FLAG(peer->lsdb_nei_flags, LSDB_PEER_UPDATE_LINK_WITHDRAW);
     }
 
     if (CHECK_FLAG(peer->lsdb_nei_flags, LSDB_PEER_UPDATE_PREFIX_IP4_WITHDRAW))
     {
         list_head = peer->lsdb_nei->withdraw_prefix_ip4;
         for (ALL_LIST_ELEMENTS(list_head, node, nnode, prefix_head))
         {
             if (NULL == bgp_ls_lookup_nlri_prefix(prefix_head, bgp->lsdb_loc->withdraw_prefix_ip4))
             {
                 new_prefix = bgp_ls_nlri_prefix_dup(prefix_head);
                 listnode_add(bgp->lsdb_loc->withdraw_prefix_ip4, new_prefix);
             }
         }
         UNSET_FLAG(peer->lsdb_nei_flags, LSDB_PEER_UPDATE_PREFIX_IP4_WITHDRAW);
     }
 
     if (CHECK_FLAG(peer->lsdb_nei_flags, LSDB_PEER_UPDATE_PREFIX_IP6_WITHDRAW))
     {
         list_head = peer->lsdb_nei->withdraw_prefix_ip6;
         for (ALL_LIST_ELEMENTS(list_head, node, nnode, prefix_head))
         {
             if (NULL == bgp_ls_lookup_nlri_prefix(prefix_head, bgp->lsdb_loc->withdraw_prefix_ip6))
             {
                 new_prefix = bgp_ls_nlri_prefix_dup(prefix_head);
                 listnode_add(bgp->lsdb_loc->withdraw_prefix_ip6, new_prefix);
             }
         }
         UNSET_FLAG(peer->lsdb_nei_flags, LSDB_PEER_UPDATE_PREFIX_IP6_WITHDRAW);
     }
 
     bgp->lsdb_loc->route_distinguisher = peer->lsdb_nei->route_distinguisher;
     bgp->lsdb_loc->type = peer->lsdb_nei->type;
     return;
 }
 
 void convert_uint32_to_in6_addr(uint32_t sid[4], struct in6_addr* addr) {
     for(int i = 0; i < 4; ++i) {
         uint32_t net_order = htonl(sid[i]);
         memcpy(&addr->s6_addr[i * 4], &net_order, sizeof(uint32_t));
     }
 }
 
 long long current_time_in_millis() {
     struct timeval tv;
     gettimeofday(&tv, NULL);
     return (long long)(tv.tv_sec) * 1000LL + (tv.tv_usec) / 1000LL; // 秒转换为毫秒并将微秒转换为毫秒
 }
 
 /*bgp parse nlri field in received update packet*/
 int32_t bgp_nlri_parse_linkstate(struct peer *peer, struct attr *attr,
                              struct bgp_nlri *packet, int32_t withdraw)
 {
     void *ls_nlri = NULL;
     uint8_t *pnt;
     uint8_t *lim;
     afi_t afi;
     safi_t safi;
     uint16_t route_dist_len = 0;
     uint16_t nlri_type;
     uint16_t nlri_length;
     int32_t ret;
     int32_t actFlag = 0;
     char act[4] = "del";
 
     /* Start processing the NLRI - there may be multiple in the MP_REACH */
     pnt = packet->nlri;
     lim = pnt + packet->length;
     afi = packet->afi;
     safi = packet->safi;
 
     BGPLS_DEBUG("parse link state subsequent address family identifier(%s) length(%u) withdraw(%u)",
                safi2str(safi), packet->length, withdraw);
 
     if (afi != AFI_BGPLS)
     {
         flog_warn(EC_BGP_LS_NLRI_INVALID, "BGP link state address family not supported");
         return BGP_NLRI_PARSE_ERROR_LS_NOT_SUPPORTED;
     }
 
     if (safi == SAFI_BGP_LS)
     {
         route_dist_len = 0;
     }
     else if(safi == SAFI_BGP_LS_VPN)
     {
         /*Route Distinguisher length*/
         route_dist_len = 8;
     }
     else
     {
         flog_warn(EC_BGP_LS_NLRI_INVALID, "BGP link state subsequent address family not supported");
         return BGP_NLRI_PARSE_ERROR_LS_NOT_SUPPORTED;
     }
 
     if (packet->length < (BGP_LS_NLRI_TLV_TL_LENGTH + route_dist_len))
     {
         flog_err(EC_BGP_LS_NLRI_INVALID, "BGP link state nlri length too short (%u)",
                  packet->length);
         return BGP_NLRI_PARSE_ERROR_LS_LENGTH;
     }
 
     for (; pnt < lim; pnt += nlri_length)
     {
         /* When packet overflow occurs return immediately. */
         if (pnt + BGP_LS_NLRI_TLV_TL_LENGTH + route_dist_len > lim)
             return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
 
         /*parse NLRI Type*/
         DECODE_UINT16(pnt,nlri_type);
 
         /*parse NLRI Length*/
         DECODE_UINT16(pnt,nlri_length);
 
         BGPLS_DEBUG("parse link state nlri type(%u) length(%u)",nlri_type, nlri_length);
 
         /* When packet length too short occur return immediately. */
         if (nlri_length < route_dist_len)
             return BGP_NLRI_PARSE_ERROR_LS_LENGTH;
 
         /*skip Route Distinguisher*/
         pnt += route_dist_len;
 
         /* When packet overflow occur return immediately. */
         if ((pnt + nlri_length) > lim)
             return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
 
         ls_nlri = NULL;
         switch (nlri_type)
         {
             case BGP_LS_NLRI_TYPE_NODE:
                 ls_nlri = XCALLOC(MTYPE_BGPLS_NLRI, sizeof(NLRI_NODE));			
                 if (NULL == ls_nlri)
                 {
                     return BGP_NLRI_PARSE_ERROR;
                 }
                 memset(ls_nlri, 0, sizeof(NLRI_NODE));
                 ret = bgp_ls_nlri_node_parse((NLRI_NODE *)ls_nlri, pnt, nlri_length - route_dist_len);
                 if (BGP_LS_RET_OK != ret)
                 {
                     flog_err(EC_BGP_LS_NLRI_INVALID,
                              "%u:%s - Error in processing Node NLRI size %d reason(%d)",
                              peer->bgp->vrf_id, peer->host, nlri_length, ret);
                     XFREE(MTYPE_BGPLS_NLRI, ls_nlri);
                     return BGP_NLRI_PARSE_ERROR_LS_NODE;
                 }
                 bgp_ls_attr_fill_nlri((NLRI_NODE *)ls_nlri, attr, nlri_type);
 
                 if (!withdraw)
                 {
                     bgp_ls_db_list_update_add(peer->lsdb_nei, &peer->lsdb_nei_flags, ls_nlri,nlri_type, &actFlag);
                     if (actFlag == 0) {
                         strcpy(act, "add");
                     } else {
                         strcpy(act, "put");
                     }
                 }
                 else
                 {
                     bgp_ls_db_list_update_del(peer->lsdb_nei,&peer->lsdb_nei_flags,ls_nlri,nlri_type);
                     /*Receive the unreach update from neighbor, but do not notify other modules to do withdraw*/
                     //bgp_ls_free_nlri_node_list(peer->lsdb_nei->withdraw_node);
                 }

                 break;
             case BGP_LS_NLRI_TYPE_LINK:
                 ls_nlri = XCALLOC(MTYPE_BGPLS_NLRI, sizeof(NLRI_LINK));
                 if (NULL == ls_nlri)
                 {
                     return BGP_NLRI_PARSE_ERROR;
                 }
                 memset(ls_nlri, 0, sizeof(NLRI_LINK));
                 ret = bgp_ls_nlri_link_parse((NLRI_LINK *)ls_nlri, pnt, nlri_length - route_dist_len);
                 if (BGP_LS_RET_OK != ret)
                 {
                     flog_err(EC_BGP_LS_NLRI_INVALID,
                              "%u:%s - Error in processing Link NLRI size %d reason(%d)",
                              peer->bgp->vrf_id, peer->host, nlri_length, ret);
                     XFREE(MTYPE_BGPLS_NLRI, ls_nlri);
                     return BGP_NLRI_PARSE_ERROR_LS_LINK;
                 }
                 bgp_ls_attr_fill_nlri((NLRI_LINK *)ls_nlri, attr, nlri_type);
 
                 if (!withdraw)
                 {
                     bgp_ls_db_list_update_add(peer->lsdb_nei, &peer->lsdb_nei_flags, ls_nlri,nlri_type, &actFlag);
                     if (actFlag == 0) {
                         strcpy(act, "add");
                     } else {
                         strcpy(act, "put");
                     }
                 }
                 else
                 {
                     bgp_ls_db_list_update_del(peer->lsdb_nei,&peer->lsdb_nei_flags,ls_nlri,nlri_type);
                     /*Receive the unreach update from neighbor, but do not notify other modules to do withdraw*/
                    // bgp_ls_free_nlri_link_list(peer->lsdb_nei->withdraw_link);
                 }
 
                 break;
             case BGP_LS_NLRI_TYPE_IP4_PREFIX:
                 ls_nlri = XCALLOC(MTYPE_BGPLS_NLRI, sizeof(NLRI_PREFIX));
                 if (NULL == ls_nlri)
                 {
                     return BGP_NLRI_PARSE_ERROR;
                 }
                 memset(ls_nlri, 0, sizeof(NLRI_PREFIX));
                 ret = bgp_ls_nlri_ip4_prefix_parse((NLRI_PREFIX *)ls_nlri, pnt, nlri_length - route_dist_len);
                 if (BGP_LS_RET_OK != ret)
                 {
                     flog_err(EC_BGP_LS_NLRI_INVALID,
                              "%u:%s - Error in processing IPv4 Topology Prefix NLRI size %d reason(%d)",
                              peer->bgp->vrf_id, peer->host, nlri_length, ret);
                     XFREE(MTYPE_BGPLS_NLRI, ls_nlri);
                     return BGP_NLRI_PARSE_ERROR_LS_IP4P;
                 }
                 bgp_ls_attr_fill_nlri((NLRI_PREFIX *)ls_nlri, attr, nlri_type);
                 if (!withdraw)
                 {
                     bgp_ls_db_list_update_add(peer->lsdb_nei, &peer->lsdb_nei_flags, ls_nlri,nlri_type, &actFlag);
                     if (actFlag == 0) {
                         strcpy(act, "add");
                     } else {
                         strcpy(act, "put");
                     }
                 }
                 else
                 {
                     bgp_ls_db_list_update_del(peer->lsdb_nei,&peer->lsdb_nei_flags,ls_nlri,nlri_type);
                     /*Receive the unreach update from neighbor, but do not notify other modules to do withdraw*/
                     //bgp_ls_free_nlri_prefix_list(peer->lsdb_nei->withdraw_prefix_ip4);
                 }
 
                 break;
             case BGP_LS_NLRI_TYPE_IP6_PREFIX:
                 ls_nlri = XCALLOC(MTYPE_BGPLS_NLRI, sizeof(NLRI_PREFIX));
                 if (NULL == ls_nlri)
                 {
                     return BGP_NLRI_PARSE_ERROR;
                 }
                 memset(ls_nlri, 0, sizeof(NLRI_PREFIX));
                 ret = bgp_ls_nlri_ip6_prefix_parse((NLRI_PREFIX *)ls_nlri, pnt, nlri_length - route_dist_len);
                 if (BGP_LS_RET_OK != ret)
                 {
                     flog_err(EC_BGP_LS_NLRI_INVALID,
                              "%u:%s - Error in processing IPv6 Topology Prefix NLRI size %d reason(%d)",
                              peer->bgp->vrf_id, peer->host, nlri_length, ret);
                     XFREE(MTYPE_BGPLS_NLRI, ls_nlri);
                     return BGP_NLRI_PARSE_ERROR_LS_IP6P;
                 }
                 bgp_ls_attr_fill_nlri((NLRI_PREFIX *)ls_nlri, attr, nlri_type);
 
                 if (!withdraw)
                 {
                     bgp_ls_db_list_update_add(peer->lsdb_nei, &peer->lsdb_nei_flags, ls_nlri,nlri_type, &actFlag);
                     if (actFlag == 0) {
                         strcpy(act, "add");
                     } else {
                         strcpy(act, "put");
                     }
                 }
                 else
                 {
                     bgp_ls_db_list_update_del(peer->lsdb_nei,&peer->lsdb_nei_flags,ls_nlri,nlri_type);
                     /*Receive the unreach update from neighbor, but do not notify other modules to do withdraw*/
                     //bgp_ls_free_nlri_prefix_list(peer->lsdb_nei->withdraw_prefix_ip6);
                 }
 
                 break;
 
             case BGP_LS_NLRI_TYPE_TE_POLICY:
                 ls_nlri = XCALLOC(MTYPE_BGPLS_NLRI, sizeof(NLRI_TE_POLICY));
                 if (NULL == ls_nlri)
                 {
                     return BGP_NLRI_PARSE_ERROR;
                 }
                 memset(ls_nlri, 0, sizeof(NLRI_TE_POLICY));
                 ret = bgp_ls_nlri_te_policy_parse((NLRI_TE_POLICY *)ls_nlri, pnt, nlri_length - route_dist_len);
                 if (BGP_LS_RET_OK != ret)
                 {
                     flog_err(EC_BGP_LS_NLRI_INVALID,
                              "%u:%s - Error in processing IPv6 Topology Te Policy size %d reason(%d)",
                              peer->bgp->vrf_id, peer->host, nlri_length, ret);
                     XFREE(MTYPE_BGPLS_NLRI, ls_nlri);
                     return BGP_NLRI_PARSE_ERROR_LS_IP6P;
                 }
                 bgp_ls_attr_fill_nlri((NLRI_TE_POLICY *)ls_nlri, attr, nlri_type);
 
                 if (!withdraw)
                 {
                     bgp_ls_db_list_update_add(peer->lsdb_nei, &peer->lsdb_nei_flags, ls_nlri,nlri_type, &actFlag);
                     if (actFlag == 0) {
                         strcpy(act, "add");
                     } else {
                         strcpy(act, "put");
                     }
                 }
                 else
                 {
                     bgp_ls_db_list_update_del(peer->lsdb_nei,&peer->lsdb_nei_flags,ls_nlri,nlri_type);
                 }
 
                 break;
 
             case BGP_LS_NLRI_TYPE_SR6_SID:
                 ls_nlri = XCALLOC(MTYPE_BGPLS_NLRI, sizeof(NLRI_SR6_SID));
                 if (NULL == ls_nlri)
                 {
                     return BGP_NLRI_PARSE_ERROR;
                 }
                 memset(ls_nlri, 0, sizeof(NLRI_SR6_SID));
                 ret = bgp_ls_nlri_sr6_sid_parse((NLRI_SR6_SID *)ls_nlri, pnt, nlri_length - route_dist_len);
                 if (BGP_LS_RET_OK != ret)
                 {
                     flog_err(EC_BGP_LS_NLRI_INVALID,
                              "%u:%s - Error in processing SRV6 SID NLRI size %d reason(%d)",
                              peer->bgp->vrf_id, peer->host, nlri_length, ret);
                     XFREE(MTYPE_BGPLS_NLRI, ls_nlri);
                     return BGP_NLRI_PARSE_ERROR_LS_IP6P;
                 }
                 bgp_ls_attr_fill_nlri((NLRI_SR6_SID *)ls_nlri, attr, nlri_type);
 
                 if (!withdraw)
                 {
                     bgp_ls_db_list_update_add(peer->lsdb_nei, &peer->lsdb_nei_flags, ls_nlri,nlri_type, &actFlag);
                     if (actFlag == 0) {
                         strcpy(act, "add");
                     } else {
                         strcpy(act, "put");
                     }
                 }
                 else
                 {
                     bgp_ls_db_list_update_del(peer->lsdb_nei,&peer->lsdb_nei_flags,ls_nlri,nlri_type);
                     /*Receive the unreach update from neighbor, but do not notify other modules to do withdraw*/
                     bgp_ls_free_nlri_prefix_list(peer->lsdb_nei->withdraw_sr6_sid);
                 }

                 break;
             default:
                 break;
         }
     }
 
     /* Packet length consistency check. */
     if (pnt != lim)
         return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
 
     if (peer->lsdb_nei_flags)
     {
         //TODO: send TOPO change event to Controller
 
         // auv: call eventpump.sendEvent_Topo
         // XXX: Don't use this, use kafka to report this event
         // char *neighAddr, asNumber[20];
         // neighAddr = peer->host;
         // sprintf(asNumber, "%ld", peer->local_as);
         // sendEvent_Topo(neighAddr, asNumber);
         
         BGPLS_DEBUG("Send TOPO change event to Controller");
         peer->lsdb_nei_flags = 0;
     }
 
     /* download to local LSDB */
     bgp_local_lsdb_update(peer->bgp, peer);
 
     return BGP_NLRI_PARSE_OK;
 }
 
 /* initialize bgp local lsdb database */
 void bgp_lsdb_init(struct bgp *bgp)
 {
     bgp->lsdb_loc = XCALLOC(MTYPE_BGPLS_NLRI, sizeof(BGP_LS_DB));
     memset(bgp->lsdb_loc, 0, sizeof(BGP_LS_DB));
     bgp->lsdb_loc->reach_node = list_new();
     bgp->lsdb_loc->reach_link = list_new();
     bgp->lsdb_loc->reach_prefix_ip4 = list_new();
     bgp->lsdb_loc->reach_prefix_ip6 = list_new();
     bgp->lsdb_loc->reach_te_policy = list_new();
 
     bgp->lsdb_loc->withdraw_node = list_new();
     bgp->lsdb_loc->withdraw_link = list_new();
     bgp->lsdb_loc->withdraw_prefix_ip4 = list_new();
     bgp->lsdb_loc->withdraw_prefix_ip6 = list_new();
 
 
     bgp->lsdb_loc->attri_node = list_new();
     bgp->lsdb_loc->attri_link = list_new();
     bgp->lsdb_loc->attri_prefix_ip4 = list_new();
     bgp->lsdb_loc->attri_prefix_ip6 = list_new();
 
     RESET_FLAG(bgp->lsdb_flags);
 
     /*BGP notify isis/ospf client ready message*/
     //bgp_apiserver_clients_notify_ready(bgp);
 
     /*note:Temporarily request isis/ospf batch data(bulk) during initialization*/
     //bgp_apiserver_clients_notify_ls_bulk_request(bgp);
     return;
 }
 void bgp_lsdb_exit(struct bgp *bgp)
 {
     if( !bgp || !bgp->lsdb_loc )
         return;
     bgp_ls_free_nlri_node_list(bgp->lsdb_loc->reach_node);
     bgp_ls_free_nlri_link_list(bgp->lsdb_loc->reach_link);
     bgp_ls_free_nlri_prefix_list(bgp->lsdb_loc->reach_prefix_ip4);
     bgp_ls_free_nlri_prefix_list(bgp->lsdb_loc->reach_prefix_ip6);
     bgp_ls_free_nlri_te_policy_list(bgp->lsdb_loc->reach_te_policy);
 
     bgp_ls_free_nlri_node_list(bgp->lsdb_loc->withdraw_node);
     bgp_ls_free_nlri_link_list(bgp->lsdb_loc->withdraw_link);
     bgp_ls_free_nlri_prefix_list(bgp->lsdb_loc->withdraw_prefix_ip4);
     bgp_ls_free_nlri_prefix_list(bgp->lsdb_loc->withdraw_prefix_ip6);
 
     bgp_ls_free_attr_list(bgp->lsdb_loc->attri_node);
     bgp_ls_free_attr_list(bgp->lsdb_loc->attri_link);
     bgp_ls_free_attr_list(bgp->lsdb_loc->attri_prefix_ip4);
     bgp_ls_free_attr_list(bgp->lsdb_loc->attri_prefix_ip6);
 
     list_delete(&bgp->lsdb_loc->reach_node);
     list_delete(&bgp->lsdb_loc->reach_link);
     list_delete(&bgp->lsdb_loc->reach_prefix_ip4);
     list_delete(&bgp->lsdb_loc->reach_prefix_ip6);
     list_delete(&bgp->lsdb_loc->reach_te_policy);
 
     list_delete(&bgp->lsdb_loc->withdraw_node);
     list_delete(&bgp->lsdb_loc->withdraw_link);
     list_delete(&bgp->lsdb_loc->withdraw_prefix_ip4);
     list_delete(&bgp->lsdb_loc->withdraw_prefix_ip6);
 
     list_delete(&bgp->lsdb_loc->attri_node);
     list_delete(&bgp->lsdb_loc->attri_link);
     list_delete(&bgp->lsdb_loc->attri_prefix_ip4);
     list_delete(&bgp->lsdb_loc->attri_prefix_ip6);
 
     bgp->lsdb_loc->reach_node = NULL;
     bgp->lsdb_loc->reach_link = NULL;
     bgp->lsdb_loc->reach_prefix_ip4 = NULL;
     bgp->lsdb_loc->reach_prefix_ip6 = NULL;
     bgp->lsdb_loc->reach_te_policy = NULL;
 
     bgp->lsdb_loc->withdraw_node = NULL;
     bgp->lsdb_loc->withdraw_link = NULL;
     bgp->lsdb_loc->withdraw_prefix_ip4 = NULL;
     bgp->lsdb_loc->withdraw_prefix_ip6 = NULL;
 
     bgp->lsdb_loc->attri_node = NULL;
     bgp->lsdb_loc->attri_link = NULL;
     bgp->lsdb_loc->attri_prefix_ip4 = NULL;
     bgp->lsdb_loc->attri_prefix_ip6 = NULL;
 
     XFREE(MTYPE_BGPLS_NLRI, bgp->lsdb_loc);
     bgp->lsdb_loc = NULL;
 
     RESET_FLAG(bgp->lsdb_flags);
     return;
 }
 
 #if 0
 static void bgp_ls_local_add_peer(struct bgp *bgp)
 {
     bgp->bgpls_peers_num++;
     return;
 }
 
 static void bgp_ls_local_del_peer(struct bgp *bgp)
 {
     if (1 == bgp->bgpls_peers_num)
     {
         bgp->bgpls_peers_num = 0;
     }
     else
     {
         bgp->bgpls_peers_num--;
     }
     return;
 }
 #endif
 
 /*Initialize neighbor node data*/
 void bgp_peer_lsdb_init(struct peer *peer)
 {
     //bgp_ls_local_add_peer(peer->bgp);
     peer->lsdb_nei = XCALLOC(MTYPE_BGPLS_NLRI, sizeof(BGP_LS_DB));
     memset(peer->lsdb_nei, 0, sizeof(BGP_LS_DB));
     peer->lsdb_nei->reach_node = list_new();
     peer->lsdb_nei->reach_link = list_new();
     peer->lsdb_nei->reach_prefix_ip4 = list_new();
     peer->lsdb_nei->reach_prefix_ip6 = list_new();
     peer->lsdb_nei->reach_sr6_sid =  list_new();
     peer->lsdb_nei->reach_te_policy = list_new();
 
     peer->lsdb_nei->withdraw_node = list_new();
     peer->lsdb_nei->withdraw_link = list_new();
     peer->lsdb_nei->withdraw_prefix_ip4 = list_new();
     peer->lsdb_nei->withdraw_prefix_ip6 = list_new();
     peer->lsdb_nei->withdraw_sr6_sid = list_new();
 
     peer->lsdb_nei->attri_node = list_new();
     peer->lsdb_nei->attri_link = list_new();
     peer->lsdb_nei->attri_prefix_ip4 = list_new();
     peer->lsdb_nei->attri_prefix_ip6 = list_new();
     peer->lsdb_nei->attri_sr6_sid = list_new();
 
     RESET_FLAG(peer->lsdb_nei_flags);
 
     return;
 }
 
 /* when peer down, peer lsdb data cleanup */
 void bgp_peer_lsdb_clean(struct peer *peer)
 {
     BGPLS_DEBUG("bgp peer lsdb is cleaning.");
 
     if (NULL == peer->lsdb_nei)
     {
        BGPLS_DEBUG("bgp peer lsdb is NULL.");
        return;
     }
     bgp_ls_free_nlri_node_list(peer->lsdb_nei->reach_node);
     bgp_ls_free_nlri_link_list(peer->lsdb_nei->reach_link);
     bgp_ls_free_nlri_prefix_list(peer->lsdb_nei->reach_prefix_ip4);
     bgp_ls_free_nlri_prefix_list(peer->lsdb_nei->reach_prefix_ip6);
     bgp_ls_free_nlri_sr6_sid_list(peer->lsdb_nei->reach_sr6_sid);
     bgp_ls_free_nlri_te_policy_list(peer->lsdb_nei->reach_te_policy);
 
     bgp_ls_free_nlri_node_list(peer->lsdb_nei->withdraw_node);
     bgp_ls_free_nlri_link_list(peer->lsdb_nei->withdraw_link);
     bgp_ls_free_nlri_prefix_list(peer->lsdb_nei->withdraw_prefix_ip4);
     bgp_ls_free_nlri_prefix_list(peer->lsdb_nei->withdraw_prefix_ip6);
     bgp_ls_free_nlri_sr6_sid_list(peer->lsdb_nei->withdraw_sr6_sid);
 
     bgp_ls_free_attr_list(peer->lsdb_nei->attri_node);
     bgp_ls_free_attr_list(peer->lsdb_nei->attri_link);
     bgp_ls_free_attr_list(peer->lsdb_nei->attri_prefix_ip4);
     bgp_ls_free_attr_list(peer->lsdb_nei->attri_prefix_ip6);
     bgp_ls_free_attr_list(peer->lsdb_nei->attri_sr6_sid);
 }
 
 /*When deleting a neighbor, delete the neighbor data*/
 void bgp_peer_lsdb_delete(struct peer *peer)
 {
     //bgp_ls_local_del_peer(peer->bgp);
 
     bgp_ls_free_nlri_node_list(peer->lsdb_nei->reach_node);
     bgp_ls_free_nlri_link_list(peer->lsdb_nei->reach_link);
     bgp_ls_free_nlri_prefix_list(peer->lsdb_nei->reach_prefix_ip4);
     bgp_ls_free_nlri_prefix_list(peer->lsdb_nei->reach_prefix_ip6);
     bgp_ls_free_nlri_sr6_sid_list(peer->lsdb_nei->reach_sr6_sid);
     bgp_ls_free_nlri_te_policy_list(peer->lsdb_nei->reach_te_policy);
 
     bgp_ls_free_nlri_node_list(peer->lsdb_nei->withdraw_node);
     bgp_ls_free_nlri_link_list(peer->lsdb_nei->withdraw_link);
     bgp_ls_free_nlri_prefix_list(peer->lsdb_nei->withdraw_prefix_ip4);
     bgp_ls_free_nlri_prefix_list(peer->lsdb_nei->withdraw_prefix_ip6);
     bgp_ls_free_nlri_sr6_sid_list(peer->lsdb_nei->withdraw_sr6_sid);
 
     bgp_ls_free_attr_list(peer->lsdb_nei->attri_node);
     bgp_ls_free_attr_list(peer->lsdb_nei->attri_link);
     bgp_ls_free_attr_list(peer->lsdb_nei->attri_prefix_ip4);
     bgp_ls_free_attr_list(peer->lsdb_nei->attri_prefix_ip6);
     bgp_ls_free_attr_list(peer->lsdb_nei->attri_sr6_sid);
 
     list_delete(&peer->lsdb_nei->reach_node);
     list_delete(&peer->lsdb_nei->reach_link);
     list_delete(&peer->lsdb_nei->reach_prefix_ip4);
     list_delete(&peer->lsdb_nei->reach_prefix_ip6);
     list_delete(&peer->lsdb_nei->reach_sr6_sid);
     list_delete(&peer->lsdb_nei->reach_te_policy);
 
     list_delete(&peer->lsdb_nei->withdraw_node);
     list_delete(&peer->lsdb_nei->withdraw_link);
     list_delete(&peer->lsdb_nei->withdraw_prefix_ip4);
     list_delete(&peer->lsdb_nei->withdraw_prefix_ip6);
     list_delete(&peer->lsdb_nei->withdraw_sr6_sid);
 
     list_delete(&peer->lsdb_nei->attri_node);
     list_delete(&peer->lsdb_nei->attri_link);
     list_delete(&peer->lsdb_nei->attri_prefix_ip4);
     list_delete(&peer->lsdb_nei->attri_prefix_ip6);
     list_delete(&peer->lsdb_nei->attri_sr6_sid);
 
     peer->lsdb_nei->reach_node = NULL;
     peer->lsdb_nei->reach_link = NULL;
     peer->lsdb_nei->reach_prefix_ip4 = NULL;
     peer->lsdb_nei->reach_prefix_ip6 = NULL;
     peer->lsdb_nei->reach_sr6_sid = NULL;
     peer->lsdb_nei->reach_te_policy = NULL;
 
     peer->lsdb_nei->withdraw_node = NULL;
     peer->lsdb_nei->withdraw_link = NULL;
     peer->lsdb_nei->withdraw_prefix_ip4 = NULL;
     peer->lsdb_nei->withdraw_prefix_ip6 = NULL;
     peer->lsdb_nei->withdraw_sr6_sid = NULL;
 
     peer->lsdb_nei->attri_node = NULL;
     peer->lsdb_nei->attri_link = NULL;
     peer->lsdb_nei->attri_prefix_ip4 = NULL;
     peer->lsdb_nei->attri_prefix_ip6 = NULL;

     peer->lsdb_nei->attri_sr6_sid = NULL;
 
     XFREE(MTYPE_BGPLS_NLRI, peer->lsdb_nei);
     peer->lsdb_nei = NULL;
     RESET_FLAG(peer->lsdb_nei_flags);
     return;
 }
 
 
 
/*
 * ecm_pbuf.c
 *
 *  Created on: 2014-10-27
 *      Author: wshine
 */

#include <string.h>
#include <stdint.h>

#include "ecm_pbuf.h"
#include "ecm_memp.h"
#include "ecm_intf.h"

/**
 * Allocates a pbuf of the given type (possibly a chain for PBUF_POOL type).
 *
 * The actual memory allocated for the pbuf is determined by the
 * layer at which the pbuf is allocated and the requested size
 * (from the size parameter).
 *
 * @param layer flag to define header size
 * @param length size of the pbuf's payload
 * @param type this parameter decides how and where the pbuf
 * should be allocated as follows:
 *
 * - PBUF_RAM: buffer memory for pbuf is allocated as one large
 *             chunk. This includes protocol headers as well.
 * - PBUF_ROM: no buffer memory is allocated for the pbuf, even for
 *             protocol headers. Additional headers must be prepended
 *             by allocating another pbuf and chain in to the front of
 *             the ROM pbuf. It is assumed that the memory used is really
 *             similar to ROM in that it is immutable and will not be
 *             changed. Memory which is dynamic should generally not
 *             be attached to PBUF_ROM pbufs. Use PBUF_REF instead.
 * - PBUF_REF: no buffer memory is allocated for the pbuf, even for
 *             protocol headers. It is assumed that the pbuf is only
 *             being used in a single thread. If the pbuf gets queued,
 *             then pbuf_take should be called to copy the buffer.
 * - PBUF_POOL: the pbuf is allocated as a pbuf chain, with pbufs from
 *              the pbuf pool that is allocated during pbuf_init().
 *
 * @return the allocated pbuf. If multiple pbufs where allocated, this
 * is the first pbuf of a pbuf chain.
 */
struct ecm_pbuf *ecm_pbuf_alloc(uint16_t length)
{
    struct ecm_pbuf *p, *q, *r;
    uint16_t offset ;
    int32_t rem_len; /* remaining length */

    /* determine header offset */
    offset = 0;
    /* allocate head of pbuf chain into p */
    p = (struct ecm_pbuf *)ecm_memp_malloc(MEMP_EC_PBUF_POOL);//wshine 2015-10-26 23:51:09
    if (p == NULL)
    {
      return NULL;
    }

    p->type = TYPE_PBUF_POOL;
    p->next = NULL;

    /* make the payload pointer point 'offset' bytes into pbuf data memory */
    p->payload = EC_LWIP_MEM_ALIGN((void *)((uint8_t *)p + (EC_SIZEOF_STRUCT_PBUF + offset)));
    /* the total length of the pbuf chain is the requested size */
    p->tot_len = length;
    /* set the length of the first pbuf in the chain */
    p->len = EC_LWIP_MIN(length, EC_PBUF_POOL_BUFSIZE_ALIGNED - EC_LWIP_MEM_ALIGN_SIZE(offset));
    /* set reference count (needed here in case we fail) */
    p->ref = 1;
    /* now allocate the tail of the pbuf chain */
    /* remember first pbuf for linkage in next iteration */
    r = p;
    /* remaining length to be allocated */
    rem_len = length - p->len;
    /* any remaining pbufs to be allocated? */
    while (rem_len > 0)
    {
		q = (struct ecm_pbuf *)ecm_memp_malloc(MEMP_EC_PBUF_POOL);//wshine 2015-10-26 23:50:21
		if (q == NULL)
		{
	    /* free chain so far allocated */
		    ecm_pbuf_free(p);
		/* bail out unsuccesfully */
		    return NULL;
		}

		p->type = TYPE_PBUF_POOL;
		q->flags = 0;
		q->next = NULL;
		/* make previous pbuf point to this pbuf */
		r->next = q;
		/* set total length of this pbuf and next in chain */
		q->tot_len = (uint16_t)rem_len;
		/* this pbuf length is pool size, unless smaller sized tail */
		q->len = EC_LWIP_MIN((uint16_t)rem_len, EC_PBUF_POOL_BUFSIZE_ALIGNED);
		q->payload = (void *)((uint8_t *)q + EC_SIZEOF_STRUCT_PBUF);
		q->ref = 1;
		/* calculate remaining length to be allocated */
		rem_len -= q->len;
		/* remember this pbuf for linkage in next iteration */
		r = q;
    }
    /* end of chain */
    /*r->next = NULL;*/

  /* set reference count */
	p->ref = 1;
	/* set flags */
	p->flags = 0;
	return p;
}

/**
 * Dereference a pbuf chain or queue and deallocate any no-longer-used
 * pbufs at the head of this chain or queue.
 *
 * Decrements the pbuf reference count. If it reaches zero, the pbuf is
 * deallocated.
 *
 * For a pbuf chain, this is repeated for each pbuf in the chain,
 * up to the first pbuf which has a non-zero reference count after
 * decrementing. So, when all reference counts are one, the whole
 * chain is free'd.
 *
 * @param p The pbuf (chain) to be dereferenced.
 *
 * @return the number of pbufs that were de-allocated
 * from the head of the chain.
 *
 * @note MUST NOT be called on a packet queue (Not verified to work yet).
 * @note the reference counter of a pbuf equals the number of pointers
 * that refer to the pbuf (or into the pbuf).
 *
 * @internal examples:
 *
 * Assuming existing chains a->b->c with the following reference
 * counts, calling pbuf_free(a) results in:
 *
 * 1->2->3 becomes ...1->3
 * 3->3->3 becomes 2->3->3
 * 1->1->2 becomes ......1
 * 2->1->1 becomes 1->1->1
 * 1->1->1 becomes .......
 *
 */
uint8_t ecm_pbuf_free(struct ecm_pbuf *p)
{
	uint16_t type;
	struct ecm_pbuf *q;
	uint8_t count;

	if (p == NULL)
	{
		return 0;
	}

    count = 0;
	/* de-allocate all consecutive pbufs from the head of the chain that
	* obtain a zero reference count after decrementing*/
	while (p != NULL)
	{
		uint16_t ref;
		uint32_t key;
		key = GateHwi_enter(ecm_gate);
		/* decrease reference count (number of pointers to pbuf) */
		ref = --(p->ref);
		GateHwi_leave(ecm_gate, key);
		/* this pbuf is no longer referenced to? */
		if (ref == 0)
		{
			/* remember next pbuf in chain for next iteration */
			q = p->next;
			type = p->type;
			/* is this a pbuf from the pool? */
			if(type == TYPE_PBUF_POOL)
			{
			    ecm_memp_free(MEMP_EC_PBUF_POOL, p);//wshine 2015-10-26 23:49:41
			}else
			{
//              mem_free(p); /*from mem.c*/
			}

			count++;
			/* proceed to next pbuf */
			p = q;
			/* p->ref > 0, this pbuf is still referenced to */
			/* (and so the remaining pbufs in chain as well) */
        } else {
		  /* stop walking through the chain */
		  p = NULL;
		}
	}
	/* return number of de-allocated pbufs */
	return count;
}


void ecm_pbuf_ref(struct ecm_pbuf *p)
{
	uint32_t old_level;
	/* pbuf given? */
	if (p != NULL)
	{
		old_level = GateHwi_enter(ecm_gate);
		++(p->ref);
		GateHwi_leave(ecm_gate, old_level);
	}
}

uint8_t ecm_pbuf_clen(struct ecm_pbuf *p)
{
	uint8_t len;

	len = 0;
	while (p != NULL)
	{
		++len;
		p = p->next;
	}
	return len;
}

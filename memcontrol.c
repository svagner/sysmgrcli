#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include "include/common.h"

void *
xmalloc (unsigned long const size, char *label)
{
	void *result = malloc (size);
	struct xmemctl *entry;


	if (!result)
		FATAL_ARGS("Memory exhausted %s. %s", label, strerror(errno));
	entry = malloc(sizeof(struct xmemctl));
	entry->ptr = result;
	strcpy(entry->label, label);
	entry->size = size;
	LIST_INSERT_HEAD(&memctl, entry, xmemctl_list);
#ifdef DEBUGMALLOC	
	DPRINT_ARGS("MALLOC: %p size %ld label %s", entry->ptr, entry->size, label);
#endif
	return result;
}

void 
xfree (void *ptr)
{
	if (!ptr)
		return;
	struct xmemctl *xmemctl_entry;
	LIST_FOREACH(xmemctl_entry, &memctl, xmemctl_list)
	{
#ifdef DEBUGMALLOC	
			DPRINT_ARGS("MEM FOUND: %p size %ld label %s", xmemctl_entry->ptr, xmemctl_entry->size, xmemctl_entry->label);
#endif
		if (xmemctl_entry->ptr==ptr)
		{
#ifdef DEBUGMALLOC	
			DPRINT_ARGS("MEMFREE: %p size %ld label %s", ptr, xmemctl_entry->size, xmemctl_entry->label);
#endif
			LIST_REMOVE(xmemctl_entry, xmemctl_list);
			free(xmemctl_entry);
			xmemctl_entry=NULL;
			break;
		};
	};

};

void 
xfree_all (void)
{
	struct xmemctl *xmemctl_entry;
	LIST_FOREACH(xmemctl_entry, &memctl, xmemctl_list)
	{
#ifdef DEBUGMALLOC	
	    DPRINT_ARGS("MEMFREEALL: %p size %ld label %s", xmemctl_entry->ptr, xmemctl_entry->size, xmemctl_entry->label);
#endif
	    LIST_REMOVE(xmemctl_entry, xmemctl_list);
	    free(xmemctl_entry);
	    //xmemctl_entry=NULL;
	};
};

void *
xrealloc (register void *ptr, register unsigned long const size)
{
	struct xmemctl *xmemctl_entry, *entry;

	register void *result = realloc (ptr, size);
	//xfree(ptr);
	int i = 0;

	if (!result)
		FATAL("Memory exhausted");
	LIST_FOREACH(xmemctl_entry, &memctl, xmemctl_list)
	{
		if (xmemctl_entry->ptr==ptr)
		{
#ifdef DEBUGMALLOC	
			DPRINT_ARGS("[ID:%d] MEMREALLOC: %p size %ld to %d", i, ptr, xmemctl_entry->size, size);
#endif
			LIST_REMOVE(xmemctl_entry, xmemctl_list);
			xfree(xmemctl_entry);
			xmemctl_entry=NULL;
			entry = xmalloc(sizeof(struct xmemctl), "reallocated");
			entry->ptr = result;
			entry->size = size;
			LIST_INSERT_HEAD(&memctl, entry, xmemctl_list);
#ifdef DEBUGMALLOC	
			DPRINT_ARGS("%p size %ld", entry, entry->size);
#endif
			return result;
		};
		i++;
	};
	return result;
}

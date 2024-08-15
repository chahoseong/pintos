#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <stdbool.h>
#include "vm/mapping.h"
#include "filesys/off_t.h"

typedef struct hash page_table_t;

enum segment
  {
    SEG_CODE,
    SEG_STACK,
    SEG_MAPPING,
  };

struct page
  {
    struct hash_elem elem;
    void *address;
    enum segment segment;
    bool writable;
    struct file *file;
    off_t position;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    mapid_t mapid;
  };

void page_table_init (page_table_t *table);
void page_table_destroy (page_table_t *table);
void page_table_insert (page_table_t *table, struct page *page);
struct page * page_table_lookup (page_table_t *table, const void *address);

#endif /* vm/page.h */
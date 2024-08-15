#ifndef VM_MAPPING_H
#define VM_MAPPING_H

#include <list.h>
#include "filesys/file.h"

typedef int mapid_t;
#define MAP_FAILED ((mapid_t) -1)

struct mapping
  {
    struct list_elem elem;
    mapid_t mapid;
    struct file *file;
  };

#endif /* vm/mapping.h */
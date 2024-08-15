#include "swap.h"
#include <bitmap.h>
#include <list.h>
#include "devices/block.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

struct slot
  {
    struct list_elem elem;
    tid_t tid;
    void *upage;
    size_t index;
  };

static struct list swap_table;
static struct lock swap_table_lock;
static struct bitmap *slot_map;
static size_t slot_count;

static struct slot * find_swap_slot (tid_t tid, void *upage);

void
swap_table_init (void)
{
  list_init (&swap_table);
  lock_init (&swap_table_lock);

  struct block *b = block_get_role (BLOCK_SWAP);
  slot_count = (block_size (b) * BLOCK_SECTOR_SIZE) / PGSIZE;
  slot_map = bitmap_create (slot_count);
}

void
swap_table_remove (tid_t tid, void *upage)
{
  lock_acquire (&swap_table_lock);
  struct slot *s = find_swap_slot (tid, upage);
  if (s != NULL)
    {
      list_remove (&s->elem);
      bitmap_set (slot_map, s->index, false);
      free (s);
    }
  lock_release (&swap_table_lock);
}

off_t
swap_table_swap_in (tid_t tid, void *upage, void *kpage)
{
  lock_acquire (&swap_table_lock);

  struct block *b = block_get_role (BLOCK_SWAP);
  size_t index = bitmap_scan (slot_map, 0, 1, false);

  ASSERT (index != BITMAP_ERROR);

  off_t start = (PGSIZE * index) / BLOCK_SECTOR_SIZE;
  off_t ofs = start;
  size_t write_bytes = PGSIZE;
  uint8_t *buffer = kpage;

  while (write_bytes > 0)
    {
      block_write (b, ofs, buffer);
      ++ofs;
      write_bytes -= BLOCK_SECTOR_SIZE;
      buffer += BLOCK_SECTOR_SIZE;
    }

  struct slot *s = malloc (sizeof (struct slot));
  s->tid = tid;
  s->upage = upage;
  s->index = index;
  list_push_back (&swap_table, &s->elem);
  bitmap_set (slot_map, index, true);

  lock_release (&swap_table_lock);

  return start;
}

void
swap_table_swap_out (tid_t tid, void *upage, void *kpage, off_t position)
{
  lock_acquire (&swap_table_lock);

  struct slot *s = find_swap_slot (tid, upage);
  if (s != NULL)
    {
      struct block *b = block_get_role (BLOCK_SWAP);
      size_t read_bytes = PGSIZE;
      uint8_t *buffer = kpage;
      
      while (read_bytes > 0)
        {
          block_read (b, position, buffer);
          ++position;
          read_bytes -= BLOCK_SECTOR_SIZE;
          buffer += BLOCK_SECTOR_SIZE;
        }

      list_remove (&s->elem);
      bitmap_set (slot_map, s->index, false);
      
      free (s);
    }

  lock_release (&swap_table_lock);
}

bool
swap_table_is_swapped (tid_t tid, void *upage)
{
  return find_swap_slot (tid, upage) != NULL;
}

static struct slot *
find_swap_slot (tid_t tid, void *upage)
{
  for (struct list_elem *cursor = list_begin (&swap_table); cursor != list_end (&swap_table); cursor = list_next (cursor))
    {
      struct slot *s = list_entry (cursor, struct slot, elem);
      if (s->tid == tid && s->upage == upage)
        return s;
    }
  return NULL;
}
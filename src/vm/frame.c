#include "frame.h"
#include "page.h"
#include "swap.h"
#include <list.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

struct frame
  {
    struct list_elem elem;
    tid_t tid;
    uint32_t *pagedir;
    page_table_t *extra_page_table;
    void *upage;
    void *kpage;
  };

static struct list frame_table = LIST_INITIALIZER (frame_table);
static struct list locked_frame_list = LIST_INITIALIZER (locked_frame_list);
static struct lock frame_table_lock;

static void frame_table_update (void);
static void lock_frame (struct frame *);
static void unlock_frame (struct frame *);
static struct frame * find_frame_with_upage (struct list *list, const void *upage);
static struct frame * find_frame_with_kpage (struct list *list, const void *kpage);

void
frame_table_init (void)
{
  lock_init (&frame_table_lock);
}

static void
frame_table_update (void)
{
  if (list_empty (&frame_table))
    return;

  lock_acquire (&frame_table_lock);

  struct list_elem *cursor = list_begin (&frame_table);
  while (cursor != list_end (&frame_table))
    {
      struct frame *f = list_entry (cursor, struct frame, elem);
      if (f->pagedir != NULL && pagedir_is_accessed (f->pagedir, f->upage))
        {
          struct list_elem *prev = cursor;
          cursor = list_remove (prev);
          list_push_front (&frame_table, prev);
        }
      else
        cursor = list_next (cursor);
    }

  lock_release (&frame_table_lock);
}

void *
frame_table_set_frame (void *upage)
{
  void *kpage = palloc_get_page (PAL_USER);
  struct frame *f;

  if (!kpage)
    {
      frame_table_update ();

      lock_acquire (&frame_table_lock);
      f = list_entry (list_back (&frame_table), struct frame, elem);
      list_remove (&f->elem);
      lock_release (&frame_table_lock);

      struct page *p = page_table_lookup (f->extra_page_table, f->upage);
      switch (p->segment)
        {
          case SEG_CODE:
          case SEG_STACK:
            if (p->writable)
              {
                if (pagedir_is_dirty (f->pagedir, f->upage) || !swap_table_is_swapped (f->tid, f->upage))
                  p->position = swap_table_swap_in (f->tid, f->upage, f->kpage);
              }
            break;
          case SEG_MAPPING:
            if (pagedir_is_dirty (f->pagedir, f->upage))
              {
                file_seek (p->file, p->position);
                file_write (p->file, f->kpage, PGSIZE);
              }
            break;
        }

      pagedir_clear_page (f->pagedir, f->upage);
    }
  else
    {
      f = malloc (sizeof (struct frame));
      f->kpage = kpage;
    }

  struct thread *t = thread_current ();

  f->tid = t->tid;
  f->pagedir = t->pagedir;
  f->extra_page_table = &t->extra_page_table;
  f->upage = upage;

  lock_acquire (&frame_table_lock);
  list_push_front (&frame_table, &f->elem);
  lock_release (&frame_table_lock);

  return f->kpage;
}

void *
frame_table_get_frame (void *upage)
{
  lock_acquire (&frame_table_lock);
  struct frame *f = find_frame_with_upage (&frame_table, upage);
  lock_release (&frame_table_lock);
  return f != NULL ? f->kpage : NULL;
}

void
frame_table_clear_frame (void * upage)
{
  lock_acquire (&frame_table_lock);
  struct frame *f = find_frame_with_upage (&frame_table, upage);
  if (f != NULL)
    {
      list_remove (&f->elem);
      free (f);
    }
  lock_release (&frame_table_lock);
}

void
frame_table_lock_frame (void *kpage)
{
  lock_acquire (&frame_table_lock);
  struct frame *f = find_frame_with_kpage (&frame_table, kpage);
  if (f != NULL)
    lock_frame (f);
  lock_release (&frame_table_lock);
}

static void
lock_frame (struct frame *f)
{
  list_remove (&f->elem);
  list_push_back (&locked_frame_list, &f->elem);
}

void
frame_table_unlock_frame (void *kpage)
{
  lock_acquire (&frame_table_lock);
  struct frame *f = find_frame_with_kpage (&locked_frame_list, kpage);
  if (f != NULL)
    unlock_frame (f);
  lock_release (&frame_table_lock);
}

static void
unlock_frame (struct frame *f)
{
  list_remove (&f->elem);
  list_push_front (&frame_table, &f->elem);
}

static struct frame *
find_frame_with_upage (struct list *list, const void *upage)
{
  for (struct list_elem *cursor = list_begin (list); cursor != list_end (list); cursor = list_next (cursor))
    {
      struct frame *f = list_entry (cursor, struct frame, elem);
      if (f->upage == upage)
        return f;
    }
  return NULL;
}

static struct frame *
find_frame_with_kpage (struct list *list, const void *kpage)
{
  for (struct list_elem *cursor = list_begin (list); cursor != list_end (list); cursor = list_next (cursor))
    {
      struct frame *f = list_entry (cursor, struct frame, elem);
      if (f->kpage == kpage)
        return f;
    }
  return NULL;
}
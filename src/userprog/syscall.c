#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#define STDOUT_BUFFER_SIZE 512

static void syscall_handler (struct intr_frame *);

static void halt (void);
static tid_t exec (const char *cmd_line);
static int wait (tid_t tid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);

static void pop_stack (void **esp, void *value, size_t size);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int number = 0;
  pop_stack (&f->esp, &number, sizeof number);

  switch (number)
    {
      case SYS_HALT:
        halt ();
        break;
      case SYS_EXIT:
        {
          int status;
          pop_stack (&f->esp, &status, sizeof status);

          exit (status);
        }
        break;
      case SYS_EXEC:
        {
          char *cmd_line;
          pop_stack (&f->esp, &cmd_line, sizeof cmd_line);

          f->eax = exec (cmd_line);
        }
        break;
      case SYS_WAIT:
        {
          tid_t tid;
          pop_stack (&f->esp, &tid, sizeof tid);

          f->eax = wait (tid);
        }
        break;
      case SYS_CREATE:
        {
          char *file;
          pop_stack (&f->esp, &file, sizeof file);

          unsigned initial_size;
          pop_stack (&f->esp, &initial_size, sizeof initial_size);

          f->eax = create (file, initial_size);
        }
        break;
      case SYS_REMOVE:
        {
          char *file;
          pop_stack (&f->esp, &file, sizeof file);

          f->eax = remove (file);
        }
        break;
      case SYS_OPEN:
        {
          char *file;
          pop_stack (&f->esp, &file, sizeof file);

          f->eax = open (file);
        }
        break;
      case SYS_FILESIZE:
        {
          int fd;
          pop_stack (&f->esp, &fd, sizeof fd);

          f->eax = filesize (fd);
        }
        break;
      case SYS_READ:
        {
          int fd;
          pop_stack (&f->esp, &fd, sizeof fd);

          void *buffer;
          pop_stack (&f->esp, &buffer, sizeof buffer);

          unsigned size;
          pop_stack (&f->esp, &size, sizeof size);

          f->eax = read (fd, buffer, size);
        }
        break;
      case SYS_WRITE:
        {
          int fd;
          pop_stack (&f->esp, &fd, sizeof fd);

          void *buffer;
          pop_stack (&f->esp, &buffer, sizeof buffer);

          unsigned size;
          pop_stack (&f->esp, &size, sizeof size);

          f->eax = write (fd, buffer, size);
        }
        break;
      case SYS_SEEK:
        {
          int fd;
          pop_stack (&f->esp, &fd, sizeof fd);

          unsigned position;
          pop_stack (&f->esp, &position, sizeof position);

          seek (fd, position);
        }
        break;
      case SYS_TELL:
        {
          int fd;
          pop_stack (&f->esp, &fd, sizeof fd);

          f->eax = tell (fd);
        }
        break;
      case SYS_CLOSE:
        {
          int fd;
          pop_stack (&f->esp, &fd, sizeof fd);
          
          close (fd);
        }
        break;
      default:
        exit (-1);
    }
}

static void
halt (void)
{
  shutdown_power_off ();
}

void
exit (int status)
{
  struct thread *t = thread_current ();
  t->exit_status = status;
  printf ("%s: exit(%d)\n", t->name, status);
  thread_exit ();
}

static tid_t
exec (const char *cmd_line)
{
  if (is_user_vaddr (cmd_line))
    return process_execute (cmd_line);
  else
    return TID_ERROR;
}

static int
wait (tid_t tid)
{
  return process_wait (tid);
}

static bool
create (const char *file, unsigned initial_size)
{
  if (file == NULL)
    exit (-1);
  if (!is_user_vaddr (file))
    return false;

  lock_acquire (&file_lock);
  bool result = filesys_create (file, initial_size);
  lock_release (&file_lock);
  return result;
}

static bool
remove (const char *file)
{
  if (!is_user_vaddr (file))
    return false;

  lock_acquire (&file_lock);
  bool result = filesys_remove (file);
  lock_release (&file_lock);
  return result;
}

static int
open (const char *file)
{
  if (file != NULL && is_user_vaddr (file))
    {
      struct thread *t = thread_current ();
      int fd = STDOUT_FILENO + 1;

      /* Find unused file descriptor. */
      while (fd < NOFILE)
        {
          if (t->open_files[fd] == NULL)
            break;
          else
            fd++;
        }

      if (fd < NOFILE)
        {
          lock_acquire (&file_lock);
          t->open_files[fd] = filesys_open (file);
          lock_release (&file_lock);
          if (t->open_files[fd] != NULL)
            return fd;
        }
    }

  return -1;
}

static int
filesize (int fd)
{
  if (fd < 0 || fd >= NOFILE)
    goto error;
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
    goto error;

  struct thread *t = thread_current ();

  if (t->open_files[fd] != NULL)
    return file_length (t->open_files[fd]);

error:
  return -1;
}

static int
read (int fd, void *buffer, unsigned size)
{
  if (fd < 0 || fd >= NOFILE)
    goto error;
  if (!(is_user_vaddr (buffer) && is_user_vaddr (buffer + size)))
    exit (-1);

  struct thread *t = thread_current ();

  if (fd == STDIN_FILENO)
    {
      unsigned read_bytes = 0;
      while (read_bytes < size)
        {
          uint8_t data = input_getc ();
          memcpy ((uint8_t*)buffer + read_bytes, &data, sizeof data);
          read_bytes += sizeof (data);
        }
      return size;
    }
  else if (t->open_files[fd] != NULL)
    return file_read (t->open_files[fd], buffer, size);

error:
  return -1;
}

static int
write (int fd, const void *buffer, unsigned size)
{
  if (fd < 0 || fd >= NOFILE)
    goto error;
  if (!(is_user_vaddr (buffer) && is_user_vaddr (buffer + size)))
    goto error;

  struct thread *t = thread_current ();

  if (fd == STDOUT_FILENO)
    {
      int remaining = size;
      int offset = 0;

      while (remaining > STDOUT_BUFFER_SIZE)
        {
          putbuf (buffer + offset, STDOUT_BUFFER_SIZE);
          remaining -= STDOUT_BUFFER_SIZE;
          offset += STDOUT_BUFFER_SIZE;
        }
      
      if (remaining > 0)
        putbuf (buffer + offset, remaining);

      return size;
    }
  else if (t->open_files[fd] != NULL)
    return file_write (t->open_files[fd], buffer, size);

error:
  return -1;
}

static void
seek (int fd, unsigned position)
{
  if (fd >= 0 && fd < NOFILE)
    file_seek (thread_current ()->open_files[fd], position);
}

static unsigned
tell (int fd)
{
  if (fd >= 0 && fd < NOFILE)
    return file_tell (thread_current ()->open_files[fd]);
  else
    return 0;
}

static void
close (int fd)
{
  if (fd >= 0 && fd < NOFILE)
    {
      struct thread *t = thread_current ();
      lock_acquire (&file_lock);
      file_close (t->open_files[fd]);
      lock_release (&file_lock);
      t->open_files[fd] = NULL;
    }
}

static void
pop_stack (void **esp, void *value, size_t size)
{
  memcpy (value, *esp, size);
  *esp += size;
  if (!is_user_vaddr (*esp))
    exit (-1);
}
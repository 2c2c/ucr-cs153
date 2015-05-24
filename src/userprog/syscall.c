//cleanup
#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <inttypes.h>
#include <list.h> 
typedef int pid_t;
typedef int fid_t;

//increment each allocation of an fid to a given file created
static fid_t global_fid = 2;

static struct lock flock;

static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static int read_address (const void * address);
static void halt (void);
static void exit (int status);
static pid_t exec (const char *cmd_line);
static int wait (pid_t pid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);

static struct file_helper* get_file(int fid);

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

}

static void
syscall_handler (struct intr_frame *frame) 
{

  int syscall = read_address (frame -> esp);
  
  if (syscall == SYS_HALT)
  {
    halt();
  }
  else if (syscall == SYS_EXIT)
  {
    exit (read_address(frame -> esp + 4));
  }
  else if (syscall == SYS_EXEC)
  {
    frame -> eax = (uint32_t) exec((const char *) read_address (frame -> esp + 4) );
  }
  else if (syscall == SYS_WAIT)
  {
    frame -> eax = (uint32_t) wait ((pid_t) read_address (frame -> esp + 4) );
  }
  else if (syscall == SYS_CREATE)
  {
    frame -> eax = (uint32_t) create ((const char *) read_address (frame -> esp + 4),
					  (unsigned) read_address (frame -> esp + 8) );
  }
  else if (syscall == SYS_REMOVE)
  {
    frame -> eax = (uint32_t) remove ((const char *) read_address (frame -> esp + 4) );
  }
  else if (syscall == SYS_OPEN)
  {
    frame -> eax = (uint32_t) open ((const char *) read_address (frame -> esp + 4) );
  }
  else if (syscall == SYS_FILESIZE)
  {
    frame -> eax = (uint32_t) filesize (read_address (frame -> esp + 4) );
  }
  else if (syscall == SYS_READ)
  {
    frame -> eax = (uint32_t) read (read_address (frame -> esp + 4),
		          (void *) read_address (frame -> esp + 8),
		          (unsigned) read_address (frame -> esp + 12) );
  }
  else if (syscall == SYS_WRITE)
  {
    frame -> eax = (uint32_t) read (read_address (frame -> esp + 4),
		          (const void *) read_address (frame -> esp + 8),
		          (unsigned) read_address (frame -> esp + 12) );
  }
  else if (syscall == SYS_SEEK)
  {
    seek (read_address (frame -> esp + 4),
	  (unsigned) read_address (frame -> esp + 8) );
  }
  else if (syscall == SYS_TELL)
  {
    frame -> eax = (uint32_t) tell (read_address (frame -> esp + 4) );
  }
  else if (syscall == SYS_CLOSE)
  {
    close (read_address (frame -> esp + 4) );
  }
  else 
  {
    printf("not a system call: what a disaster");
    thread_exit ();
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
  struct thread *t;

  t = thread_current ();
  if (lock_held_by_current_thread (&flock) )
    lock_release (&flock);

//while the list of files a thread owns is NOT empty
//iterate through each entry and run close() on said file
//set thread's return status
  thread_exit ();
}

static pid_t
exec (const char *cmd_line)
{
  lock_acquire (&flock);
  //exec file
  //int exec_status  = process_execute (cmd_line);
  lock_release (&flock);
  return 0;
  //return exec_status;
}

static int
wait (pid_t pid)
{
  //need process_wait implemented
  //return process_wait (pid);
}

static bool
create (const char *file, unsigned initial_size)
{
  if (file == NULL)
    exit (-1);
  lock_acquire(&flock);
  int create_status = filesys_create (file, initial_size);
  lock_release(&flock);
  return create_status;
}

static bool
remove (const char *file)
{
   if (file == NULL)
     exit (-1);
   lock_acquire (&flock);
   bool remove_status = filesys_remove (file);
   lock_release (&flock);
   return remove_status;
}

static int
open (const char *file)
{
  struct file *sysfile;
  struct file_helper *ufile;

  if (sysfile == NULL)
    return -1;

  lock_acquire (&flock);
  sysfile = filesys_open (file);
  lock_release (&flock);

  //if failed to open
  if (sysfile == NULL)
    return -1;

  ufile = (struct file_helper *) malloc (sizeof (struct file_helper));
  if (ufile == NULL)
    {
      file_close (file);
      return -1;
    }

  lock_acquire (&flock);
  ufile->file = file;
  //global_fid is static global var that handles allocation of fids
  ufile->fid = global_fid;
  global_fid++;
  //add the file_helper struct to the list of file_helpers in the current thread
  lock_release (&flock);

  return ufile->fid;
}

static int
filesize (int fd)
{
  struct file_helper *ufile;	
  int size = -1;
  ufile = get_file (fd);
  if (ufile == NULL)
  {
    return -1;
  }

  lock_acquire (&flock);
  size = file_length (ufile->file);
  lock_release (&flock);

  return size;
}

static int
read (int fd, void *buffer, unsigned length)
{
  struct file_helper *ufile;
  int read_status = -1;

  lock_acquire (&flock);
  //if stdin use getc
  if (fd == STDIN_FILENO)
    {
      int i;
      for (i = 0; i < length; ++i)
      {
        *(unsigned char *)(buffer + i) = input_getc ();
      }
      read_status = length;
    }
  //can't read from stdout
  else if (fd == STDOUT_FILENO)
    read_status = -1;
  //check if entire memory length is in userspace
  else if ( !is_user_vaddr (buffer) || !is_user_vaddr (buffer + length) )
    {
      lock_release (&flock);
      exit (-1);
    }
  //file case
  else
    {
      //return 
      ufile = get_file (fd);
      if (ufile == NULL)
        read_status = -1;
      else
        read_status = file_read (ufile->file, buffer, length);
    }
  lock_release (&flock);

  return read_status;
}

static int
write (int fd, const void *buffer, unsigned length)
{
  struct file_helper *ufile;
  int write_status = -1;

  lock_acquire (&flock);
  if (fd == STDIN_FILENO)
    write_status = -1;
  else if (fd == STDOUT_FILENO)
    {
      putbuf (buffer, length);
      write_status = length;
    }
  else if ( !is_user_vaddr (buffer) || !is_user_vaddr (buffer + length) )
    {
      lock_release (&flock);
      exit (-1);
    }
  else
    {
     ufile = get_file (fd);
      if (ufile == NULL)
      {
        write_status = -1;
      }
      else
      {
        write_status = file_write (ufile->file, buffer, length);
      }
    }
  lock_release (&flock);

  return write_status;
}

static void
seek (int fd, unsigned position)
{
  struct file_helper *ufile;

  ufile = get_file (fd);
  if (!ufile)
    exit (-1);

  lock_acquire (&flock);
  file_seek (ufile->file, position);
  lock_release (&flock);
}

static unsigned
tell (int fd)
{
  struct file_helper *ufile;

  unsigned int tell_status;

  ufile = get_file (fd);
  if (!ufile)
  {
    exit (-1);
  }
  lock_acquire (&flock);
  tell_status = file_tell (ufile->file);
  lock_release (&flock);

  return tell_status;
}

static void
close (int fd)
{
  struct file_helper *ufile;

  ufile = get_file (fd);

  if (ufile == NULL)
    exit (-1);

  lock_acquire (&flock);
  list_remove (&ufile -> elem);
  file_close (ufile -> file);
  free (ufile);
  lock_release (&flock);
}

static struct file_helper *
get_file (int fid)
{
  struct list_elem *e;
  struct thread *t;

  t = thread_current();
  for (e = list_begin (&t->owned_files); e != list_end (&t->owned_files); e = list_next (e))
    {
      struct file_helper *fh = list_entry (e, struct file_helper, elem);
      if (fh->fid == fid)
        return fh;
    }
  return NULL;
}


//read 4 bytes from memory
//returns error if not from userspace
//uses get_user to read a single byte and appropiately logical shifts and ORs bits together to create a 4byte return value
//
//NEEDS TO BE BUG TESTED, bits might be in backwards order
static int
read_address(const void * address) {
  if(address >= PHYS_BASE) 
  {
     exit (-1); 
  }
  uint8_t *byte = (uint8_t *) address;
  int result = 0;
  int temp;
  int i = 0;
  //i is used two ways: ith byte position
  //(so address position plus 0,1,2,3 bytes)
  //or number of bits to shift (0,8,16,24 bits)
  for (i; i <= 3; i++)
  {
    temp = get_user (byte + i);
    if (temp == -1)
    {
      exit (-1);
    }
    result |= (temp << i*8);
  }
  return result;
}

 	

/* Reads a byte at user virtual address UADDR.
 *    UADDR must be below PHYS_BASE.
 *       Returns the byte value if successful, -1 if a segfault
 *          occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}
 
/* Writes BYTE to user address UDST.
 *    UDST must be below PHYS_BASE.
 *       Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}


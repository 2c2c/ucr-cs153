//cleanup
#include "userprog/syscall.h"
#include "userprog/process.h"
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
void soft_lock(void);
void soft_release(void);
static struct file_helper* get_file(int fid);

static void syscall_handler (struct intr_frame *);
static bool safe_ptr (const void *ptr);

void
soft_lock (void)
{
  if (!lock_held_by_current_thread (&flock))
    lock_acquire (&flock);
}

void
soft_release (void)
{
  if (lock_held_by_current_thread (&flock))
    lock_release (&flock);
}
void
syscall_init (void) 
{
  lock_init(&flock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *frame) 
{

  int syscall = read_address (frame -> esp);
  //printf("\nsyscall: %d\n", syscall);
  
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
    frame -> eax = (uint32_t) write (read_address (frame -> esp + 4),
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
    //printf("not a system call: what a disaster");
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
  struct thread *t = thread_current ();

  //REQUIRED output
  printf("%s: exit(%d)\n", thread_current()->name, status);

  soft_release ();

  //while the list of files a thread owns is NOT empty
  //iterate through each entry and run close() on said file
  struct list_elem * f;
  while (!list_empty (&(t->owned_files)))
  {
    f = list_begin (&(t->owned_files));
    fid_t fd = (list_entry (f, struct file_helper, elem))-> fid;
    //printf("close %d\n",fd);
    close (fd); 
  }

  //close file assoc with current thread
  if (t->bin != NULL)
  {
    soft_lock ();
    file_allow_write (t->bin);
    file_close (t->bin);
    soft_release();
  }

  //list of children
  struct list_elem * c;
  while (!list_empty (&(t->children)))
  {
    struct child *child = list_entry (c, struct child, elem);
    if (!(child -> is_fin))
    {
      struct thread *th_orphan = get_thread (child -> pid);
      th_orphan -> parent_tid = 1;
    }
   list_remove (& (child -> elem));
   palloc_free_page(child);
  }
  
  //get parent of current thread
  struct thread *p = get_thread (t -> parent_tid);
  struct list_elem *pe = list_begin(&(p -> children));
  for (pe ; pe != list_end(& (p -> children)); pe = list_next (pe))
  {
    struct child *pe_entry = list_entry(pe, struct child, elem);
    if (pe_entry -> pid == t -> tid)
    {
      pe_entry -> is_fin = true;
      pe_entry -> return_value = status;
    }
    if (pe_entry -> is_waiting)
    {
      thread_unblock (p);
    }
  }

  //set thread's return status
  t -> loaded = status;
  
  thread_exit ();
}

static pid_t
exec (const char *cmd_line)
{
  if (!safe_ptr(cmd_line))
     return (-1); 
  soft_lock ();
  int exec_status  = process_execute (cmd_line);
  soft_release ();

  return exec_status;
}

static int
wait (pid_t pid)
{
  return process_wait (pid);
}

static bool
create (const char *file, unsigned initial_size)
{
  if (!safe_ptr(file))
     return false; 
  soft_lock ();
  bool create_status = filesys_create (file, initial_size);
  soft_release ();
  return create_status;
}

static bool
remove (const char *file)
{
  if (!safe_ptr(file))
     return false; 
   soft_lock ();
   bool remove_status = filesys_remove (file);
   soft_release ();
   return remove_status;
}

static int
open (const char *file)
{
  if (!safe_ptr(file))
     return -1; 

  soft_lock ();
  struct file *file_o;
  struct file_helper *ufile;

  file_o = filesys_open (file);
  //file DNE case
  if (file_o == NULL)
  {
    //printf("hello\n");
    soft_release ();
    return -1;
  }

  ufile = (struct file_helper *) malloc (sizeof (struct file_helper));
  //allocation error
  if (ufile == NULL)
  {
      filesys_remove (file_o);
      soft_release ();
      return -1;
  }
  //printf("HOW, %s", file);

  //setup file_helper and push onto thread's list of owned files
  ufile->file = file_o;
  //global_fid is static global var that handles allocation of fids
  ufile->fid = global_fid;
  global_fid++;
  //add the file_helper struct to the list of file_helpers in the current thread
  struct thread * tc = thread_current();
  list_push_back (&tc->owned_files, &ufile->elem);

  soft_release ();

  return ufile->fid;
}

static int
filesize (int fd)
{
  struct file_helper *ufile;	
  int size = -1;
  ufile = get_file (fd);

  soft_lock ();
  size = file_length (ufile->file);
  soft_release ();

  return size;
}

static int
read (int fd, void *buffer, unsigned length)
{
  //check buffer+len eventualy
  if (!safe_ptr(buffer))
     exit (-1); 
  struct file_helper *ufile;
  int read_status = -1;
  soft_lock ();

  //if stdin use getc
  if (fd == STDIN_FILENO)
    {
      int i;
      for (i = 0; i < length; i++)
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
      soft_release ();
      exit (-1);
    }
  //file case
  else
    {
      ufile = get_file (fd);
      //shouldnt even get here ?
      if (ufile == NULL)
        read_status = -1;
      else
        read_status = file_read (ufile->file, buffer, length);
    }
  soft_release ();

  return read_status;
}

static int
write (int fd, const void *buffer, unsigned length)
{
  //printf("\nwrite fd: %d\n",fd);

  if (!safe_ptr(buffer) || !safe_ptr(buffer+length))
     exit (-1); 
  
  //can't write on stdin
  if (fd == STDIN_FILENO)
    exit (-1);

  struct file_helper *ufile;
  int write_status = -1;

  if (fd == STDOUT_FILENO)
    {
      putbuf (buffer, length);
      write_status = length;
    }
  //file writecase
  else
    {
       soft_lock ();
       ufile = get_file (fd);
       write_status = file_write (ufile->file, buffer, length);
       soft_release ();
    }

  return write_status;
}

static void
seek (int fd, unsigned position)
{
  struct file_helper *ufile;

  ufile = get_file (fd);
  if (!ufile)
    exit (-1);

  soft_lock ();
  file_seek (ufile->file, position);
  soft_release ();
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
  soft_lock ();
  tell_status = file_tell (ufile->file);
  soft_release ();

  return tell_status;
}

static void
close (int fd)
{
  soft_lock ();

  struct file_helper *ufile;
  ufile = get_file (fd);

  list_remove (&ufile -> elem);
  file_close (ufile -> file);
  free (ufile);
  soft_release ();
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
  //get_file about to return NULL, abandon ship
  soft_release ();
  exit (-1);
}


//read 4 bytes from memory
//returns error if not from userspace
//uses get_user to read a single byte and appropiately logical shifts and ORs bits together to create a 4byte return value
//
//NEEDS TO BE BUG TESTED, bits might be in backwards order
static int
read_address(const void * address) {
  if (!safe_ptr(address))
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

//general pointer safety function
//design doc B3 answer
static bool
safe_ptr (const void *p)
{
  struct thread *ct = thread_current();
  if (p == NULL  ||
      !is_user_vaddr (p) ||
      pagedir_get_page (ct -> pagedir, p) == NULL
     )
  {
    //redundantly going to exit in caller functions as well for safety
    exit (-1);
    return false;
  }
  else
  {
    return true;
  }
}

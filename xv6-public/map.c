#include "wmap.h"
#include "types.h"
#include "defs.h"
#include "param.h"
#include "stat.h"
#include "mmu.h"
#include "memlayout.h"
#include "proc.h"
#include "fs.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "file.h"
#include "fcntl.h"
#include <sys/types.h>

//macro defs
#define LEN_TO_PAGE(va)   (0x1000 * ((int)(va) / PGSIZE))

//global defs

//helper functions

/**
 * Add values to process struct wmapinfo
 * Add to end of array
 * skips if full
*/
int add_mappings(struct proc* p, uint addr, int length, int a_len, int flags, int fd)
{
    if (p->_wmapinfo.total_mmaps == MAX_WMMAP_INFO)
    {
        return -1;
    }
    //cprintf("proc:%d, addr:%x, length:%d, a_len%d, flags:%d, fd:%d\n", p, addr, length, a_len, flags, fd);

    //add to mappings
    int index = p->_wmapinfo.total_mmaps;
    p->_wmapinfo.addr[index] = addr;
    p->_wmapinfo.length[index] = length;
    p->_wmapinfo.alloc_length[index] = a_len;
    p->_wmapinfo.n_loaded_pages[index] = 0;
    p->_wmapinfo.flags[index] = flags;
    p->_wmapinfo.fds[index] = fd;
    p->_wmapinfo.total_mmaps++;

    return 0;
}

/**
 * Remove values from process struct wmapinfo
 * Modifies array to be contiguous
*/
void remove_mappings(struct proc* p, int index)
{
    if (index > p->_wmapinfo.total_mmaps)
    {
        return;
    }

    //remove value
    for (int i = index; i < p->_wmapinfo.total_mmaps - 1; i++)
    {
        //shift next down
        p->_wmapinfo.addr[i] = p->_wmapinfo.addr[i+1];
        p->_wmapinfo.length[i] = p->_wmapinfo.length[i+1];
        p->_wmapinfo.alloc_length[i] = p->_wmapinfo.alloc_length[i+1];
        p->_wmapinfo.n_loaded_pages[i] = p->_wmapinfo.n_loaded_pages[i+1];
        p->_wmapinfo.flags[i] = p->_wmapinfo.flags[i+1];
        p->_wmapinfo.fds[i] = p->_wmapinfo.fds[i+1];
    }

    //decrement value
    p->_wmapinfo.total_mmaps--;
}

/**
 * Given a process, and index i to mapping info,
 * Compute if addr with a_len is overlapped with existsing
*/
int within_bounds(struct proc* proc, int i, uint addr, int a_len)
{
    //check if addr start within bounds
    if (addr >= proc->_wmapinfo.addr[i] && 
    addr < (proc->_wmapinfo.addr[i] + LEN_TO_PAGE(proc->_wmapinfo.alloc_length[i])))
    {
        //error return
        return -1;
    }

    //check if addr end withing bounds
    if ((addr + LEN_TO_PAGE(a_len)) >= proc->_wmapinfo.addr[i] && 
    (addr + LEN_TO_PAGE(a_len)) <= (proc->_wmapinfo.addr[i] + LEN_TO_PAGE(proc->_wmapinfo.alloc_length[i])))
    {
        //error return
        return -1;
    }

    //check if covers bounds
    if ((addr <= proc->_wmapinfo.addr[i]) && 
    ((addr + LEN_TO_PAGE(a_len)) >= (proc->_wmapinfo.addr[i] + LEN_TO_PAGE(proc->_wmapinfo.alloc_length[i]))))
    {
        //error return
        return -1;
    }

    //default return
    return 0;
}

/**
 * Find space for address
 * Simple linear search where if overlap found, address set to page after overlapped page
 * continue while loop on new addr
*/
uint find_space(struct proc* p, int length)
{
    //cprintf("Finding addr\n");
    uint addr = 0x60000000;

    //find addr
    while (addr < 0x80000000)
    {
        //check if address would be out of bounds
        if (addr + LEN_TO_PAGE(length) > 0x80000000)
        {
            return 0x0;
        }

        int overlap = 0;
        int i;
        for (i = 0; i < p->_wmapinfo.total_mmaps; i++)
        {
            //check for overlap
            if (within_bounds(p, i, addr, length) < 0)
            {
                overlap = 1;
                break;
            }
        }

        //check if no overlap found
        if (overlap == 0)
        {
            return addr;
        }
        else
        {
            //add change addr to end of overlapped value
            addr = p->_wmapinfo.addr[i] + LEN_TO_PAGE(p->_wmapinfo.alloc_length[i]);
        }
    }

    //defalt return
    return 0x0;
}


/**
 * wmap system call
 * 4 modes of operation
 * 
 * a) MAP_ANONYMOUS: It's NOT a file-backed mapping. 
 * You can ignore the last argument (fd) if this flag is provided.
 * 
 * b) MAP_SHARED: This flag tells wmap that the mapping is shared. 
 * You might be wondering, what does "shared" mean here? 
 * It will probably make much more sense if you also know about the MAP_PRIVATE flag. 
 * Memory mappings are copied from the parent to the child across the fork system call. 
 * If the mapping is MAP_SHARED, then changes made by the child will be visible to the parent and vice versa. 
 * However, if the mapping is MAP_PRIVATE, each process will have its own copy of the mapping.
 * 
 * c) MAP_PRIVATE: Mapping is not shared. 
 * You still need to copy the mappings from parent to child, but these mappings should use different "physical" pages. 
 * In other words, the same virtual addresses are mapped in child, but to a different set of physical pages. 
 * This flag will cause modifications to memory to be invisible to other processes. 
 * Moreover, if it's a file-backed mapping, modifications to memory are NOT carried through to the underlying file. 
 * See Best Practices for a guide on implementation. Between the flags MAP_SHARED and MAP_PRIVATE, one of them must be specified in flags. 
 * These two flags can NOT be used together.
 * 
 * d) MAP_FIXED: This has to do with the first argument of the wmap - the addr argument. 
 * Without MAP_FIXED, this address would be interpreted as a hint to where the mapping should be placed. 
 * If MAP_FIXED is set, then the mapping MUST be placed at exactly "addr". 
 * In this project, you only implement the latter. 
 * In other words, you don't care about the addr argument, unless MAP_FIXED has been set. 
 * Also, a valid addr will be a multiple of page size and within 0x60000000 and 0x80000000 (see A Note on Address Allocation).
 * 
 * All mapped memory is readable/writable. If you look at the man page for mmap, you'll see a prot (protection) argument. We don't have that argument and assume prot to always be PROT_READ | PROT_WRITE.
 * The maximum number of memory maps is 16.
 * For file-backed mapping, you can always expect the map size to be equal to the file size in our tests
*/
int sys_wmap(void)
{
    //fetch args
    uint addr;
    int length;
    int a_len;
    int flags;
    int fd;
    int a;

    if ((argint(0, &a) < 0) | (argint(1, &length) < 0) | (argint(2, &flags) < 0) | (argint(3, &fd) < 0))
    {
        //error occured return failiure
        return FAILED;
    }
    addr = (uint)a;

    //get calling process
    struct proc* proc = myproc();

    //check if private or shared error in input
    if ((((flags & MAP_PRIVATE) == MAP_PRIVATE) && ((flags & MAP_SHARED) == MAP_SHARED)) |
        (((flags & MAP_PRIVATE) != MAP_PRIVATE) && ((flags & MAP_SHARED) != MAP_SHARED)))
    {
        //error return
        return FAILED;
    }

    //parse flags and check for errors
    a_len = PGROUNDUP(length);
    if ((flags & MAP_FIXED) == MAP_FIXED)
    {
        //check for valid address bounds
        if ((addr < 0x60000000) | 
        ((addr + (0x1000 * (a_len / PGSIZE))) > 0x80000000) | 
        (addr % PGSIZE != 0))
        {
            //error return
            return FAILED;
        }

        //check if region avaliable
        for (int i = 0; i < proc->_wmapinfo.total_mmaps; i++)
        {
            if (within_bounds(proc, i, addr, a_len) < 0)
            {
                //error return
                return FAILED;
            }
        }
    }
    else
    {
        //find address mapping
        if ((addr = find_space(proc, a_len)) == 0x0)
        {
            //no address avaliable
            return FAILED;
        }
    }

    //add mapping
    if (add_mappings(proc, addr, length, a_len, flags, fd) < 0)
    {
        //error return
        return FAILED;
    }

    //return address on success
    return addr;
}

/**
 * wunmap removes the mapping starting at addr from the process virtual address space. 
 * If it's a file-backed mapping with MAP_SHARED, it writes the memory data back to the file to ensure the file remains up-to-date. 
 * So, wunmap does not partially unmap any mmap.
*/
int sys_wunmap(void)
{
    //get address
    uint addr;
    int a;
    if (argint(0, &a) < 0)
    {
        //error return
        return FAILED;
    }
    addr = (uint)a;

    //get process
    struct proc* p = myproc();

    //find address to map
    int i;
    for (i = 0; i < p->_wmapinfo.total_mmaps; i++)
    {
        if (addr == p->_wmapinfo.addr[i])
        {
            //match found
            break;
        }
    }

    //check if map not found
    if (i == p->_wmapinfo.total_mmaps)
    {
        //error return
        return FAILED;
    }

    //check if file backed
    if (((p->_wmapinfo.flags[i] & MAP_ANONYMOUS) == MAP_ANONYMOUS) && 
    ((p->_wmapinfo.flags[i] & MAP_SHARED) == MAP_SHARED))
    {
        //write to file
        struct file* f;
        if(p->_wmapinfo.fds[i] < 0 || p->_wmapinfo.fds[i] >= NOFILE || (f=myproc()->ofile[p->_wmapinfo.fds[i]]) == 0)
        {
            //error return
            return FAILED;
        }
        
        //write from each virtual address
        uint addr_cpy = addr;
        int n = 0;
        while (n != p->_wmapinfo.alloc_length[i])
        {
            filewrite(f, (char*)addr_cpy, PGSIZE);

            n += PGSIZE;
            addr_cpy += 0x1000;
        }

    }

    //remove mapping
    remove_mappings(p, i);

    //free physical mappings
    int n = 0;
    while(n != p->_wmapinfo.alloc_length[i])
    {
        pte_t* pte = walkpgdir(p->pgdir, (const void*)addr, 0);
        kfree((char*)P2V(PTE_ADDR(*pte)));
        *pte = 0;

        n += PGSIZE;
        addr += 0x1000;
    }
    
    //default return
    return SUCCESS;
}

/**
 * wremap is used to grow or shrink an existing mapping. 
 * The existing mapping can be modified in-place, or moved to a new address depending on the flags: 
 * If flags is 0, then wremap tries to grow/shrink the mapping in-place, and fails if there's not enough space. 
 * If MREMAP_MAYMOVE flag is set, then wremap should also try allocating the requested newsize by moving the mapping. 
 * Note that you're allowed to move the mapping only if you can't grow it in-place.
 * 
 * If wremap fails, the existing mapping should be left intact. 
 * In other words, you should only remove the old mapping after the new one succeeds.
*/
int sys_wremap(void)
{
    uint oldaddr;
    int oldsize, newsize, flags;
    if (argint(0, (int *)&oldaddr) < 0 || argint(1, &oldsize) < 0 ||
        argint(2, &newsize) < 0 || argint(3, &flags) < 0){
        return FAILED;
    }
    // Check if oldaddr is page aligned and within valid range
    if (oldaddr % PGSIZE != 0 || oldaddr < 0x60000000 || oldaddr >= KERNBASE) {
        return FAILED;
    }
    // Check if newsize is greater than 0
    if (newsize <= 0) {
        return FAILED;
    }
    // Get current process
    struct proc *p = myproc();

    // Find the mapping corresponding to oldaddr
    int mapping_index = -1;
    for (int i = 0; i < p->_wmapinfo.total_mmaps; i++)
    {
        if (oldaddr == p->_wmapinfo.addr[i])
        {
            mapping_index = i;
            break;
        }
    }
    // If mapping not found, return failure
    if (mapping_index == -1){
        return FAILED;
    }

    if(flags==0){
        //resizing in place
        if (newsize <= oldsize) {
            // Update the length of the mapping
            p->_wmapinfo.length[mapping_index] = newsize;
            return oldaddr; // Return the original address to indicate success
        } else {
            // Not enough space to grow the mapping in place, return failure
            return FAILED;
        }
        
    }
    //default return
    return SUCCESS;
}

/**
 * Add a new system call getpgdirinfo to retrieve information about the process address space 
 * by populating struct pgdirinfo. You should only gather information 
 * (either for calculating n_pages or returning va/pa pairs) on pages with PTE_U set 
 * (i.e. user pages). The only way to do that is to directly consult the page table 
 * for the process.
 *
 * This system call should calculate how many physical pages are currently allocated 
 * in the current process's address space and store it in n_upages. 
 * It should also populate va[MAX_UPAGE_INFO] and pa[MAX_UPAGE_INFO] with the first 
 * MAX_UPAGE_INFO (see Hints) pages' virtual address and physical address, 
 * ordered by the virtual addresses.
*/
int sys_getpgdirinfo(void)
{
    //get pointer
    struct pgdirinfo* ptr;
    char* _ptr;
    if (argptr(0, &_ptr, sizeof(struct pgdirinfo)) < 0)
    {
        //error return
        return FAILED;
    }
    ptr = (struct pgdirinfo*)_ptr;

    //go through entire table
    pte_t* pgdir = myproc()->pgdir;

    if(pgdir != 0x0)
    {
        //start scanning
        ptr->n_upages = 0;

        for (int i = 0; i < NPDENTRIES; i++)
        {
            //check if page table in directory
            if ((pgdir[i] & PTE_P) == PTE_P)
            {
                pte_t* pgtab = (pte_t*)P2V(PTE_ADDR(pgdir[i]));
                for (int j = 0; j < NPDENTRIES; j++)
                {
                    //check if valid entry and user entry
                    pte_t entry = pgtab[j];
                    if ((entry != 0) && ((entry & PTE_P) == PTE_P) && ((entry & PTE_U) == PTE_U))
                    {
                        ptr->pa[ptr->n_upages] = PTE_ADDR(entry);
                        ptr->va[ptr->n_upages] = PGADDR(i, j, 0);
                        ptr->n_upages++;
                    }
                }
            }
        }
        return SUCCESS;
    }

    //default return
    return FAILED;
}

/**
 * Add a new system call getwmapinfo to retrieve information about the process address space 
 * by populating struct wmapinfo.
 * 
 * This system call should calculate the current number of memory maps (mmaps) 
 * in the process's address space and store the result in total_mmaps. 
 * It should also populate addr[MAX_WMMAP_INFO] and length[MAX_WMAP_INFO] 
 * with the address and length of each wmap. You can expect that the number of 
 * mmaps in the current process will not exceed MAX_UPAGE_INFO. 
 * The n_loaded_pages[MAX_WMAP_INFO] should store how many pages have been 
 * physically allocated for each wmap (corresponding index of addr and length arrays). 
 * This field should reflect lazy allocation.
*/
int sys_getwmapinfo(void)
{
    //get pointer
    struct wmapinfo* ptr;
    char* _ptr;
    if (argptr(0, &_ptr, sizeof(struct wmapinfo)) < 0)
    {
        //error return
        return FAILED;
    }
    ptr = (struct wmapinfo*)_ptr;

    //copy values
    struct proc* p = myproc();
    ptr->total_mmaps = p->_wmapinfo.total_mmaps;
    for (int i = 0; i < ptr->total_mmaps; i++)
    {
        ptr->addr[i] = p->_wmapinfo.addr[i];
        ptr->length[i] = p->_wmapinfo.length[i];
        ptr->alloc_length[i] = p->_wmapinfo.alloc_length[i];
        ptr->n_loaded_pages[i] = p->_wmapinfo.n_loaded_pages[i];
        ptr->flags[i] = p->_wmapinfo.flags[i];
        ptr->fds[i] = p->_wmapinfo.fds[i];
    }

    //default return
    return SUCCESS;
}

int page_fault_handler(uint addr)
{
    //cprintf("Page Fault Handler\n");
    //check if mapped
    struct proc* p = myproc();
    
    //check all mappings
    for(int i = 0; i < p->_wmapinfo.total_mmaps; i++)
    {
      //check if within bounds
      if(addr >= p->_wmapinfo.addr[i] && addr < (p->_wmapinfo.addr[i] + LEN_TO_PAGE(p->_wmapinfo.alloc_length[i])))
      {
        char success = 0;
        //add to pgdir
        addr = PGROUNDDOWN(addr);
        void* mem = (void*)kalloc();

        //error checking for kalloc success.
        if (mem == 0){
            cprintf("Kalloc error\n");
            return -1;
        }

        //check flags for copy on write
        if (((p->_wmapinfo.flags[i] & MAP_PRIVATE) == MAP_PRIVATE))
        {
            //find address of parent mem
            struct proc* parent_proc = p->parent;
            // check if parent has same mappings
            int parent_mapping_index = -1;
            for (int j = 0; j < parent_proc->_wmapinfo.total_mmaps; j++)
            {
                if (addr >= parent_proc->_wmapinfo.addr[j] &&
                addr < (parent_proc->_wmapinfo.addr[j] + LEN_TO_PAGE(parent_proc->_wmapinfo.alloc_length[j])))
                {
                    //overlap found
                    parent_mapping_index = j;
                    break;
                }
            }

            if (parent_mapping_index != -1){
                //need to copy on write here
                //cprintf("copy on write\n");
                // Determine the physical address of the parent's memory corresponding to addr
                uint parent_physical_address = PTE_ADDR(walkpgdir(parent_proc->pgdir, (void *)addr, 0)[0]);
                void* parent_mem = P2V(parent_physical_address);
                // Copy the content of the parent's memory to the newly allocated memory in the child process
                memmove(mem, parent_mem, PGSIZE);
                success = 1;
            }

            //else continue
        }

        //fill with file contents
        if (((p->_wmapinfo.flags[i] & MAP_ANONYMOUS) != MAP_ANONYMOUS) && (success != 1))
        {
            //cprintf("write from file\n");
            //find offset within file
            uint a_start = p->_wmapinfo.addr[i];
            int off = 0;
            while (off < p->_wmapinfo.alloc_length[i])
            {
                if (a_start == addr)
                {
                    //match found, exit
                    break;
                }
                //else increment vals
                off += PGSIZE;
                a_start += 0x1000;
            }

            //write contents of file to memory
            struct file* f = p->ofile[p->_wmapinfo.fds[i]];
            ilock(f->ip);
            int bytesRead = readi(f->ip, (char*)mem, off, PGSIZE);
            iunlock(f->ip);
            if (bytesRead < 0)
            {
                cprintf("Failed to read file\n");
                kfree(mem); // Free the allocated memory
                return -1;  // Return an error code
            }

            else if (bytesRead == 0)
            {
                cprintf("End of file reached\n");
                kfree(mem); // Free the allocated memory
                return -1;  // Return an error code
            }

            //filing the rest with 0s
            if (bytesRead < PGSIZE)
            {
                int remainingBytes = PGSIZE - bytesRead;
                // Zero-fill the remaining part of the page
                memset(mem + bytesRead, 0, remainingBytes);
            }

            success = 1;
        }

        //fill with empty
        if ((success != 1) && (memset(mem, 0, PGSIZE) == 0x0))
        {
            cprintf("Segmentation Fault\n");
            kfree(mem);
            return -1;
        }

        //allocate
        if (mappages(p->pgdir, (void*)addr, PGSIZE, V2P(mem), PTE_W | PTE_U) < 0)
        {
          cprintf("Segmentation Fault\n");
          kfree(mem);
          return -1;
        }

        //increase mapping allocs and return
        p->_wmapinfo.n_loaded_pages[i]++;
        return 0;
      }
    }
    //else error
    cprintf("Segmentation Fault\n");
    return -1;
}

/**
 * Copy mappings from p to np
 * Make sure to copy memory values
 * If shared memory map to same Physical Memory
 * Called from proc.c fork() function
*/
void copy_mappings(struct proc* p, struct proc* np)
{
    //TODO: FIX

    //go through all mappings of the parent process
    for(int i=0;i<p->_wmapinfo.total_mmaps;++i){
        void *mem = kalloc();
        if (mem == 0){
            cprintf("Kalloc error\n");
            return;
        }

        //check if mapping is shared.
        if ((p->_wmapinfo.flags[i] & MAP_SHARED) == MAP_SHARED){
            //move the child process, to the same physical address as parent
            //memmove(mem, (void*)p->_wmapinfo.addr[i], PGSIZE);
        }
        else{
            //if mapping private
            //zero initialize the mem
            memset(mem, 0, PGSIZE);
        }
        if (mappages(np->pgdir, (void*)p->_wmapinfo.addr[i], PGSIZE, V2P(mem), PTE_W | PTE_U) < 0)
        {
            //mapping failure
            cprintf("Mapping failure\n");
            kfree(mem); 
            return; 
        }
        np->_wmapinfo.n_loaded_pages[i]++;
    }

}

/**
 * Unmap all memory
 * Only umap unshared memory if child
 * If parent unmap all memory
 * Called from proc.c exit() function
*/
void unmap(struct proc* p)
{

}
#include "wmap.h"
#include "types.h"
#include "defs.h"
#include "param.h"
#include "stat.h"
#include "mmu.h"
#include "proc.h"
#include "fs.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "file.h"
#include "fcntl.h"

//macro defs
#define LEN_TO_PAGE(va)   (0x1000 * ((int)(va) / PGSIZE))

//global defs

//helper functions

/**
 * Add values to process struct wmapinfo
 * Add to end of array
 * skips if full
*/
int add_mappings(struct proc* p, uint addr, int length, int flags, int fd)
{
    if (p->_wmapinfo.total_mmaps == MAX_WMMAP_INFO)
    {
        return -1;
    }

    //add to mappings
    int index = p->_wmapinfo.total_mmaps;
    p->_wmapinfo.addr[index] = addr;
    p->_wmapinfo.length[index] = length;
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
int remove_mappings(struct proc* p, int index)
{
    //remove value
    for (int i = index; i < p->_wmapinfo.total_mmaps - 1; i++)
    {
        //shift next down
        p->_wmapinfo.addr[i] = p->_wmapinfo.addr[i+1];
        p->_wmapinfo.length[i] = p->_wmapinfo.length[i+1];
        p->_wmapinfo.n_loaded_pages[i] = p->_wmapinfo.n_loaded_pages[i+1];
        p->_wmapinfo.flags[i] = p->_wmapinfo.flags[i+1];
        p->_wmapinfo.fds[i] = p->_wmapinfo.fds[i+1];
    }

    //decrement value
    p->_wmapinfo.total_mmaps--;
}

/**
 * Find space for address
 * Simple linear search where if overlap found, address set to page after overlapped page
 * continue while loop on new addr
*/
uint find_space(struct proc* p, int length)
{
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
            //check if addr start within bounds
            if (addr >= p->_wmapinfo.addr[i] && 
            addr <= (p->_wmapinfo.addr[i] + LEN_TO_PAGE(p->_wmapinfo.length[i])))
            {
                overlap = 1;
                break;
            }

            //check if addr end withing bounds
            if ((addr + LEN_TO_PAGE(length)) >= p->_wmapinfo.addr[i] && 
            (addr + LEN_TO_PAGE(length)) <= (p->_wmapinfo.addr[i] + LEN_TO_PAGE(p->_wmapinfo.length[i])))
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
            addr = p->_wmapinfo.addr[i] + LEN_TO_PAGE(p->_wmapinfo.length[i]);
        }
    }
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
    int flags;
    int fd;

    if (argint(0, &addr) < 0 | argint(1, &length) < 0 | argint(2, &flags) < 0 | argint(3, &fd) < 0)
    {
        //error occured return failiure
        return FAILED;
    }

    //get calling process
    struct proc* proc = myproc();
    struct pde_t* pde = proc->pgdir;

    //check if private or shared error in input
    if ((flags & MAP_PRIVATE == MAP_PRIVATE && flags & MAP_SHARED == MAP_SHARED) |
        (flags & MAP_PRIVATE != MAP_PRIVATE && flags & MAP_SHARED != MAP_SHARED))
    {
        //error return
        return FAILED;
    }

    //parse flags and check for errors
    length = PGROUNDUP(length);
    if (flags & MAP_FIXED == MAP_FIXED)
    {
        //check for valid address bounds
        if (addr < 0x60000000 | 
        (addr + (0x1000 * (length / PGSIZE))) > 0x80000000 | 
        addr % PGSIZE != 0)
        {
            //error return
            return FAILED;
        }

        //check if region avaliable
        for (int i = 0; i < proc->_wmapinfo.total_mmaps; i++)
        {
            //check if addr start within bounds
            if (addr >= proc->_wmapinfo.addr[i] && 
            addr <= (proc->_wmapinfo.addr[i] + LEN_TO_PAGE(proc->_wmapinfo.length[i])))
            {
                //error return
                return FAILED;
            }

            //check if addr end withing bounds
            if ((addr + LEN_TO_PAGE(length)) >= proc->_wmapinfo.addr[i] && 
            (addr + LEN_TO_PAGE(length)) <= (proc->_wmapinfo.addr[i] + LEN_TO_PAGE(proc->_wmapinfo.length[i])))
            {
                //error return
                return FAILED;
            }
        }
    }
    else
    {
        //find address mapping
        addr = find_space(proc, length);
    }

    //map pages
    int n = 0;
    uint addr_cpy = addr;
    while (n != length)
    {
        //handle physical address in trap
        if (mappages(pde, addr_cpy, 4096, 0x0, PTE_W | PTE_U) < 0)
        {
            //error return
            return FAILED;
        }

        //incrememnt values
        n += 4096;
        addr_cpy += 0x1000;
    }

    //add mapping
    if (add_mappings(proc, addr, length, flags, fd) < 0)
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
    if (argint(0, &addr) < 0)
    {
        //error return
        return FAILED;
    }

    
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

}

int page_fault_handler(void)
{
    //check if mapped
    uint addr = rcr2();
    struct proc* p = myproc();
    char success = 0;
    //check all mappings
    for(int i = 0; i < p->_wmapinfo.total_mmaps; i++)
    {
      //check if within bounds
      if(addr >= p->_wmapinfo.addr[i] && addr <= (p->_wmapinfo.addr[i] + LEN_TO_PAGE(p->_wmapinfo.length[i])))
      {
        //add to pgdir
        addr = PGROUNDDOWN(addr);
        void* mem = kalloc();

        //fill memory
        //TODO: check flags for copy on write or file
        if (memset(mem, 0, PGSIZE) == 0x0)
        {
          cprintf("Segmentation Fault\n");
          return -1;
        }

        //allocate
        if (mappages(p->pgdir, addr, PGSIZE, V2P(mem), PTE_W | PTE_U) < 0)
        {
          cprintf("Segmentation Fault\n");
          return -1;
        }

        //add to pgdirinfo
        int index = p->_pgdirinfo.n_upages;
        p->_wmapinfo.n_loaded_pages[i]++;
        p->_pgdirinfo.n_upages++;
        p->_pgdirinfo.va[index] = addr;
        p->_pgdirinfo.pa[index] = V2P(mem);
        p->_pgdirinfo.n_upages++;

        return 0;
      }
    }
    //else error
    cprintf("Segmentation Fault\n");
    return -1;
}
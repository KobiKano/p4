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


/**
 * wmap system call
 * 4 modes of operation
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
    
}

/**
 * wunmap removes the mapping starting at addr from the process virtual address space. 
 * If it's a file-backed mapping with MAP_SHARED, it writes the memory data back to the file to ensure the file remains up-to-date. 
 * So, wunmap does not partially unmap any mmap.
*/
int sys_wunmap(void)
{

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
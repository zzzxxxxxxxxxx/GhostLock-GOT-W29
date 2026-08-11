/* pagemap_probe.c - check /proc/self/pagemap readability + PFN of a user page */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
int main(void) {
  size_t sz = 0x1000;
  void *p = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) { perror("mmap"); return 1; }
  memset(p, 0x41, sz);
  uintptr_t va = (uintptr_t)p;
  int fd = open("/proc/self/pagemap", O_RDONLY);
  if (fd < 0) { printf("pagemap open FAILED errno=%d\n", errno); return 1; }
  off_t off = (off_t)(va / 0x1000) * 8;
  uint64_t entry = 0;
  ssize_t r = pread(fd, &entry, 8, off);
  if (r != 8) { printf("pagemap pread r=%zd errno=%d\n", r, errno); return 1; }
  printf("va=%p entry=0x%016llx pfn=0x%llx phys=0x%llx present=%d\n",
         p, (unsigned long long)entry,
         (unsigned long long)(entry & 0xfffffffffffffULL),
         (unsigned long long)((entry & 0xfffffffffffffULL) << 12),
         (int)((entry >> 63) & 1));
  return 0;
}

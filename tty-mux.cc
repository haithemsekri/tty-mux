
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <termios.h>
#include <pty.h>

#define FatalLog(format, ...) \
    fprintf(stderr, "%s: %d: fatal: " format, __FILE__, __LINE__, __VA_ARGS__); \
    exit(-1)

#define AssertEqual(l,r) \
   if(l != r) FatalLog("assertion failure on (%s == %s)\n", ##l, ##r);

#define AssertNotEqual(l,r) \
   if(l == r) FatalLog("assertion failure on (%s != %s)\n", ##l, ##r);

#define AssertInRange(l,v,r) \
   if((v > r) || (v < l)) FatalLog("assertion failure on (%s =< %s =< %s)\n", ##l, ##v, ##r);

#define ASSERT(expr, format, ...) \
   do { if (!(expr)) { \
   FatalLog("assertion failure (%s): " format, #expr, ##__VA_ARGS__); } } while(0)

#define ErrorLog(format, ...) \
    fprintf(stderr, "%s: %d: error: " format, __FILE__, __LINE__, ##__VA_ARGS__)

#define WarnLog(format, ...) \
    fprintf(stdout, "%s: %d: Warning: " format, __FILE__, __LINE__, ##__VA_ARGS__)

#define PrintLog(format, ...) \
    fprintf(stdout, "%s: %d: debug: " format, __FILE__, __LINE__, ##__VA_ARGS__)

#define SIZE_OF_ARRARY(buff) (sizeof(buff) / sizeof(buff[0]))

static int FdsWaitForEvent(fd_set * rfds, int * fds, uint32_t fdsSize, uint32_t ms) {
   ASSERT(rfds != NULL, "Invalid argument\n");
   ASSERT(fds != NULL, "Invalid argument\n");
   ASSERT(fdsSize != 0, "Invalid argument\n");

   int nfds = -1;
   uint32_t fdi = 0;
   struct timeval timeout = {ms / 1000, (ms % 1000) * 1000};

   FD_ZERO(rfds);

   for(fdi = 0; fdi < fdsSize; fdi++) {
      if(fds[fdi] > 0) {
         FD_SET(fds[fdi], rfds);
         if(fds[fdi] > nfds) {
            nfds = fds[fdi];
         }
      }
   }

   ASSERT(nfds > 0, "Invalid argument\n");

   return select(nfds + 1, rfds, NULL, NULL, &timeout);
}

int FdSetNonBlock(int fd)
{
   int flags;
   ASSERT(fd > 0, "Invalid argument\n");
   flags = fcntl(fd, F_GETFL);
   ASSERT(flags > 0, "fcntl failed (errno == %s).\n", strerror(errno));
   ASSERT(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0, "fcntl failed (errno == %s).\n", strerror(errno));
   return fd;
}

int OpenTtyDevice(const char * path)
{
   ASSERT(path != NULL, "Invalid argument\n");

   errno = 0;

   char realPath[256];
   memset(realPath, 0x00, sizeof(realPath));
   ASSERT(realpath(path, realPath) != NULL, "No such file or directory (%s)\n", path);
   ASSERT(access(path, F_OK |  R_OK | W_OK) == 0, "File  (%s) access error (errno == %s)\n", path, strerror(errno));

   int fd = open(realPath, O_RDWR | O_NOCTTY | O_NDELAY);
   ASSERT(fd >= 0, "File (%s) open error (errno == %s)\n", path, strerror(errno));
   FdSetNonBlock(fd);

   struct termios options;
   int flag;
   memset(&options, 0, sizeof(options));
   (void) cfmakeraw(&options);
   (void) tcsetattr(fd, TCSANOW, &options);
   flag = TIOCM_DTR;
   (void) ioctl(fd, TIOCMBIS, &flag);
   PrintLog("device %s, fd %d\n", path, fd);
   return fd;
}

void ForwardFdsData(int * srcFds, unsigned srcFdsLen, int * destFds, unsigned destFdsLen)
{
   ASSERT(srcFds != NULL, "Invalid argument\n");
   ASSERT(destFds != NULL, "Invalid argument\n");

   unsigned fdii;
   unsigned fdoi;

   for(fdii = 0; fdii < srcFdsLen; fdii++) {
      if(srcFds[fdii] > 0) {
         char buff[2048];
         ssize_t nr = read(srcFds[fdii], buff, SIZE_OF_ARRARY(buff));
         if(nr > 0) {
            for(fdoi = 0; fdoi < destFdsLen; fdoi++) {
               if(destFds[fdoi] > 0) {
                  ssize_t nw = write(destFds[fdoi], buff, nr);
                  if(nw <= 0) {
                     close(destFds[fdoi]);
                     destFds[fdoi] = -1;
                  }
               }
            }
         } else if(nr == 0) {
            close(srcFds[fdii]);
            srcFds[fdii] = -1;
         }
      }
   }
}


int OpenTtySlave(const char * path, unsigned id)
{
   ASSERT(path != NULL, "Invalid argument\n");

   errno = 0;

   char realPath[256];
   memset(realPath, 0x00, sizeof(realPath));
   ASSERT(realpath(path, realPath) != NULL, "No such file or directory (%s)\n", path);
   ASSERT(access(path, F_OK |  R_OK | W_OK) == 0, "File  (%s) access error (errno == %s)\n", path, strerror(errno));


   char childPath[256];
   snprintf(childPath, SIZE_OF_ARRARY(childPath), "%s-%u", path, id);
   unlink(childPath);
   //ASSERT(access(childPath, F_OK) != 0, "File (%s) already exist\n", childPath);

   PrintLog("Open child tty %s\n", childPath);
   char name[256];
   struct termios tt;
   int master, slave;
   ASSERT(openpty(&master, &slave, name, &tt, NULL) == 0, "openpty error (errno == %s)\n", strerror(errno));
   PrintLog("%s is linked to %s\n", childPath, name);
   ASSERT(symlink(name, childPath) == 0, "symlink error (errno == %s)\n", strerror(errno));
   FdSetNonBlock(master);
   PrintLog("device %s, fd %d\n", childPath, master);
   return master;
}

static struct sigaction sigAction;
static bool exitNow = false;

static void SignalHandler(int iSigNum, siginfo_t *pInfo, void *vPtr)
{
   (void) pInfo;
   (void) vPtr;
   (void) iSigNum;
   exitNow = true;
}

int main(int argc, char * argv[]) {
   int guid = getuid();
   ASSERT(guid == 0, "programm must ran with sudo (guid == %d)\n", guid);
   ASSERT(argc >= 3, "Invalid argument\n");

   unsigned nSlaves = atoi(argv[2]);
   ASSERT(nSlaves < 5, "Invalid argument\n");

   pid_t pid;
   pid = getpid();
   printf("started (pid == %d).\n", pid);
   memset(&sigAction, 0, sizeof(sigAction));
   sigAction.sa_sigaction = SignalHandler;
   sigAction.sa_flags = SA_SIGINFO;
   sigaction(SIGINT, &sigAction, NULL);
   sigaction(SIGTERM, &sigAction, NULL);
   sigaction(SIGQUIT, &sigAction, NULL);
   sigaction(SIGINT, &sigAction, NULL);
   sigaction(SIGKILL, &sigAction, NULL);
   exitNow = false;

   int masterFd = OpenTtyDevice(argv[1]);
   int slaveFds[nSlaves];

   for(uint8_t i = 0; i < nSlaves; i++) {
      slaveFds[i] = OpenTtySlave(argv[1], i);
   }

   while(!exitNow && (masterFd > 0)) {
      int fds[nSlaves + 1];

      for(uint8_t i = 0; i < nSlaves; i++) {
         fds[i] = slaveFds[i];
      }

      fds[nSlaves] = masterFd;
      fd_set rfds;
      int ret = FdsWaitForEvent(&rfds, fds, nSlaves + 1, UINT32_MAX);
      if(exitNow) {
         break;
      }

      if(ret > 0) {
         ForwardFdsData(&masterFd, 1, slaveFds, nSlaves);
         ForwardFdsData(slaveFds, nSlaves, &masterFd, 1);
      }
   }

   if(masterFd > 0) {
      PrintLog("close fd %d\n", masterFd);
      close(masterFd);
   }

   for(uint8_t i = 0; i < nSlaves; i++) {
      if(slaveFds[i] > 0) {
         PrintLog("close fd %d\n", slaveFds[i]);
         close(slaveFds[i]);
      }
   }
   return 0;
}


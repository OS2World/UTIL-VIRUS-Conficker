/*********************************************************************

Copyright (c) 2009, SRI International. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

   * Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

   * Redistributions in binary form must reproduce the above
     copyright notice, this list of conditions and the following
     disclaimer in the documentation and/or other materials
     provided with the distribution.

   * Neither the name of the SRI International nor the names of its
     contributors may be used to endorse or promote products
     derived from this software without specific prior written
     permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*********************************************************************/ 



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>


/* default connect timeout in ms */

#define DEFAULT_TIMEOUT 200

int count = 0;
uint32_t previp  = 0;
int verbose = 0;

typedef union {
  int16_t s16[8];
  uint16_t u16[8];
  int32_t s32[4];
} result_t;

typedef union {
  int64_t s64;
  int32_t s32[2];
  uint32_t u32[2];
  int16_t s16[4];
} var_t;

/* This array clearly has some magic structure, but we don't know what it is yet */
uint32_t magic[64] =
  {
    0xffffffff, 0xffffffff,	0xf0f6bfbb,	0xbb5a5ff3,
    0xf3977011,	0xeb67bfbf,	0x5f9bfac8,	0x34d88091,
    0x1e2282df,	0x573402c4,	0xc0000084,	0x03000209,
    0x01600002,	0x00005000,	0x801000c0,	0x00500040,
    0x000000a1,	0x01000000,	0x01000000,	0x00022a20,
    0x00000080,	0x04000000,	0x40020000,	0x88000000,
    0x00000180,	0x00081000,	0x08801900,	0x00800b81,
    0x00000280,	0x080002c0,	0x00a80000,	0x00008000,
    0x00100040,	0x00100000,	0x00000000,	0x00000000,
    0x10000008,	0x00000000,	0x00000000,	0x00000004,
    0x00000002,	0x00000000,	0x00040000,	0x00000000,
    0x00000000,	0x00000000,	0x00410000,	0x82000000,
    0x00000000,	0x00000000,	0x00000001,	0x00000000,
    0x00000000,	0x00000000,	0x00000000,	0x00000000,
    0x00000000,	0x00000000,	0x00000000,	0x00000000,
    0x00000000,	0x00000000,	0x00000008,	0x80000000
  };

#define magic_shift(x) (1 << ((x >> 5) & 0x1F)) & magic[x >> 10]


/* NB: the portgen() function below is endian-dependent, and reverse-engineered 
   for a little-endian (e.g. x86, VAX, Alpha, etc.) machine.  Changes will be required
   for the array offsets in the unions to run on a big-endian (e.g. most SPARC, Power(PC), MIPS, etc.)
   machine.  Other than the endian issue, I believe this is portable. 
   
   Credit: Drew Dean for improving readability of the portgen function

*/

int portgen(int ip, result_t *res, int week)
{
  var_t v;	
  int64_t KONST = 0x15A4E35;
  int i;
	
  memset(res, 0, sizeof(result_t));
  v.s32[0] = ~ip;

  do {
    do {
      v.s64 = KONST * v.u32[0] + 1;
      res->s16[0] ^= v.s16[2];
      
      for (i=1; i < 10; i++) {
	v.s64 = KONST * v.u32[0] + 1;
	res->s16[(i%2)*2] ^= v.s32[1] >> i;
      }

    } while (magic_shift(res->s32[0]));
		
  } while (magic_shift(res->s32[1]) || res->s32[0] == res->s32[1]);

  v.s32[0] = week ^ v.s64;

  do {
    do {
      v.s64 = KONST * v.u32[0] + 1;
      res->s16[4] ^= v.s16[2];
	  
      for (i=1; i < 10; i++) {
	v.s64 = KONST * v.u32[0] + 1;
	res->s16[(i%2)*2 + 4] ^= v.s32[1] >> i;
      }
      
    } while (magic_shift(res->s32[2]));
		    
  } while (magic_shift(res->s32[3]) || res->s32[2] == res->s32[3] || 
	   res->s32[0] == res->s32[2] || res->s32[1] == res->s32[2] || 
	   res->s32[0] == res->s32[3] || res->s32[1] == res->s32[3]);
  
  return v.s64;
}




void probe_addr(struct sockaddr_in sin, int wait) {
    int sock;
    fd_set write_socks;
    fd_set read_socks;
    int rval;
    struct timeval timeout;
    int flags;

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    flags = fcntl(sock, F_GETFL, flags);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    FD_ZERO(&write_socks);
    FD_SET(sock, &write_socks);

    FD_ZERO(&read_socks);
    FD_SET(sock, &read_socks);

    timeout.tv_sec = 0;
    timeout.tv_usec = wait * 1000;
    
    if (sock == -1){
      perror("socket()");
      exit(-1);
    }
	  
    rval = connect(sock, (struct sockaddr*) &sin, sizeof(struct sockaddr_in));

    rval = select(sock + 1, &read_socks, &write_socks, NULL, &timeout);


    if (rval == 1) {
      struct in_addr in;
      in.s_addr = sin.sin_addr.s_addr;
      printf("Conficker port open %s %d\n",  inet_ntoa(in), ntohs(sin.sin_port));

      if (sin.sin_addr.s_addr != previp) {
	count++;
	previp = sin.sin_addr.s_addr;
      }
    }

    close(sock);
}



void usage() {
  printf("usage: Conficker_C_P2P_Scanner [-t waittime in ms] [-v (verbose)] start-ip stop-ip \n");
  exit(0);
}




/*****************************************************************************
 *                                                                           *
 * This program scans the subnet for hosts with Conficker C's                *
 * TCP/P2P ports open. The P2P ports scanned vary depending                  *
 * on the epoch week and IP address of the host that is scanned.             *
 *                                                                           *
 *  Usage: Conficker_C_P2P_Scanner [-t waittime in ms] [-v] start-ip stop-ip *
 *                                                                           *
 * Recommended wait time is over 80ms to limit false negatives               *
 *                                                                           *
 * Warning: Works only on little-endian platforms!                           *
 *****************************************************************************/


int main(int argc, char** argv) {
  uint a1,a2;
  result_t res;  
  int i, rc;
  struct timeval tv;
  int week;
  struct sockaddr_in sin;
  int wait = DEFAULT_TIMEOUT;
  int c;



  gettimeofday(&tv, 0);

  week = (tv.tv_sec-0x54600)/(3600*24*7);  


  while ((c = getopt(argc, argv, "t:v")) != -1) {
    switch (c) {
    case 't':
      wait = atoi(optarg);
      printf("Wait time set to %d ms.  \n", wait);
      if (wait < 80)
	printf("Minimum recommened wait time is 80ms! \n");
      break;
    case 'v':
      verbose = 1;
      break;
    default:
      usage();
    }
  }

  if (argc < optind+2) 
    usage();
	
    

    
  a1 = ntohl(inet_addr(argv[optind]));
  a2 = ntohl(inet_addr(argv[optind+1]));

  if (a2 < a1) {
    printf("IP2 must be greater than IP1... Exiting\n");
    exit(0);
  }


  printf("Scanning %d IP addresses from %s to %s \n", a2-a1+1, argv[1], argv[2]);
  
  do {
    int tcp = 1;
    sin.sin_family = AF_INET;
    rc=portgen(htonl(a1), &res, week);

    sin.sin_addr.s_addr = htonl(a1);
    if (verbose) 
      printf("scanning %s\n", inet_ntoa(sin.sin_addr));
	

    for (i=0;i<8;i++) {
      
      if (res.u16[i]) {
	if (tcp) {
	  sin.sin_port = htons(res.u16[i]);
	  probe_addr(sin, wait);
	}
	tcp = !tcp;

      }
      
    }
  }while (a1++ < a2);

  printf("Number of  suspected Conficker hosts found: %d\n", count);

  return 0;
}

/*
$Id:$


 DVBSNOOP

 a dvb sniffer  and mpeg2 stream analyzer tool
 http://dvbsnoop.sourceforge.net/

 (c) 2011   Christian Praehauser

$Log:$

*/


#include "dvbsnoop.h"
#include "misc/cmdline.h"
#include "misc/output.h"
#include "misc/sig_abort.h"

#include "ts/tslayer.h"
#include "ts/ts2secpes.h"
#include "ts/ts_cc_check.h"

#include "dvb_api.h"
#include "file_io.h"
#include "dmx_error.h"
#include "dmx_bb.h"

#define BBBUFSZ		8192

void bbFrameDecode(OPTION *opt, u_char *buf, unsigned len, unsigned long count)
{
   out_nl (1,"\n------------------------------------------------------------");
   out_nl (1,"BB-Frame: %08lu   ISI: %hhu, Length: %d (0x%04x)",
		count, buf[1], len, len);

   if (opt->inpPidFile) {
   	out_nl (1,"from file: %s",opt->inpPidFile);
   } else {
   	out_receive_time (1, opt);
   }

   out_nl (1,"------------------------------------------------------------");
       // hex output (also on wrong packets)
       if (opt->buffer_hexdump) {
           printhex_buf (0, buf, len);
           out_NL(0);
       }
       // -- decode protocol
       if (opt->printdecode) {
       }
}


int  doReadBB (OPTION *opt)

{
  int     fd_dmx = 0, fd_dvr = 0;
  long    count;
  char    *f;
  int     openMode;
  int     fileMode, bread, verbose = 4;
  long    dmx_buffer_size = BBBUFSZ * 20;
  unsigned char bbbuf[BBBUFSZ];
  unsigned wrpos = 0, skip = 0, bblen = 0, inbuflen = BBBUFSZ;


  

  if (opt->inpPidFile) {
  	f        = opt->inpPidFile;
  	openMode = O_RDONLY | O_LARGEFILE | O_BINARY;
        fileMode = 1;
  } else {
  	f        = opt->devDvr;
  	openMode = O_RDONLY;
        fileMode = 0;
  } 


  if((fd_dvr = open(f,openMode)) < 0){
      IO_error(f);
      return -1;
  }

  /*
   -- init demux
  */

  if (!fileMode) {
    struct dmx_bb_filter_params flt;

    if((fd_dmx = open(opt->devDemux,O_RDWR)) < 0){
        IO_error(opt->devDemux);
	close (fd_dvr);
        return -1;
    }


    // -- alloc dmx buffer for TS
    if (opt->rd_buffer_size > 0) {
	    dmx_buffer_size = opt->rd_buffer_size;
    }

    // -- full Transport Stream Read?? (special DVB-API-PID...)
    if (opt->ts_raw_mode) {
	    opt->pid = DMX_ISI_ALL;
    }


    if (ioctl(fd_dmx,DMX_SET_BUFFER_SIZE, dmx_buffer_size) < 0) {
	IO_error ("DMX_SET_BUFFER_SIZE failed: ");
	close (fd_dmx);
	close (fd_dvr);
	return -1;
    }

    memset (&flt, 0, sizeof (struct dmx_bb_filter_params));

    flt.isi = opt->pid;
    flt.input  = DMX_IN_FRONTEND;
    flt.output = DMX_OUT_TS_TAP;
    flt.type = DMX_BB_FRAME;
    flt.flags = DMX_IMMEDIATE_START;

    if (ioctl(fd_dmx,DMX_SET_BB_FILTER,&flt) < 0) {
	IO_error ("DMX_SET_PES_FILTER failed: ");
	close (fd_dmx);
	close (fd_dvr);
	return -1;
    }

  }

/*
  -- read TS packets for pid
*/

  count = 0;
  while ( ! isSigAbort() ) {

	bread = read(fd_dvr, &bbbuf[wrpos], inbuflen-wrpos);
	if (bread < 0)
		break;

    // -- error or eof?
    if (bread < 0) {
	int err;
	
	err = IO_error("read");
	// if (err == ETIMEDOUT) break;		// Timout, abort
	continue;
    }

    if (bread == 0) {
	if (!fileMode) continue;	// DVRmode = no eof!
	else {			// filemode eof 
	  break;
	}
    }
	wrpos += bread;
	if (verbose > 3)
		fprintf(stdout, "read: %d (%u) byte(s)\n",
			bread, wrpos);



	if (verbose > 3)
		fprintf(stdout, "BB decaps: %u/%d frame byte(s)\n",
			wrpos, bblen);
	if (!bblen && wrpos >= (skip + 10)) {
		// Extract length of bbframe data field
		bblen = (bbbuf[skip+4] << 8) | bbbuf[skip+5];
		bblen = skip + 10 + (bblen >> 3);
		if (bblen > sizeof(bbbuf)) {
			bblen = 0;
			bread = -1;
			break;
		}
	}
	if (bblen && wrpos >= bblen) {
		if (verbose)
			fprintf(stdout, "BB decaps: %u byte(s)\n", bblen);
		count++;

		bbFrameDecode(opt, (u_char*) &bbbuf[skip], bblen-skip, count);

		if (wrpos > bblen) {
			memmove(&bbbuf[0], &bbbuf[bblen], wrpos - bblen);
			if (verbose)
				fprintf(stdout, "move: %u byte(s)\n", wrpos - bblen);
		}
		wrpos -= bblen;
		bblen = 0;
	}



    // count packets ?
    if (opt->rd_packet_count > 0) {
       if (count >= opt->rd_packet_count) break;
    }

  } // while

  // -- Stop Demux
  if (!fileMode) {
     ioctl (fd_dmx, DMX_STOP, 0);

     close(fd_dmx);
  }

  close(fd_dvr);
  return 0;
}

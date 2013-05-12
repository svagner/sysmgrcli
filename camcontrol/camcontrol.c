/*
 * Copyright (c) 1997-2007 Kenneth D. Merry
 * All rights reserved.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: stable/9/sbin/camcontrol/camcontrol.c 243296 2012-11-19 18:26:08Z emaste $");

#include <sys/ioctl.h>
#include <sys/stdint.h>
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/sbuf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <limits.h>
#include <fcntl.h>
#include <ctype.h>
#include <err.h>
#include <libutil.h>

#include <cam/cam.h>
#include <cam/cam_debug.h>
#include <cam/cam_ccb.h>
#include <cam/scsi/scsi_all.h>
#include <cam/scsi/scsi_da.h>
#include <cam/scsi/scsi_pass.h>
#include <cam/scsi/scsi_message.h>
//#include <cam/scsi/smp_all.h>
#include <cam/ata/ata_all.h>
#include <camlib.h>

#include "smp_all.h"

int
main()
{
	union ccb ccb;
	int bufsize, fd;
	unsigned int i;
	int need_close = 0;
	int error = 0;
	int skip_device = 0;
	struct periph_match_result *periph_result[2];
	int device_count = 0;


	if ((fd = open(XPT_DEVICE, O_RDWR)) == -1) {
		warn("couldn't open %s", XPT_DEVICE);
		return(1);
	}

	bzero(&ccb, sizeof(union ccb));

	ccb.ccb_h.path_id = CAM_XPT_PATH_ID;
	ccb.ccb_h.target_id = CAM_TARGET_WILDCARD;
	ccb.ccb_h.target_lun = CAM_LUN_WILDCARD;

	ccb.ccb_h.func_code = XPT_DEV_MATCH;
	bufsize = sizeof(struct dev_match_result) * 100;
	ccb.cdm.match_buf_len = bufsize;
	ccb.cdm.matches = (struct dev_match_result *)malloc(bufsize);
	if (ccb.cdm.matches == NULL) {
		warnx("can't malloc memory for matches");
		close(fd);
		return(1);
	}
	ccb.cdm.num_matches = 0;

	ccb.cdm.num_patterns = 0;
	ccb.cdm.pattern_buf_len = 0;

	do {
		if (ioctl(fd, CAMIOCOMMAND, &ccb) == -1) {
			warn("error sending CAMIOCOMMAND ioctl");
			error = 1;
			break;
		}

		if ((ccb.ccb_h.status != CAM_REQ_CMP)
		 || ((ccb.cdm.status != CAM_DEV_MATCH_LAST)
		    && (ccb.cdm.status != CAM_DEV_MATCH_MORE))) {
			warnx("got CAM error %#x, CDM error %d\n",
			      ccb.ccb_h.status, ccb.cdm.status);
			error = 1;
			break;
		}
		for (i = 0; i < ccb.cdm.num_matches; i++) {
			switch (ccb.cdm.matches[i].type) {
			case DEV_MATCH_BUS: {
				struct bus_match_result *bus_result;

				/*
				 * Only print the bus information if the
				 * user turns on the verbose flag.
				 */

				bus_result =
					&ccb.cdm.matches[i].result.bus_result;

				break;
			}
			case DEV_MATCH_DEVICE: {
				struct device_match_result *dev_result;
				char vendor[16], product[48], revision[16];
				char fw[5], tmpstr[256];

				dev_result =
				     &ccb.cdm.matches[i].result.device_result;

					skip_device = 0;

				if (dev_result->protocol == PROTO_SCSI) {
				    cam_strvis((u_int8_t *)vendor, (u_int8_t *)dev_result->inq_data.vendor,
					   sizeof(dev_result->inq_data.vendor),
					   sizeof(vendor));
				    cam_strvis((u_int8_t *)product,
					   (u_int8_t *)dev_result->inq_data.product,
					   sizeof(dev_result->inq_data.product),
					   sizeof(product));
				    cam_strvis((u_int8_t *)revision,
					   (u_int8_t *)dev_result->inq_data.revision,
					  sizeof(dev_result->inq_data.revision),
					   sizeof(revision));
					periph_result[0] = &ccb.cdm.matches[i+1].result.periph_result;
					periph_result[1] = &ccb.cdm.matches[i+2].result.periph_result;
				    printf("[%d] vendor:%s product:%s revision%s at scbus%d target %d lun %d device: %s%d, %s%d", i, vendor, product, revision, dev_result->path_id, dev_result->target_id, dev_result->target_lun, periph_result[0]->periph_name,periph_result[0]->unit_number, periph_result[1]->periph_name,periph_result[1]->unit_number);
				    device_count++;
				} else if (dev_result->protocol == PROTO_ATA ||
				    dev_result->protocol == PROTO_SATAPM) {
				    cam_strvis((u_int8_t *)product,
					   dev_result->ident_data.model,
					   sizeof(dev_result->ident_data.model),
					   sizeof(product));
				    cam_strvis((u_int8_t *)revision,
					   dev_result->ident_data.revision,
					  sizeof(dev_result->ident_data.revision),
					   sizeof(revision));
					periph_result[0] = &ccb.cdm.matches[i+1].result.periph_result;
					periph_result[1] = &ccb.cdm.matches[i+2].result.periph_result;
				    printf("[%d] product:%s revision:%s at scbus%d target %d lun %d device: %s%d, %s%d", i, product, revision, dev_result->path_id, dev_result->target_id, dev_result->target_lun, periph_result[0]->periph_name,periph_result[0]->unit_number, periph_result[1]->periph_name,periph_result[1]->unit_number);
				    device_count++;
				} else if (dev_result->protocol == PROTO_SEMB) {
					struct sep_identify_data *sid;

					sid = (struct sep_identify_data *)
					    &dev_result->ident_data;
					cam_strvis((u_int8_t *)vendor, sid->vendor_id,
					    sizeof(sid->vendor_id),
					    sizeof(vendor));
					cam_strvis((u_int8_t *)product, sid->product_id,
					    sizeof(sid->product_id),
					    sizeof(product));
					cam_strvis((u_int8_t *)revision, sid->product_rev,
					    sizeof(sid->product_rev),
					    sizeof(revision));
					cam_strvis((u_int8_t *)fw, sid->firmware_rev,
					    sizeof(sid->firmware_rev),
					    sizeof(fw));
					periph_result[0] = &ccb.cdm.matches[i+1].result.periph_result;
					periph_result[1] = &ccb.cdm.matches[i+2].result.periph_result;
					printf("[%d] vendor:%s product:%s at scbus%d target %d lun %d device: %s%d, %s%d", i, vendor, product, dev_result->path_id, dev_result->target_id, dev_result->target_lun, periph_result[0]->periph_name,periph_result[0]->unit_number, periph_result[1]->periph_name,periph_result[1]->unit_number);
					device_count++;
				}

				need_close = 1;

				break;
			}
			case DEV_MATCH_PERIPH: {
				struct periph_match_result *periph_result;

				periph_result =
				      &ccb.cdm.matches[i].result.periph_result;

				if (skip_device != 0)
					break;

				if (need_close > 1)
					printf(",");


				/*printf("[%d] %s%d", i,
					periph_result->periph_name,
					periph_result->unit_number);*/
				if (need_close == 2)
					printf("\n");

				need_close++;
				break;
			}
			default:
				fprintf(stdout, "unknown match type\n");
				break;
			}

		}
	} while ((ccb.ccb_h.status == CAM_REQ_CMP)
		&& (ccb.cdm.status == CAM_DEV_MATCH_MORE));

	printf("\nDevices: %d\n", device_count);

	close(fd);

	return(error);
}

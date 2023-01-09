/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __PACKET_IO__
#define __PACKET_IO__

#include "headers.p4"
#include "defines.p4"

control packetio_ingress(inout headers_t hdr,
                         inout standard_metadata_t standard_metadata) {

    register<bit<32>>(1) syn_counter;
    register<bit<32>>(1) fin_counter;

    apply {
        if (standard_metadata.ingress_port == CPU_PORT) {
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
            exit;
        }

	if(hdr.tcp.isValid()){
	    bit<32> syn_value;
	    bit<32> fin_value;
	    syn_counter.read(syn_value, 0);
	    fin_counter.read(fin_value, 0);

	    if ((hdr.tcp.ctrl & 0b000010) >> 1 == 1) {
	        syn_value = syn_value + 1;
	        syn_counter.write(0, syn_value);
		digest<statistic_t>(1, {syn_value, fin_value});
	    }
	    if ((hdr.tcp.ctrl & 0b000001) == 1) {
	        fin_value = fin_value + 1;
	        fin_counter.write(0, fin_value);
		digest<statistic_t>(1, {syn_value, fin_value});
	    }
	}
    }
}

control packetio_egress(inout headers_t hdr,
                        inout standard_metadata_t standard_metadata) {
    apply {
        if (standard_metadata.egress_port == CPU_PORT) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = standard_metadata.ingress_port;
        }
    }
}

#endif

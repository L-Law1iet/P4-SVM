// main.p4
#include <core.p4>
#include <v1model.p4>

#define HASH_BASE 10w0
#define HASH_MAX 10w1023
#define ETH_TYPE_IPV4 0x0800
#define IP_PROTO_TCP 8w6
#define IP_PROTO_UDP 8w17

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
    bit<8>  flags;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length_;
    bit<16> checksum;
}


struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}

struct mac_learn_digest_t {
    bit<32> win_pkglength;
    bit<32> win_pkgcount;
    bit<32> win_maxlength;
    bit<32> win_minlength;
    bit<48> win_maxint;
    bit<48> win_minint;
    bit<8> win_fin;
    bit<8> win_syn;
    bit<8> category;
}

struct local_metadata_t { 
    bit<32> hashed_address;
}

parser parser_impl(
        packet_in packet,
        out headers_t hdr,
        inout local_metadata_t user_md,
        inout standard_metadata_t st_md) {
    state start { transition parse_ethernet; }

    state parse_ethernet {
	packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETH_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }    
}

control deparser(
        packet_out pkt,
        in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
    }
}

control ingress(
        inout headers_t hdr,
        inout local_metadata_t user_md,
        inout standard_metadata_t st_md) {

    // registers
    register<bit<32>>(1024) pkt_counter;
    register<bit<48>>(1024) last_time_reg;
    register<bit<48>>(1024) win_interval_reg;
    register<bit<48>>(1024) win_maxint_reg;
    register<bit<48>>(1024) win_minint_reg;
    register<bit<32>>(1024) win_pkgcount_reg;
    register<bit<32>>(1024) win_pkglength_reg;
    register<bit<32>>(1024) win_maxlength_reg;
    register<bit<32>>(1024) win_minlength_reg;
    register<bit<8>>(1024) win_fin_reg;
    register<bit<8>>(1024) win_syn_reg;

    action drop() {
        mark_to_drop(st_md);
    }

	action compute_server_flow () {
        hash(user_md.hashed_address, HashAlgorithm.crc16, HASH_BASE,
        {hdr.ipv4.dst_addr, 7w11, hdr.ipv4.src_addr}, HASH_MAX);
	}

	action compute_client_flow () {
        hash(user_md.hashed_address, HashAlgorithm.crc16, HASH_BASE,
        {hdr.ipv4.src_addr, 7w11, hdr.ipv4.dst_addr}, HASH_MAX);
	}

    apply {
    bit<8> fin_value = 0;
	bit<8> syn_value = 0;
	bit<32> pkt_counter_value;
    bit<32> curr_pcaket_length;
    bit<32> cal_pcaket_length;
    bit<48> last_time;
    bit<48> win_interval = 0;
    bit<48> win_maxint = 0;
    bit<48> win_minint = 0;
    bit<32> win_pkgcount = 0;
    bit<32> win_pkglength = 0;
    bit<32> win_maxlength = 0;
    bit<32> win_minlength = 0;
    bit<8> win_fin = 0;
    bit<8> win_syn = 0;
    bit<48> curr_interval = 0;
    int<64> predict = 0;
    bit<8> category = 0;

    if(hdr.ipv4.isValid()){
        if(st_md.ingress_port == 1){
            compute_server_flow();
        }
        else{
            compute_client_flow();
        }
        table_block.apply();
	}

    // read registers
	pkt_counter.read(pkt_counter_value, user_md.hashed_address);
    last_time_reg.read(last_time, user_md.hashed_address);
    last_time_reg.write(user_md.hashed_address, st_md.ingress_global_timestamp);
    win_interval_reg.read(win_interval, user_md.hashed_address);
    win_maxint_reg.read(win_maxint, user_md.hashed_address);
    win_minint_reg.read(win_minint, user_md.hashed_address);
    win_pkgcount_reg.read(win_pkgcount, user_md.hashed_address);
    win_pkglength_reg.read(win_pkglength, user_md.hashed_address);
    win_maxlength_reg.read(win_maxlength, user_md.hashed_address);
    win_minlength_reg.read(win_minlength, user_md.hashed_address);    
    win_fin_reg.read(win_fin, user_md.hashed_address);
    win_syn_reg.read(win_syn, user_md.hashed_address);

    curr_pcaket_length = st_md.packet_length;

    // 計算與上一個packet的interval
    if(pkt_counter_value < 2){
        pkt_counter_value = pkt_counter_value + 1;
        pkt_counter.write(user_md.hashed_address, pkt_counter_value);
    }
    else if(pkt_counter_value >= 2){
        curr_interval = st_md.ingress_global_timestamp - last_time;
    }

	if(hdr.tcp.isValid()){
            if (hdr.tcp.flags == 1) {
                fin_value = 1;
            }
            if (hdr.tcp.flags == 2) {
                syn_value = 1;
            }
        }

    // 計算time window, 時間為2秒。
    win_interval = win_interval + curr_interval;
    if(win_interval < 2000000){
        // 計算 packet count
        win_pkgcount = win_pkgcount + 1;
        // 計算 time window內總共傳輸量
        win_pkglength = win_pkglength + st_md.packet_length;
        //計算 fin,syn flags 數
        win_fin = win_fin + fin_value;
        win_syn = win_syn + syn_value;
        // 計算 max packet length, min packet length
        if(win_pkgcount == 1){
            win_maxlength = st_md.packet_length;
            win_minlength = st_md.packet_length;
        }
        if(win_pkgcount >= 2){
            if(st_md.packet_length > win_maxlength){
                win_maxlength = st_md.packet_length;
            }
            if(st_md.packet_length < win_minlength){
                win_minlength = st_md.packet_length;
            }            
        }
        // 計算max iat, min iat
        if(win_pkgcount == 2){
            win_maxint = curr_interval;
            win_minint = curr_interval;
        }
        if(win_pkgcount > 2){
            if(curr_interval > win_maxint){
                win_maxint = curr_interval;
            }
            if(curr_interval < win_minint){
                win_minint = curr_interval;
            }
        }
        // 寫入 registers
        win_interval_reg.write(user_md.hashed_address,win_interval);
        win_maxint_reg.write(user_md.hashed_address,win_maxint);
        win_minint_reg.write(user_md.hashed_address,win_minint);
        win_pkgcount_reg.write(user_md.hashed_address,win_pkgcount);
        win_pkglength_reg.write(user_md.hashed_address,win_pkglength);
        win_maxlength_reg.write(user_md.hashed_address,win_maxlength);
        win_minlength_reg.write(user_md.hashed_address,win_minlength);
        win_fin_reg.write(user_md.hashed_address,win_fin);
        win_syn_reg.write(user_md.hashed_address,win_syn);
    }
    // 超過time window時間,重置register,進行svm計算得出預測結果
    if(win_interval >= 2000000){
        win_interval_reg.write(user_md.hashed_address,0);
        win_maxint_reg.write(user_md.hashed_address,0);
        win_minint_reg.write(user_md.hashed_address,0);
        win_pkgcount_reg.write(user_md.hashed_address,0);
        win_pkglength_reg.write(user_md.hashed_address,0);
        win_maxlength_reg.write(user_md.hashed_address,0);
        win_minlength_reg.write(user_md.hashed_address,0);
        win_fin_reg.write(user_md.hashed_address,0);
        win_syn_reg.write(user_md.hashed_address,0);
        predict = predict + (int<64>)(bit<64>)win_pkglength * 98;
        predict = predict + (int<64>)(bit<64>)win_pkgcount * 7231;
        predict = predict - (int<64>)(bit<64>)win_maxlength * 2920;
        predict = predict + (int<64>)(bit<64>)win_minlength * 14047;
        predict = predict + (int<64>)(bit<64>)win_maxint * 41;
        predict = predict + (int<64>)(bit<64>)win_minint * 97076;
        predict = predict - (int<64>)(bit<64>)win_fin * 41573;
        predict = predict - (int<64>)(bit<64>)win_syn * 34703;
        predict = predict + 1422790;
        // 若predict值大於0為良性流量,小於0為DDoS攻擊
        if(predict > 0){
            category = 0;
        }
        else{
            category = 1;
        }
        // 將統計資料透過digest給controller
        digest<mac_learn_digest_t>(1, {win_pkglength, win_pkgcount, win_maxlength, win_minlength, win_maxint, win_minint, win_fin, win_syn, category});
    }
    if(st_md.ingress_port == 1){
        st_md.egress_spec = 2;
    }
    if(st_md.ingress_port == 2){
        st_md.egress_spec = 1;
    }
    
    }
}
control egress(
        inout headers_t hdr,
        inout local_metadata_t user_md,
        inout standard_metadata_t st_md) {
    apply { }
}
control no_verify_checksum(
        inout headers_t hdr,
        inout local_metadata_t user_md) {
    apply { }
}
control no_compute_checksum(
        inout headers_t hdr,
        inout local_metadata_t user_md) {
    apply { }
}
V1Switch(parser_impl(),
        no_verify_checksum(),
        ingress(),
        egress(),
        no_compute_checksum(),
        deparser()
) main;

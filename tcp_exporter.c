#include <stdio.h>
#include <stdlib.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <json-c/json.h>
#include <arpa/inet.h> 
#include <string.h>

// Function to log connection events in JSON format
void log_connection_event(const char *event_type, struct nf_conntrack *ct, const char *state) {
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];  // Buffer for IPv4 addresses
    uint32_t src, dst;

    // Retrieve the original source and destination IP addresses
    src = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);  // Original source IP
    dst = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);  // Original destination IP

    // Convert IP addresses from binary to human-readable form
    inet_ntop(AF_INET, &src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &dst, dst_ip, sizeof(dst_ip));

    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "event_type", json_object_new_string(event_type));
    json_object_object_add(jobj, "original_source_host", json_object_new_string(src_ip));
    json_object_object_add(jobj, "original_destination_host", json_object_new_string(dst_ip));
    json_object_object_add(jobj, "reply_source_host", json_object_new_string(dst_ip));
    json_object_object_add(jobj, "reply_destination_host", json_object_new_string(src_ip));
    json_object_object_add(jobj, "state", json_object_new_string(state));

    // Print JSON log
    printf("%s\n", json_object_to_json_string(jobj));

    json_object_put(jobj); // Free JSON object
}


// Event handler for connection track events
static int event_callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
    switch (type) {
        case NFCT_T_NEW:
            log_connection_event("new", ct, "Opening");
            break;
        case NFCT_T_UPDATE:
            log_connection_event("update", ct, "Open");
            break;
        case NFCT_T_DESTROY:
            log_connection_event("close", ct, "Closed");
            break;
        default:
            break;
    }
    return NFCT_CB_CONTINUE;
}

int main() {
    struct nfct_handle *handle;

    // Initialize conntrack handler
    handle = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_UPDATE);
    if (!handle) {
        perror("nfct_open");
        return EXIT_FAILURE;
    }

    // Register callback for connection events
    nfct_callback_register(handle, NFCT_T_ALL, event_callback, NULL);

    // Loop to listen for connection events
    nfct_catch(handle);

    nfct_close(handle);
    return EXIT_SUCCESS;
}

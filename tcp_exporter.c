#include <stdio.h>
#include <stdlib.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <json-c/json.h>
#include <arpa/inet.h> 
#include <string.h>
#include <microhttpd.h>
#include <stdio.h>
#include <string.h>

#define PORT 9318

int open_connections = 0;
int opening_connections = 0;
int closing_connections = 0;
int closed_connections = 0;
int log_json_flag = 0;  // Global flag to indicate whether to log JSON data

/**
 * @brief Serves metrics in Prometheus format over HTTP.
 *
 * @param cls Context for the request.
 * @param connection Connection object from MHD.
 * @param url The requested URL.
 * @param method The HTTP method (e.g., GET).
 * @param version The HTTP version.
 * @param upload_data Data uploaded via the request.
 * @param upload_data_size Size of the uploaded data.
 * @param con_cls Connection-specific context.
 * @return MHD_Result result of the response queuing.
 */
enum MHD_Result serve_metrics(void *cls, struct MHD_Connection *connection,
                              const char *url, const char *method, const char *version,
                              const char *upload_data, size_t *upload_data_size, void **con_cls) {
    const char *metrics_template =
        "# HELP conntrack_open_connections Number of open connections\n"
        "# TYPE conntrack_open_connections gauge\n"
        "conntrack_open_connections %d\n"
        "# HELP conntrack_opening_connections Number of opening connections\n"
        "# TYPE conntrack_opening_connections gauge\n"
        "conntrack_opening_connections %d\n"
        "# HELP conntrack_closing_connections Number of closing connections\n"
        "# TYPE conntrack_closing_connections gauge\n"
        "conntrack_closing_connections %d\n"
        "# HELP conntrack_closed_connections Number of closed connections\n"
        "# TYPE conntrack_closed_connections gauge\n"
        "conntrack_closed_connections %d\n";

    char response[1024];
    snprintf(response, sizeof(response), metrics_template,
             open_connections, opening_connections, closing_connections, closed_connections);

    struct MHD_Response *http_response;
    http_response = MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, http_response);
    MHD_destroy_response(http_response);
    return ret;
}

/**
 * @brief Starts the HTTP server to expose the metrics.
 *
 * @return 0 on success, 1 on failure.
 */
int start_http_server() {
    struct MHD_Daemon *daemon;
    daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL, &serve_metrics, NULL, MHD_OPTION_END);
    if (NULL == daemon) {
        return 1;
    }
    printf("HTTP server running on port %d\n", PORT);
    return 0;
}

/**
 * @brief Updates connection counters based on the connection state.
 *
 * @param state The state of the connection (Opening, Open, Closing, Closed).
 */
void update_connection_counters(const char *state) {
    if (strcmp(state, "Opening") == 0) {
        opening_connections++;
    } else if (strcmp(state, "Open") == 0) {
        open_connections++;
    } else if (strcmp(state, "Closing") == 0) {
        closing_connections++;
    } else if (strcmp(state, "Closed") == 0) {
        closed_connections++;
    }
}

/**
 * @brief Logs connection events and updates counters based on state.
 *
 * @param event_type The type of event (e.g., new, update, close).
 * @param ct The connection track object.
 * @param state The state of the connection (e.g., Opening, Open, Closed).
 */
void log_connection_event(const char *event_type, struct nf_conntrack *ct, const char *state) {
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    uint32_t src, dst;

    src = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
    dst = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);

    inet_ntop(AF_INET, &src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &dst, dst_ip, sizeof(dst_ip));

    // Log the connection event in JSON format if the --log-json flag is set
    if (log_json_flag) {
        json_object *jobj = json_object_new_object();
        json_object_object_add(jobj, "event_type", json_object_new_string(event_type));
        json_object_object_add(jobj, "original_source_host", json_object_new_string(src_ip));
        json_object_object_add(jobj, "original_destination_host", json_object_new_string(dst_ip));
        json_object_object_add(jobj, "reply_source_host", json_object_new_string(dst_ip));
        json_object_object_add(jobj, "reply_destination_host", json_object_new_string(src_ip));
        json_object_object_add(jobj, "state", json_object_new_string(state));

        printf("%s\n", json_object_to_json_string(jobj));

        json_object_put(jobj); // Free JSON object
    }

    update_connection_counters(state);
}

/**
 * @brief Callback function to handle connection tracking events.
 *
 * @param type The type of connection tracking message (new, update, destroy).
 * @param ct The connection track object.
 * @param data User-defined data (unused).
 * @return NFCT_CB_CONTINUE to continue processing events.
 */
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

/**
 * @brief Main function that starts the HTTP server and listens for connection events.
 *
 * @param argc Number of command-line arguments.
 * @param argv Command-line arguments.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int main(int argc, char *argv[]) {
    // Check for --log-json flag in command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--log-json") == 0) {
            log_json_flag = 1;  // Enable JSON logging if flag is passed
            break;
        }
    }

    // Start the HTTP server to expose metrics
    start_http_server();

    // Initialize conntrack handler
    struct nfct_handle *handle;
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
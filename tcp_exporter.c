#include <stdio.h>
#include <stdlib.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <json-c/json.h>
#include <arpa/inet.h>
#include <string.h>
#include <microhttpd.h>
#include <netinet/tcp.h>

#define PORT 9318
#define INITIAL_BUFFER_SIZE 1024

// Structure to track connections by host and port
struct connection_metrics {
    char host[INET_ADDRSTRLEN];
    uint16_t port;
    int opening_connections;
    int open_connections;
    int closing_connections;
    int closed_connections;
};

#define MAX_HOSTS 100

// TODO: This cannot be a global variable
// due the fact that this have to be recomputed on per request.
struct connection_metrics metrics[MAX_HOSTS];
int metrics_count = 0;

/**
 * @brief Find or add a connection metric for a given host and port.
 *
 * @param ip_str The IP address as a string.
 * @param port The port number.
 * @return A pointer to the corresponding connection_metrics structure.
 */
struct connection_metrics *find_or_add_metrics(const char *ip_str, uint16_t port) {
    for (int i = 0; i < metrics_count; i++) {
        if (strcmp(metrics[i].host, ip_str) == 0 && metrics[i].port == port) {
            return &metrics[i];
        }
    }

    // If not found, add a new entry
    if (metrics_count < MAX_HOSTS) {
        strcpy(metrics[metrics_count].host, ip_str);
        metrics[metrics_count].port = port;
        metrics[metrics_count].opening_connections = 0;
        metrics[metrics_count].open_connections = 0;
        metrics[metrics_count].closing_connections = 0;
        metrics[metrics_count].closed_connections = 0;
        return &metrics[metrics_count++];
    }

    return NULL;
}

/**
 * @brief Maps TCP state to Prometheus state.
 *
 * @param tcp_state The TCP state.
 * @return Corresponding state string.
 */
const char *map_tcp_state_to_prometheus(int tcp_state) {
    switch (tcp_state) {
        case TCP_SYN_SENT:
        case TCP_SYN_RECV:
            return "Opening";
        case TCP_ESTABLISHED:
            return "Open";
        case TCP_FIN_WAIT1:
        case TCP_CLOSE_WAIT:
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
        case TCP_FIN_WAIT2:
            return "Closing";
        case TCP_CLOSE:
            return "Closed";
        default:
            return NULL;
    }
}

int append_to_buffer(char **response, size_t *response_size, const char *new_content) {
    size_t new_content_len = strlen(new_content);
    size_t current_len = strlen(*response);

    // Check if buffer needs to be resized
    if (current_len + new_content_len + 1 > *response_size) {
        size_t new_size = *response_size * 2 + new_content_len;  // Double the buffer size
        char *new_buffer = realloc(*response, new_size);
        if (!new_buffer) {
            fprintf(stderr, "Failed to allocate memory\n");
            return 1;  // Memory allocation failed
        }
        *response = new_buffer;
        *response_size = new_size;
    }

    // Append the new content
    strcat(*response, new_content);
    return 0;
}

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
    size_t buffer_size = INITIAL_BUFFER_SIZE;
    char *response = malloc(buffer_size);
    if (!response) {
        perror("failed to allocate memory for response");
        return MHD_NO;
    }
    response[0] = '\0';

       // For each host, add its metrics
    for (int i = 0; i < metrics_count; i++) {
        char buffer[1024];
        snprintf(buffer, sizeof(buffer),
                 "# HELP conntrack_opening_connections How many connections to the remote host are currently opening?\n"
                 "# TYPE conntrack_opening_connections gauge\n"
                 "conntrack_open_connections{host=\"%s:%u\"} %d\n"
                 "# HELP conntrack_open_connections How many open connections are there to the remote host?\n"
                 "# TYPE conntrack_open_connections gauge\n"
                 "conntrack_opening_connections{host=\"%s:%u\"} %d\n"
                 "# HELP conntrack_closing_connections How many connections to the remote host are currently closing?\n"
                 "# TYPE conntrack_closing_connections gauge\n"
                 "conntrack_closing_connections{host=\"%s:%u\"} %d\n"
                 "# HELP conntrack_closed_connections How many connections to the remote host have recently closed?\n"
                 "# TYPE conntrack_closed_connections gauge\n"
                 "conntrack_closed_connections{host=\"%s:%u\"} %d\n",
                 metrics[i].host, metrics[i].port, metrics[i].opening_connections,
                 metrics[i].host, metrics[i].port, metrics[i].open_connections,
                 metrics[i].host, metrics[i].port, metrics[i].closing_connections,
                 metrics[i].host, metrics[i].port, metrics[i].closed_connections);

        if (append_to_buffer(&response, &buffer_size, buffer)) {
            free(response);
            return MHD_NO;
        }
    }

    struct MHD_Response *http_response;
    http_response = MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_MUST_FREE);
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
    daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, PORT, NULL, NULL, &serve_metrics, NULL, MHD_OPTION_END);
    if (NULL == daemon) {
        return 1;
    }
    printf("HTTP server running on port %d\n", PORT);
    return 0;
}

/**
 * @brief Logs connection events and updates counters based on state.
 *
 * @param ct The connection track object.
 * @param state The state of the connection (e.g., Opening, Open, Closed).
 */
void log_connection_event(struct nf_conntrack *ct, const char *state) {
    char src_ip[INET_ADDRSTRLEN];
    uint32_t src_ip_bin = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
    uint16_t src_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);

    inet_ntop(AF_INET, &src_ip_bin, src_ip, sizeof(src_ip));

    struct connection_metrics *metrics = find_or_add_metrics(src_ip, src_port);

    if (metrics != NULL) {
        if (strcmp(state, "Opening") == 0) {
            metrics->opening_connections++;
        } else if (strcmp(state, "Open") == 0) {
            metrics->open_connections++;
        } else if (strcmp(state, "Closing") == 0) {
            metrics->closing_connections++;
        } else if (strcmp(state, "Closed") == 0) {
            metrics->closed_connections++;
        }
    }
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
    int tcp_state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
    const char *state = map_tcp_state_to_prometheus(tcp_state);

    if (state != NULL) {
        log_connection_event(ct, state);
    }

    return NFCT_CB_CONTINUE;
}

/**
 * @brief Main function that starts the HTTP server and listens for connection events.
 *
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int main() {
    if (start_http_server() == 1) {
        perror("unable to start http server");
        return EXIT_FAILURE;
    }

    struct nfct_handle *handle;
    handle = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_UPDATE);
    if (!handle) {
        perror("nfct_open");
        return EXIT_FAILURE;
    }

    nfct_callback_register(handle, NFCT_T_ALL, event_callback, NULL);
    nfct_catch(handle);

    nfct_close(handle);
    return EXIT_SUCCESS;
}

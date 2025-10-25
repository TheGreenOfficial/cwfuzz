//compile:gcc cwfuzz.c -o cwfuzz -lcurl -lpthread -O3 -w
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/time.h>

#define MAX_URL_LENGTH 4096
#define MAX_HEADER_LENGTH 512
#define MAX_PAYLOAD_LENGTH 1024
#define MAX_THREADS 500
#define MAX_WORDLIST_SIZE 999999
#define MAX_HEADERS 50
#define CONNECTION_REUSE 10

typedef struct {
    char url[MAX_URL_LENGTH];
    char method[16];
    char headers[MAX_HEADERS][MAX_HEADER_LENGTH];
    int header_count;
    char data[MAX_PAYLOAD_LENGTH];
    char** wordlist;
    int wordlist_size;
    int threads;
    int hide_codes[100];
    int hide_count;
    int show_codes[100];
    int show_count;
    int delay;
    int timeout;
    int follow_redirects;
    char proxy[256];
    char output_file[256];
    FILE* output_fp;
    int show_colors;
    int verbose;
} FuzzConfig;

typedef struct {
    int index;
    char* payload;
    FuzzConfig* config;
    CURL* curl;
    struct curl_slist* headers;
} FuzzRequest;

typedef struct {
    char* data;
    size_t size;
    long response_code;
    double total_time;
    curl_off_t content_length;
    int lines;
    int words;
} FuzzResponse;

typedef struct {
    CURL* easy_handle;
    char* payload;
    int index;
    int used;
} ConnectionPool;

volatile int running = 1;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t curl_mutex = PTHREAD_MUTEX_INITIALIZER;
int current_index = 0;
int requests_completed = 0;
int filtered_requests = 0;
ConnectionPool* connection_pool = NULL;
int pool_size = 0;

void handle_signal(int sig) {
    running = 0;
    printf("\nFinishing pending requests...\n");
}

size_t write_callback(void* contents, size_t size, size_t nmemb, FuzzResponse* response) {
    size_t total_size = size * nmemb;
    if(response->size + total_size > 1000000) return 0; // Limit response size
    
    char* ptr = realloc(response->data, response->size + total_size + 1);
    if (!ptr) return 0;
    response->data = ptr;
    memcpy(response->data + response->size, contents, total_size);
    response->size += total_size;
    response->data[response->size] = '\0';
    return total_size;
}

int load_wordlist(FuzzConfig* config, const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error opening wordlist: %s\n", filename);
        return -1;
    }
    
    // First pass: count lines
    int count = 0;
    char buffer[MAX_PAYLOAD_LENGTH];
    while (fgets(buffer, sizeof(buffer), file)) count++;
    rewind(file);
    
    config->wordlist = malloc(count * sizeof(char*));
    if (!config->wordlist) {
        fclose(file);
        return -1;
    }
    
    // Second pass: load data
    int actual_count = 0;
    while (fgets(buffer, sizeof(buffer), file) && actual_count < count) {
        buffer[strcspn(buffer, "\r\n")] = 0;
        if (strlen(buffer) > 0) {
            config->wordlist[actual_count] = malloc(strlen(buffer) + 1);
            if (!config->wordlist[actual_count]) {
                fprintf(stderr, "Memory allocation failed\n");
                fclose(file);
                return -1;
            }
            strcpy(config->wordlist[actual_count], buffer);
            actual_count++;
        }
    }
    
    config->wordlist_size = actual_count;
    fclose(file);
    return actual_count;
}

char* build_target_url(FuzzConfig* config, const char* payload) {
    static __thread char result[MAX_URL_LENGTH];
    const char* placeholder = "FUZZ";
    char* pos = strstr(config->url, placeholder);
    if (!pos) {
        strncpy(result, config->url, MAX_URL_LENGTH);
        return result;
    }
    int prefix_len = pos - config->url;
    int suffix_len = strlen(pos + strlen(placeholder));
    if (prefix_len + strlen(payload) + suffix_len >= MAX_URL_LENGTH) return NULL;
    
    memcpy(result, config->url, prefix_len);
    strcpy(result + prefix_len, payload);
    strcat(result, pos + strlen(placeholder));
    return result;
}

char* build_post_data(FuzzConfig* config, const char* payload) {
    static __thread char result[MAX_PAYLOAD_LENGTH];
    const char* placeholder = "FUZZ";
    char* pos = strstr(config->data, placeholder);
    if (!pos || strlen(config->data) == 0) return config->data;
    int prefix_len = pos - config->data;
    int suffix_len = strlen(pos + strlen(placeholder));
    if (prefix_len + strlen(payload) + suffix_len >= MAX_PAYLOAD_LENGTH) return NULL;
    
    memcpy(result, config->data, prefix_len);
    strcpy(result + prefix_len, payload);
    strcat(result, pos + strlen(placeholder));
    return result;
}

void count_lines_words(FuzzResponse* response) {
    response->lines = 0;
    response->words = 0;
    if (!response->data) return;
    
    char* ptr = response->data;
    int in_word = 0;
    
    while (*ptr) {
        if (*ptr == '\n') response->lines++;
        if (isspace(*ptr)) {
            if (in_word) {
                response->words++;
                in_word = 0;
            }
        } else {
            in_word = 1;
        }
        ptr++;
    }
    if (in_word) response->words++;
}

int should_show_response(FuzzConfig* config, FuzzResponse* response) {
    if (config->show_count > 0) {
        for (int i = 0; i < config->show_count; i++) {
            if (config->show_codes[i] == response->response_code) return 1;
        }
        return 0;
    }
    if (config->hide_count > 0) {
        for (int i = 0; i < config->hide_count; i++) {
            if (config->hide_codes[i] == response->response_code) return 0;
        }
    }
    return 1;
}

void print_colored_response(long code) {
    if (code >= 200 && code < 300) printf("\033[32m");
    else if (code >= 300 && code < 400) printf("\033[34m");  
    else if (code >= 400 && code < 500) printf("\033[33m");
    else if (code >= 500) printf("\033[31m");
}

CURL* get_connection(FuzzConfig* config) {
    pthread_mutex_lock(&curl_mutex);
    
    // Find unused connection
    for (int i = 0; i < pool_size; i++) {
        if (!connection_pool[i].used) {
            connection_pool[i].used = 1;
            CURL* curl = connection_pool[i].easy_handle;
            pthread_mutex_unlock(&curl_mutex);
            return curl;
        }
    }
    
    // Create new connection
    if (pool_size < config->threads * CONNECTION_REUSE) {
        CURL* curl = curl_easy_init();
        if (curl) {
            connection_pool = realloc(connection_pool, (pool_size + 1) * sizeof(ConnectionPool));
            connection_pool[pool_size].easy_handle = curl;
            connection_pool[pool_size].used = 1;
            connection_pool[pool_size].index = pool_size;
            pool_size++;
            pthread_mutex_unlock(&curl_mutex);
            return curl;
        }
    }
    
    pthread_mutex_unlock(&curl_mutex);
    return curl_easy_init(); // Fallback
}

void return_connection(CURL* curl) {
    pthread_mutex_lock(&curl_mutex);
    for (int i = 0; i < pool_size; i++) {
        if (connection_pool[i].easy_handle == curl) {
            connection_pool[i].used = 0;
            break;
        }
    }
    pthread_mutex_unlock(&curl_mutex);
}

void setup_curl_handle(CURL* curl, FuzzConfig* config, FuzzResponse* response, const char* url, const char* post_data) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, config->timeout);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, config->follow_redirects);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "cwfuzz/1.0");
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_FASTOPEN, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    
    if (strlen(config->proxy) > 0) curl_easy_setopt(curl, CURLOPT_PROXY, config->proxy);
    
    if (strcasecmp(config->method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (post_data && strlen(post_data) > 0) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    } else if (strcasecmp(config->method, "HEAD") == 0) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    }
}

void perform_request(FuzzRequest* req) {
    FuzzConfig* config = req->config;
    char* target_url = build_target_url(config, req->payload);
    if (!target_url) return;
    
    CURL* curl = get_connection(config);
    if (!curl) return;
    
    FuzzResponse response = {0};
    response.data = malloc(1);
    
    // Setup headers once per connection
    if (!req->headers) {
        for (int i = 0; i < config->header_count; i++) {
            req->headers = curl_slist_append(req->headers, config->headers[i]);
        }
    }
    if (req->headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req->headers);
    
    char* post_data = build_post_data(config, req->payload);
    setup_curl_handle(curl, config, &response, target_url, post_data);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.response_code);
        curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &response.total_time);
        curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &response.content_length);
        count_lines_words(&response);
        
        if (should_show_response(config, &response)) {
            pthread_mutex_lock(&mutex);
            if (config->show_colors) print_colored_response(response.response_code);
            printf("%08d: %-4ld %7d L\t%-7d W\t%-7lu Ch\t\"%s\"", 
                   req->index + 1, response.response_code, response.lines, 
                   response.words, (unsigned long)response.content_length, req->payload);
            if (config->show_colors) printf("\033[0m");
            printf("\n");
            
            if (config->output_fp) {
                fprintf(config->output_fp, "%08d: %-4ld %7d L\t%-7d W\t%-7lu Ch\t\"%s\"\n", 
                       req->index + 1, response.response_code, response.lines,
                       response.words, (unsigned long)response.content_length, req->payload);
            }
            pthread_mutex_unlock(&mutex);
        } else {
            pthread_mutex_lock(&mutex);
            filtered_requests++;
            pthread_mutex_unlock(&mutex);
        }
    }
    
    free(response.data);
    return_connection(curl);
}

void* fuzz_thread(void* arg) {
    FuzzConfig* config = (FuzzConfig*)arg;
    FuzzRequest req = {.config = config, .headers = NULL};
    
    while (running) {
        pthread_mutex_lock(&mutex);
        int index = current_index++;
        pthread_mutex_unlock(&mutex);
        
        if (index >= config->wordlist_size) break;
        
        req.index = index;
        req.payload = config->wordlist[index];
        perform_request(&req);
        
        pthread_mutex_lock(&mutex);
        requests_completed++;
        pthread_mutex_unlock(&mutex);
        
        if (config->delay > 0) usleep(config->delay * 1000);
    }
    
    if (req.headers) curl_slist_free_all(req.headers);
    return NULL;
}

void parse_codes(const char* str, int* codes, int* count) {
    if (!str) return;
    char* str_copy = strdup(str);
    char* token = strtok(str_copy, ",");
    *count = 0;
    while (token && *count < 100) {
        codes[(*count)++] = atoi(token);
        token = strtok(NULL, ",");
    }
    free(str_copy);
}

void print_banner() {
    printf("\n********************************************************\n");
    printf("*       cwfuzz 1.0 - The C Web Fuzzer By TheGreen      *\n");
    printf("********************************************************\n\n");
}

void print_usage() {
    print_banner();
    printf("Usage: cwfuzz [options]\n\n");
    printf("Options:\n");
    printf("  -h, --help         : This help\n");
    printf("  -u url             : Specify URL\n");
    printf("  -w wordlist        : Specify wordlist file\n");
    printf("  -c                 : Show colors\n");
    printf("  -t threads         : Number of threads (default: 50)\n");
    printf("  -d postdata        : POST data\n");
    printf("  -H header          : HTTP header\n");
    printf("  -X method          : HTTP method (default: GET)\n");
    printf("  --hc codes         : Hide responses with these codes\n");
    printf("  --delay ms         : Delay between requests\n");
    printf("  --timeout s        : Request timeout (default: 10)\n");
    printf("  -L, --follow       : Follow redirects\n");
    printf("  --proxy proxy      : Use proxy\n");
    printf("  -o file            : Output file\n");
    printf("  -v                 : Verbose mode\n\n");
}

void init_config(FuzzConfig* config) {
    memset(config, 0, sizeof(FuzzConfig));
    strcpy(config->method, "GET");
    config->threads = 50;
    config->timeout = 10;
    config->follow_redirects = 0;
    config->output_fp = NULL;
    config->show_colors = 0;
    config->verbose = 0;
}

void cleanup_config(FuzzConfig* config) {
    for (int i = 0; i < config->wordlist_size; i++) free(config->wordlist[i]);
    free(config->wordlist);
    if (config->output_fp) fclose(config->output_fp);
    
    // Cleanup connection pool
    for (int i = 0; i < pool_size; i++) {
        curl_easy_cleanup(connection_pool[i].easy_handle);
    }
    free(connection_pool);
}

int main(int argc, char* argv[]) {
    FuzzConfig config;
    init_config(&config);
    
    static struct option long_options[] = {
        {"hc", required_argument, 0, 1000},
        {"delay", required_argument, 0, 1001},
        {"timeout", required_argument, 0, 1002},
        {"follow", no_argument, 0, 'L'},
        {"proxy", required_argument, 0, 1003},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    char* wordlist_file = NULL;
    char* url = NULL;
    struct timeval start_time, end_time;
    
    while ((opt = getopt_long(argc, argv, "u:w:cd:H:X:t:o:Lhv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'u': url = optarg; break;
            case 'w': wordlist_file = optarg; break;
            case 'c': config.show_colors = 1; break;
            case 'd': strncpy(config.data, optarg, sizeof(config.data) - 1); break;
            case 'H': 
                if (config.header_count < MAX_HEADERS) {
                    strncpy(config.headers[config.header_count], optarg, sizeof(config.headers[config.header_count]) - 1);
                    config.header_count++;
                } break;
            case 'X': strncpy(config.method, optarg, sizeof(config.method) - 1); break;
            case 't': 
                config.threads = atoi(optarg);
                if (config.threads > MAX_THREADS) config.threads = MAX_THREADS;
                if (config.threads < 1) config.threads = 1; break;
            case 'o': 
                strncpy(config.output_file, optarg, sizeof(config.output_file) - 1);
                config.output_fp = fopen(config.output_file, "w");
                if (!config.output_fp) {
                    fprintf(stderr, "Error opening output file: %s\n", config.output_file);
                    return 1;
                } break;
            case 'L': config.follow_redirects = 1; break;
            case 'v': config.verbose = 1; break;
            case 1000: parse_codes(optarg, config.hide_codes, &config.hide_count); break;
            case 1001: config.delay = atoi(optarg); break;
            case 1002: config.timeout = atoi(optarg); break;
            case 1003: strncpy(config.proxy, optarg, sizeof(config.proxy) - 1); break;
            case 'h': print_usage(); cleanup_config(&config); return 0;
            default: print_usage(); cleanup_config(&config); return 1;
        }
    }
    
    if (!url) {
        fprintf(stderr, "Error: No URL specified (-u)\n");
        print_usage();
        return 1;
    }
    strncpy(config.url, url, sizeof(config.url) - 1);
    
    if (!wordlist_file) {
        fprintf(stderr, "Error: No wordlist specified (-w)\n");
        print_usage();
        return 1;
    }
    
    if (!strstr(config.url, "FUZZ") && !strstr(config.data, "FUZZ")) {
        fprintf(stderr, "Error: URL or POST data must contain FUZZ placeholder\n");
        return 1;
    }
    
    printf("Loading wordlist... ");
    fflush(stdout);
    int wordcount = load_wordlist(&config, wordlist_file);
    if (wordcount <= 0) {
        fprintf(stderr, "Error: Failed to load wordlist\n");
        return 1;
    }
    printf("Loaded %d words\n", wordcount);
    
    print_banner();
    printf("Target: %s\n", config.url);
    if (strlen(config.data) > 0) printf("Data: %s\n", config.data);
    printf("Total requests: %d\n", config.wordlist_size);
    printf("Threads: %d\n", config.threads);
    if (config.verbose) {
        printf("Connection reuse: %d per thread\n", CONNECTION_REUSE);
        printf("Timeout: %d seconds\n", config.timeout);
    }
    printf("\n");
    printf("=====================================================================\n");
    printf("ID           Response   Lines    Word       Chars       Payload\n");
    printf("=====================================================================\n");
    
    curl_global_init(CURL_GLOBAL_ALL);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    gettimeofday(&start_time, NULL);
    
    pthread_t threads[config.threads];
    for (int i = 0; i < config.threads && running; i++) {
        if (pthread_create(&threads[i], NULL, fuzz_thread, &config) != 0) {
            fprintf(stderr, "Error creating thread %d\n", i);
        }
    }
    
    for (int i = 0; i < config.threads; i++) pthread_join(threads[i], NULL);
    
    gettimeofday(&end_time, NULL);
    double total_time = (end_time.tv_sec - start_time.tv_sec) + 
                       (end_time.tv_usec - start_time.tv_usec) / 1000000.0;
    
    printf("\nTotal time: %.6f\n", total_time);
    printf("Processed Requests: %d\n", requests_completed);
    printf("Filtered Requests: %d\n", filtered_requests);
    if (total_time > 0) printf("Requests/sec.: %.2f\n", requests_completed / total_time);
    
    cleanup_config(&config);
    curl_global_cleanup();
    return 0;
}
int parse_http_request(register struct kevent const *const kephttp, char *);
int get_response(char *bufout, register struct kevent const *const kephttp, int page_is_read);

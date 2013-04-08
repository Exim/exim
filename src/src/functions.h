/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2012 */
/* See the file NOTICE for conditions of use and distribution. */


/* Prototypes for functions that appear in various modules. Gathered together
to avoid having a lot of tiddly little headers with only a couple of lines in
them. However, some functions that are used (or not used) by utility programs
are in in fact in separate headers. */


#ifdef EXIM_PERL
extern uschar *call_perl_cat(uschar *, int *, int *, uschar **, uschar *,
                 uschar **);
extern void    cleanup_perl(void);
extern uschar *init_perl(uschar *);
#endif


#ifdef SUPPORT_TLS
extern const char *
               std_dh_prime_default(void);
extern const char *
               std_dh_prime_named(const uschar *);
extern int     tls_client_start(int, host_item *, address_item *,
                 uschar *, uschar *, uschar *, uschar *, uschar *, uschar *,
# ifdef EXPERIMENTAL_OCSP
                 uschar *,
# endif
                 int, int);
extern void    tls_close(BOOL, BOOL);
extern int     tls_feof(void);
extern int     tls_ferror(void);
extern int     tls_getc(void);
extern int     tls_read(BOOL, uschar *, size_t);
extern int     tls_server_start(const uschar *);
extern BOOL    tls_smtp_buffered(void);
extern int     tls_ungetc(int);
extern int     tls_write(BOOL, const uschar *, size_t);
extern uschar *tls_validate_require_cipher(void);
extern void    tls_version_report(FILE *);
#ifndef USE_GNUTLS
extern BOOL    tls_openssl_options_parse(uschar *, long *);
#endif
#endif


/* Everything else... */

extern acl_block *acl_read(uschar *(*)(void), uschar **);
extern int     acl_check(int, uschar *, uschar *, uschar **, uschar **);
extern int     acl_eval(int, uschar *, uschar **, uschar **);

extern tree_node *acl_var_create(uschar *);
extern void    acl_var_write(uschar *, uschar *, void *);
extern uschar *auth_b64encode(uschar *, int);
extern int     auth_b64decode(uschar *, uschar **);
extern int     auth_call_pam(uschar *, uschar **);
extern int     auth_call_pwcheck(uschar *, uschar **);
extern int     auth_call_radius(uschar *, uschar **);
extern int     auth_call_saslauthd(uschar *, uschar *, uschar *, uschar *,
                 uschar **);
extern int     auth_check_serv_cond(auth_instance *);
extern int     auth_check_some_cond(auth_instance *, uschar *, uschar *, int);

extern int     auth_get_data(uschar **, uschar *, int);
extern int     auth_get_no64_data(uschar **, uschar *);
extern uschar *auth_xtextencode(uschar *, int);
extern int     auth_xtextdecode(uschar *, uschar **);

extern void    cancel_cutthrough_connection(const char *);
extern int     check_host(void *, uschar *, uschar **, uschar **);
extern uschar **child_exec_exim(int, BOOL, int *, BOOL, int, ...);
extern pid_t   child_open_uid(uschar **, uschar **, int, uid_t *, gid_t *,
                 int *, int *, uschar *, BOOL);
extern uschar *cutthrough_finaldot(void);
extern BOOL    cutthrough_flush_send(void);
extern BOOL    cutthrough_headers_send(void);
extern BOOL    cutthrough_predata(void);
extern BOOL    cutthrough_puts(uschar *, int);
extern BOOL    cutthrough_put_nl(void);

extern void    daemon_go(void);

#ifdef EXPERIMENTAL_DCC
extern int     dcc_process(uschar **);
#endif

extern void    debug_logging_activate(uschar *, uschar *);
extern void    debug_print_argv(uschar **);
extern void    debug_print_ids(uschar *);
extern void    debug_print_string(uschar *);
extern void    debug_print_tree(tree_node *);
extern void    debug_vprintf(const char *, va_list);
extern void    decode_bits(unsigned int *, unsigned int *,
                  int, int, uschar *, bit_table *, int, uschar *, int);
extern address_item *deliver_make_addr(uschar *, BOOL);
extern void    delivery_log(int, address_item *, int, uschar *);
extern int     deliver_message(uschar *, BOOL, BOOL);
extern void    deliver_msglog(const char *, ...) PRINTF_FUNCTION(1,2);
extern void    deliver_set_expansions(address_item *);
extern int     deliver_split_address(address_item *);
extern void    deliver_succeeded(address_item *);
#ifdef WITH_OLD_DEMIME
extern int     demime(uschar **);
#endif
extern BOOL    directory_make(const uschar *, const uschar *, int, BOOL);
#ifndef DISABLE_DKIM
extern BOOL    dkim_transport_write_message(address_item *, int, int,
                   int, uschar *, uschar *, uschar *, uschar *, rewrite_rule *,
                   int, uschar *, uschar *, uschar *, uschar *, uschar *, uschar *);
#endif
extern dns_address *dns_address_from_rr(dns_answer *, dns_record *);
extern void    dns_build_reverse(uschar *, uschar *);
extern void    dns_init(BOOL, BOOL);
extern int     dns_basic_lookup(dns_answer *, uschar *, int);
extern BOOL    dns_is_secure(dns_answer *);
extern int     dns_lookup(dns_answer *, uschar *, int, uschar **);
extern int     dns_special_lookup(dns_answer *, uschar *, int, uschar **);
extern dns_record *dns_next_rr(dns_answer *, dns_scan *, int);
extern uschar *dns_text_type(int);
extern void    dscp_list_to_stream(FILE *);
extern BOOL    dscp_lookup(const uschar *, int, int *, int *, int *);

extern void    enq_end(uschar *);
extern BOOL    enq_start(uschar *);
extern void    exim_exit(int);
extern void    exim_nullstd(void);
extern void    exim_setugid(uid_t, gid_t, BOOL, uschar *);
extern int     exim_tvcmp(struct timeval *, struct timeval *);
extern void    exim_wait_tick(struct timeval *, int);
extern BOOL    expand_check_condition(uschar *, uschar *, uschar *);
extern uschar *expand_string(uschar *);
extern uschar *expand_string_copy(uschar *);
extern int_eximarith_t expand_string_integer(uschar *, BOOL);
extern void    modify_variable(uschar *, void *);

extern int     filter_interpret(uschar *, int, address_item **, uschar **);
extern BOOL    filter_personal(string_item *, BOOL);
extern BOOL    filter_runtest(int, uschar *, BOOL, BOOL);
extern BOOL    filter_system_interpret(address_item **, uschar **);

extern uschar * fn_hdrs_added(void);

extern void    header_add(int, const char *, ...);
extern int     header_checkname(header_line *, BOOL);
extern BOOL    header_match(uschar *, BOOL, BOOL, string_item *, int, ...);
extern int     host_address_extract_port(uschar *);
extern uschar *host_and_ident(BOOL);
extern int     host_aton(uschar *, int *);
extern void    host_build_hostlist(host_item **, uschar *, BOOL);
extern ip_address_item *host_build_ifacelist(uschar *, uschar *);
extern void    host_build_log_info(void);
extern void    host_build_sender_fullhost(void);
extern BOOL    host_find_byname(host_item *, uschar *, int, uschar **, BOOL);
extern int     host_find_bydns(host_item *, uschar *, int, uschar *, uschar *,
                 uschar *,uschar **, BOOL *);
extern ip_address_item *host_find_interfaces(void);
extern BOOL    host_is_in_net(uschar *, uschar *, int);
extern BOOL    host_is_tls_on_connect_port(int);
extern int     host_item_get_port(host_item *);
extern void    host_mask(int, int *, int);
extern int     host_name_lookup(void);
extern int     host_nmtoa(int, int *, int, uschar *, int);
extern uschar *host_ntoa(int, const void *, uschar *, int *);
extern int     host_scan_for_local_hosts(host_item *, host_item **, BOOL *);

extern void    invert_address(uschar *, uschar *);
extern int     ip_bind(int, int, uschar *, int);
extern int     ip_connect(int, int, uschar *, int, int);
extern int     ip_get_address_family(int);
extern void    ip_keepalive(int, uschar *, BOOL);
extern int     ip_recv(int, uschar *, int, int);
extern int     ip_socket(int, int);

extern uschar *local_part_quote(uschar *);
extern int     log_create(uschar *);
extern int     log_create_as_exim(uschar *);
extern void    log_close_all(void);

#ifdef WITH_CONTENT_SCAN
extern int     malware(uschar **);
extern int     malware_in_file(uschar *);
#endif
extern int     match_address_list(uschar *, BOOL, BOOL, uschar **,
                 unsigned int *, int, int, uschar **);
extern int     match_check_list(uschar **, int, tree_node **, unsigned int **,
                 int(*)(void *, uschar *, uschar **, uschar **), void *, int,
                 uschar *, uschar **);
extern int     match_isinlist(uschar *, uschar **, int, tree_node **,
                 unsigned int *, int, BOOL, uschar **);
extern int     match_check_string(uschar *, uschar *, int, BOOL, BOOL, BOOL,
                 uschar **);
extern void    md5_end(md5 *, const uschar *, int, uschar *);
extern void    md5_mid(md5 *, const uschar *);
extern void    md5_start(md5 *);
extern void    millisleep(int);
#ifdef WITH_CONTENT_SCAN
struct mime_boundary_context;
extern int     mime_acl_check(uschar *acl, FILE *f,
                 struct mime_boundary_context *, uschar **, uschar **);
extern int     mime_decode(uschar **);
extern int     mime_regex(uschar **);
#endif
extern uschar *moan_check_errorcopy(uschar *);
extern BOOL    moan_skipped_syntax_errors(uschar *, error_block *, uschar *,
                 BOOL, uschar *);
extern void    moan_smtp_batch(uschar *, const char *, ...) PRINTF_FUNCTION(2,3);
extern void    moan_tell_someone(uschar *, address_item *,
                 const uschar *, const char *, ...) PRINTF_FUNCTION(4,5);
extern BOOL    moan_to_sender(int, error_block *, header_line *, FILE *, BOOL);
extern void    moan_write_from(FILE *);
extern FILE   *modefopen(const uschar *, const char *, mode_t);

extern void   open_cutthrough_connection( address_item * addr );

extern uschar *parse_extract_address(uschar *, uschar **, int *, int *, int *,
                 BOOL);
extern int     parse_forward_list(uschar *, int, address_item **, uschar **,
                 uschar *, uschar *, error_block **);
extern uschar *parse_find_address_end(uschar *, BOOL);
extern uschar *parse_find_at(uschar *);
extern uschar *parse_fix_phrase(uschar *, int, uschar *, int);
extern uschar *parse_message_id(uschar *, uschar **, uschar **);
extern uschar *parse_quote_2047(uschar *, int, uschar *, uschar *, int, BOOL);
extern uschar *parse_date_time(uschar *str, time_t *t);
extern int     vaguely_random_number(int);
#ifdef SUPPORT_TLS
extern int     vaguely_random_number_fallback(int);
#endif

extern BOOL    queue_action(uschar *, int, uschar **, int, int);
extern void    queue_check_only(void);
extern void    queue_list(int, uschar **, int);
extern void    queue_count(void);
extern void    queue_run(uschar *, uschar *, BOOL);

extern int     random_number(int);
#ifdef WITH_CONTENT_SCAN
extern int     recv_line(int, uschar *, int);
#endif
extern int     rda_interpret(redirect_block *, int, uschar *, uschar *,
                 uschar *, uschar *, uschar *, ugid_block *, address_item **,
                 uschar **, error_block **, int *, uschar *);
extern int     rda_is_filter(const uschar *);
extern BOOL    readconf_depends(driver_instance *, uschar *);
extern void    readconf_driver_init(uschar *, driver_instance **,
                 driver_info *, int, void *, int, optionlist *, int);
extern uschar *readconf_find_option(void *);
extern void    readconf_main(void);
extern void    readconf_print(uschar *, uschar *, BOOL);
extern uschar *readconf_printtime(int);
extern uschar *readconf_readname(uschar *, int, uschar *);
extern int     readconf_readtime(uschar *, int, BOOL);
extern void    readconf_rest(BOOL);
extern uschar *readconf_retry_error(uschar *, uschar *, int *, int *);
extern void    read_message_body(BOOL);
extern void    receive_bomb_out(uschar *, uschar *);
extern BOOL    receive_check_fs(int);
extern BOOL    receive_check_set_sender(uschar *);
extern BOOL    receive_msg(BOOL);
extern int     receive_statvfs(BOOL, int *);
extern void    receive_swallow_smtp(void);
#ifdef WITH_CONTENT_SCAN
extern int     regex(uschar **);
#endif
extern BOOL    regex_match_and_setup(const pcre *, uschar *, int, int);
extern const pcre *regex_must_compile(uschar *, BOOL, BOOL);
extern void    retry_add_item(address_item *, uschar *, int);
extern BOOL    retry_check_address(uschar *, host_item *, uschar *, BOOL,
                 uschar **, uschar **);
extern retry_config *retry_find_config(uschar *, uschar *, int, int);
extern BOOL    retry_ultimate_address_timeout(uschar *, uschar *,
                 dbdata_retry *, time_t);
extern void    retry_update(address_item **, address_item **, address_item **);
extern uschar *rewrite_address(uschar *, BOOL, BOOL, rewrite_rule *, int);
extern uschar *rewrite_address_qualify(uschar *, BOOL);
extern header_line *rewrite_header(header_line *, uschar *, uschar *,
               rewrite_rule *, int, BOOL);
extern uschar *rewrite_one(uschar *, int, BOOL *, BOOL, uschar *,
                 rewrite_rule *);
extern void    rewrite_test(uschar *);
extern uschar *rfc2047_decode2(uschar *, BOOL, uschar *, int, int *, int *,
                 uschar **);
extern int     route_address(address_item *, address_item **, address_item **,
                 address_item **, address_item **, int);
extern int     route_check_prefix(uschar *, uschar *);
extern int     route_check_suffix(uschar *, uschar *);
extern BOOL    route_findgroup(uschar *, gid_t *);
extern BOOL    route_finduser(uschar *, struct passwd **, uid_t *);
extern BOOL    route_find_expanded_group(uschar *, uschar *, uschar *, gid_t *,
                 uschar **);
extern BOOL    route_find_expanded_user(uschar *, uschar *, uschar *,
                 struct passwd **, uid_t *, uschar **);
extern void    route_init(void);
extern void    route_tidyup(void);

extern uschar *search_find(void *, uschar *, uschar *, int, uschar *, int,
                 int, int *);
extern int     search_findtype(uschar *, int);
extern int     search_findtype_partial(uschar *, int *, uschar **, int *,
                 int *);
extern void   *search_open(uschar *, int, int, uid_t *, gid_t *);
extern void    search_tidyup(void);
extern void    set_process_info(const char *, ...) PRINTF_FUNCTION(1,2);
extern void    sha1_end(sha1 *, const uschar *, int, uschar *);
extern void    sha1_mid(sha1 *, const uschar *);
extern void    sha1_start(sha1 *);
extern int     sieve_interpret(uschar *, int, uschar *, uschar *, uschar *,
                 uschar *, address_item **, uschar **);
extern void    sigalrm_handler(int);
extern BOOL    smtp_buffered(void);
extern void    smtp_closedown(uschar *);
extern int     smtp_connect(host_item *, int, int, uschar *, int, BOOL, const uschar *);
extern int     smtp_feof(void);
extern int     smtp_ferror(void);
extern uschar *smtp_get_connection_info(void);
extern BOOL    smtp_get_interface(uschar *, int, address_item *, BOOL *,
                 uschar **, uschar *);
extern BOOL    smtp_get_port(uschar *, address_item *, int *, uschar *);
extern int     smtp_getc(void);
extern int     smtp_handle_acl_fail(int, int, uschar *, uschar *);
extern void    smtp_log_no_mail(void);
extern void    smtp_message_code(uschar **, int *, uschar **, uschar **);
extern BOOL    smtp_read_response(smtp_inblock *, uschar *, int, int, int);
extern void    smtp_respond(uschar *, int, BOOL, uschar *);
extern void    smtp_notquit_exit(uschar *, uschar *, uschar *, ...);
extern void    smtp_send_prohibition_message(int, uschar *);
extern int     smtp_setup_msg(void);
extern BOOL    smtp_start_session(void);
extern int     smtp_ungetc(int);
extern BOOL    smtp_verify_helo(void);
extern int     smtp_write_command(smtp_outblock *, BOOL, const char *, ...) PRINTF_FUNCTION(3,4);
#ifdef WITH_CONTENT_SCAN
extern int     spam(uschar **);
extern FILE   *spool_mbox(unsigned long *, uschar *);
#endif
extern BOOL    spool_move_message(uschar *, uschar *, uschar *, uschar *);
extern BOOL    spool_open_datafile(uschar *);
extern int     spool_open_temp(uschar *);
extern int     spool_read_header(uschar *, BOOL, BOOL);
extern int     spool_write_header(uschar *, int, uschar **);
extern int     stdin_getc(void);
extern int     stdin_feof(void);
extern int     stdin_ferror(void);
extern int     stdin_ungetc(int);
extern uschar *string_append(uschar *, int *, int *, int, ...);
extern uschar *string_base62(unsigned long int);
extern uschar *string_cat(uschar *, int *, int *, const uschar *, int);
extern uschar *string_copy_dnsdomain(uschar *);
extern uschar *string_copy_malloc(uschar *);
extern uschar *string_copylc(uschar *);
extern uschar *string_copynlc(uschar *, int);
extern uschar *string_dequote(uschar **);
extern BOOL    string_format(uschar *, int, const char *, ...) ALMOST_PRINTF(3,4);
extern uschar *string_format_size(int, uschar *);
extern int     string_interpret_escape(uschar **);
extern int     string_is_ip_address(uschar *, int *);
extern uschar *string_log_address(address_item *, BOOL, BOOL);
extern uschar *string_nextinlist(uschar **, int *, uschar *, int);
extern uschar *string_open_failed(int, const char *, ...) PRINTF_FUNCTION(2,3);
extern uschar *string_printing2(uschar *, BOOL);
extern uschar *string_split_message(uschar *);
extern uschar *string_unprinting(uschar *);
extern BOOL    string_vformat(uschar *, int, const char *, va_list);
extern int     strcmpic(const uschar *, const uschar *);
extern int     strncmpic(const uschar *, const uschar *, int);
extern uschar *strstric(uschar *, uschar *, BOOL);

extern uschar *tod_stamp(int);
extern BOOL    transport_check_waiting(uschar *, uschar *, int, uschar *,
                 BOOL *);
extern void    transport_init(void);
extern BOOL    transport_pass_socket(uschar *, uschar *, uschar *, uschar *,
                 int);
extern uschar *transport_rcpt_address(address_item *, BOOL);
extern BOOL    transport_set_up_command(uschar ***, uschar *, BOOL, int,
                 address_item *, uschar *, uschar **);
extern void    transport_update_waiting(host_item *, uschar *);
extern BOOL    transport_write_block(int, uschar *, int);
extern BOOL    transport_write_string(int, const char *, ...);
extern BOOL    transport_write_message(address_item *, int, int, int, uschar *,
                 uschar *, uschar *, uschar *, rewrite_rule *, int);
extern void    tree_add_duplicate(uschar *, address_item *);
extern void    tree_add_nonrecipient(uschar *);
extern void    tree_add_unusable(host_item *);
extern int     tree_insertnode(tree_node **, tree_node *);
extern tree_node *tree_search(tree_node *, uschar *);
extern void    tree_write(tree_node *, FILE *);
extern void    tree_walk(tree_node *, void (*)(uschar*, uschar*, void*), void *);

#ifdef WITH_CONTENT_SCAN
extern void    unspool_mbox(void);
#endif

extern int     verify_address(address_item *, FILE *, int, int, int, int,
                 uschar *, uschar *, BOOL *);
extern int     verify_check_dnsbl(uschar **);
extern int     verify_check_header_address(uschar **, uschar **, int, int, int,
                 uschar *, uschar *, int, int *);
extern int     verify_check_headers(uschar **);
extern int     verify_check_host(uschar **);
extern int     verify_check_notblind(void);
extern int     verify_check_this_host(uschar **, unsigned int *, uschar*,
                 uschar *, uschar **);
extern address_item *verify_checked_sender(uschar *);
extern void    verify_get_ident(int);
extern BOOL    verify_sender(int *, uschar **);
extern BOOL    verify_sender_preliminary(int *, uschar **);
extern void    version_init(void);

extern ssize_t write_to_fd_buf(int, const uschar *, size_t);

/* End of functions.h */

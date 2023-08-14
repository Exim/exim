/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2022 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


/* Prototypes for functions that appear in various modules. Gathered together
to avoid having a lot of tiddly little headers with only a couple of lines in
them. However, some functions that are used (or not used) by utility programs
are in in fact in separate headers. */
#ifndef _FUNCTIONS_H_
#define _FUNCTIONS_H_

#include <ctype.h>
#include <sys/time.h>


#ifdef EXIM_PERL
extern gstring *call_perl_cat(gstring *, uschar **, uschar *,
                 uschar **) WARN_UNUSED_RESULT;
extern void    cleanup_perl(void);
extern uschar *init_perl(uschar *);
#endif


#ifndef DISABLE_TLS
extern const char *
               std_dh_prime_default(void);
extern const char *
               std_dh_prime_named(const uschar *);

extern uschar * tls_cert_crl_uri(void *, uschar * mod);
extern uschar * tls_cert_ext_by_oid(void *, uschar *, int);
extern uschar * tls_cert_issuer(void *, uschar * mod);
extern uschar * tls_cert_not_before(void *, uschar * mod);
extern uschar * tls_cert_not_after(void *, uschar * mod);
extern uschar * tls_cert_ocsp_uri(void *, uschar * mod);
extern uschar * tls_cert_serial_number(void *, uschar * mod);
extern uschar * tls_cert_signature(void *, uschar * mod);
extern uschar * tls_cert_signature_algorithm(void *, uschar * mod);
extern uschar * tls_cert_subject(void *, uschar * mod);
extern uschar * tls_cert_subject_altname(void *, uschar * mod);
extern uschar * tls_cert_version(void *, uschar * mod);

extern uschar * tls_cert_der_b64(void * cert);
extern uschar * tls_cert_fprt_md5(void *);
extern uschar * tls_cert_fprt_sha1(void *);
extern uschar * tls_cert_fprt_sha256(void *);

extern void    tls_clean_env(void);
extern BOOL    tls_client_start(client_conn_ctx *, smtp_connect_args *,
		  void *, tls_support *, uschar **);
extern void    tls_client_creds_reload(BOOL);

extern void    tls_close(void *, int);
extern BOOL    tls_could_getc(void);
extern void    tls_daemon_init(void);
extern int     tls_daemon_tick(void);
extern BOOL    tls_dropprivs_validate_require_cipher(BOOL);
extern BOOL    tls_export_cert(uschar *, size_t, void *);
extern int     tls_feof(void);
extern int     tls_ferror(void);
extern uschar *tls_field_from_dn(uschar *, const uschar *);
extern void    tls_free_cert(void **);
extern int     tls_getc(unsigned);
extern uschar *tls_getbuf(unsigned *);
extern void    tls_get_cache(unsigned);
extern BOOL    tls_hasc(void);
extern BOOL    tls_import_cert(const uschar *, void **);
extern BOOL    tls_is_name_for_cert(const uschar *, void *);
# ifdef USE_OPENSSL
extern BOOL    tls_openssl_options_parse(uschar *, long *);
# endif
extern int     tls_read(void *, uschar *, size_t);
extern int     tls_server_start(uschar **);
extern void    tls_shutdown_wr(void *);
extern BOOL    tls_smtp_buffered(void);
extern int     tls_ungetc(int);
#if defined(EXIM_HAVE_INOTIFY) || defined(EXIM_HAVE_KEVENT)
extern void    tls_watch_discard_event(int);
extern void    tls_watch_invalidate(void);
#endif
extern int     tls_write(void *, const uschar *, size_t, BOOL);
extern uschar *tls_validate_require_cipher(void);
extern gstring *tls_version_report(gstring *);

# ifdef SUPPORT_DANE
extern int     tlsa_lookup(const host_item *, dns_answer *, BOOL);
# endif

#endif	/*DISABLE_TLS*/


/* Everything else... */

extern acl_block *acl_read(uschar *(*)(void), uschar **);
extern int     acl_check(int, uschar *, uschar *, uschar **, uschar **);
extern uschar *acl_current_verb(void);
extern int     acl_eval(int, uschar *, uschar **, uschar **);

extern tree_node *acl_var_create(uschar *);
extern void    acl_var_write(uschar *, uschar *, void *);

#ifdef EXPERIMENTAL_ARC
extern void   *arc_ams_setup_sign_bodyhash(void);
extern const uschar *arc_header_feed(gstring *, BOOL);
extern gstring *arc_sign(const uschar *, gstring *, uschar **);
extern void     arc_sign_init(void);
extern const uschar *acl_verify_arc(void);
extern uschar * fn_arc_domains(void);
#endif

extern void    assert_no_variables(void *, int, const char *, int);
extern int     auth_call_pam(const uschar *, uschar **);
extern int     auth_call_pwcheck(uschar *, uschar **);
extern int     auth_call_radius(const uschar *, uschar **);
extern int     auth_call_saslauthd(const uschar *, const uschar *,
	         const uschar *, const uschar *, uschar **);
extern int     auth_check_serv_cond(auth_instance *);
extern int     auth_check_some_cond(auth_instance *, uschar *, uschar *, int);
extern int     auth_client_item(void *, auth_instance *, const uschar **,
		 unsigned, int, uschar *, int);


extern int     auth_get_data(uschar **, const uschar *, int);
extern int     auth_get_no64_data(uschar **, uschar *);
extern int     auth_prompt(const uschar *);
extern int     auth_read_input(const uschar *);
extern gstring * auth_show_supported(gstring *);
extern uschar *auth_xtextencode(uschar *, int);
extern int     auth_xtextdecode(uschar *, uschar **);
extern uschar *authenticator_current_name(void);

#ifdef EXPERIMENTAL_ARC
extern gstring *authres_arc(gstring *);
#endif
#ifndef DISABLE_DKIM
extern gstring *authres_dkim(gstring *);
#endif
#ifdef SUPPORT_DMARC
extern gstring *authres_dmarc(gstring *);
#endif
extern gstring *authres_smtpauth(gstring *);
#ifdef SUPPORT_SPF
extern gstring *authres_spf(gstring *);
#endif

extern uschar *b64encode(const uschar *, int);
extern uschar *b64encode_taint(const uschar *, int, const void *);
extern int     b64decode(const uschar *, uschar **);
extern int     bdat_getc(unsigned);
extern uschar *bdat_getbuf(unsigned *);
extern BOOL    bdat_hasc(void);
extern int     bdat_ungetc(int);
extern void    bdat_flush_data(void);

extern void    bits_clear(unsigned int *, size_t, int *);
extern void    bits_set(unsigned int *, size_t, int *);

extern void    cancel_cutthrough_connection(BOOL, const uschar *);
extern gstring *cat_file(FILE *, gstring *, uschar *);
extern gstring *cat_file_tls(void *, gstring *, uschar *);
extern int     check_host(void *, const uschar *, const uschar **, uschar **);
extern uschar **child_exec_exim(int, BOOL, int *, BOOL, int, ...);
extern pid_t   child_open_exim_function(int *, const uschar *);
extern pid_t   child_open_exim2_function(int *, uschar *, uschar *,
		 const uschar *);
extern pid_t   child_open_function(uschar **, uschar **, int,
		 int *, int *, BOOL, const uschar *);
extern pid_t   child_open_uid(const uschar **, const uschar **, int,
		 uid_t *, gid_t *, int *, int *, uschar *, BOOL, const uschar *);
extern BOOL    cleanup_environment(void);
extern void    cutthrough_data_puts(uschar *, int);
extern void    cutthrough_data_put_nl(void);
extern uschar *cutthrough_finaldot(void);
extern BOOL    cutthrough_flush_send(void);
extern BOOL    cutthrough_headers_send(void);
extern BOOL    cutthrough_predata(void);
extern void    release_cutthrough_connection(const uschar *);

extern void    daemon_go(void);

#ifdef EXPERIMENTAL_DCC
extern int     dcc_process(uschar **);
#endif

extern void    debug_logging_activate(const uschar *, const uschar *);
extern void    debug_logging_from_spool(const uschar *);
extern void    debug_logging_stop(BOOL);
extern void    debug_print_argv(const uschar **);
extern void    debug_print_ids(uschar *);
extern void    debug_printf_indent(const char *, ...) PRINTF_FUNCTION(1,2);
extern void    debug_print_string(uschar *);
extern void    debug_print_tree(const char *, tree_node *);
extern void    debug_vprintf(int, const char *, va_list);
extern void    debug_pretrigger_setup(const uschar *);
extern void    debug_pretrigger_discard(void);
extern void    debug_print_socket(int);
extern void    debug_trigger_fire(void);

extern void    decode_bits(unsigned int *, size_t, int *,
	           const uschar *, bit_table *, int, uschar *, int);
extern void    delete_pid_file(void);
extern void    deliver_local(address_item *, BOOL);
extern address_item *deliver_make_addr(uschar *, BOOL);
extern void    delivery_log(int, address_item *, int, uschar *);
extern int     deliver_message(uschar *, BOOL, BOOL);
extern void    deliver_msglog(const char *, ...) PRINTF_FUNCTION(1,2);
extern void    deliver_set_expansions(address_item *);
extern int     deliver_split_address(address_item *);
extern void    deliver_succeeded(address_item *);

extern void    delivery_re_exec(int);

extern void    die_tainted(const uschar *, const uschar *, int);
extern BOOL    directory_make(const uschar *, const uschar *, int, BOOL);
#ifndef DISABLE_DKIM
extern uschar *dkim_exim_query_dns_txt(const uschar *);
extern void    dkim_exim_sign_init(void);

extern BOOL    dkim_transport_write_message(transport_ctx *,
		  struct ob_dkim *, const uschar ** errstr);
#endif
extern dns_address *dns_address_from_rr(dns_answer *, dns_record *);
extern int     dns_basic_lookup(dns_answer *, const uschar *, int);
extern uschar *dns_build_reverse(const uschar *);
extern time_t  dns_expire_from_soa(dns_answer *, int);
extern void    dns_init(BOOL, BOOL, BOOL);
extern BOOL    dns_is_aa(const dns_answer *);
extern BOOL    dns_is_secure(const dns_answer *);
extern int     dns_lookup(dns_answer *, const uschar *, int, const uschar **);
extern void    dns_pattern_init(void);
extern int     dns_special_lookup(dns_answer *, const uschar *, int, const uschar **);
extern dns_record *dns_next_rr(const dns_answer *, dns_scan *, int);
extern uschar *dns_text_type(int);
extern void    dscp_list_to_stream(FILE *);
extern BOOL    dscp_lookup(const uschar *, int, int *, int *, int *);

extern void    enq_end(uschar *);
extern BOOL    enq_start(uschar *, unsigned);
#ifndef DISABLE_EVENT
extern uschar *event_raise(uschar *, const uschar *, uschar *, int *);
extern void    msg_event_raise(const uschar *, const address_item *);
#endif

extern int     exim_chown_failure(int, const uschar*, uid_t, gid_t);
extern const uschar * exim_errstr(int);
extern void    exim_exit(int) NORETURN;
extern void    exim_gettime(struct timeval *);
extern void    exim_nullstd(void);
extern void    exim_setugid(uid_t, gid_t, BOOL, const uschar *);
extern void    exim_underbar_exit(int) NORETURN;
extern void    exim_wait_tick(struct timeval *, int);
extern int     exp_bool(address_item *addr,
  uschar *mtype, uschar *mname, unsigned dgb_opt, uschar *oname, BOOL bvalue,
  uschar *svalue, BOOL *rvalue);
extern BOOL    expand_check_condition(uschar *, uschar *, uschar *);
extern uschar *expand_file_big_buffer(const uschar *);
extern uschar *expand_string(uschar *);	/* public, cannot make const */
extern const uschar *expand_cstring(const uschar *); /* ... so use this one */
extern uschar *expand_getkeyed(const uschar *, const uschar *);

extern uschar *expand_hide_passwords(uschar * );
extern uschar *expand_string_copy(const uschar *);
extern int_eximarith_t expand_string_integer(uschar *, BOOL);
extern void    modify_variable(uschar *, void *);

extern BOOL    fd_ready(int, time_t);

extern int     filter_interpret(const uschar *, int, address_item **, uschar **);
extern BOOL    filter_personal(string_item *, BOOL);
extern BOOL    filter_runtest(int, uschar *, BOOL, BOOL);
extern BOOL    filter_system_interpret(address_item **, uschar **);

extern uschar * fn_hdrs_added(void);
extern void    force_fd(int, int);

extern void    header_add(int, const char *, ...);
extern header_line *header_add_at_position_internal(BOOL, uschar *, BOOL, int, const char *, ...);
extern int     header_checkname(header_line *, BOOL);
extern BOOL    header_match(uschar *, BOOL, BOOL, string_item *, int, ...);
extern int     host_address_extract_port(uschar *);
extern uschar *host_and_ident(BOOL);
extern int     host_aton(const uschar *, int *);
extern void    host_build_hostlist(host_item **, const uschar *, BOOL);
extern ip_address_item *host_build_ifacelist(const uschar *, uschar *);
extern void    host_build_log_info(void);
extern void    host_build_sender_fullhost(void);
extern int     host_find_byname(host_item *, const uschar *, int,
				const uschar **, BOOL);
extern int     host_find_bydns(host_item *, const uschar *, int, uschar *, uschar *,
                 uschar *, const dnssec_domains *, const uschar **, BOOL *);
extern ip_address_item *host_find_interfaces(void);
extern BOOL    host_is_in_net(const uschar *, const uschar *, int);
extern BOOL    host_is_tls_on_connect_port(int);
extern int     host_item_get_port(host_item *);
extern void    host_mask(int, int *, int);
extern int     host_name_lookup(void);
extern int     host_nmtoa(int, int *, int, uschar *, int);
extern uschar *host_ntoa(int, const void *, uschar *, int *);
extern int     host_scan_for_local_hosts(host_item *, host_item **, BOOL *);

extern uschar *imap_utf7_encode(uschar *, const uschar *,
				 uschar, uschar *, uschar **);

extern void    invert_address(uschar *, uschar *);
extern int     ip_addr(void *, int, const uschar *, int);
extern int     ip_bind(int, int, uschar *, int);
extern int     ip_connect(int, int, const uschar *, int, int, const blob *);
extern int     ip_connectedsocket(int, const uschar *, int, int,
                 int, host_item *, uschar **, const blob *);
extern int     ip_get_address_family(int);
extern void    ip_keepalive(int, const uschar *, BOOL);
extern int     ip_recv(client_conn_ctx *, uschar *, int, time_t);
extern int     ip_socket(int, int);

extern int     ip_tcpsocket(const uschar *, uschar **, int, host_item *);
extern int     ip_unixsocket(const uschar *, uschar **);
extern int     ip_streamsocket(const uschar *, uschar **, int, host_item *);

extern int     ipv6_nmtoa(int *, uschar *);

extern uschar *local_part_quote(uschar *);
extern int     log_open_as_exim(const uschar * const);
extern void    log_close_all(void);

extern macro_item * macro_create(const uschar *, const uschar *, BOOL);
extern BOOL    macro_read_assignment(uschar *);
extern uschar *macros_expand(int, int *, BOOL *);
extern void    mainlog_close(void);
#ifdef WITH_CONTENT_SCAN
extern int     malware(const uschar *, int);
extern int     malware_in_file(uschar *);
extern void    malware_init(void);
extern gstring * malware_show_supported(gstring *);
#endif
extern int     match_address_list(const uschar *, BOOL, BOOL, const uschar **,
                 unsigned int *, int, int, const uschar **);
extern int     match_address_list_basic(const uschar *, const uschar **, int);
extern int     match_check_list(const uschar **, int, tree_node **, unsigned int **,
                 int(*)(void *, const uschar *, const uschar **, uschar **), void *, int,
                 const uschar *, const uschar **);
extern int     match_isinlist(const uschar *, const uschar **, int, tree_node **,
                 unsigned int *, int, BOOL, const uschar **);
extern int     match_check_string(const uschar *, const uschar *, int, BOOL, BOOL, BOOL,
                 const uschar **);

extern void    message_start(void);
extern void    message_tidyup(void);
extern void    md5_end(md5 *, const uschar *, int, uschar *);
extern void    md5_mid(md5 *, const uschar *);
extern void    md5_start(md5 *);
extern void    millisleep(int);
#ifdef WITH_CONTENT_SCAN
struct mime_boundary_context;
extern int     mime_acl_check(uschar *acl, FILE *f,
                 struct mime_boundary_context *, uschar **, uschar **);
extern int     mime_decode(const uschar **);
extern ssize_t mime_decode_base64(FILE *, FILE *, uschar *);
extern int     mime_regex(const uschar **);
extern void    mime_set_anomaly(int);
#endif
extern uschar *moan_check_errorcopy(uschar *);
extern BOOL    moan_skipped_syntax_errors(uschar *, error_block *, uschar *,
                 BOOL, uschar *);
extern void    moan_smtp_batch(uschar *, const char *, ...) PRINTF_FUNCTION(2,3);
extern BOOL    moan_send_message(uschar *, int, error_block *eblock,
		 header_line *, FILE *, uschar *);
extern void    moan_tell_someone(uschar *, address_item *,
                 const uschar *, const char *, ...) PRINTF_FUNCTION(4,5);
extern BOOL    moan_to_sender(int, error_block *, header_line *, FILE *, BOOL);
extern void    moan_write_from(FILE *);
extern void    moan_write_references(FILE *, uschar *);
extern FILE   *modefopen(const uschar *, const char *, mode_t);

extern int     open_cutthrough_connection( address_item * addr );

extern uschar *parse_extract_address(const uschar *, uschar **, int *, int *, int *,
                 BOOL);
extern int     parse_forward_list(const uschar *, int, address_item **, uschar **,
                 const uschar *, const uschar *, error_block **);
extern uschar *parse_find_address_end(const uschar *, BOOL);
extern const uschar *parse_find_at(const uschar *);
extern const uschar *parse_fix_phrase(const uschar *, int);
extern const uschar *parse_message_id(const uschar *, uschar **, uschar **);
extern const uschar *parse_quote_2047(const uschar *, int, const uschar *,
				      BOOL);
extern const uschar *parse_date_time(const uschar *str, time_t *t);
extern void priv_drop_temp(const uid_t, const gid_t);
extern void priv_restore(void);
extern int     vaguely_random_number(int);
#ifndef DISABLE_TLS
extern int     vaguely_random_number_fallback(int);
#endif

extern BOOL    queue_action(uschar *, int, uschar **, int, int);
extern void    queue_check_only(void);
extern unsigned queue_count(void);
extern unsigned queue_count_cached(void);
extern void    queue_list(int, uschar **, int);
#ifndef DISABLE_QUEUE_RAMP
extern void    queue_notify_daemon(const uschar * hostname);
#endif
extern void    queue_run(uschar *, uschar *, BOOL);

extern int     random_number(int);
extern const uschar *rc_to_string(int);
extern int     rda_interpret(redirect_block *, int, const uschar *, const uschar *,
                 const uschar *, const uschar *, const uschar *, const ugid_block *, address_item **,
                 uschar **, error_block **, int *, const uschar *);
extern int     rda_is_filter(const uschar *);
extern BOOL    readconf_depends(driver_instance *, uschar *);
extern void    readconf_driver_init(uschar *, driver_instance **,
                 driver_info *, int, void *, int, optionlist *, int);
extern uschar *readconf_find_option(void *);
extern void    readconf_main(BOOL);
extern void    readconf_options_from_list(optionlist *, unsigned, const uschar *, uschar *);
extern BOOL    readconf_print(const uschar *, uschar *, BOOL);
extern uschar *readconf_printtime(int);
extern uschar *readconf_readname(uschar *, int, uschar *);
extern int     readconf_readtime(const uschar *, int, BOOL);
extern void    readconf_rest(void);
extern uschar *readconf_retry_error(const uschar *, const uschar *, int *, int *);
extern void    readconf_save_config(const uschar *);
extern void    read_message_body(BOOL);
extern void    receive_bomb_out(uschar *, uschar *) NORETURN;
extern BOOL    receive_check_fs(int);
extern BOOL    receive_check_set_sender(uschar *);
extern BOOL    receive_msg(BOOL);
extern int_eximarith_t receive_statvfs(BOOL, int *);
extern void    receive_swallow_smtp(void);
#ifdef WITH_CONTENT_SCAN
extern int     regex(const uschar **);
#endif
extern BOOL    regex_match(const pcre2_code *, const uschar *, int, uschar **);
extern BOOL    regex_match_and_setup(const pcre2_code *, const uschar *, int, int);
extern const pcre2_code *regex_must_compile(const uschar *, BOOL, BOOL);
extern void    retry_add_item(address_item *, uschar *, int);
extern BOOL    retry_check_address(const uschar *, host_item *, uschar *, BOOL,
                 uschar **, uschar **);
extern retry_config *retry_find_config(const uschar *, const uschar *, int, int);
extern BOOL    retry_ultimate_address_timeout(uschar *, const uschar *,
                 dbdata_retry *, time_t);
extern void    retry_update(address_item **, address_item **, address_item **);
extern const uschar *rewrite_address(const uschar *, BOOL, BOOL, rewrite_rule *, int);
extern const uschar *rewrite_address_qualify(const uschar *, BOOL);
extern header_line *rewrite_header(header_line *,
               const uschar *, const uschar *,
               rewrite_rule *, int, BOOL);
extern const uschar *rewrite_one(const uschar *, int, BOOL *, BOOL, uschar *,
                 rewrite_rule *);
extern void    rewrite_test(const uschar *);
extern uschar *rfc2047_decode2(uschar *, BOOL, const uschar *, int, int *,
				     int *, uschar **);
extern int     route_address(address_item *, address_item **, address_item **,
                 address_item **, address_item **, int);
extern int     route_check_prefix(const uschar *, const uschar *, unsigned *);
extern int     route_check_suffix(const uschar *, const uschar *, unsigned *);
extern BOOL    route_findgroup(uschar *, gid_t *);
extern BOOL    route_finduser(const uschar *, struct passwd **, uid_t *);
extern BOOL    route_find_expanded_group(uschar *, uschar *, uschar *, gid_t *,
                 uschar **);
extern BOOL    route_find_expanded_user(uschar *, uschar *, uschar *,
                 struct passwd **, uid_t *, uschar **);
extern void    route_init(void);
extern gstring * route_show_supported(gstring *);
extern void    route_tidyup(void);
extern uschar *router_current_name(void);

extern uschar *search_args(int, uschar *, uschar *, uschar **, const uschar *);
extern uschar *search_find(void *, const uschar *, uschar *, int,
		 const uschar *, int, int, int *, const uschar *);
extern int     search_findtype(const uschar *, int);
extern int     search_findtype_partial(const uschar *, int *, const uschar **, int *,
                 int *, const uschar **);
extern void   *search_open(const uschar *, int, int, uid_t *, gid_t *);
extern void    search_tidyup(void);
extern void    set_process_info(const char *, ...) PRINTF_FUNCTION(1,2);
extern void    sha1_end(hctx *, const uschar *, int, uschar *);
extern void    sha1_mid(hctx *, const uschar *);
extern void    sha1_start(hctx *);
extern int     sieve_interpret(const uschar *, int, const uschar *,
		 const uschar *, const uschar *, const uschar *,
		 address_item **, uschar **);
extern void    sigalrm_handler(int);
extern int     smtp_boundsock(smtp_connect_args *);
extern void    smtp_closedown(uschar *);
extern void    smtp_command_timeout_exit(void) NORETURN;
extern void    smtp_command_sigterm_exit(void) NORETURN;
extern void    smtp_data_timeout_exit(void) NORETURN;
extern void    smtp_data_sigint_exit(void) NORETURN;
extern void    smtp_deliver_init(void);
extern uschar *smtp_cmd_hist(void);
extern int     smtp_connect(smtp_connect_args *, const blob *);
extern int     smtp_feof(void);
extern int     smtp_ferror(void);
extern uschar *smtp_get_connection_info(void);
extern BOOL    smtp_get_interface(uschar *, int, address_item *,
                 uschar **, uschar *);
extern BOOL    smtp_get_port(uschar *, address_item *, int *, uschar *);
extern int     smtp_getc(unsigned);
extern uschar *smtp_getbuf(unsigned *);
extern void    smtp_get_cache(unsigned);
extern BOOL    smtp_hasc(void);
extern int     smtp_handle_acl_fail(int, int, uschar *, uschar *);
extern void    smtp_log_no_mail(void);
extern void    smtp_message_code(uschar **, int *, uschar **, uschar **, BOOL);
extern void    smtp_proxy_tls(void *, uschar *, size_t, int *, int, const uschar *) NORETURN;
extern BOOL    smtp_read_response(void *, uschar *, int, int, int);
extern void   *smtp_reset(void *);
extern void    smtp_respond(uschar *, int, BOOL, uschar *);
extern void    smtp_notquit_exit(uschar *, uschar *, uschar *, ...);
extern void    smtp_port_for_connect(host_item *, int);
extern void    smtp_send_prohibition_message(int, uschar *);
extern int     smtp_setup_msg(void);
extern int     smtp_sock_connect(smtp_connect_args *, int, const blob *);
extern BOOL    smtp_start_session(void);
extern int     smtp_ungetc(int);
extern BOOL    smtp_verify_helo(void);
extern int     smtp_write_command(void *, int, const char *, ...) PRINTF_FUNCTION(3,4);
#ifdef WITH_CONTENT_SCAN
extern int     spam(const uschar **);
extern FILE   *spool_mbox(unsigned long *, const uschar *, uschar **);
#endif
extern void    spool_clear_header_globals(void);
extern BOOL    spool_move_message(uschar *, uschar *, uschar *, uschar *);
extern int     spool_open_datafile(uschar *);
extern int     spool_open_temp(uschar *);
extern int     spool_read_header(uschar *, BOOL, BOOL);
extern uschar *spool_sender_from_msgid(const uschar *);
extern int     spool_write_header(uschar *, int, uschar **);
extern int     stdin_getc(unsigned);
extern int     stdin_feof(void);
extern int     stdin_ferror(void);
extern BOOL    stdin_hasc(void);
extern int     stdin_ungetc(int);

extern void    store_exit(void);
extern void    store_init(void);
extern void    store_writeprotect(int);

extern gstring *string_append(gstring *, int, ...) WARN_UNUSED_RESULT;
extern gstring *string_append_listele(gstring *, uschar, const uschar *) WARN_UNUSED_RESULT;
extern gstring *string_append_listele_n(gstring *, uschar, const uschar *, unsigned) WARN_UNUSED_RESULT;
extern gstring *string_append2_listele_n(gstring *, const uschar *, const uschar *, unsigned) WARN_UNUSED_RESULT;
extern uschar *string_base62(unsigned long int);
extern gstring *string_cat (gstring *, const uschar *     ) WARN_UNUSED_RESULT;
extern gstring *string_catn(gstring *, const uschar *, int) WARN_UNUSED_RESULT;
extern int     string_compare_by_pointer(const void *, const void *);
extern uschar *string_copy_dnsdomain(uschar *);
extern uschar *string_copy_malloc(const uschar *);
extern uschar *string_dequote(const uschar **);
extern uschar *string_format_size(int, uschar *);
extern int     string_interpret_escape(const uschar **);
extern int     string_is_ip_address(const uschar *, int *);
#ifdef SUPPORT_I18N
extern BOOL    string_is_utf8(const uschar *);
#endif
extern const uschar *string_printing2(const uschar *, int);
extern uschar *string_split_message(uschar *);
extern uschar *string_unprinting(uschar *);
#ifdef SUPPORT_I18N
extern uschar *string_address_utf8_to_alabel(const uschar *, uschar **);
extern uschar *string_domain_alabel_to_utf8(const uschar *, uschar **);
extern uschar *string_domain_utf8_to_alabel(const uschar *, uschar **);
extern uschar *string_localpart_alabel_to_utf8(const uschar *, uschar **);
extern uschar *string_localpart_utf8_to_alabel(const uschar *, uschar **);
#endif

#define string_format(buf, siz, fmt, ...) \
	string_format_trc(buf, siz, US __FUNCTION__, __LINE__, fmt, __VA_ARGS__)
extern BOOL    string_format_trc(uschar *, int, const uschar *, unsigned,
			const char *, ...) ALMOST_PRINTF(5,6);

#define string_vformat(g, flgs, fmt, ap) \
	string_vformat_trc(g, US __FUNCTION__, __LINE__, \
			 STRING_SPRINTF_BUFFER_SIZE, flgs, fmt, ap)
extern gstring *string_vformat_trc(gstring *, const uschar *, unsigned,
			unsigned, unsigned, const char *, va_list);

#define string_open_failed(fmt, ...) \
	string_open_failed_trc(US __FUNCTION__, __LINE__, fmt, __VA_ARGS__)
extern uschar *string_open_failed_trc(const uschar *, unsigned,
			const char *, ...) PRINTF_FUNCTION(3,4);

#define string_nextinlist(lp, sp, b, l) \
	string_nextinlist_trc((lp), (sp), (b), (l), US __FUNCTION__, __LINE__)
extern uschar *string_nextinlist_trc(const uschar **listptr, int *separator, uschar *buffer, int buflen,
			const uschar * func, int line);

extern int     strcmpic(const uschar *, const uschar *);
extern int     strncmpic(const uschar *, const uschar *, int);
extern uschar *strstric(uschar *, uschar *, BOOL);
extern const uschar *strstric_c(const uschar *, const uschar *, BOOL);

extern int     test_harness_fudged_queue_time(int);
extern void    tcp_init(void);
#ifdef EXIM_TFO_PROBE
extern void    tfo_probe(void);
#endif
extern void    tls_modify_variables(tls_support *);
extern uschar *tod_stamp(int);

extern BOOL    transport_check_waiting(const uschar *, const uschar *, int, uschar *,
                 oicf, void*);
extern uschar *transport_current_name(void);
extern void    transport_do_pass_socket(const uschar *, const uschar *,
		 const uschar *, uschar *, int);
extern void    transport_init(void);
extern BOOL    transport_pass_socket(const uschar *, const uschar *, const uschar *, uschar *, int
#ifdef EXPERIMENTAL_ESMTP_LIMITS
			, unsigned, unsigned, unsigned
#endif
			);
extern uschar *transport_rcpt_address(address_item *, BOOL);
extern BOOL    transport_set_up_command(const uschar ***, const uschar *,
		 unsigned, int, address_item *, const uschar *, uschar **);
extern void    transport_update_waiting(host_item *, uschar *);
extern BOOL    transport_write_block(transport_ctx *, uschar *, int, BOOL);
extern void    transport_write_reset(int);
extern BOOL    transport_write_string(int, const char *, ...);
extern BOOL    transport_headers_send(transport_ctx *,
                 BOOL (*)(transport_ctx *, uschar *, int));
extern gstring * transport_show_supported(gstring *);
extern BOOL    transport_write_message(transport_ctx *, int);
extern void    tree_add_duplicate(const uschar *, address_item *);
extern void    tree_add_nonrecipient(const uschar *);
extern void    tree_add_unusable(const host_item *);
extern void    tree_dup(tree_node **, tree_node *);
extern int     tree_insertnode(tree_node **, tree_node *);
extern tree_node *tree_search(tree_node *, const uschar *);
extern void    tree_write(tree_node *, FILE *);
extern void    tree_walk(tree_node *, void (*)(uschar*, uschar*, void*), void *);

#ifdef WITH_CONTENT_SCAN
extern void    unspool_mbox(void);
#endif
#ifdef SUPPORT_I18N
extern gstring *utf8_version_report(gstring *);
#endif

extern int     verify_address(address_item *, FILE *, int, int, int, int,
                 uschar *, uschar *, BOOL *);
extern int     verify_check_dnsbl(int, const uschar **, uschar **);
extern int     verify_check_header_address(uschar **, uschar **, int, int, int,
                 uschar *, uschar *, int, int *);
extern int     verify_check_headers(uschar **);
extern int     verify_check_header_names_ascii(uschar **);
extern int     verify_check_host(uschar **);
extern int     verify_check_notblind(BOOL);
extern int     verify_check_given_host(const uschar **, const host_item *);
extern int     verify_check_this_host(const uschar **, unsigned int *,
	         const uschar*, const uschar *, const uschar **);
extern address_item *verify_checked_sender(uschar *);
extern void    verify_get_ident(int);
extern void    verify_quota(uschar *);
extern int     verify_quota_call(const uschar *, int, int, uschar **);
extern BOOL    verify_sender(int *, uschar **);
extern BOOL    verify_sender_preliminary(int *, uschar **);
extern void    version_init(void);

extern BOOL    write_chunk(transport_ctx *, uschar *, int);
extern ssize_t write_to_fd_buf(int, const uschar *, size_t);


/******************************************************************************/
/* Predicate: if an address is in a tainted pool.
By extension, a variable pointing to this address is tainted.
*/

static inline BOOL
is_tainted(const void * p)
{
#if defined(COMPILE_UTILITY) || defined(MACRO_PREDEF) || defined(EM_VERSION_C)
return FALSE;

#else
extern BOOL is_tainted_fn(const void *);
return is_tainted_fn(p);
#endif
}

static inline BOOL
is_incompatible(const void * old, const void * new)
{
#if defined(COMPILE_UTILITY) || defined(MACRO_PREDEF) || defined(EM_VERSION_C)
return FALSE;

#else
extern BOOL is_incompatible_fn(const void *, const void *);
return is_incompatible_fn(old, new);
#endif
}

/******************************************************************************/
/* String functions */
static inline uschar * __Ustrcat(uschar * dst, const uschar * src, const char * func, int line)
{
#if !defined(COMPILE_UTILITY) && !defined(MACRO_PREDEF)
if (!is_tainted(dst) && is_tainted(src)) die_tainted(US"Ustrcat", CUS func, line);
#endif
return US strcat(CS dst, CCS src);
}
static inline uschar * __Ustrcpy(uschar * dst, const uschar * src, const char * func, int line)
{
#if !defined(COMPILE_UTILITY) && !defined(MACRO_PREDEF)
if (!is_tainted(dst) && is_tainted(src)) die_tainted(US"Ustrcpy", CUS func, line);
#endif
return US strcpy(CS dst, CCS src);
}
static inline uschar * __Ustrncat(uschar * dst, const uschar * src, size_t n, const char * func, int line)
{
#if !defined(COMPILE_UTILITY) && !defined(MACRO_PREDEF)
if (!is_tainted(dst) && is_tainted(src)) die_tainted(US"Ustrncat", CUS func, line);
#endif
return US strncat(CS dst, CCS src, n);
}
static inline uschar * __Ustrncpy(uschar * dst, const uschar * src, size_t n, const char * func, int line)
{
#if !defined(COMPILE_UTILITY) && !defined(MACRO_PREDEF)
if (!is_tainted(dst) && is_tainted(src)) die_tainted(US"Ustrncpy", CUS func, line);
#endif
return US strncpy(CS dst, CCS src, n);
}
/*XXX will likely need unchecked copy also */


/* Advance the string pointer given over any whitespace.
Return the next char as there's enought places using it to be useful. */

#define Uskip_whitespace(sp) skip_whitespace(CUSS sp)

static inline uschar skip_whitespace(const uschar ** sp)
{ while (isspace(**sp)) (*sp)++; return **sp; }


/******************************************************************************/

#if !defined(MACRO_PREDEF) && !defined(COMPILE_UTILITY)
/* exim_chown - in some NFSv4 setups *seemes* to be an issue with
chown(<exim-uid>, <exim-gid>).

Probably because the idmapping is broken, misconfigured or set up in
an unusal way. (see Bug 2931). As I'm not sure, if this was a single
case of misconfiguration, or if there are more such broken systems
out, I try to impose as least impact as possible and for now just write
a panic log entry pointing to the bug report. You're encouraged to
contact the developers, if you experience this issue.

fd     the file descriptor (or -1 if not valid)
name   the file name for error messages or for file operations,
  if fd is < 0
owner  the owner
group  the group

returns 0 on success, -1 on failure */

static inline int
exim_fchown(int fd, uid_t owner, gid_t group, const uschar *name)
{
return fchown(fd, owner, group)
  ? exim_chown_failure(fd, name, owner, group) : 0;
}

static inline int
exim_chown(const uschar *name, uid_t owner, gid_t group)
{
return chown(CCS name, owner, group)
  ? exim_chown_failure(-1, name, owner, group) : 0;
}
#endif	/* !MACRO_PREDEF && !COMPILE_UTILITY */

/******************************************************************************/
/* String functions */

#if !defined(MACRO_PREDEF)
/*************************************************
*            Copy and save string                *
*************************************************/

/* This function assumes that memcpy() is faster than strcpy().
The result is explicitly nul-terminated.
*/

static inline uschar *
string_copyn_taint_trc(const uschar * s, unsigned len,
	const void * proto_mem, const char * func, int line)
{
uschar * ss;
unsigned slen = Ustrlen(s);
if (len > slen) len = slen;
ss = store_get_3(len + 1, proto_mem, func, line);
memcpy(ss, s, len);
ss[len] = '\0';
return ss;
}

static inline uschar *
string_copy_taint_trc(const uschar * s, const void * proto_mem, const char * func, int line)
{ return string_copyn_taint_trc(s, Ustrlen(s), proto_mem, func, line); }

static inline uschar *
string_copyn_trc(const uschar * s, unsigned len, const char * func, int line)
{ return string_copyn_taint_trc(s, len, s, func, line); }
static inline uschar *
string_copy_trc(const uschar * s, const char * func, int line)
{ return string_copy_taint_trc(s, s, func, line); }


/* String-copy functions explicitly setting the taint status */

#define string_copyn_taint(s, len, proto_mem) \
	string_copyn_taint_trc((s), (len), (proto_mem), __FUNCTION__, __LINE__)
#define string_copy_taint(s, proto_mem) \
	string_copy_taint_trc((s), (proto_mem), __FUNCTION__, __LINE__)

/* Simple string-copy functions maintaining the taint */

#define string_copyn(s, len) \
	string_copyn_trc((s), (len), __FUNCTION__, __LINE__)
#define string_copy(s) \
	string_copy_trc((s), __FUNCTION__, __LINE__)


/*************************************************
*       Copy, lowercase and save string          *
*************************************************/

/*
Argument: string to copy
Returns:  copy of string in new store, with letters lowercased
*/

static inline uschar *
string_copylc(const uschar * s)
{
uschar * ss = store_get(Ustrlen(s) + 1, s);
uschar * p = ss;
while (*s) *p++ = tolower(*s++);
*p = 0;
return ss;
}



/*************************************************
* Copy, lowercase, and save string, given length *
*************************************************/

/* It is assumed the data contains no zeros. A zero is added
onto the end.

Arguments:
  s         string to copy
  n         number of characters

Returns:    copy of string in new store, with letters lowercased
*/

static inline uschar *
string_copynlc(uschar * s, int n)
{
uschar * ss = store_get(n + 1, s);
uschar * p = ss;
while (n-- > 0) *p++ = tolower(*s++);
*p = 0;
return ss;
}


# ifndef COMPILE_UTILITY
/*************************************************
*     Copy and save string in longterm store     *
*************************************************/

/* This function assumes that memcpy() is faster than strcpy().

Argument: string to copy
Returns:  copy of string in new store
*/

static inline uschar *
string_copy_perm(const uschar *s, BOOL force_taint)
{
int old_pool = store_pool;
int len = Ustrlen(s) + 1;
uschar *ss;

store_pool = POOL_PERM;
ss = store_get(len, force_taint ? GET_TAINTED : s);
memcpy(ss, s, len);
store_pool = old_pool;
return ss;
}
# endif



/* sprintf into a buffer, taint-unchecked */

static inline void
string_format_nt(uschar * buf, int siz, const char * fmt, ...)
{
gstring gs = { .size = siz, .ptr = 0, .s = buf };
va_list ap;
va_start(ap, fmt);
(void) string_vformat(&gs, SVFMT_TAINT_NOCHK, fmt, ap);
va_end(ap);
}



/******************************************************************************/
/* Growable-string functions */

/* Create a growable-string with some preassigned space */

#define string_get_tainted(size, proto_mem) \
	string_get_tainted_trc((size), (proto_mem), __FUNCTION__, __LINE__)

static inline gstring *
string_get_tainted_trc(unsigned size, const void * proto_mem, const char * func, unsigned line)
{
gstring * g = store_get_3(sizeof(gstring) + size, proto_mem, func, line);
g->size = size;		/*XXX would be good if we could see the actual alloc size */
g->ptr = 0;
g->s = US(g + 1);
return g;
}

#define string_get(size) \
	string_get_trc((size), __FUNCTION__, __LINE__)

static inline gstring *
string_get_trc(unsigned size, const char * func, unsigned line)
{
return string_get_tainted_trc(size, GET_UNTAINTED, func, line);
}

/* NUL-terminate the C string in the growable-string, and return it. */

static inline uschar *
string_from_gstring(gstring * g)
{
if (!g) return NULL;
g->s[g->ptr] = '\0';
return g->s;
}

static inline unsigned
gstring_length(const gstring * g)
{
return g ? (unsigned)g->ptr : 0;
}


#define gstring_release_unused(g) \
	gstring_release_unused_trc(g, __FUNCTION__, __LINE__)

static inline void
gstring_release_unused_trc(gstring * g, const char * file, unsigned line)
{
if (g) store_release_above_3(g->s + (g->size = g->ptr + 1), file, line);
}


/* sprintf-append to a growable-string */

#define string_fmt_append(g, fmt, ...) \
	string_fmt_append_f_trc(g, US __FUNCTION__, __LINE__, \
	SVFMT_EXTEND|SVFMT_REBUFFER, fmt, __VA_ARGS__)

#define string_fmt_append_f(g, flgs, fmt, ...) \
	string_fmt_append_f_trc(g, US __FUNCTION__, __LINE__, \
	flgs,         fmt, __VA_ARGS__)

static inline gstring *
string_fmt_append_f_trc(gstring * g, const uschar * func, unsigned line,
  unsigned flags, const char *format, ...)
{
va_list ap;
va_start(ap, format);
g = string_vformat_trc(g, func, line, STRING_SPRINTF_BUFFER_SIZE,
			flags, format, ap);
va_end(ap);
return g;
}


/* Copy the content of a string to tainted memory.  The proto_mem arg
will always be tainted, and suitable as a prototype. */

static inline void
gstring_rebuffer(gstring * g, const void * proto_mem)
{
uschar * s = store_get_3(g->size, proto_mem, __FUNCTION__, __LINE__);
memcpy(s, g->s, g->ptr);
g->s = s;
}


# ifndef COMPILE_UTILITY
/******************************************************************************/
/* Use store_malloc for DNSA structs, and explicit frees. Using the same pool
for them as the strings we proceed to copy from them meant they could not be
released, hence blowing 64k for every DNS lookup. That mounted up. With malloc
we do have to take care over marking tainted all copied strings.  A separate pool
could be used and would handle that implicitly. */

#define store_get_dns_answer() store_get_dns_answer_trc(CUS __FUNCTION__, __LINE__)

static inline dns_answer *
store_get_dns_answer_trc(const uschar * func, unsigned line)
{
return store_malloc_3(sizeof(dns_answer), CCS func, line);
}

#define store_free_dns_answer(dnsa) store_free_dns_answer_trc(dnsa, CUS __FUNCTION__, __LINE__)

static inline void
store_free_dns_answer_trc(dns_answer * dnsa, const uschar * func, unsigned line)
{
store_free_3(dnsa, CCS func, line);
}

/******************************************************************************/
/* Routines with knowledge of spool layout */

static inline void
spool_pname_buf(uschar * buf, int len)
{
snprintf(CS buf, len, "%s/%s/input", spool_directory, queue_name);
}

static inline uschar *
spool_dname(const uschar * purpose, uschar * subdir)
{
return string_sprintf("%s/%s/%s/%s",
	spool_directory, queue_name, purpose, subdir);
}
# endif

static inline uschar *
spool_q_sname(const uschar * purpose, const uschar * q, uschar * subdir)
{
return string_sprintf("%s%s%s%s%s",
		    q, *q ? "/" : "",
		    purpose,
		    *subdir ? "/" : "", subdir);
}

static inline uschar *
spool_sname(const uschar * purpose, uschar * subdir)
{
return spool_q_sname(purpose, queue_name, subdir);
}

static inline uschar *
spool_q_fname(const uschar * purpose, const uschar * q,
	const uschar * subdir, const uschar * fname, const uschar * suffix)
{
return string_sprintf("%s/%s/%s/%s/%s%s",
	spool_directory, q, purpose, subdir, fname, suffix);
}

static inline uschar *
spool_fname(const uschar * purpose, const uschar * subdir, const uschar * fname,
	const uschar * suffix)
{
#ifdef COMPILE_UTILITY		/* version avoiding string-extension */
int len = Ustrlen(spool_directory) + 1 + Ustrlen(queue_name) + 1 + Ustrlen(purpose) + 1
	+ Ustrlen(subdir) + 1 + Ustrlen(fname) + Ustrlen(suffix) + 1;
uschar * buf = store_get(len, GET_UNTAINTED);
string_format(buf, len, "%s/%s/%s/%s/%s%s",
	spool_directory, queue_name, purpose, subdir, fname, suffix);
return buf;
#else
return spool_q_fname(purpose, queue_name, subdir, fname, suffix);
#endif
}

static inline void
set_subdir_str(uschar * subdir_str, const uschar * name,
	int search_sequence)
{
subdir_str[0] = split_spool_directory == (search_sequence == 0)
       ? name[5] : '\0';
subdir_str[1] = '\0';
}

/******************************************************************************/
/* Time calculations */

/* Diff two times (later, earlier) returning diff in 1st arg */
static inline void
timediff(struct timeval * later, const struct timeval * earlier)
{
later->tv_sec -= earlier->tv_sec;
if ((later->tv_usec -= earlier->tv_usec) < 0)
  {
  later->tv_sec--;
  later->tv_usec += 1000*1000;
  }
}

static inline void
timesince(struct timeval * diff, const struct timeval * then)
{
gettimeofday(diff, NULL);
timediff(diff, then);
}

static inline uschar *
string_timediff(const struct timeval * diff)
{
static uschar buf[sizeof("0.000s")];

if (diff->tv_sec >= 5 || !LOGGING(millisec))
  return readconf_printtime((int)diff->tv_sec);

snprintf(CS buf, sizeof(buf), "%u.%03us", (uint)diff->tv_sec, (uint)diff->tv_usec/1000);
return buf;
}


static inline uschar *
string_timesince(const struct timeval * then)
{
struct timeval diff;
timesince(&diff, then);
return string_timediff(&diff);
}

static inline void
report_time_since(const struct timeval * t0, const uschar * where)
{
# ifdef MEASURE_TIMING
struct timeval diff;
timesince(&diff, t0);
fprintf(stderr, "%d %s:\t%ld.%06ld\n",
       (uint)getpid(), where, (long)diff.tv_sec, (long)diff.tv_usec);
# endif
}


static inline void
testharness_pause_ms(int millisec)
{
#ifndef MEASURE_TIMING
if (f.running_in_test_harness && f.testsuite_delays) millisleep(millisec);
#endif
}

/******************************************************************************/
/* Taint-checked file opens */

static inline int
exim_open2(const char *pathname, int flags)
{
if (!is_tainted(pathname)) return open(pathname, flags);
log_write(0, LOG_MAIN|LOG_PANIC, "Tainted filename '%s'", pathname);
errno = EACCES;
return -1;
}
static inline int
exim_open(const char *pathname, int flags, mode_t mode)
{
if (!is_tainted(pathname)) return open(pathname, flags, mode);
log_write(0, LOG_MAIN|LOG_PANIC, "Tainted filename '%s'", pathname);
errno = EACCES;
return -1;
}
#ifdef EXIM_HAVE_OPENAT
static inline int
exim_openat(int dirfd, const char *pathname, int flags)
{
if (!is_tainted(pathname)) return openat(dirfd, pathname, flags);
log_write(0, LOG_MAIN|LOG_PANIC, "Tainted filename '%s'", pathname);
errno = EACCES;
return -1;
}
static inline int
exim_openat4(int dirfd, const char *pathname, int flags, mode_t mode)
{
if (!is_tainted(pathname)) return openat(dirfd, pathname, flags, mode);
log_write(0, LOG_MAIN|LOG_PANIC, "Tainted filename '%s'", pathname);
errno = EACCES;
return -1;
}
#endif

static inline FILE *
exim_fopen(const char *pathname, const char *mode)
{
if (!is_tainted(pathname)) return fopen(pathname, mode);
log_write(0, LOG_MAIN|LOG_PANIC, "Tainted filename '%s'", pathname);
errno = EACCES;
return NULL;
}

static inline DIR *
exim_opendir(const uschar * name)
{
if (!is_tainted(name)) return opendir(CCS name);
log_write(0, LOG_MAIN|LOG_PANIC, "Tainted dirname '%s'", name);
errno = EACCES;
return NULL;
}

/******************************************************************************/
# if !defined(COMPILE_UTILITY)
/* Process manipulation */

static inline pid_t
exim_fork(const unsigned char * purpose)
{
pid_t pid;
DEBUG(D_any) debug_printf("%s forking for %s\n", process_purpose, purpose);
if ((pid = fork()) == 0)
  {
  process_purpose = purpose;
  DEBUG(D_any) debug_printf("postfork: %s\n", purpose);
  }
else
  {
  testharness_pause_ms(100); /* let child work */
  DEBUG(D_any) debug_printf("%s forked for %s: %d\n", process_purpose, purpose, (int)pid);
  }
return pid;
}


static inline pid_t
child_open_exim(int * fdptr, const uschar * purpose)
{ return child_open_exim_function(fdptr, purpose); }

static inline pid_t
child_open_exim2(int * fdptr, uschar * sender,
  uschar * sender_auth, const uschar * purpose)
{ return child_open_exim2_function(fdptr, sender, sender_auth, purpose); }

static inline pid_t
child_open(uschar **argv, uschar **envp, int newumask, int *infdptr,
  int *outfdptr, BOOL make_leader, const uschar * purpose)
{ return child_open_function(argv, envp, newumask, infdptr,
  outfdptr, make_leader, purpose);
}

/* Return 1 if fd is usable per pollbits, else 0 */
static inline int
poll_one_fd(int fd, short pollbits, int tmo_millisec)
{
struct pollfd p = {.fd = fd, .events = pollbits};
return poll(&p, 1, tmo_millisec);
}

/******************************************************************************/
/* Client-side smtp log string, for debug */

static inline void
smtp_debug_cmd(const uschar * buf, int mode)
{
HDEBUG(D_transport|D_acl|D_v) debug_printf_indent("  SMTP%c> %s\n",
  mode == SCMD_BUFFER ? '|' : mode == SCMD_MORE ? '+' : '>', buf);

#  ifndef DISABLE_CLIENT_CMD_LOG
  {
  int len = Ustrcspn(buf, " \n");
  int old_pool = store_pool;
  store_pool = POOL_PERM;	/* Main pool ACL allocations eg. callouts get released */
  client_cmd_log = string_append_listele_n(client_cmd_log, ':', buf, MIN(len, 8));
  if (mode == SCMD_BUFFER) 
    {
    client_cmd_log = string_catn(client_cmd_log, US"|", 1); 
    (void) string_from_gstring(client_cmd_log);
    }
  store_pool = old_pool;
  }
#  endif
}


static inline void
smtp_debug_cmd_report(void)
{
#  ifndef DISABLE_CLIENT_CMD_LOG
debug_printf("cmdlog: '%s'\n", client_cmd_log ? client_cmd_log->s : US"(unset)");
#  endif
}



# endif	/* !COMPILE_UTILITY */

/******************************************************************************/
#endif	/* !MACRO_PREDEF */

#endif  /* _FUNCTIONS_H_ */

/* vi: aw
*/
/* End of functions.h */

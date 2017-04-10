This documents the patches applied on the upstream `exim-4_89` branch:

### 1. XCLIENT support

 - Applied [here](https://github.com/SpamExperts/exim/commit/7c63e5c04da12dfaa4b17b3f007ad63c60935af8)
 - Based on this [patch](http://highsecure.ru/patch-exim-xclient)
 - Add support for [XCLIENT](http://www.postfix.org/XCLIENT_README.html)
 - Adds a new main option `xclient_allow_hosts`, only exposing the XCLIENT
   ESTMP extension to the specified hosts in the list.
 - Internal ticket `#19841`

### 2. Extend auth ACLs

 - Applied [here](https://github.com/SpamExperts/exim/commit/f571e17cab58e2f368994559ad94c534dcc2f515)
 - Run ACL `acl_smtp_auth` AFTER the AUTH is completed instead of before
 - Add new ACL `acl_smtp_auth_accept` runs on AUTH success
 - Add new ACL `acl_smtp_auth_fail` runs on AUTH failure
 - Copy the `set_id` in `$smtp_command_argument` and make that information
   available in the auth ACLs. This contains the user information.
 - Internal ticket `#16054`

### 3. Add events for temporary failures

 - Applied [here](https://github.com/SpamExperts/exim/commit/f3f393c68852477d91a6d8ad7d294171d58b41a8)
 - Add new event `msg:defer:delivery` for temporary delivery error
 - Add new event `msg:defer:delivery:frozen` for temporary delivery error,
   resulting in the message being frozen
 - Add new event `msg:fail:delivery:expired` for permanent delivery error,
   resulting in the message being removed from the queue.
 - Add new event `msg:fail:delivery:bounced` for permanent delivery error,
   resulting in the message being removed from the queue and bounced.
 - Internal ticket `#21627`

### 4. Destination response in callout checks

 - Applied [here](https://github.com/SpamExperts/exim/commit/e8d9d96bbb991b562c905ec414a8443e067fd5f7)
 - Exposes the destination response for callout checks.
 - Adds a new variable `$recipient_verify_message`, containing the upstream
   response for SMTP callout verifications on the recipient.
 - Adds a new variable `$recipient_verify_cache`, set to True if the callout
   check was based on on the cache, False otherwise.
 - Adds a new variable `$sender_verify_message`, containing the upstream
   response for SMTP callout verifications on the sender.
 - Adds a new variable `$sender_verify_cache`, set to True if the callout
   check was based on on the cache, False otherwise.
 - Internal ticket `#11866`, `#16480`

### 5. Synthesized SPF in DMARC check

 - Applied [here](https://github.com/SpamExperts/exim/commit/8270cf0d8b421b23e6958b38fc29987314e3cab7)
 - Resolve not using synthesized SPF sender domain in DMARC.
 - [Exim bug](https://bugs.exim.org/show_bug.cgi?id=1994)
 - Internal ticket `#30818`
 - _(Patch sent to upstream)_

### 6. Diagnostic-Code to the unroutable addresses

 - Applied [here](https://github.com/SpamExperts/exim/commit/5474322b42fbdde2c9620a05d8ea2abe24524109)
 - Add Diagnostic code for unroutable addresses.
 - [Exim bug](https://bugs.exim.org/show_bug.cgi?id=1846)
 - Internal ticket `#30350`
 - _(Rejected from upstream)_

### 7. Not-QUIT ACL connection lost after dot

 - Applied [here](https://github.com/SpamExperts/exim/commit/c1f443f258a90a5f1c8652ae7874a2e47f525657)
 - Change `connection-lost` to `connection-lost-after-dot`.
 - Internal ticket `#6423`

### 8. Expansion of local parts larger than 256 characters

 - Applied [here](https://github.com/SpamExperts/exim/commit/dcd13bcbe04da6baf58b8b182ef38fb90f19d251)
 - Logs failing to expand local parts larger than 256 characters to mainlog 
   instead of panic log.
 - Internal ticket `#8057`

### 9. Extend header add buffer size

 - Applied [here](https://github.com/SpamExperts/exim/commit/9d04866981beb997db4b109e9c671b0066c8924d)
 - Increase `HEADER_ADD_BUFFER_SIZE` value from `8192 * 4` to `8192 * 10`
 - Internal ticket `#8958`

### 10. Installing exim as exim4

 - Applied [here](https://github.com/SpamExperts/exim/commit/0f566795bb1e0492926b17626e404c79ca0955db)
 - Based on this [Debian patch](https://anonscm.debian.org/git/pkg-exim4/exim4.git/tree/debian/patches/32_exim4.dpatch)
 - Accommodates source for installing exim as exim4.

### 11. Disable version in binary

 - Applied [here](https://github.com/SpamExperts/exim/commit/51bdf1e7aff74abdd5000a58634bacae95355e1f)
 - Based on this [Debian patch](https://anonscm.debian.org/git/pkg-exim4/exim4.git/tree/debian/patches/35_install.dpatch)
 - Exim's installation scripts install the binary as exim-<version> - disable
   this feature.


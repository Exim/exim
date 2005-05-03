$Cambridge: exim/doc/doc-txt/README.SIEVE,v 1.4 2005/05/03 10:02:27 ph10 Exp $

              Notes on the Sieve implementation for Exim

Exim Filter Versus Sieve Filter

Exim supports two incompatible filters: The traditional Exim filter and
the Sieve filter. Since Sieve is a extensible language, it is important
to understand "Sieve" in this context as "the specific implementation
of Sieve for Exim".

The Exim filter contains more features, such as variable expansion, and
better integration with the host environment, like external processes
and pipes.

Sieve is a standard for interoperable filters, defined in RFC 3028,
with multiple implementations around. If interoperability is important,
then there is no way around it.


Exim Implementation

The Exim Sieve implementation offers the core as defined by RFC 3028, the
"envelope" (RFC 3028), the "fileinto" (RFC 3028), the "copy" (RFC 3894)
and the "vacation" (draft-ietf-sieve-vacation-01.txt) extension,
the "i;ascii-numeric" comparator, but not the "reject" extension.
Exim does not support MDMs, so adding it just to the sieve filter makes
little sense.

The Sieve filter is integrated in Exim and works very similar to the
Exim filter: Sieve scripts are recognized by the first line containing
"# sieve filter".  When using "keep" or "fileinto" to save a mail into a
folder, the resulting string is available as the variable $address_file
in the transport that stores it.  A suitable transport could be:

localuser:
  driver = appendfile
  file = ${if eq{$address_file}{inbox} \
              {/var/mail/$local_part} \
              {${if eq{${substr_0_1:$address_file}}{/} \
                    {$address_file} \
                    {$home/$address_file} \
              }} \
         }
  delivery_date_add
  envelope_to_add
  return_path_add
  mode = 0600

Absolute files are stored where specified, relative files are stored
relative to $home and "inbox" goes to the standard mailbox location.

To enable "vacation", set sieve_vacation_directory for the router to
the directory where vacation databases are held (don't put anything
else in that directory) and point reply_transport to an autoreply
transport.


RFC Compliance

Exim requires the first line to be "# sieve filter".  Of course the RFC
does not enforce that line.  Don't expect examples to work without adding
it, though.

RFC 3028 requires using CRLF to terminate the end of a line.
The rationale was that CRLF is universally used in network protocols
to mark the end of the line.  This implementation does not embed Sieve
in a network protocol, but uses Sieve scripts as part of the Exim MTA.
Since all parts of Exim use \n as newline character, this implementation
does, too.  You can change this by defining the macro RFC_EOL at compile
time to enforce CRLF being used.

Exim violates RFC 2822, section 3.6.8, by accepting 8-bit header names, so
this implementation repeats this violation to stay consistent with Exim.
This is in preparation to UTF-8 data.

Sieve scripts can not contain NUL characters in strings, but mail
headers could contain MIME encoded NUL characters, which could never
be matched by Sieve scripts using exact comparisons.  For that reason,
this implementation extends the Sieve quoted string syntax with \0
to describe a NUL character, violating \0 being the same as 0 in
RFC 3028.  Even without using \0, the following tests are all true in
this implementation.  Implementations that use C-style strings will only
evaulate the first test as true.

Subject: =?iso-8859-1?q?abc=00def

header :contains "Subject" ["abc"]
header :contains "Subject" ["def"]
header :matches "Subject" ["abc?def"]

Note that by considering Sieve to be a MUA, RFC 2047 can be interpreted
in a way that NUL characters truncating strings is allowed for Sieve
implementations, although not recommended.  It is further allowed to use
encoded NUL characters in headers, but that's not recommended either.
The above example shows why.  Good code should still be able to deal
with it.

RFC 3028 states that if an implementation fails to convert a character
set to UTF-8, two strings can not be equal if one contains octects greater
than 127.  Assuming that all unknown character sets are one-byte character
sets with the lower 128 octects being US-ASCII is not sound, so this
implementation violates RFC 3028 and treats such MIME words literally.
That way at least something could be matched.

The folder specified by "fileinto" must not contain the character
sequence ".." to avoid security problems.  RFC 3028 does not specifiy the
syntax of folders apart from keep being equivalent to fileinto "INBOX".
This implementation uses "inbox" instead.

Sieve script errors currently cause that messages are silently filed into
"inbox".  RFC 3028 requires that the user is notified of that condition.
This may be implemented in future by adding a header line to mails that
are filed into "inbox" due to an error in the filter.


Strings Containing Header Names Or Envelope Elements

RFC 3028 does not specify what happens if a string denoting a header
field or envelope element does not contain a valid name, e.g. it
contains a colon for a header or it is not "from" or "to" for envelopes.
This implementation generates an error instead of ignoring the header
field in order to ease script debugging, which fits in the common picture
of Sieve.


Header Test With Invalid MIME Encoding In Header

Some MUAs process invalid base64 encoded data, generating junk.
Others ignore junk after seeing an equal sign in base64 encoded data.
RFC 2047 does not specify how to react in this case, other than stating
that a client must not forbid to process a message for that reason.
RFC 2045 specifies that invalid data should be ignored (appearantly
looking at end of line characters).  It also specifies that invalid data
may lead to rejecting messages containing them (and there it appears to
talk about true encoding violations), which is a clear contradiction to
ignoring them.

RFC 3028 does not specify how to process incorrect MIME words.
This implementation treats them literally, as it does if the word is
correct, but its character set can not be converted to UTF-8.


Address Test For Multiple Addresses Per Header

A header may contain multiple addresses.  RFC 3028 does not explicitly
specify how to deal with them, but since the "address" test checks if
anything matches anything else, matching one address suffices to
satify the condition.  That makes it impossible to test if a header
contains a certain set of addresses and no more, but it is more logical
than letting the test fail if the header contains an additional address
besides the one the test checks for.


Semantics Of Keep

The keep command is equivalent to fileinto "inbox": It saves the
message and resets the implicit keep flag.  It does not set the
implicit keep flag; there is no command to set it once it has
been reset.


Semantics of Fileinto

RFC 3028 does not specify if "fileinto" tries to create a mail folder,
in case it does not exist.  This implementation allows to configure
that aspect using the appendfile transport options "create_directory",
"create_file" and "file_must_exist".  See the appendfile transport in
the Exim specification for details.


Semantics of Redirect

Sieve scripts are supposed to be interoperable between servers, so this
implementation does not allow redirecting mail to unqualified addresses,
because the domain would depend on the used system and on systems with
virtual mail domains it is probably not what the user expects it to be.


String Arguments

There has been confusion if the string arguments to "require" are to be
matched case-sensitive or not.  This implementation matches them with
the match type ":is" (default, see section 2.7.1) and the comparator
"i;ascii-casemap" (default, see section 2.7.3).  The RFC defines the
command defaults clearly, so any different implementations violate RFC
3028.  The same is valid for comparator names, also specified as strings.


Number Units

There is a mistake in RFC 3028: The suffix G denotes gibi-, not tebibyte.
The mistake os obvious, because RFC 3028 specifies G to denote 2^30
(which is gibi, not tebi), and that's what this implementation uses as
scaling factor for the suffix G.


Sieve Syntax and Semantics

RFC 3028 confuses syntax and semantics sometimes.  It uses a generic
grammar as syntax for actions and tests and performs many checks during
semantic analysis.  Syntax is specified as grammar rule, semantics
with natural language, despire the latter often talking about syntax.
The intention was to provide a framework for the syntax that describes
current commands as well as future extensions, and describing commands
by semantics.  Since the semantic analysis is not specified by formal
rules, it is easy to get that phase wrong, as demonstrated by the mistake
in RFC 3028 to forbid "elsif" being followed by "elsif" (which is allowed
in Sieve, it's just not specified correctly).

RFC 3028 does not define if semantic checks are strict (always treat
unknown extensions as errors) or lazy (treat unknown extensions as error,
if they are executed), and since it employs a very generic grammar,
it is not unreasonable for an implementation using a parser for the
generic grammar to indeed process scripts that contain unknown commands
in dead code.  It is just required to treat disabled but known extensions
the same as unknown extensions.

The following suggestion for section 8.2 gives two grammars, one for
the framework, and one for specific commands, thus removing most of the
semantic analysis.  Since the parser can not parse unsupported extensions,
the result is strict error checking.  As required in section 2.10.5, known
but not enabled extensions must behave the same as unknown extensions,
so those also result strictly in errors (though at the thin semantic
layer), even if they can be parsed fine.

8.2. Grammar

The atoms of the grammar are lexical tokens.  White space or comments may
appear anywhere between lexical tokens, they are not part of the grammar.
The grammar is specified in ABNF with two extensions to describe tagged
arguments that can be reordered and grammar extensions: { } denotes a
sequence of symbols that may appear in any order.  Example:

  start =  { a b c }

is equivalent to:

  start =  ( a b c ) / ( a c b ) / ( b a c ) / ( b c a ) / ( c a b ) / ( c b a )

The symbol =) is used to append to a rule:

  start =  a
  start =) b

is equivalent to

  start =  a b

All Sieve commands, including extensions, MUST be words of the following
generic grammar with the start symbol "start".  They SHOULD be specified
using a specific grammar, though.

   argument        = string-list / number / tag
   arguments       = *argument [test / test-list]
   block           = "{" commands "}"
   commands        = *command
   string          = quoted-string / multi-line
   string-list     = "[" string *("," string) "]" / string
   test            = identifier arguments
   test-list       = "(" test *("," test) ")"
   command         = identifier arguments ( ";" / block )
   start           = command

The basic Sieve commands are specified using the following grammar, which
language is a subset of the generic grammar above.  The start symbol is
"start".

  address-part     =  ":localpart" / ":domain" / ":all"
  comparator       =  ":comparator" string
  match-type       =  ":is" / ":contains" / ":matches"
  string           =  quoted-string / multi-line
  string-list      =  "[" string *("," string) "]" / string
  address-test     =  "address" { [address-part] [comparator] [match-type] }
                      string-list string-list
  test-list        =  "(" test *("," test) ")"
  allof-test       =  "allof" test-list
  anyof-test       =  "anyof" test-list
  exists-test      =  "exists" string-list
  false-test       =  "false"
  true=test        =  "true"
  header-test      =  "header" { [comparator] [match-type] }
                      string-list string-list
  not-test         =  "not" test
  relop            =  ":over" / ":under"
  size-test        =  "size" relop number
  block            =  "{" commands "}"
  if-command       =  "if" test block *( "elsif" test block ) [ "else" block ]
  stop-command     =  "stop" { stop-options } ";"
  stop-options     =
  keep-command     =  "keep" { keep-options } ";"
  keep-options     =
  discard-command  =  "discard" { discard-options } ";"
  discard-options  =
  redirect-command =  "redirect" { redirect-options } string ";"
  redirect-options =
  require-command  =  "require" { require-options } string-list ";"
  require-options  =
  test             =  address-test / allof-test / anyof-test / exists-test
                      / false-test / true-test / header-test / not-test
                      / size-test
  command          =  if-command / stop-command / keep-command
                      / discard-command / redirect-command
  commands         =  *command
  start            =  *require-command commands

The extensions "envelope" and "fileinto" are specified using the following
grammar extension.

  envelope-test    =  "envelope" { [comparator] [address-part] [match-type] }
                      string-list string-list
  test             =/ envelope-test

  fileinto-command =  "fileinto" { fileinto-options } string ";"
  fileinto-options =
  command          =/ fileinto-command

The extension "copy" is specified as:

  fileinto-options =) ":copy"
  redirect-options =) ":copy"


The i;ascii-numeric Comparator

RFC 2244 describes this comparator and specifies that non-numeric strings
are considered equal with an ordinal value higher than any numeric string.
Although not stated explicitly, this includes the empty string.  A range
of at least 2^31 is required.  This implementation does not limit the
range, because it does not convert numbers to binary representation
before comparing them.


The vacation extension

The extension "vacation" is specified using the following grammar
extension.

  vacation-command =  "vacation" { vacation-options } <reason: string>
  vacation-options =  [":days" number]
                      [":subject" string]
                      [":from" string]
                      [":addresses" string-list]
                      [":mime"]
                      [":handle" string]
  command          =/ vacation-command


Semantics Of ":mime"

The draft does not specify how strings using MIME entities are used
to compose messages.  As a result, different implementations generate
different mails.  The Exim Sieve implementation splits the reason into
header and body.  It adds the header to the mail header and uses the body
as mail body.  Be aware, that other imlementations compose a multipart
structure with the reason as only part.  Both conform to the specification
(or lack thereof).


Semantics Of Not Using ":mime"

Sieve scripts are written in UTF-8, so is the reason string in this
case.  This implementation adds MIME headers to indicate that.  This
is not required by the vacation draft, which does not specify how
the UTF-8 reason is processed to compose the resulting message.


Default Subject

The draft specifies that the default message subject is "Re: "
plus the old subject, stripped by any leading "Re: " strings.
This string is to be taken literally, unlike some software which
matches a regular expression like "[rR][eE]: *".  Using this
subject is dangerous, because many mailing lists verify addresses
by sending a secret key in the subject of a message, asking to
reply to the message for confirmation.  Using the default vacation
subject confirms any subscription request of this kind, allowing
to subscribe a third party to any mailing list, either to annoy
the user or to declare spam as legitimate mail by proving to
use opt-in.  The draft specifies to use "Re: " in front of the
subject, but this implementation uses "Auto: ", as suggested in
RFC 3834, section 3.1.5.


Rate Limiting Responses

In absence of a handle, this implementation hashes the reason,
":subject" option, ":mime" option and ":from" option and uses the hex
string representation as filename within the "sieve_vacation_directory"
to store the recipient addresses for this vacation parameter set.

The draft specifies that sites may define a minimum ":days" value than 1.
This implementation uses 1.  The maximum value MUST greater than 7,
and SHOULD be greater than 30.  This implementation uses a maximum of 31.

Vacation recipient address databases older than 31 days are automatically
removed.  Users do not have to remove them manually when modifying their
scripts.  Don't put anything but vacation databases in that directory
or you risk that it will be removed, too!


Global Reply Address Blacklist

The draft requires that each implementation offers a global black list
of addresses that will never be replied to.  Exim offers this as option
"never_mail" in the autoreply transport.


Interaction With Other Sieve Elements

The draft describes the interaction with vacation, discard, keep,
fileinto and redirect.  It MUST describe compatibility with other
actions, but doesn't.  In this implementation, vacation is compatible
with any other action.

# Make file for Exim documentation from xfpt source.

notarget:;    @echo "** You must specify a target, in the form x.y, where x is 'filter', 'spec',"
	      @echo "** or 'test', and y is 'xml', 'fo', 'ps', 'pdf', 'html', 'txt', or 'info'."
	      @echo "** One other possible targets 'exim.8', 'spec.utf8'".
	      exit 1


############################# EVERYTHING ###############################
#
# Generate all the documentation files...
#
## removed info files as I cannot generate them -  spec.info filter.info
## removed html files as superceded by new website code
everything:		spec.pdf 	spec.ps  	spec.txt \
				filter.pdf 	filter.ps filter.txt \
				exim.8

############################## MAN PAGE ################################

exim.8:       spec.xml x2man
	      ./x2man

########################################################################

# .PHONY doesn't work here, because it forces a rebuild of all dependent
# targets, always. It sets the internal timestamp of its target to
# now().
# But it may happen that local_params does not change
FORCE:
local_params: FORCE GenLocalParams
	@set -e; \
	trap 'rm -f $$tmp' EXIT; \
	tmp=`mktemp`; \
	./GenLocalParams $$tmp; \
	cmp -s $@ $$tmp || mv $$tmp $@

############################### FILTER #################################

filter.xml:      local_params filter.xfpt
		 xfpt filter.xfpt

filter-pr.xml:   filter.xml Pre-xml
		 ./Pre-xml -bookinfo <filter.xml >filter-pr.xml

filter-txt.xml:  filter.xml Pre-xml
		 ./Pre-xml -ascii -html -quoteliteral <filter.xml >filter-txt.xml

filter-info.xml: filter.xml Pre-xml
		 ./Pre-xml -ascii -html <filter.xml >filter-info.xml

filter.fo:       filter-pr.xml MyStyle-filter-fo.xsl MyStyle-fo.xsl MyStyle.xsl
		 /bin/rm -rf filter.fo filter-pr.fo
		 xmlto -x MyStyle-filter-fo.xsl fo filter-pr.xml
		 /bin/mv -f filter-pr.fo filter.fo

# Do not use pdf2ps from the PDF version; better PS is generated directly.

###
### PS/PDF generation using fop
###

fop-filter.ps:   filter.fo
		 fop filter.fo -ps filter-tmp.ps
		 mv filter-tmp.ps filter.ps

# Do not use ps2pdf from the PS version; better PDF is generated directly. It
# contains cross links etc.

fop-filter.pdf:  filter.fo PageLabelPDF
		 fop filter.fo -pdf filter-tmp.pdf
		 ./PageLabelPDF 2 <filter-tmp.pdf >filter.pdf

###
### PS/PDF generation using SDoP
###

sdop-filter.ps:  filter-pr.xml
		 sdop -o filter.ps filter-pr.xml

sdop-filter.pdf: filter.ps
		 ps2pdf filter.ps filter.pdf

###
### PS/PDF default setting
###

filter.ps:  sdop-filter.ps

filter.pdf: sdop-filter.pdf

###
###

filter.txt:   filter-txt.xml Tidytxt MyStyle-txt-html.xsl MyStyle-html.xsl \
                MyStyle.xsl
	      /bin/rm -rf filter-txt.html
	      xmlto -x MyStyle-txt-html.xsl html-nochunks filter-txt.xml
	      command -v w3m >/dev/null
	      LC_ALL=C w3m -dump filter-txt.html | ./Tidytxt >filter.txt
	      ./SanityTestText filter.txt

# I have not found a way of making docbook2texi write its output anywhere
# other than the file name that it makes up. The --to-stdout option does not
# work.

filter.info:  filter-info.xml
	      docbook2texi filter-info.xml
	      perl -ne 's/conceptindex/cindex/;s/optionindex/findex/;print;' \
		<exim_filtering.texi | ./Tidytxt >filter.texinfo
	      /bin/rm -rf exim_filtering.texi
	      makeinfo -o filter.info filter.texinfo

########################################################################


################################ SPEC ##################################

spec.xml:      spec.xfpt local_params
	       xfpt $<

spec-pr.xml:   spec.xml Pre-xml
	       ./Pre-xml -optbreak <spec.xml >spec-pr.xml

spec-txt.xml:  spec.xml Pre-xml
	       ./Pre-xml -ascii -html -noindex -quoteliteral \
		 <spec.xml >spec-txt.xml

spec-info.xml: spec.xml Pre-xml
	       ./Pre-xml -ascii -html -noindex <spec.xml >spec-info.xml

spec.fo:       spec-pr.xml MyStyle-spec-fo.xsl MyStyle-fo.xsl MyStyle.xsl \
               MyTitleStyle.xsl
	       /bin/rm -rf spec.fo spec-pr.fo
	       xmlto -x MyStyle-spec-fo.xsl fo spec-pr.xml
	       /bin/mv -f spec-pr.fo spec.fo

###
### PS/PDF generation using fop
###

# Do not use pdf2ps from the PDF version; better PS is generated directly.

fop-spec.ps:  spec.fo
	      FOP_OPTS=-Xmx512m fop spec.fo -ps spec-tmp.ps
	      mv spec-tmp.ps spec.ps

# Do not use ps2pdf from the PS version; better PDF is generated directly. It
# contains cross links etc. We post-process it to add page label information
# so that the page identifiers shown by acroread are the correct page numbers.

fop-spec.pdf: spec.fo PageLabelPDF
	      FOP_OPTS=-Xmx512m fop spec.fo -pdf spec-tmp.pdf
	      ./PageLabelPDF 12 <spec-tmp.pdf >spec.pdf

###
### PS/PDF generation using SDoP
###

sdop-spec.ps:  spec-pr.xml
	       sdop -o spec.ps spec-pr.xml

sdop-spec.pdf: spec.ps
	       ps2pdf spec.ps spec.pdf

###
### PS/PDF default setting
###

spec.ps:  sdop-spec.ps

spec.pdf: sdop-spec.pdf

###
###

spec-txt.html:     spec-txt.xml \
		MyStyle-txt-html.xsl MyStyle-html.xsl MyStyle.xsl
	      xmlto -x MyStyle-txt-html.xsl html-nochunks $<

spec.utf8:	spec-txt.html Tidytxt
		@grep -iq 'LC_CTYPE=.*utf-\?8' local_params || { \
			echo 'your current locale does not support UTF-8' >&2; \
			false; }
		command -v w3m >/dev/null
		w3m -dump $< | ./Tidytxt -utf8 >$@

spec.txt: spec-txt.html Tidytxt
	      command -v w3m >/dev/null
	      LC_ALL=C w3m -dump $< | ./Tidytxt >$@
	      ./SanityTestText spec.txt


# I have not found a way of making docbook2texi write its output anywhere
# other than the file name that it makes up. The --to-stdout option does not
# work.

spec.info:    spec-info.xml
	      docbook2texi spec-info.xml
	      ./TidyInfo <the_exim_mta.texi >spec.texinfo
	      /bin/rm -rf the_exim_mta.texi
	      makeinfo -o spec.info --no-split spec.texinfo

########################################################################


################################ TEST ##################################

# These targets (similar to the above)  are for running little tests.

test.xml:     test.xfpt
	      xfpt test.xfpt

test-pr.xml:  test.xml Pre-xml
	      ./Pre-xml <test.xml >test-pr.xml

test-html.xml: test.xml Pre-xml
	      ./Pre-xml -html -oneindex <test.xml >test-html.xml

test-txt.xml: test.xml Pre-xml
	      ./Pre-xml -ascii -html -noindex -quoteinfo \
		<test.xml >test-txt.xml

test-info.xml: test.xml Pre-xml
	      ./Pre-xml -ascii -html -noindex <test.xml >test-info.xml

test.fo:      test-pr.xml MyStyle-spec-fo.xsl MyStyle-fo.xsl MyStyle.xsl \
                MyTitleStyle.xsl
	      /bin/rm -rf test.fo test-pr.fo
	      xmlto -x MyStyle-spec-fo.xsl fo test-pr.xml
	      /bin/mv -f test-pr.fo test.fo

###
### PS/PDF generation using fop
###

# Do not use pdf2ps from the PDF version; better PS is generated directly.

fop-test.ps:  test.fo
	      fop test.fo -ps test-tmp.ps
	      mv test-tmp.ps test.ps

# Do not use ps2pdf from the PS version; better PDF is generated directly. It
# contains cross links etc.

fop-test.pdf: test.fo
	      fop test.fo -pdf test-tmp.pdf
	      mv test-tmp.pdf test.pdf

###
### PS/PDF generation using SDoP
###

sdop-test.ps:  test-pr.xml
	       sdop -o test.ps test-pr.xml

sdop-test.pdf: test.ps
	       ps2pdf test.ps test.pdf

###
### PS/PDF default setting
###

test.ps:  sdop-test.ps

test.pdf: sdop-test.pdf

###
###


test.txt:     test-txt.xml Tidytxt MyStyle-txt-html.xsl MyStyle-html.xsl \
                MyStyle.xsl
	      /bin/rm -rf test-txt.html
	      xmlto -x MyStyle-txt-html.xsl html-nochunks test-txt.xml
	      command -v w3m >/dev/null
	      w3m -dump test-txt.html | Tidytxt >test.txt

# I have not found a way of making docbook2texi write its output anywhere
# other than the file name that it makes up. The --to-stdout option does not
# work.

test.info:    test-info.xml
	      docbook2texi test-info.xml
	      ./TidyInfo <short_title.texi >test.texinfo
	      /bin/rm -rf short_title.texi
	      makeinfo -o test.info test.texinfo

########################################################################


############################## OS FIXUP ################################

# Yes, we've advanced so far in text processing that we now have to
# hardcode in complete paths and so become dependent upon exactly where
# files were installed for xsl:import.  Which of course varies by OS.

os-fixup:
	./OS-Fixups

########################################################################


################################ CLEAN #################################

clean:; /bin/rm -rf exim.8 \
	      filter*.xml spec*.xml test*.xml \
	      *.fo *.pdf *.ps \
	      filter*.html spec*.html test*.html \
	      filter*.txt spec*.txt test*.txt \
	      *.info* *.texinfo *.texi

########################################################################

# $Cambridge: exim/doc/doc-docbook/Makefile,v 1.7 2006/02/01 11:01:01 ph10 Exp $

# Make file for Exim documentation from xfpt source.

notarget:;    @echo "** You must specify a target, in the form x.y, where x is 'filter', 'spec',"
	      @echo "** or 'test', and y is 'xml', 'fo', 'ps', 'pdf', 'html', 'txt', or 'info'."
	      @echo "** One other possible target is 'exim.8'".
	      exit 1


############################## MAN PAGE ################################

exim.8:       spec.xml x2man
	      ./x2man

########################################################################


############################### FILTER #################################

filter.xml:   filter.xfpt
	      xfpt filter.xfpt

filter-fo.xml: filter.xml Pre-xml
	      ./Pre-xml -bookinfo <filter.xml >filter-fo.xml

filter-html.xml: filter.xml Pre-xml
	      ./Pre-xml -html <filter.xml >filter-html.xml

filter-txt.xml: filter.xml Pre-xml
	      ./Pre-xml -ascii -html -quoteliteral <filter.xml >filter-txt.xml

filter-info.xml: filter.xml Pre-xml
	      ./Pre-xml -ascii -html <filter.xml >filter-info.xml

filter.fo:    filter-fo.xml MyStyle-filter-fo.xsl MyStyle-fo.xsl MyStyle.xsl
	      /bin/rm -rf filter.fo filter-fo.fo
	      xmlto -x MyStyle-filter-fo.xsl fo filter-fo.xml
	      /bin/mv -f filter-fo.fo filter.fo

# Do not use pdf2ps from the PDF version; better PS is generated directly.

filter.ps:    filter.fo
	      fop filter.fo -ps filter-tmp.ps
	      mv filter-tmp.ps filter.ps

# Do not use ps2pdf from the PS version; better PDF is generated directly. It
# contains cross links etc.

filter.pdf:   filter.fo
	      fop filter.fo -pdf filter-tmp.pdf
	      mv filter-tmp.pdf filter.pdf

filter.html:  filter-html.xml TidyHTML-filter MyStyle-nochunk-html.xsl \
                MyStyle-html.xsl MyStyle.xsl
	      /bin/rm -rf filter.html filter-html.html
	      xmlto -x MyStyle-nochunk-html.xsl html-nochunks filter-html.xml
	      /bin/mv -f filter-html.html filter.html
	      ./TidyHTML-filter

filter.txt:   filter-txt.xml Tidytxt MyStyle-txt-html.xsl MyStyle-html.xsl \
                MyStyle.xsl
	      /bin/rm -rf filter-txt.html
	      xmlto -x MyStyle-txt-html.xsl html-nochunks filter-txt.xml
	      w3m -dump filter-txt.html | ./Tidytxt >filter.txt

# I have not found a way of making docbook2texi write its output anywhere
# other than the file name that it makes up. The --to-stdout option does not
# work.

filter.info:  filter-info.xml
	      docbook2texi filter-info.xml
	      perl -ne 's/conceptindex/cindex/;s/optionindex/findex/;print;' \
		<exim_filtering.texi | Tidytxt >filter.texinfo
	      /bin/rm -rf exim_filtering.texi
	      makeinfo -o filter.info filter.texinfo

########################################################################


################################ SPEC ##################################

spec.xml:     spec.xfpt
	      xfpt spec.xfpt

spec-fo.xml:  spec.xml Pre-xml
	      ./Pre-xml -optbreak <spec.xml >spec-fo.xml

spec-html.xml: spec.xml Pre-xml
	      ./Pre-xml -html -oneindex \
		<spec.xml >spec-html.xml

spec-txt.xml: spec.xml Pre-xml
	      ./Pre-xml -ascii -html -noindex -quoteliteral \
		<spec.xml >spec-txt.xml

spec-info.xml: spec.xml Pre-xml
	      ./Pre-xml -ascii -html -noindex <spec.xml >spec-info.xml

spec.fo:      spec-fo.xml MyStyle-spec-fo.xsl MyStyle-fo.xsl MyStyle.xsl \
              MyTitleStyle.xsl
	      /bin/rm -rf spec.fo spec-fo.fo
	      xmlto -x MyStyle-spec-fo.xsl fo spec-fo.xml
	      /bin/mv -f spec-fo.fo spec.fo

# Do not use pdf2ps from the PDF version; better PS is generated directly.

spec.ps:      spec.fo
	      FOP_OPTS=-Xmx512m fop spec.fo -ps spec-tmp.ps
	      mv spec-tmp.ps spec.ps

# Do not use ps2pdf from the PS version; better PDF is generated directly. It
# contains cross links etc. We post-process it to add page label information
# so that the page identifiers shown by acroread are the correct page numbers.

spec.pdf:     spec.fo PageLabelPDF
	      FOP_OPTS=-Xmx512m fop spec.fo -pdf spec-tmp.pdf
	      ./PageLabelPDF <spec-tmp.pdf >spec.pdf

spec.html:    spec-html.xml TidyHTML-spec MyStyle-chunk-html.xsl \
                MyStyle-html.xsl MyStyle.xsl
	      /bin/rm -rf spec.html
	      xmlto -x MyStyle-chunk-html.xsl -o spec.html html spec-html.xml
	      ./TidyHTML-spec

spec.txt:     spec-txt.xml Tidytxt MyStyle-txt-html.xsl MyStyle-html.xsl \
                MyStyle.xsl
	      /bin/rm -rf spec-txt.html
	      xmlto -x MyStyle-txt-html.xsl html-nochunks spec-txt.xml
	      w3m -dump spec-txt.html | ./Tidytxt >spec.txt

# I have not found a way of making docbook2texi write its output anywhere
# other than the file name that it makes up. The --to-stdout option does not
# work.

spec.info:    spec-info.xml
	      docbook2texi spec-info.xml
	      perl -ne 's/conceptindex/cindex/;s/optionindex/findex/;print;' \
		<the_exim_mta.texi >spec.texinfo
	      /bin/rm -rf the_exim_mta.texi
	      makeinfo -o spec.info spec.texinfo

########################################################################


################################ TEST ##################################

# These targets (similar to the above)  are for running little tests.

test.xml:     test.xfpt
	      xfpt test.xfpt

test-fo.xml:  test.xml Pre-xml
	      ./Pre-xml <test.xml >test-fo.xml

test-html.xml: test.xml Pre-xml
	      ./Pre-xml -html -oneindex <test.xml >test-html.xml

test-txt.xml: test.xml Pre-xml
	      ./Pre-xml -ascii -html -noindex -quoteinfo \
		<test.xml >test-txt.xml

test-info.xml: test.xml Pre-xml
	      ./Pre-xml -ascii -html -noindex <test.xml >test-info.xml

test.fo:      test-fo.xml MyStyle-spec-fo.xsl MyStyle-fo.xsl MyStyle.xsl \
                MyTitleStyle.xsl
	      /bin/rm -rf test.fo test-fo.fo
	      xmlto -x MyStyle-spec-fo.xsl fo test-fo.xml
	      /bin/mv -f test-fo.fo test.fo

# Do not use pdf2ps from the PDF version; better PS is generated directly.

test.ps:      test.fo
	      fop test.fo -ps test-tmp.ps
	      mv test-tmp.ps test.ps

# Do not use ps2pdf from the PS version; better PDF is generated directly. It
# contains cross links etc.

test.pdf:     test.fo
	      fop test.fo -pdf test-tmp.pdf
	      mv test-tmp.pdf test.pdf

test.html:    test-html.xml MyStyle-nochunk-html.xsl MyStyle-html.xsl \
                MyStyle.xsl
	      /bin/rm -rf test.html test-html.html
	      xmlto -x MyStyle-nochunk-html.xsl html-nochunks test-html.xml
	      /bin/mv -f test-html.html test.html

test.txt:     test-txt.xml Tidytxt MyStyle-txt-html.xsl MyStyle-html.xsl \
                MyStyle.xsl
	      /bin/rm -rf test-txt.html
	      xmlto -x MyStyle-txt-html.xsl html-nochunks test-txt.xml
	      w3m -dump test-txt.html | Tidytxt >test.txt

# I have not found a way of making docbook2texi write its output anywhere
# other than the file name that it makes up. The --to-stdout option does not
# work.

test.info:    test-info.xml
	      docbook2texi test-info.xml
	      perl -ne 's/conceptindex/cindex/;s/optionindex/findex/;print;' \
		<short_title.texi >test.texinfo
	      /bin/rm -rf short_title.texi
	      makeinfo -o test.info test.texinfo

########################################################################


################################ CLEAN #################################

clean:; /bin/rm -rf exim.8 \
	      filter*.xml spec*.xml test*.xml \
	      *.fo *.html *.pdf *.ps \
	      filter*.txt spec*.txt test*.txt \
	      *.info* *.texinfo *.texi

########################################################################

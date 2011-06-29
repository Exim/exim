# Makefile for Exim documentation

ps:;        sgcal-fr spec.src -v -to z-gcode -index z-rawindex
	    sgtops z-gcode -to z-ps

txt:;       g2man       
	    sgcal-fr spec.src -style online -v -to z-txt -index z-rawindex

contents:;  @DoConts

index:;     @DoIndex

# The file z-rawindex is included by the filter source to create a TOC.
# First empty it, then do a dummy format to create it, then do a second
# pass. This works because the TOC occupies no more than the rest of the
# first page.

filterps:;  /bin/rm -rf z-rawindex
	    touch z-rawindex
	    sgcal-fr filter.src -v -to z-gcode -index z-rawindex
	    sgcal-fr filter.src -v -to z-gcode -index /dev/null
	    sgtops z-gcode -to filter.ps

filtertxt:; /bin/rm -rf z-rawindex
	    touch z-rawindex
	    sgcal-fr filter.src -style online -v -to filter.txt -index z-rawindex
	    sgcal-fr filter.src -style online -v -to filter.txt -index /dev/null

clean:;     /bin/rm -f z*

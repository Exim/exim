<!-- $Cambridge: exim/doc/doc-docbook/MyStyle-chunk-html.xsl,v 1.7 2010/05/30 18:16:12 nm4 Exp $ -->

<!-- This stylesheet driver imports the DocBook XML stylesheet for chunked
HTML output, and then imports my common stylesheet for HTML output. Finally, it
fiddles with the chunking parameters to arrange for chapter chunking only (no
section chunking). -->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version='1.0'>

<xsl:import href="/usr/share/sgml/docbook/xsl-stylesheets-1.70.1/xhtml/chunk.xsl"/>
<xsl:import href="MyStyle-html.xsl"/>


<!-- No section chunking; don't output the list of chunks -->

<xsl:param name="chunk.section.depth" select="0"></xsl:param>
<xsl:param name="chunk.quietly" select="1"/>


</xsl:stylesheet>

<!-- $Cambridge: exim/doc/doc-docbook/MyStyle-spec-fo.xsl,v 1.3 2006/02/01 11:01:01 ph10 Exp $ -->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version='1.0'>

<!-- This stylesheet driver imports the DocBook XML stylesheet for FO output,
and then imports my common stylesheet that makes changes that are wanted for
all forms of output. Then it imports my FO stylesheet that contains changes for
all printed output. Finally, there are some changes that apply only when
printing the Exim specification document. -->

<xsl:import href="/usr/share/sgml/docbook/xsl-stylesheets-1.68.1/fo/docbook.xsl"/>
<xsl:import href="MyStyle.xsl"/>
<xsl:import href="MyStyle-fo.xsl"/>

<!-- Special for the spec document -->

<!-- Arrange for the table of contents to be an even number of pages. The name
"lot" includes all pages that contain a "list of titles", which in our case is
only the TOC. -->

<xsl:template name="force.page.count">
  <xsl:param name="element" select="local-name(.)"/>
  <xsl:param name="master-reference" select="''"/>
  <xsl:choose>
    <xsl:when test="$master-reference = 'lot'">end-on-even</xsl:when>
    <xsl:otherwise>no-force</xsl:otherwise>
  </xsl:choose>
</xsl:template>

</xsl:stylesheet>

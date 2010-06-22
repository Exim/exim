<!-- $Cambridge: exim/doc/doc-docbook/MyStyle-spec-fo.xsl,v 1.7 2010/05/30 18:16:12 nm4 Exp $ -->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version='1.0'>

<!-- This stylesheet driver imports the DocBook XML stylesheet for FO output,
and then imports my common stylesheet that makes changes that are wanted for
all forms of output. Then it imports my FO stylesheet that contains changes for
all printed output. Finally, there are some changes that apply only when
printing the Exim specification document. -->

<xsl:import href="/usr/share/sgml/docbook/xsl-stylesheets-1.70.1/fo/docbook.xsl"/>
<xsl:import href="MyStyle.xsl"/>
<xsl:import href="MyStyle-fo.xsl"/>

<!-- Special for the spec document -->

</xsl:stylesheet>

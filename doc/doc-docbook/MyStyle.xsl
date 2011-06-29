<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version='1.0'>

<!-- This file contains changes to the Docbook XML stylesheets that I want to
have happen in all forms of output. It is imported by all the drivers. -->


<!-- Set body font size -->

<xsl:param name="body.font.master">11</xsl:param>

<!-- Set no relative indent for titles and body -->

<xsl:param name="body.start.indent">0pt</xsl:param>
<xsl:param name="title.margin.left">0pt</xsl:param>


<!-- This removes the dot at the end of run-in titles, which we use
for formal paragraphs for command line options. -->

<xsl:param name="runinhead.default.title.end.punct" select="' '"></xsl:param>


<!-- Without this setting, variable lists get misformatted in the FO case,
causing overprinting. Maybe with a later release of fop the need to do this
might go away. -->

<xsl:param name="variablelist.as.blocks" select="1"></xsl:param>


<!--
Cause sections to be numbered, and to include the outer component number.
-->

<xsl:param name="section.autolabel">1</xsl:param>
<xsl:param name="section.label.includes.component.label">1</xsl:param>


<!--
Specify TOCs only for top-level things. No TOCs for components (e.g. chapters)
-->

<xsl:param name="generate.toc">
article   toc,title
book      toc,title
</xsl:param>


<!-- Turn off the poor hyphenation -->

<xsl:param name="hyphenate">false</xsl:param>


<!-- Generate only numbers, no titles, in cross references. -->

<xsl:param name="xref.with.number.and.title">0</xsl:param>


<!-- Output variable names in italic rather than the default monospace. -->

<xsl:template match="varname">
  <xsl:call-template name="inline.italicseq"/>
</xsl:template>


<!-- Output file names in italic rather than the default monospace. -->

<xsl:template match="filename">
  <xsl:call-template name="inline.italicseq"/>
</xsl:template>


<!-- Output function names in italic rather than the default boldface. -->

<xsl:template match="function">
  <xsl:call-template name="inline.italicseq"/>
</xsl:template>


<!-- Output options in bold rather than the default monospace. -->

<xsl:template match="option">
  <xsl:call-template name="inline.boldseq"/>
</xsl:template>


<!--
Make a number of more detailed changes to the style that involve more than just
fiddling with a parameter.
-->

<xsl:param name="local.l10n.xml" select="document('')"/>
<l:i18n xmlns:l="http://docbook.sourceforge.net/xmlns/l10n/1.0">
  <l:l10n language="en">

    <!-- Turn the text "Revision History" into nothing, because we only have
    the info for the latest revision in the file. -->

    <l:gentext key="revhistory" text=""/>
    <l:gentext key="RevHistory" text=""/>

    <!-- The default (as modified above) gives us "Chapter xxx" or "Section
    xxx", with a capital letter at the start. So we have to make an more
    complicated explicit change to give just the number. -->

    <l:context name="xref-number">
      <l:template name="chapter" text="%n"/>
      <l:template name="sect1" text="%n"/>
      <l:template name="sect2" text="%n"/>
      <l:template name="section" text="%n"/>
    </l:context>

    <!-- I think that having a trailing dot after section numbers looks fussy,
    whereas you need it after just the digits of a chapter number. In both
    cases we want to get rid of the word "chapter" or "section". -->

    <l:context name="title-numbered">
      <l:template name="chapter" text="%n.&#160;%t"/>
      <l:template name="sect1" text="%n&#160;%t"/>
      <l:template name="sect2" text="%n&#160;%t"/>
      <l:template name="section" text="%n&#160;%t"/>
    </l:context>

  </l:l10n>
</l:i18n>


<!-- The default has far too much space on either side of displays and lists -->

<xsl:attribute-set name="verbatim.properties">
  <xsl:attribute name="space-before.minimum">0em</xsl:attribute>
  <xsl:attribute name="space-before.optimum">0em</xsl:attribute>
  <xsl:attribute name="space-before.maximum">0em</xsl:attribute>
  <xsl:attribute name="space-after.minimum">0em</xsl:attribute>
  <xsl:attribute name="space-after.optimum">0em</xsl:attribute>
  <xsl:attribute name="space-after.maximum">0em</xsl:attribute>
  <xsl:attribute name="start-indent">0.3in</xsl:attribute>
</xsl:attribute-set>

<xsl:attribute-set name="list.block.spacing">
  <xsl:attribute name="space-before.optimum">0em</xsl:attribute>
  <xsl:attribute name="space-before.minimum">0em</xsl:attribute>
  <xsl:attribute name="space-before.maximum">0em</xsl:attribute>
  <xsl:attribute name="space-after.optimum">0em</xsl:attribute>
  <xsl:attribute name="space-after.minimum">0em</xsl:attribute>
  <xsl:attribute name="space-after.maximum">0em</xsl:attribute>
</xsl:attribute-set>

<!-- List item spacing -->

<xsl:attribute-set name="list.item.spacing">
  <xsl:attribute name="space-before.optimum">0.8em</xsl:attribute>
  <xsl:attribute name="space-before.minimum">0.8em</xsl:attribute>
  <xsl:attribute name="space-before.maximum">1em</xsl:attribute>
</xsl:attribute-set>

<!-- Reduce the space after informal tables -->

<xsl:attribute-set name="informal.object.properties">
  <xsl:attribute name="space-before.minimum">1em</xsl:attribute>
  <xsl:attribute name="space-before.optimum">1em</xsl:attribute>
  <xsl:attribute name="space-before.maximum">2em</xsl:attribute>
  <xsl:attribute name="space-after.minimum">0em</xsl:attribute>
  <xsl:attribute name="space-after.optimum">0em</xsl:attribute>
  <xsl:attribute name="space-after.maximum">0em</xsl:attribute>
</xsl:attribute-set>

<!-- Reduce the space after section titles. 0 is not small enough. -->

<xsl:attribute-set name="section.title.level1.properties">
  <xsl:attribute name="space-after.minimum">-6pt</xsl:attribute>
  <xsl:attribute name="space-after.optimum">-4pt</xsl:attribute>
  <xsl:attribute name="space-after.maximum">0pt</xsl:attribute>
</xsl:attribute-set>

<!-- Slightly reduce the space before paragraphs -->

<xsl:attribute-set name="normal.para.spacing">
  <xsl:attribute name="space-before.optimum">0.8em</xsl:attribute>
  <xsl:attribute name="space-before.minimum">0.8em</xsl:attribute>
  <xsl:attribute name="space-before.maximum">1.0em</xsl:attribute>
</xsl:attribute-set>


<xsl:attribute-set name="table.cell.padding">
  <xsl:attribute name="padding-left">2pt</xsl:attribute>
  <xsl:attribute name="padding-right">2pt</xsl:attribute>
  <xsl:attribute name="padding-top">0pt</xsl:attribute>
  <xsl:attribute name="padding-bottom">0pt</xsl:attribute>
</xsl:attribute-set>



<!-- Turn off page header rule -->
<xsl:param name="header.rule" select="0"></xsl:param>

<!-- Remove page header content -->
<xsl:template name="header.content"/>

<!-- Remove space for page header -->
<xsl:param name="body.margin.top" select="'0in'"></xsl:param>
<xsl:param name="region.before.extent" select="'0in'"></xsl:param>

<!-- Turn off page footer rule -->
<xsl:param name="footer.rule" select="0"></xsl:param>


</xsl:stylesheet>

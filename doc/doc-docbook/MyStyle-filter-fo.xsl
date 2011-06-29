<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version='1.0'>

<!-- This stylesheet driver imports the DocBook XML stylesheet for FO output,
and then imports my common stylesheet that makes changes that are wanted for
all forms of output. Then it imports my FO stylesheet that contains changes for
all printed output. Finally, there are some changes that apply only when
printing the filter document. -->

<xsl:import href="http://docbook.sourceforge.net/release/xsl/current/fo/docbook.xsl"/>
<xsl:import href="MyStyle.xsl"/>
<xsl:import href="MyStyle-fo.xsl"/>

<!-- For the filter document, we do not want a title page and verso, as it
isn't really a "book", though we use the book XML style. It turns out that this
can be fiddled simply by changing the text "Table of Contents" to the title of
the document.

However, it seems that we have to repeat here the language-specific changes
that are also present in MyStyle.xsl, because this overrides rather than adds
to the settings. -->

<xsl:param name="local.l10n.xml" select="document('')"/>
<l:i18n xmlns:l="http://docbook.sourceforge.net/xmlns/l10n/1.0">
  <l:l10n language="en">

   <l:gentext key="TableofContents" text="Exim&#x2019;s interfaces to mail filtering"/>

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

</xsl:stylesheet>

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version='1.0'>

<!-- This stylesheet driver imports my common stylesheet that makes some
changes that are wanted for all forms of output. Then it makes changes that are
specific to HTML output. -->

<xsl:import href="MyStyle.xsl"/>


<!-- This removes the title of the current page from the top of the page -
redundant because each page is a chapter, whose title shows just below. It also
removes the titles of the next/prev at the bottom of the page, but I don't
think that matters too much. -->

<xsl:param name="navig.showtitles" select="'0'"/>


<!-- This allows for the setting of RevisionFlag on elements. -->

<xsl:param name="show.revisionflag" select="'1'"/>

<!-- This adds an in-line style to the generated HTML. We need this for the
RevisionFlag stuff. While we are at it, we also set the style for
<literallayout> blocks. -->

<xsl:template name="system.head.content">
<style type="text/css">
<xsl:text>
div.added    { background-color: #ffff99; }
div.deleted  { text-decoration: line-through;
               background-color: #FF7F7F; }
div.changed  { background-color: #99ff99; }
div.off      {  }

span.added   { background-color: #ffff99; }
span.deleted { text-decoration: line-through;
               background-color: #FF7F7F; }
span.changed { background-color: #99ff99; }
span.off     {  }

<!-- Styles for <literallayout> -->

pre.literallayout {
  background-color: #E8E8D0;
  padding-left: 0.5cm;
  padding-top:  5px;
  padding-bottom: 5px;
}

div[class=changed] pre.literallayout {
  background-color: #99ff99;
  padding-left: 0.5cm;
  padding-top:  5px;
  padding-bottom: 5px;
}

div.literallayout {
  background-color: #E8E8D0;
  padding-left: 0.5cm;
  padding-top:  5px;
  padding-bottom: 5px;
}

div[class=changed] div.literallayout {
  background-color: #99ff99;
  padding-left: 0.5cm;
  padding-top:  5px;
  padding-bottom: 5px;
}

</xsl:text>
</style>
</xsl:template>

<!-- Here's the template for the actual revision flag thingy. -->

<xsl:template match="*[@revisionflag]">
  <xsl:choose>
    <xsl:when test="local-name(.) = 'para' or local-name(.) = 'simpara'                     or local-name(.) = 'formalpara'                     or local-name(.) = 'section'                     or local-name(.) = 'sect1'                     or local-name(.) = 'sect2'                     or local-name(.) = 'sect3'                     or local-name(.) = 'sect4'                     or local-name(.) = 'sect5'                     or local-name(.) = 'chapter'                     or local-name(.) = 'preface'                     or local-name(.) = 'itemizedlist'                     or local-name(.) = 'varlistentry'                     or local-name(.) = 'glossary'                     or local-name(.) = 'bibliography'                     or local-name(.) = 'index'                     or local-name(.) = 'appendix'">
      <div class="{@revisionflag}">
        <xsl:apply-imports/>
      </div>
    </xsl:when>
    <xsl:when test="local-name(.) = 'phrase' or local-name(.) = 'ulink'                     or local-name(.) = 'link'                     or local-name(.) = 'filename'                     or local-name(.) = 'literal'                     or local-name(.) = 'member'                     or local-name(.) = 'glossterm'                     or local-name(.) = 'sgmltag'                     or local-name(.) = 'quote'                     or local-name(.) = 'emphasis'                     or local-name(.) = 'command'                     or local-name(.) = 'xref'">
      <span class="{@revisionflag}">
        <xsl:apply-imports/>
      </span>
    </xsl:when>
    <xsl:when test="local-name(.) = 'listitem' or local-name(.) = 'entry'                     or local-name(.) = 'title'">
      <!-- nop; these are handled directly in the stylesheet -->
      <xsl:apply-imports/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:message>
        <xsl:text>Revisionflag on unexpected element: </xsl:text>
        <xsl:value-of select="local-name(.)"/>
        <xsl:text> (Assuming block)</xsl:text>
      </xsl:message>
      <div class="{@revisionflag}">
        <xsl:apply-imports/>
      </div>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>


<!-- The default uses short chapter titles in the TOC! I want them only for
use in footer lines in printed output. So we have to modify this template. I
changed "titleabbrev.markup" to "title.markup". -->

<xsl:template name="toc.line">
  <xsl:param name="toc-context" select="."/>
  <xsl:param name="depth" select="1"/>
  <xsl:param name="depth.from.context" select="8"/>

 <span>
  <xsl:attribute name="class"><xsl:value-of select="local-name(.)"/></xsl:attribute>
  <a>
    <xsl:attribute name="href">
      <xsl:call-template name="href.target">
        <xsl:with-param name="context" select="$toc-context"/>
      </xsl:call-template>
    </xsl:attribute>

    <xsl:variable name="label">
      <xsl:apply-templates select="." mode="label.markup"/>
    </xsl:variable>
    <xsl:copy-of select="$label"/>
    <xsl:if test="$label != ''">
      <xsl:value-of select="$autotoc.label.separator"/>
    </xsl:if>

    <xsl:apply-templates select="." mode="title.markup"/>
  </a>
  </span>
</xsl:template>


<!-- The default stylesheets generate both chapters and sections with <h2>
headings in the HTML. The argument is that the HTML headings don't go deep
enough to match the DocBook levels. But surely it would be better to stop them
at the bottom end? Anyway, the Exim documents have only one level of section
within chapters, and even if they went to two, it wouldn't exhaust HTML's
capabilities. So I have copied the style stuff here, making a 1-character
change from "+ 1" to "+ 2" in roughly the middle. -->

<xsl:template name="section.heading">
  <xsl:param name="section" select="."/>
  <xsl:param name="level" select="1"/>
  <xsl:param name="allow-anchors" select="1"/>
  <xsl:param name="title"/>
  <xsl:param name="class" select="'title'"/>

  <xsl:variable name="id">
    <xsl:choose>
      <!-- if title is in an *info wrapper, get the grandparent -->
      <xsl:when test="contains(local-name(..), 'info')">
        <xsl:call-template name="object.id">
          <xsl:with-param name="object" select="../.."/>
        </xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="object.id">
          <xsl:with-param name="object" select=".."/>
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>

  <!-- HTML H level is two higher than section level -->
  <xsl:variable name="hlevel" select="$level + 2"/>
  <xsl:element name="h{$hlevel}">
    <xsl:attribute name="class"><xsl:value-of select="$class"/></xsl:attribute>
    <xsl:if test="$css.decoration != '0'">
      <xsl:if test="$hlevel&lt;3">
        <xsl:attribute name="style">clear: both</xsl:attribute>
      </xsl:if>
    </xsl:if>
    <xsl:if test="$allow-anchors != 0">
      <xsl:call-template name="anchor">
        <xsl:with-param name="node" select="$section"/>
        <xsl:with-param name="conditional" select="0"/>
      </xsl:call-template>
    </xsl:if>
    <xsl:copy-of select="$title"/>
  </xsl:element>
</xsl:template>


</xsl:stylesheet>

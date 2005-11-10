<!-- $Cambridge: exim/doc/doc-docbook/MyStyle-fo.xsl,v 1.2 2005/11/10 12:30:13 ph10 Exp $ -->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:fo="http://www.w3.org/1999/XSL/Format"
                version="1.0">

<!-- This stylesheet driver contains changes that I want to apply to the
printed output form of both the filter document and the main Exim
specification. It is imported by MyStyle-filter-fo.xsl and MyStyle-spec-fo.xsl.
-->

<xsl:import href="MyTitleStyle.xsl"/>



<!-- Set A4 paper, double sided -->

<xsl:param name="paper.type" select="'A4'"></xsl:param>

<!-- This currently causes errors
<xsl:param name="double.sided" select="1"></xsl:param>
-->

<!-- Allow for typed index entries. The "role" setting works with DocBook
version 4.2 or earlier. Later versions (which we are not currently using)
need "type". -->

<xsl:param name="index.on.type" select="1"></xsl:param>
<xsl:param name="index.on.role" select="1"></xsl:param>


<!-- The default uses short chapter titles in the TOC! I want them only for
use in footer lines. So we have to modify this template. I changed
"titleabbrev.markup" to "title.markup". While I'm here, I also made chapter
entries print in bold. -->

<xsl:template name="toc.line">
  <xsl:variable name="id">
    <xsl:call-template name="object.id"/>
  </xsl:variable>

  <xsl:variable name="label">
    <xsl:apply-templates select="." mode="label.markup"/>
  </xsl:variable>

  <fo:block text-align-last="justify"
            end-indent="{$toc.indent.width}pt"
            last-line-end-indent="-{$toc.indent.width}pt">
    <fo:inline keep-with-next.within-line="always">
      <!-- Added lines for bold -->
      <xsl:choose>
        <xsl:when test="self::chapter">
          <xsl:attribute name="font-weight">bold</xsl:attribute>
        </xsl:when>
        <xsl:when test="self::index">
          <xsl:attribute name="font-weight">bold</xsl:attribute>
        </xsl:when>
      </xsl:choose>
      <!--  ..................  -->
      <fo:basic-link internal-destination="{$id}">
        <xsl:if test="$label != ''">
          <xsl:copy-of select="$label"/>
          <xsl:value-of select="$autotoc.label.separator"/>
        </xsl:if>
        <xsl:apply-templates select="." mode="title.markup"/>
      </fo:basic-link>
    </fo:inline>
    <fo:inline keep-together.within-line="always">
      <xsl:text> </xsl:text>
      <fo:leader leader-pattern="dots"
                 leader-pattern-width="3pt"
                 leader-alignment="reference-area"
                 keep-with-next.within-line="always"/>
      <xsl:text> </xsl:text>
      <fo:basic-link internal-destination="{$id}">
        <fo:page-number-citation ref-id="{$id}"/>
      </fo:basic-link>
    </fo:inline>
  </fo:block>
</xsl:template>


<!--
Adjust the sizes of the fonts for titles; the defaults are too gross.
-->

<!-- Level 1 is sect1 level -->

<xsl:attribute-set name="section.title.level1.properties">
  <xsl:attribute name="font-size">
    <xsl:value-of select="$body.font.master * 1.2"></xsl:value-of>
    <xsl:text>pt</xsl:text>
  </xsl:attribute>
</xsl:attribute-set>


<!-- Fiddling with chapter titles is more messy -->

<xsl:template match="title" mode="chapter.titlepage.recto.auto.mode">
  <fo:block xmlns:fo="http://www.w3.org/1999/XSL/Format"
            xsl:use-attribute-sets="chapter.titlepage.recto.style"
            margin-left="{$title.margin.left}"
            font-size="17pt"
            font-weight="bold"
            font-family="{$title.font.family}">
    <xsl:call-template name="component.title">
      <xsl:with-param name="node" select="ancestor-or-self::chapter[1]"/>
    </xsl:call-template>
  </fo:block>
</xsl:template>

<xsl:template match="title" mode="chapter.titlepage.verso.auto.mode">
  <fo:block xmlns:fo="http://www.w3.org/1999/XSL/Format"
            xsl:use-attribute-sets="chapter.titlepage.recto.style"
            margin-left="{$title.margin.left}"
            font-size="17pt"
            font-weight="bold"
            font-family="{$title.font.family}">
    <xsl:call-template name="component.title">
      <xsl:with-param name="node" select="ancestor-or-self::chapter[1]"/>
    </xsl:call-template>
  </fo:block>
</xsl:template>


<!-- This provides a hard pagebreak mechanism as a get-out -->

<xsl:template match="processing-instruction('hard-pagebreak')">
  <fo:block xmlns:fo="http://www.w3.org/1999/XSL/Format" break-before='page'>
  </fo:block>
</xsl:template>


<!-- Sort out the footer. Useful information is available at
http://www.sagehill.net/docbookxsl/PrintHeaders.html
-->


<xsl:attribute-set name="footer.content.properties">
  <!-- <xsl:attribute name="font-family">serif</xsl:attribute> -->
  <!-- <xsl:attribute name="font-size">9pt</xsl:attribute> -->
  <xsl:attribute name="font-style">italic</xsl:attribute>
</xsl:attribute-set>


<!-- Things that can be inserted into the footer are:

<fo:page-number/>
Inserts the current page number.

<xsl:apply-templates select="." mode="title.markup"/>
Inserts the title of the current chapter, appendix, or other component.

<xsl:apply-templates select="." mode="titleabbrev.markup"/>
Inserts the titleabbrev of the current chapter, appendix, or other component,
if it is available. Otherwise it inserts the regular title.

<xsl:apply-templates select="." mode="object.title.markup"/>
Inserts the chapter title with chapter number label. Likewise for appendices.

<fo:retrieve-marker ... />      Used to retrieve the current section name.

<xsl:apply-templates select="//corpauthor[1]"/>
Inserts the value of the first corpauthor element found anywhere in the
document.

<xsl:call-template name="datetime.format">
  <xsl:with-param ...
Inserts a date timestamp.

<xsl:call-template name="draft.text"/>
Inserts the Draft message if draft.mode is currently on.

<fo:external-graphic ... />
Inserts a graphical image.
See the section Graphic in header or footer for details.
-->


<xsl:template name="footer.content">
  <xsl:param name="pageclass" select="''"/>
  <xsl:param name="sequence" select="''"/>
  <xsl:param name="position" select="''"/>
  <xsl:param name="gentext-key" select="''"/>

  <fo:block>
    <!-- pageclass can be front, body, back -->
    <!-- sequence can be odd, even, first, blank -->
    <!-- position can be left, center, right -->
    <xsl:choose>
      <xsl:when test="$pageclass = 'titlepage'">
        <!-- nop; no footer on title pages -->
      </xsl:when>

      <xsl:when test="$double.sided != 0 and $sequence = 'even'
                      and $position='left'">
        <fo:page-number/>
      </xsl:when>

      <xsl:when test="$double.sided != 0 and ($sequence = 'odd' or $sequence = 'first')
                      and $position='right'">
        <fo:page-number/>
      </xsl:when>

      <xsl:when test="$double.sided = 0 and $position='center'">
        <fo:page-number/>
      </xsl:when>

      <xsl:when test="$double.sided = 0 and $position='right'">
        <xsl:apply-templates select="." mode="titleabbrev.markup"/>
      </xsl:when>

      <xsl:when test="$sequence='blank'">
        <xsl:choose>
          <xsl:when test="$double.sided != 0 and $position = 'left'">
            <fo:page-number/>
          </xsl:when>
          <xsl:when test="$double.sided = 0 and $position = 'center'">
            <fo:page-number/>
          </xsl:when>
          <xsl:otherwise>
            <!-- nop -->
          </xsl:otherwise>
        </xsl:choose>
      </xsl:when>

      <xsl:otherwise>
        <!-- nop -->
      </xsl:otherwise>
    </xsl:choose>
  </fo:block>
</xsl:template>

</xsl:stylesheet>

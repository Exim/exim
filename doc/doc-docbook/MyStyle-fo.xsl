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

<!-- Let's have whatever fop extensions there are -->

<xsl:param name="fop.extensions" select="1"></xsl:param>

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


<!-- The default cell widths make the centre one too large -->

<xsl:param name="footer.column.widths">4 1 4</xsl:param>


<!-- Put the abbreviated chapter titles in running feet, and add the chapter
number afterwards in parentheses. I changed title.markup to titleabbrev.markup,
and added some lines.
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

      <!-- This clause added by PH -->
      <xsl:when test="$double.sided = 0 and $position='right' and $pageclass='body'">
        <xsl:apply-templates select="." mode="titleabbrev.markup"/>
          <xsl:text> (</xsl:text>
          <xsl:apply-templates select="." mode="label.markup"/>
          <xsl:text>)</xsl:text>
      </xsl:when>

      <!-- Changed title.markup to titleabbrev.markup for TOC -->
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


<!-- Arrange for ordered list numbers to be in parentheses instead of just
followed by a dot, which I don't like. Unfortunately, this styling is
output-specific, so we have to do it separately for FO and HTML output. -->

<xsl:param name="orderedlist.label.width" select="'2.0em'"></xsl:param>

<xsl:attribute-set name="orderedlist.label.properties">
  <xsl:attribute name="text-align">left</xsl:attribute>
</xsl:attribute-set>

<xsl:template match="orderedlist/listitem" mode="item-number">
  <xsl:variable name="numeration">
    <xsl:call-template name="list.numeration">
      <xsl:with-param name="node" select="parent::orderedlist"/>
    </xsl:call-template>
  </xsl:variable>

  <xsl:variable name="type">
    <xsl:choose>
      <xsl:when test="$numeration='arabic'">(1)</xsl:when>
      <xsl:when test="$numeration='loweralpha'">(a)</xsl:when>
      <xsl:when test="$numeration='lowerroman'">(i)</xsl:when>
      <xsl:when test="$numeration='upperalpha'">(A)</xsl:when>
      <xsl:when test="$numeration='upperroman'">(I)</xsl:when>
      <!-- What!? This should never happen -->
      <xsl:otherwise>
        <xsl:message>
          <xsl:text>Unexpected numeration: </xsl:text>
          <xsl:value-of select="$numeration"/>
        </xsl:message>
        <xsl:value-of select="1."/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>

  <xsl:variable name="item-number">
    <xsl:call-template name="orderedlist-item-number"/>
  </xsl:variable>

  <xsl:if test="parent::orderedlist/@inheritnum='inherit'
                and ancestor::listitem[parent::orderedlist]">
    <xsl:apply-templates select="ancestor::listitem[parent::orderedlist][1]"
                         mode="item-number"/>
  </xsl:if>

  <xsl:number value="$item-number" format="{$type}"/>
</xsl:template>

</xsl:stylesheet>

<?xml version="1.0" encoding="ISO-8859-1"?>
<!--
   Copyright (c) 2009-2010, Fortylines LLC
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:
     * Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
     * Neither the name of fortylines nor the
       names of its contributors may be used to endorse or promote products
       derived from this software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY Fortylines LLC ''AS IS'' AND ANY
   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL Fortylines LLC BE LIABLE FOR ANY
   DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<!-- This xsl is used to display the result of running "dws build"
     in a nicely formatted HTML table. -->

<xsl:template match="book">
  <!-- Title of the page  -->

  <table border="1" cellspacing="0" cellpadding="0">
    <tr>
      <th align="left">status</th>
      <th align="left">name</th>     
    </tr>
    <xsl:for-each select="//section">
      <tr>
	<!-- print status of building the project -->
        <td>
	  <b>
	    <xsl:for-each select="status">
	      <xsl:choose>
	      <xsl:when test="@error > 0">		
		<a>
		  <xsl:attribute name="style">color: red</xsl:attribute>
		  <xsl:attribute name="href">#<xsl:value-of select="../@id"/>
		  </xsl:attribute>
		  <xsl:value-of select="."/>
		</a>
	      </xsl:when>
	      <xsl:otherwise>
		<xsl:value-of select="."/>
	      </xsl:otherwise>
	      </xsl:choose>
	    </xsl:for-each>
	  </b>
	</td>
	<!-- print name and short description of the project -->
        <td>
	    <xsl:value-of select="@id"/>
        </td>        
      </tr>
    </xsl:for-each>
  </table>

  <!-- display log output for project with errors -->      
  <xsl:for-each select="//section">
    <xsl:for-each select="status">
      <xsl:if test="@error > 0">
	<a><xsl:attribute name="name"><xsl:value-of select="../@id"/>
	    </xsl:attribute>
	</a>
	<h2><xsl:value-of select="../@id"/> errors</h2>
	<pre class="output">
	  <xsl:value-of select=".."/>
	</pre>     
      </xsl:if>
    </xsl:for-each>
  </xsl:for-each>

</xsl:template>


</xsl:stylesheet>

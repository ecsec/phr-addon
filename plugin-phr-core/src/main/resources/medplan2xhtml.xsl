<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns="http://www.w3.org/1999/xhtml"
    xmlns:p="urn:hl7-org:v3"
    exclude-result-prefixes="p">

	<xsl:output method="html" doctype-public="-//W3C//DTD XHTML 1.0 Strict//EN"
	    doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd" omit-xml-declaration="yes" indent="yes"/>

	<xsl:template match="p:ClinicalDocument">
	    <html xmlns="http://www.w3.org/1999/xhtml">
		<head>
		    <title><xsl:value-of select="p:title" /></title>
		    <style type="text/css">
			tr.d0 td {
				background-color: #DDDDDD; color: black;
			}
			tr.d1 td {
				background-color: #BBBBBB; color: black;
			}
			h1 { color:#CC3333; font-size:20pt; }
			table, th, td
			{
			border: 1px solid black;
			}
			table
			{
			border: 2px solid black;
			border-collapse:collapse;
			}
			table.myclass {
			display: inline-block; 
			margin: 20px;
			border:2px solid;
			width: 40%;
			}
			table.myclass td{
			border: 0px solid black;
			}
			table.myclass th{
			border: 0px;
			border-bottom: 2px solid black;
			width: 200%;
			}
		    </style>
		</head>
		<body style="font-family:Verdana; font-size:12pt">
		    <h1 align="center"><xsl:value-of select="p:title" /></h1>
		    <div style="width: 896px; border: 0px solid green; border-top: 2px solid black; margin-left: auto ; margin-right: auto ;" >

			<table class="myclass" cellpadding="5" style=" float: left; margin-left: 0px ; margin-right: auto ;">
			    <thead>
				<tr>
				    <th colspan="2">Patient</th>
				</tr>
			    </thead>
			    <tbody align="left" >
				<tr>
				    <td>Vorname:</td>
				    <td><xsl:value-of select="p:recordTarget/p:patientRole/p:patient/p:name/p:given" /></td>
				</tr>
				<tr>
				    <td>Nachname:</td>
				    <td><xsl:value-of select="p:recordTarget/p:patientRole/p:patient/p:name/p:family" /></td>
				</tr>
				<tr>
				    <td>Geschlecht:</td>
				    <td><xsl:value-of select="p:recordTarget/p:patientRole/p:patient/p:administrativeGenderCode/@displayName" /></td>
				</tr>
				<tr>
				    <td>Geburtsdatum:</td>
				    <td>
					<xsl:call-template name="formatdate">
					    <xsl:with-param name="DateTimeStr" select="p:recordTarget/p:patientRole/p:patient/p:birthTime/@value"/>
					</xsl:call-template>
				    </td>
				</tr>
			    </tbody>
			</table>

			<table class="myclass" cellpadding="5" style="float: right; margin-left: auto ; margin-right: 0px ;">
			    <thead>
				<tr>
				    <th colspan="2">Autor</th>
				</tr>
			    </thead>
			    <tbody align="left">
				<tr>
				    <td>Titel:</td>
				    <td><xsl:value-of select="p:author/p:assignedAuthor/p:assignedPerson/p:name/p:prefix" /></td>
				</tr>
				<tr>
				    <td>Vorname:</td>
				    <td><xsl:value-of select="p:author/p:assignedAuthor/p:assignedPerson/p:name/p:given" /></td>
				</tr>
				<tr>
				    <td>Nachname:</td>
				    <td><xsl:value-of select="p:author/p:assignedAuthor/p:assignedPerson/p:name/p:family" /></td>
				</tr>
				<tr>
				    <td>Berufsbezeichnung:</td>
				    <td><xsl:value-of select="p:author/p:functionCode/@displayName" /></td>
				</tr>
			    </tbody>
			</table>

		    </div>
		<xsl:apply-templates/> 
		</body>
	    </html>
	</xsl:template>

	<xsl:template match="p:component">
	    <xsl:apply-templates/> 
	</xsl:template>

	<xsl:template match="p:structuredBody">
	    <xsl:apply-templates/> 
	</xsl:template>

	<xsl:template match="p:section">
	    <xsl:apply-templates/> 
	</xsl:template>

	<xsl:template match="p:text">
	    <xsl:apply-templates/> 
	</xsl:template>


	<xsl:template match="p:table">
	    <table cellspacing="0" cellpadding="5" align="center" style="width: 896px">
		<xsl:apply-templates/> 
	     </table>
	</xsl:template>

	<xsl:template match="p:thead">
	    <xsl:element name="{local-name()}">
		<xsl:apply-templates/>
	    </xsl:element>
	</xsl:template>

	<xsl:template match="p:tbody">
	    <xsl:element name="{local-name()}">
		<xsl:apply-templates/> 
	    </xsl:element>
	</xsl:template>

	<xsl:template match="p:tr">
	    <xsl:element name="{local-name()}">
		<xsl:attribute name="class">     
		    <xsl:if test="(position() mod 4) = 2">
			<xsl:text>d0</xsl:text>
		    </xsl:if>
		    <xsl:if test="not((position() mod 4) = 2)">
			<xsl:text>d1</xsl:text>
		    </xsl:if>
		</xsl:attribute> 
		<xsl:apply-templates/> 
	    </xsl:element>
	</xsl:template>

	<xsl:template match="p:th">
	    <xsl:element name="{local-name()}">
		<xsl:for-each select="@*">
		    <!-- remove attribute prefix (if any) -->
		    <xsl:attribute name="{local-name()}">
			<xsl:value-of select="." />
		    </xsl:attribute>
		</xsl:for-each>
		<xsl:attribute name="style">     
		    <xsl:text>background-color: #CC3333;</xsl:text>
		</xsl:attribute> 
		<xsl:copy-of select="node()"/>
	    </xsl:element>
	</xsl:template>

	<xsl:template match="p:td">
	    <xsl:element name="{local-name()}">
		    <xsl:variable name="txt" select="." />
		    <xsl:if test="$txt = '55561003'">
			<xsl:text>Aktiv</xsl:text>
		    </xsl:if>
		    <xsl:if test="not($txt = '55561003')">
			<xsl:if test="not(starts-with($txt, '20'))">
			    <xsl:copy-of select="node()"/>
			</xsl:if>
			<xsl:if test="starts-with($txt, '20')">
			    <xsl:call-template name="formatdate">
				<xsl:with-param name="DateTimeStr" select="node()"/>
			    </xsl:call-template>
			</xsl:if>
		    </xsl:if>
	    </xsl:element>
	</xsl:template>

	<xsl:template match="*">
	    <!-- uncomment the following line to see which elements have not yet been matched -->
	    <!--<p>WARNING: Unmatched element: <xsl:value-of select="name()"/></p>-->
	</xsl:template> 

	<xsl:template name="formatdate">
	     <xsl:param name="DateTimeStr" />

	     <xsl:variable name="datestr">
		 <xsl:value-of select="$DateTimeStr" />
	     </xsl:variable>

	     <xsl:variable name="mm">
		 <xsl:value-of select="substring($datestr,7,2)" />
	     </xsl:variable>

	     <xsl:variable name="dd">
		<xsl:value-of select="substring($datestr,5,2)" />
	     </xsl:variable>

	     <xsl:variable name="yyyy">
		<xsl:value-of select="substring($datestr,1,4)" />
	     </xsl:variable>

	     <xsl:value-of select="concat($mm,'.', $dd, '.', $yyyy)" />
	</xsl:template>

</xsl:stylesheet>

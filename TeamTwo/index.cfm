<!--- gather CVE's from CISA and create killer CFcharts. 
The information can be compared to any organizations software stack and specific CVE's can be highlighted/retrieved for internal risk programs. 
We are doing some new cool charts with the data for this example. 

I am old school and prefer using CF tags instead of script but use CFscript on occasion. application.cfc and other CFC's could be used but not necessary as everything is processed here. --->	

<!---!DOCTYPE html---> <!--- BUG: Cannot use DOCTYPE HTML with CFCharts that are also HTML and the charts will not render. --->
<html lang="en">
<head>
	<title>(B.C.W.H.S.) Black Cat White Hat Security L.L.C. - CISA CVE Vulnerabilites</title>
</head>

<cfoutput>
<!--- local URL parameters --->
<cfparam name="url.monitorView" default="Adobe"><!--- Org CVE filter list and lets default with Adobe --->
<!--- local variables --->
<cfset variables.cfhttpError = 0> <!--- did we connect okay? --->
<cfset variables.getResult = ""> <!--- deserialize variable --->
<cfset variables.knownRansomwareCampaignUseKnownCount = 0> <!--- known vulnerability count --->
<cfset variables.knownRansomwareCampaignUseUnKnownCount = 0> <!--- unknown vulnerability count --->
<cfset variables.knownRansomwareCampaignUseUnKnownCountCF = 0> <!--- known CF vulnerability count --->
<cfset variables.knownRansomwareCampaignUseKnownCountCF = 0> <!--- unknown CF vulnerability count --->
<cfset variables.ColdFusion = 0> <!--- CF vulnerability count --->
<cfset variables.Adobe = 0> <!--- Adobe vulnerability count --->
<cfset variables.vendorCount = 1> <!--- Vendor count --->
<cfset variables.vendorList = ""> <!--- unique Vendor list --->
<cfset variables.vendorListAll = ""> <!--- all Vendor list --->
<cfset variables.productList = ""> <!--- unique product list --->
<cfset variables.productListAll = ""> <!--- all product list --->
<cfset variables.productCount = 1> <!--- Product count --->
<cfset variables.rowList = 0> <!--- set a few more variables for the unique org --->

<body style="background-color: ##243E50; color: ##ffffff; font-family: Verdana">

	<a href="https://bcwhs.com" target="_blank"><img src="images/bcwhsTitle.png" width="1000" height="216" style="border-radius: 10px; border: 3px ridge ##974146; display: block; margin-left: auto; margin-right: auto"></a>
	
	<!--- Call the JSON file containing the vulnerabilites from CISA, maybe you need Proxy parameters if the connection fails. --->
	<cftry>
		<cfhttp url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" method="get" result="Results" timeout="999" throwOnError="yes"> <!--- add a 1 after .json to break the connection for CFCATCH test. --->
    		<cfhttpparam type="header" name="Accept" value="application/json" >
    		<cfhttpparam type="header" name="Content-Type" value="application/json" >
		</cfhttp>
		<cfcatch type="COM.Allaire.ColdFusion.HTTPNotFound">
			<!--- set the error variable as a connection error occurred - not found.--->
            <h1 style="font-size: 23pt; text-align: center">Current CISA Catalog of Known Exploited Vulnerabilities Dashboard: Error</h1>
            <div style="border-radius: 10px; width: 99%; padding: 8px; margin-left: auto; margin-right: auto; margin-top: 0px; min-height: 100px; background-color: ##36454f; border: 3px ridge ##ED8B00;">	
				HTTPNotFound - There was an error connecting to CISA. Please check to see if there is an issue with the connection to the JSON file.
			</div>
			<!--- stop processing due to error --->
			<cfabort> 
    	</cfcatch>
    	<cfcatch type="COM.Allaire.ColdFusion.HTTPFailure">
			<!--- set the error variable as a connection error occurred. http failure due to proxy? --->
            <h1 style="font-size: 23pt; text-align: center">Current CISA Catalog of Known Exploited Vulnerabilities Dashboard: Error</h1>
            <div style="border-radius: 10px; width: 99%; padding: 8px; margin-left: auto; margin-right: auto; margin-top: 0px; min-height: 100px; background-color: ##36454f; border: 3px ridge ##ED8B00;">	
				HTTPFailure - There was an error connecting to CISA. Please check if you have a proxy set to access outside your workplace network. Add the appropriate code to the CFHTTP call.<br>
				proxyServer = "host name", proxyPort = "port number". proxyUser = "username", proxyPassword = "password"
			</div>
			<!--- stop processing due to error --->
			<cfabort> 
    	</cfcatch>
    	<cfcatch type="any">
			<!--- set the error variable as a connection error occurred of any other type.--->
            <h1 style="font-size: 23pt; text-align: center">Current CISA Catalog of Known Exploited Vulnerabilities Dashboard: Error</h1>
            <div style="border-radius: 10px; width: 99%; padding: 8px; margin-left: auto; margin-right: auto; margin-top: 0px; min-height: 100px; background-color: ##36454f; border: 3px ridge ##ED8B00;">	
				There was an general error connecting to CISA CVE JSON file. Please check the code, network connection or try again later.
			</div>
			<!--- stop processing due to error --->
			<cfabort> 
    	</cfcatch>
	</cftry>	

	<!--- deserialize the cfhttp results, and one to a query displaying new funtionality. --->
	<cfset variables.getResult = deserializeJSON(Results.filecontent)>
	<cfset variables.getResultQuery = deserializeJSON(Results.filecontent, "query")>
		
	<!--- loop over the JSON data to create datasets based on CVE information, do we care about storing data? We can do so here but this is a catch and display. We will capture using CSVWrite. --->
	<cfloop from="1" to="#arraylen(variables.getResult.vulnerabilities)#" index="i">
			
		<!--- simple count to tally up the known vs unknown ransomware --->
		<cfif variables.getResult.vulnerabilities[i].knownRansomwareCampaignUse eq "Known">
			<cfset variables.knownRansomwareCampaignUseKnownCount += 1>
		<cfelse>
			<cfset variables.knownRansomwareCampaignUseUnKnownCount += 1>
		</cfif>
		
		<!--- simple count to tally up or down the CF Vulnerabilities --->
		<cfif variables.getResult.vulnerabilities[i].product eq "ColdFusion">
			<cfset variables.ColdFusion += 1>
			<cfif variables.getResult.vulnerabilities[i].knownRansomwareCampaignUse eq "Known">
				<cfset variables.knownRansomwareCampaignUseKnownCountCF += 1> <!--- add to CF's known vulnerability --->
				<cfset variables.knownRansomwareCampaignUseKnownCount -= 1> <!--- Take one away from the known total --->
			<cfelse>
				<cfset variables.knownRansomwareCampaignUseUnKnownCountCF += 1> <!--- add to CF's unknown vulnerability --->
				<cfset variables.knownRansomwareCampaignUseUnKnownCount -= 1> <!--- Take one away from the unknown total --->
			</cfif>
		</cfif>
		
		<!--- simple count to tally up the Adobe Vulnerabilities --->
		<cfif variables.getResult.vulnerabilities[i].vendorProject eq "Adobe">
			<cfset variables.Adobe += 1>
		</cfif>
		
		<!--- populate a list of unique vendors. Could expand into array of structure but keep it simple for now. --->
		<cfif ListFind(variables.vendorList, "#variables.getResult.vulnerabilities[i].vendorProject#") eq 0>
		    <cfset variables.vendorList = listAppend(variables.vendorList, "#variables.getResult.vulnerabilities[i].vendorProject#",",")>
		</cfif> 
		<!--- populate a list of vendors for counts --->
		<cfset variables.vendorListAll = listAppend(variables.vendorListAll, "#variables.getResult.vulnerabilities[i].vendorProject#",",")>		
	</cfloop>
	
	<!--- 5 animation and 2 donut set in CFScript. Also using JSON to Query to CSV Write & Read--->
	<cfscript>
    	"animationPie"={
            "effect"=7,
            "delay"=1,
            "animate"=TRUE
    	}
    	"animationLine"={
            "effect"=3,
            "delay"=2,
            "animate"=TRUE
    	}
    	"animationDonut"={
            "effect"=5,
            "delay"=3,
            "animate"=TRUE
    	}
    	"animationDonut2"={
            "effect"=6,
            "delay"=2,
            "animate"=TRUE
    	}
    	"animationfbar"={
            "effect"=4,
            "delay"=1,
            "animate"=TRUE
    	}
    	"scaleR"={
    		"refAngle":0,
    		"aperture":360
    	}
    	theFile = GetDirectoryFromPath(GetCurrentTemplatePath()) & "CISA_CVE_All.csv"; 
    	CSVWrite(#variables.getResultQuery.vulnerabilities#,"query",#theFile#); 
    	 
    	csvCISA = CSVRead(filepath=#theFile#,outputformat="query");
	</cfscript>

	<!--- display the charts. Top row is pie chart with the same animation and theme. Using old school tables for easier view for this example, but can make it more dynamic for mobile, etc--->
	<h1 style="font-size: 23pt; text-align: center">Current CISA Catalog of Known Exploited Vulnerabilities Dashboard <br>(Total Vulnerabilities: #arraylen(variables.getResult.vulnerabilities)#)</h1>
	<div style="border-radius: 10px; width: 99%; padding: 0px; margin-left: auto; margin-right: auto; margin-top: 0px; min-height: 800px; background-color: ##36454f; border: 3px ridge ##ED8B00;">		
		<table border="0" cellpadding="0" cellspacing="0" width="100%" style="color: ##ffffff">
			<tr>
				<td colspan="3" style="color:##ffffff; border-radius: 10px 10px 0px 0px; background-color: ##2b2b2b; padding: 10px">
					<!--- download the generated CSV file, if you like. --->
					<a href="CISA_CVE_All.csv" style="color:##ffffff">Download: CISA CVE Complete CSV Generated File (CSVWrite)</a>
				</td>
			</tr>
			<tr>
				<Td valign="top" align="center" colspan="3">
					 <h2 style="text-align: left">CVEs for ColdFusion / Adobe (JSON Data)</h2>
				</td>
			</tR>
			<!--- This would be good for CFChartSet but it looks better using the current format.  
			<tr>
				<Td colspan=3 align="center">
					<cfchartset format="html" layout="1x3" height="350" width="1700" name="Pie Charts">  
						<!--- Known vs Unknown ransomware campaign for vulnerability --->
						<cfchart backgroundcolor="##36454f" format="html" type="pie" pieslicestyle="sliced" chartWidth="500" chartHeight="325" theme="spectrum_dark" title="Total ColdFusion Campaign Ransomware: Pie">
							<cfchartseries animate="#animationPie#">
					        	<cfchartdata item="Known (#variables.knownRansomwareCampaignUseKnownCount#)" value="#variables.knownRansomwareCampaignUseKnownCount#">
        						<cfchartdata item="UnKnown (#variables.knownRansomwareCampaignUseUnKnownCount#)" value="#variables.knownRansomwareCampaignUseUnKnownCount#">
        					 	<cfchartdata item="ColdFusion (K) (#variables.knownRansomwareCampaignUseKnownCountCF#)" value="#variables.knownRansomwareCampaignUseKnownCountCF#">
        					 	<cfchartdata item="ColdFusion (U) (#variables.knownRansomwareCampaignUseUnKnownCountCF#)" value="#variables.knownRansomwareCampaignUseUnKnownCountCF#">
        					</cfchartseries>
						</cfchart>
						<!--- CF vulnerabilities --->
						<cfset variables.remainingCVE = arraylen(variables.getResult.vulnerabilities) - variables.ColdFusion>
						<cfchart backgroundcolor="##36454f" format="html" type="pie" pieslicestyle="sliced" chartWidth="500" chartHeight="325" theme="spectrum_dark" title="Total ColdFusion Vulnerabilites: Pie">
						 	<cfchartseries animate="#animationPie#">
					         	<cfchartdata item="ColdFusion (#variables.ColdFusion#)" value="#variables.ColdFusion#">
        					 	<cfchartdata item="OTHER (#variables.remainingCVE#)" value="#variables.remainingCVE#">
        					</cfchartseries>
						</cfchart>
						<!--- Adobe vulnerabilities --->
						<cfset variables.remainingCVE = arraylen(variables.getResult.vulnerabilities) - variables.adobe>
					
						<cfchart backgroundcolor="##36454f" format="html" type="pie" pieslicestyle="sliced" chartWidth="500" chartHeight="325" theme="spectrum_dark" title="Total Adobe Vulnerabilites: Pie">
						 	<cfchartseries animate="#animationPie#">
					         	<cfchartdata item="Adobe (#variables.adobe#)" value="#variables.adobe#">
        					 	<cfchartdata item="OTHER (#variables.remainingCVE#)" value="#variables.remainingCVE#">
        					</cfchartseries>
						</cfchart>
					</cfchartset> 
				</Td>
			</tr---> 
			<tr >
				<Td valign="top" align="center" width="33%">
					<!--- Known vs Unknown ransomware campaign for vulnerability --->
					<cfchart backgroundcolor="##36454f" format="html" type="pie" pieslicestyle="sliced" chartWidth="500" chartHeight="325" theme="spectrum_dark" title="Total ColdFusion Campaign Ransomware: Pie">
						 <cfchartseries animate="#animationPie#">
					         <cfchartdata item="Known (#variables.knownRansomwareCampaignUseKnownCount#)" value="#variables.knownRansomwareCampaignUseKnownCount#">
        					 <cfchartdata item="UnKnown (#variables.knownRansomwareCampaignUseUnKnownCount#)" value="#variables.knownRansomwareCampaignUseUnKnownCount#">
        					 <cfchartdata item="ColdFusion (K) (#variables.knownRansomwareCampaignUseKnownCountCF#)" value="#variables.knownRansomwareCampaignUseKnownCountCF#">
        					 <cfchartdata item="ColdFusion (U) (#variables.knownRansomwareCampaignUseUnKnownCountCF#)" value="#variables.knownRansomwareCampaignUseUnKnownCountCF#">
        				</cfchartseries>
					</cfchart>
				</Td>
				<Td valign="top" align="center" width="33%">
					<!--- CF vulnerabilities --->
					<cfset variables.remainingCVECF = arraylen(variables.getResult.vulnerabilities) - variables.ColdFusion>
					
					<cfchart backgroundcolor="##36454f" format="html" type="pie" pieslicestyle="sliced" chartWidth="500" chartHeight="325" theme="spectrum_dark" title="Total ColdFusion Vulnerabilites: Pie">
						 <cfchartseries animate="#animationPie#">
					         <cfchartdata item="ColdFusion (#variables.ColdFusion#)" value="#variables.ColdFusion#">
        					 <cfchartdata item="OTHER (#variables.remainingCVECF#)" value="#variables.remainingCVECF#">
        				</cfchartseries>
					</cfchart>
				</td>
				<Td valign="top" align="center" width="33%">
					<!--- Adobe vulnerabilities --->
					<cfset variables.remainingCVE = arraylen(variables.getResult.vulnerabilities) - variables.adobe>
					
					<cfchart backgroundcolor="##36454f" format="html" type="pie" pieslicestyle="sliced" chartWidth="500" chartHeight="325" theme="spectrum_dark" title="Total Adobe Vulnerabilites: Pie">
						 <cfchartseries animate="#animationPie#">
					         <cfchartdata item="Adobe (#variables.adobe#)" value="#variables.adobe#">
        					 <cfchartdata item="OTHER (#variables.remainingCVE#)" value="#variables.remainingCVE#">
        				</cfchartseries>
					</cfchart>
				</td>
			</tr>
			<!--- display the line chart. Next row is line chart with a different animation speed and theme. The slow speed allows the top to render, then move lower into the page. --->
			<tr>
				<td colspan="3" style="background-color: ##23506E; padding: 8px; margin-bottom: 25px" align="center">
					<h2 style="text-align: left">CVE List All (JSON Data)</h2>
					
					<cfset variables.vendorListSorted = ListSort(variables.vendorList,"Text")> <!--- do it once and use it here and the donut chart --->
					<cfset variables.myStructView = {"item"={"font-angle"=-45}}> <!--- rotate the x-axis labels --->
					
					<cfchart backgroundcolor="##23506E" format="html" type="line" showLegend="false" chartWidth="1800" chartHeight="400" theme="dawn_dark" title="All Vendor Vulnerability Count: Line" xAxis="#variables.myStructView#">
						<cfchartseries animate="#animationLine#" >
							<cfloop list="#variables.vendorListSorted#" index="vendor">
								<cfset variables.vendorCount = ListValueCount(variables.vendorListAll,"#vendor#",",")>
								<cfif variables.vendorCount gt 5> <!--- Do not show the smaller number vendors to save space in the chart for this example. Can view all vendors later. --->
									<cfchartdata item="#vendor# (#variables.vendorCount#)" value="#variables.vendorCount#">
								</cfif>
							</cfloop>
						</cfchartseries>
					</cfchart>
				</td>
			</tr>
			<!--- display the new donut charts using the same all vendor list and vulnerabilities --->
			<tr>
			<td colspan="3" align="center" >
				<p style="margin-top: 20px;">	
					<!--- themes don't render very well with Donut, so we will keep it a normal but animated chart --->
					<cfchart backgroundcolor="##6F8390" format="html" scaleR="#scaleR#" showLegend="false" chartWidth="1000" chartHeight="600" title="All Vendor Vulnerability Count: Donut">
						<cfchartseries type="ring" serieslabel="Vulnerability Count" animate="#animationDonut#" >
        					<cfloop list="#variables.vendorListSorted#" index="vendor">
								<cfset variables.vendorCount = ListValueCount(variables.vendorListAll,"#vendor#",",")>
								<cfif variables.vendorCount gte 5> <!--- Do not show the smaller number vendors to save space in the chart for this example. Can view all vendors later. --->
									<cfchartdata item="#vendor# (#variables.vendorCount#)" value="#variables.vendorCount#">
								</cfif>
							</cfloop>
    					</cfchartseries>
					</cfchart>
				</p>
				</td>
			</tr>
			<tr>
				<td colspan="3" align="center">
					<h2 style="text-align: left">ALL CVEs (CSVRead Data)</h2>
					<div style="width: 98%; background-color: ##2b2b2b; border: 3px solid ##4297CF; border-radius: 10px; padding: 5px; overflow-y: scroll; min-height: 200px; max-height: 300px; margin-bottom: 20px">
			
						<table id="CVE" border="0" cellpadding="0" cellspacing="0" width="100%" style="color: ##ffffff; ">
							<tr bgcolor="##B68304" style="color:##ffffff">
								<td valign="top" width="10%">
									CVE Name
								</td>
								<td valign="top" width="10%">
									Ransomeware
								</td>
								<td valign="top" width="20%">
									Product
								</td>
								<td valign="top" width="30%">
									Vulnerability Name
								</td>
								<td valign="top" width="20%">
									Vendor
								</td>
								<td valign="top" width="10%">
									Date Added
								</td>
							</tr>
							<!--- lets go through the CSVRead Query for all the vulnerabilities. No header values so using default variable names. --->
							<cfloop query="#csvCISA#">
								<tr style="color: ##ffffff" <cfif currentRow MOD 2 EQ 0>bgcolor="##374C5B"</cfif>>
									<td>#csvCISA.col_4#</td>
									<td>#csvCISA.col_7#</td>
									<td>#csvCISA.col_6#</td>
									<td>#csvCISA.col_3#</td>
									<td>#csvCISA.col_1#</td>
									<td>#dateformat(csvCISA.col_5, "mm/dd/yyyy")#</td>
								</tr>
							</cfloop>
						</table>
					</div>
				</td>
			</tr>
		</table>
		<!--- end of the overall basic information charts. Lets filter it down to individual vendor. --->
	</div>
	<div style="border-radius: 10px; width: 99%; padding: 8px; margin-left: auto; margin-right: auto; margin-top: 50px; min-height: 800px; background-color: ##36454f; border: 3px ridge ##b0c4de;">		
		
		<!--- display the DeserializeJSON to a Query data in a scrolling window and view by selectable by Vendor--->
		<script type="text/javascript">
			function gotopage(selval){
			var value = selval.options[selval.selectedIndex].value;
			window.location.href= "/bcwhs/index.cfm?monitorView=" + value + "##CVE";
			}
		</script>
		
		<h2>#url.monitorView# CVE List (JSON->Query)</h2>
		<form id="formID" method="post" action="#cgi.script_name#" >
			Choose Vendor View: <select onchange="gotopage(this)">
				<cfloop list="#variables.vendorListSorted#" index="vendor">
					<option value="#vendor#" <cfif url.monitorView eq vendor>selected</cfif>>#vendor#</option>
				</cfloop>
			</select>
		</form>
		
		<div style="background-color: ##2b2b2b; border: 3px solid ##4297CF; border-radius: 10px; padding: 5px; overflow-y: scroll; min-height: 200px; max-height: 350px; margin-top: 25px">
			<table id="CVE" border="0" cellpadding="0" cellspacing="0" width="100%" style="color: ##ffffff;">
				<tr bgcolor="##B68304" style="color:##ffffff">
					<td valign="top" width="10%">
						CVE Name
					</td>
					<td valign="top" width="10%">
						Ransomeware
					</td>
					<td valign="top" width="20%">
						Product
					</td>
					<td valign="top" width="30%">
						Vulnerability Name
					</td>
					<td valign="top" width="20%">
						Vendor
					</td>
					<td valign="top" width="10%">
						Date Added
					</td>
				</tr>
				<!--- lets go through the JSON as a query to build a chart. Dataset is low so a loop condition should be good. --->
				<cfloop query="#variables.getResultQuery.vulnerabilities#">
					<cfif variables.getResultQuery.vulnerabilities.vendorProject eq "#url.monitorView#">
				
					<!--- populate a list of unique products. --->
					<cfif ListFind(variables.productList, "#variables.getResultQuery.vulnerabilities.product#", "|") eq 0>
					    <cfset variables.productList = listAppend(variables.productList, "#variables.getResultQuery.vulnerabilities.product#","|")><!--- there might be more than 1 product in a stack separated by a comma, lets use | instead. --->
					</cfif> 
					<!--- populate a list of products for counts --->
					<cfset variables.productListAll = listAppend(variables.productListAll, "#variables.getResultQuery.vulnerabilities.product#","|")>
				
					<tr style="color: ##ffffff" <cfif variables.rowList MOD 2 EQ 0>bgcolor="##374C5B"</cfif>>
						<td>#variables.getResultQuery.vulnerabilities.CVEID#</td>
						<td>#variables.getResultQuery.vulnerabilities.knownRansomwareCampaignUse#</td>
						<td>#variables.getResultQuery.vulnerabilities.product#</td>
						<td>#variables.getResultQuery.vulnerabilities.vulnerabilityName#</td>
						<td>#variables.getResultQuery.vulnerabilities.vendorProject#</td>
						<td>#dateformat(variables.getResultQuery.vulnerabilities.dateAdded, "mm/dd/yyyy")#</td>
					</tr>
					<cfset variables.rowList += 1><!--- count the rows for proper bg row color --->
					</cfif>
				</cfloop>
			</table>
		</div>
		<table border="0" cellpadding="0" cellspacing="0" width="100%" style="color: ##ffffff">
			<tr >
				<Td valign="top" align="center" width="100%">
					<cfset variables.productListSorted = ListSort(variables.productList,"Text","ASC","|")> <!--- sort the product list --->
					<cfset variables.myStructViewPyramid = {"item"={"font-angle"=-45}}> <!--- rotate the x-axis labels --->
					
					<!--- lets show this data with a new pyramid chart --->
					<cfchart backgroundcolor="##36454f" format="html" type="fbar" showLegend="false" chartWidth="1800" chartHeight="600" title="#url.monitorView#: Vulnerablilites By Product Count: Floating Bar" theme="feast_dark" xAxis="#variables.myStructViewPyramid#">
						 <cfchartseries animate="#animationfbar#">
					        <cfloop list="#variables.productListSorted#" index="product" DELIMITERS="|">
					        	<Cfset variables.zValue = randrange(1,5)><!--- randomize the placement with the Z value --->
								<cfset variables.productCount = ListValueCount(variables.productListAll,"#product#","|")>
								<cfchartdata item="#product# (#variables.productCount#)" value="#variables.productCount#" zvalue="#variables.zValue#">
							</cfloop>
        				</cfchartseries>
					</cfchart>
				</td>
			</tr>
			<tr>
			<td align="center" width="100%">
				<p style="margin-top: 20px;">	
					<!--- themes don't render very well with Donut, so we will keep it a normal chart but show all products. --->
					<cfchart backgroundcolor="##6F8390" format="html" scaleR="#scaleR#" showLegend="false" chartWidth="1000" chartHeight="600" title="#url.monitorView#: Vendor Vulnerability Count: Donut">
						<cfchartseries type="ring" serieslabel="Vulnerability Count" animate="#animationDonut2#" >
        					<cfloop list="#variables.productListSorted#" index="product" DELIMITERS="|">
								<cfset variables.productCount = ListValueCount(variables.productListAll,"#product#","|")>
								<cfchartdata item="#product# (#variables.productCount#)" value="#variables.productCount#">
							</cfloop>
    					</cfchartseries>
					</cfchart>
				</p>
				</td>
			</tr>
		</table>
	</div>

	<div style="background-color: ##2b2b2b; border: 3px solid ##4297CF; border-radius: 10px; padding: 5px; min-height: 120px; margin-top: 25px">
		<p>
			We are done, Thank You!<br>
		</p>
		<p>
			<b>Local CF Server Configuration</b><br>
			ColdFusion Version: 2025.0.02.331451<br>
			Tomcat Version: 10.1.34.0<br>
			Java Version: 21.0.6<br>
		</p>
		<p>
			<b>These are the new tags/functions/enhancements being implemented (9)</b><br>
			1) Several CFCatch exception types for CFHTTP.<bR>
			2) DeserializeJSON to a Query.<br>
			3) Compound assignment operators (+=, -=).<br>
			4) CSVWrite - All CVEs in root CSV file with web link for download (JSON->Query->CSV).<br>
			5) CSVRead - Read the CSV file and output all CVEs in a query list.<br>
			6) CfChart - Animations (x5).<br>
			7) CfChart - Themes (x3).<br>
			8) CfChart - Donut (x2). <br>
			9) CfChart - Floating Bar (Random Z Value).<br>
		</p>

		<p>
			<b>Removed New Features (1)</b><br>
			1) CFChartSet - Commented out as the new themes look much better for the pie charts (Lines 165-196).
		</p>
		<p>
			<b>BCWHS Team</b>: Wade Bachelder (My LLC: BCWHS.com & Me: wadeBach.com)<br>
			<a href="https://wadebach.com" target="_blank"><img src="images/wadeBach.png" width="1012" height="207" style="border-radius: 10px; border: 3px ridge ##974146; display: block; margin-left: auto; margin-right: auto"></a>
		</p>	
	</div>
</body>
</cfoutput>
<cfoutput>

	<!doctype html>
	<html lang="en">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>
			<cfif request.page.title.len()>
				#encodeForHtml( request.page.title )# &mdash;
			</cfif>
			<!---
				Wow: I didn't know this would work ("site.name" instead of ["site.name"]).
				I tried it just on a lark, and it didn't error! Cool beans!
			--->
			#encodeForHtml( application.properties.site.name )#
		</title>
		<link
			rel="stylesheet"
			type="text/css"
			href="#application.properties.site.assetPrefix#/assets/main.css"
			nonce="#getCspNonce()#"
		/>
		<script
			type="text/javascript"
			src="#application.properties.site.assetPrefix#/assets/htmx-2.0.4.min.js"
			nonce="#getCspNonce()#">
		</script>
		<script
			type="text/javascript"
			src="#application.properties.site.assetPrefix#/assets/main.js"
			nonce="#getCspNonce()#">
		</script>
		<script type="text/javascript" nonce="#getCspNonce()#">
			htmx.config.inlineScriptNonce = "#getCspNonce()#";
			htmx.config.includeIndicatorStyles = false;
		</script>
	</head>
	<body>

		<main id="main" class="main">
			#request.page.body#
		</main>

	</body>
	</html>

</cfoutput>

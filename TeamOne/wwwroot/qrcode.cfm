<cfscript>

	include "./partials/mixins.cfm";

	// ------------------------------------------------------------------------------- //
	// ------------------------------------------------------------------------------- //

	param name="url.token" type="regex" pattern=TOKEN_PARAM_REGEX;

	imageBinary = application.barcoder
		.generateBarcode( generateRemoteUrlForBarcode( url.token ), 250, 250 )
		.binary
	;

	cfcontent(
		type = "image/png",
		variable = imageBinary
	);

</cfscript>

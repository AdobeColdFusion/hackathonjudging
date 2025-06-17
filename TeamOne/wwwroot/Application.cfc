component {

	this.name = "BenNadel.ColdFusion2025.Hackathon";
	this.applicationTimeout = createTimeSpan( 1, 0, 0, 0 );

	this.sessionManagement = false;
	this.setClientCookies = false;

	this.searchImplicitScopes = false;
	this.passArrayByReference = true;
	this.serialization = {
		preserveCaseForStructKey: true,
		preserveCaseForQueryColumn: true
	};

	this.webroot = getDirectoryFromPath( getCurrentTemplatePath() );
	this.mappings = {
		"/": this.webroot,
		"/config": "#this.webroot#config",
		"/data": "#this.webroot#data",
		"/lib": "#this.webroot#lib",
		"/partials": "#this.webroot#partials",
	};

	// Local ColdFusion custom tag look-ups.
	this.customTagPaths = "#this.mappings[ '/lib' ]#/tags";

	// This will set "Content-Security-Policy" HTTP response header automatically; and the
	// nonce token in the header will correspond to `getCspNonce()` return value.
	// --
	// Caution: this breaks CFDump - see onRequest() event handler.
	this.enableCspNonceForScript = true;

	// ---
	// LIFE-CYCLE EVENTS.
	// ---

	/**
	* I initialize the application.
	*/
	public void function onApplicationStart() {

		var properties
			= application.properties
				= getPropertyFile( expandPath( "/config/dev.properties" ) )
		;

		application.dataGateway = new lib.core.DataGateway( expandPath( "/data" ) );
		application.barcoder = new lib.core.BarCoder();

	}


	/**
	* I initialize the request.
	*/
	public void function onRequestStart() {

		if ( url.keyExists( "init" ) ) {

			onApplicationStart();

		}

		// Polyfill the Lucee CFML behavior in which "field[]" notation causes multiple
		// fields to be grouped together as an array. This is the way.
		polyfillFormFieldGrouping( form );

		// By default, we want the request timeout to be relatively low so that we lock
		// page processing down. This means that we have to make a cognizant choice to
		// create slow(er) pages later on by explicitly extending the timeout.
		cfsetting(
			requestTimeout = 5,
			showDebugOutput = false
		);

	}


	/**
	* I execute the requested script and wrap the output in a layout.
	*/
	public void function onRequest( required string scriptName ) {

		request.page = {
			body: "",
			layout: true,
			title: "",
		};

		// Since I don't have robust debugging enabled, I'm just going to wrap the
		// template in a try/catch and dump-out any error. It's just a hackathon, YOLO!
		try {

			// Build up page buffer.
			savecontent variable = "request.page.body" {
				cfmodule( template = scriptName );
			}

			// Wrap in the desired layout template.
			switch ( toString( request.page.layout ) ) {
				case "true":
				case "main":
					savecontent variable = "request.page.body" {
						cfmodule( template = "./partials/layout.cfm" );
					}
				break;
			}

		} catch ( any error ) {

			savecontent variable = "request.page.body" {
				writeOutput( request.page.body );
				writeDump( error );
			}

		}

		// HACKY WORK AROUND: Adobe ColdFusion 2025's CSP functionality is incompatible
		// with the CFDump tag (it prevents the injected inline Style and Script tags from
		// working). As such, I'm checking to see if it contains a tell-tale sign of a
		// Dump, and if so, I'm going to override the Content-Security-Policy header with
		// an overly-permissive version.
		//
		// In reality, I would remove this check in a production setting, since I would
		// never to a Dump in production, and I don't need the overhead of the buffer
		// allocation and substring inspection.
		if ( request.page.body.find( "table.cfdump_" ) ) {

			cfheader(
				name = "Content-Security-Policy",
				value = "default-src * 'unsafe-inline'"
			);

		}

		writeOutput( request.page.body );

	}

	// ---
	// PRIVATE METHODS.
	// ---

	/**
	* I polyfill the "field[]" form parameter grouping behavior in Adobe ColdFusion.
	*/
	private void function polyfillFormFieldGrouping( required struct formScope ) {

		// If the fieldNames entry isn't defined, the form scope isn't populated.
		if ( isNull( formScope.fieldNames ) ) {

			return;

		}

		// The parameter map gives us every form field as an array.
		var rawFormData = getPageContext()
			.getRequest()
			.getParameterMap()
		;

		for ( var key in rawFormData.keyArray() ) {

			if ( key.right( 2 ) == "[]" ) {

				// Remove the "[]" suffix.
				var normalizedKey = key.left( -2 );
				// The underlying Java value is of type, "string[]". We need to convert
				// that value to a native ColdFusion array (ArrayList) so that it will
				// behave like any other array, complete with member methods.
				var normalizedValue = arrayNew( 1 )
					.append( rawFormData[ key ], true )
				;

				// Swap the form scope key-value pairs with the normalized versions.
				formScope[ normalizedKey ] = normalizedValue;
				formScope.delete( key );

			}

		}

		// Clean-up list of field names (removing [] notation).
		formScope.fieldNames = formScope.fieldNames
			.reReplace( "\[\](,|$)", "\1", "all" )
		;

	}

}

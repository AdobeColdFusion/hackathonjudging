<cfscript>

	TOKEN_PARAM_REGEX = "[0-9a-fA-F-]+";

	// ------------------------------------------------------------------------------- //
	// ------------------------------------------------------------------------------- //

	/**
	* I sort the given array using the given keys (uses compareNoCase() internally).
	*/
	public array function arraySortOnKeys(
		required array elements,
		required array keys
		) {

		var operators = keys.map(
			( key ) => {

				return ( a, b ) => {

					return compareNoCase( a[ key ], b[ key ] );

				};

			}
		);

		return arraySortOnOperators( elements, ...operators );

	}


	/**
	* I sort the given array using the 2...N operators.
	*/
	public array function arraySortOnOperators(
		required array elements,
		function operator1,
		function operator2,
		function operator3,
		/* ... */
		function operatorN,
		) {

		var operators = arraySlice( arguments, 2 );

		return elements.sort(
			( a, b ) => {

				// Note: for-in will inherently skip-over any undefined operators.
				for ( var operator in operators ) {

					var result = operator( a, b );

					if ( result ) {

						return result;

					}

				}

				return 0;

			}
		);

	}


	/**
	* I calculate the CSS class attribute value based on the given conditions.
	*/
	public string function classNames( /* ...inputs */ ) {

		var inputs = arrayMap( arguments, ( element ) => element );
		var names = [];

		for ( var input in inputs ) {

			// Simple values are treated like static class names.
			if ( isSimpleValue( input ) ) {

				names.append( input );

			// Structs are treated like conditional inclusions (values are either boolean
			// or non-empty simple values).
			} else if ( isStruct( input ) ) {

				for ( var key in input ) {

					var value = input[ key ];

					if (
						( isBoolean( value ) && ! value ) ||
						( ! isBoolean( value ) && ! len( value ) )
						) {

						continue;

					}

					names.append( key );

				}

			// Arrays are processed recursively.
			} else if ( isArray( input ) ) {

				names.append( classNames( argumentCollection = input ) );

			}

		}

		return names.toList( " " );

	}


	/**
	* Shorthand for writeDump().
	*/
	public void function dump( any var ) {

		// Note: there's a bug in Adobe ColdFusion in which `var` has to be explicitly
		// provided as an argument. It can't be passed-through in the argumentCollection.
		writeDump(
			argumentCollection = arguments,
			var = arguments?.var,
		);

	}


	/**
	* Shorthand for writeOutput().
	*/
	public void function echo( any value = "" ) {

		writeOutput( value );

	}


	/**
	* Shorthand for encodeForHtmlAttribute().
	*/
	public string function efa( string value = "" ) {

		return encodeForHtmlAttribute( value );

	}


	/**
	* Shorthand for encodeForHtml().
	*/
	public string function efh( string value = "" ) {

		return encodeForHtml( value );

	}


	/**
	* Shorthand for encodeForJavaScript().
	*/
	public string function efj( string value = "" ) {

		return encodeForJavaScript( value );

	}


	/**
	* Shorthand for encodeForUrl().
	*/
	public string function efu( string value = "" ) {

		return encodeForUrl( value );

	}


	/**
	* I attempt to extract a name from the given email.
	*/
	public string function emailToName( required string email ) {

		var slug = email.listFirst( "@" );
		var name = slug
			.lcase()
			.reReplace( "[\W_]+", " " )
			.trim()
		;

		if ( ! name.len() ) {

			return slug;

		}

		return ucFirst( name );

	}


	/**
	* I iterate over the form, and combine any array-like fields into a single array of
	* objects (plucking same-indexed properties from each field).
	*/
	public array function flattenForm(
		required struct formScope,
		array keys = []
		) {

		// If no keys were passed-in, search the form for all array-like keys.
		if ( ! keys.len() ) {

			for ( var key in formScope.keyArray() ) {

				if ( isArray( formScope[ key ] ) ) {

					keys.append( key );

				}

			}

		}

		var results = [];
		var maxLength = 0;

		// Find the longest of each array-like value.
		for ( var key in keys ) {

			maxLength = max( maxLength, formScope[ key ].len() );

		}

		for ( var i = 1 ; i <= maxLength ; i++ ) {

			var element = results.append( {} ).last();

			for ( var key in keys ) {

				element[ key ] = ( formScope[ key ][ i ] ?? "" );

			}

		}

		return results;

	}


	/**
	* I filter in the elements that contain at least one populated value associated with
	* the given set of keys.
	*/
	public array function filterInPopulated(
		required array elements,
		required array keys
		) {

		return elements.filter(
			( element ) => {

				for ( var key in keys ) {

					if ( len( element[ key ] ?? "" ) ) {

						return true;

					}

				}

				return false;

			}
		);

	}


	/**
	* Shorthand for location().
	*/
	public void function goto( required string nextUrl ) {

		location( url = nextUrl, addToken = false );

	}


	/**
	* I determine if the current request is a get.
	*/
	public boolean function isGet() {

		return ! isPost();

	}


	/**
	* I generate the URL to be used with the QR code.
	*/
	public string function generateRemoteUrlForBarcode() {

		return "https://youtu.be/Aq5WXmQQooo?si=o23P02cgMG8nfygu";

	}


	/**
	* I safely get the given HTTP header.
	*/
	public string function getHeader( required string name ) {

		return ( getHttpRequestData( false ).headers[ name ] ?? "" );

	}


	/**
	* I determine if the current request is being made by HTMX.
	*/
	public boolean function isHtmx() {

		return ( getHeader( "HX-Request" ) == "true" );

	}


	/**
	* I determine if the current request is a form submission.
	*/
	public boolean function isPost() {

		return ( cgi.request_method == "post" );

	}


	/**
	* I encode the post-back URL into the form action attribute.
	*/
	public string function postBackAction() {

		return efa( postBackUrl() );

	}


	/**
	* I calculate the URL for the current request.
	*/
	public string function postBackUrl() {

		// Remove any undesirable parameters from the post-back.
		var queryString = cgi.query_string
			.reReplaceNoCase( "(&|^)(init)(=[^&]*)?", "\1", "all" )
			.reReplace( "&$", "" )
		;

		return queryString.len()
			? "#cgi.script_name#?#queryString#"
			: cgi.script_name
		;

	}


	/**
	* I upper-case the first letter after each word boundary.
	*/
	public string function ucFirst( required string value ) {

		return value
			.lcase()
			.reReplace( "(^|\b)\w", "\u\0", "all" )
		;

	}


	/**
	* I set the page title (for use in the `head` tag) and echo the value.
	*/
	public string function withTitle( required string title ) {

		request.page.title = title;

		return title;

	}

</cfscript>

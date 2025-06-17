component {

	/**
	* I initialize the properties file proxy with the given filename.
	*
	* Caution: this ColdFusion component assumes that any necessary locking is being
	* performed in the calling context.
	*/
	public void function init( required string filename ) {

		variables.filename = arguments.filename;

	}

	// ---
	// PUBLIC METHODS.
	// ---

	/**
	* I read the file contents from the given directory.
	*/
	public struct function read( required string directoryPath ) {

		var filePath = "#directoryPath#/#filename#";

		if ( ! fileExists( filePath ) ) {

			return {};

		}

		return getPropertyFile( filePath, "utf-8" );

	}


	/**
	* I write the key-value pairs to the properties file.
	*/
	public void function write(
		required string directoryPath,
		required struct properties
		) {

		var filePath = "#directoryPath#/#filename#";

		for ( var key in properties ) {

			setPropertyString( filePath, key.lcase(), properties[ key ], "utf-8" );

		}

	}

}

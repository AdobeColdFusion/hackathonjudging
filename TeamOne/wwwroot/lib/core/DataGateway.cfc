component {

	include "/partials/mixins.cfm";

	// ------------------------------------------------------------------------------- //
	// ------------------------------------------------------------------------------- //

	/**
	* I initialize the data gateway to store files in the given directory.
	*
	* Caution: this ColdFusion component assumes that any necessary locking is being
	* performed in the calling context.
	*/
	public void function init( required string dataDirectory ) {

		variables.dataDirectory = arguments.dataDirectory;

		variables.userProxy = new PropertiesFileProxy( "user.properties" );
		// For the sake of the demo, the various records for each "experience" are going
		// to be stored in an experience-specific sub-directory, which each model being
		// serialized to its own CSV file.
		variables.contactsProxy = new CsvFileProxy(
			"contacts.csv",
			[ "name", "phone", "isPrimary" ]
		);
		variables.drinksProxy = new CsvFileProxy(
			"drinks.csv",
			[ "name", "description", "isSelected" ]
		);
		variables.snacksProxy = new CsvFileProxy(
			"snacks.csv",
			[ "name", "description", "isSelected" ]
		);
		variables.mealsProxy = new CsvFileProxy(
			"meals.csv",
			[ "name", "description", "isSelected" ]
		);

	}

	// ---
	// PUBLIC METHODS.
	// ---

	/**
	* I read the data model from the experience-specific sub-folder.
	*/
	public struct function read( required string subfolderName ) {

		var subfolderDirectory = "#dataDirectory#/#subfolderName#";

		lock
			type = "readonly"
			name = subfolderDirectory
			timeout = 5
			{

			if ( ! directoryExists( subfolderDirectory ) ) {

				return {
					user: {},
					contacts: [],
					snacks: [],
					drinks: [],
					meals: [],
				};

			}

			return [
				user: userProxy.read( subfolderDirectory ),
				contacts: contactsProxy.read( subfolderDirectory ),
				snacks: snacksProxy.read( subfolderDirectory ),
				drinks: drinksProxy.read( subfolderDirectory ),
				meals: mealsProxy.read( subfolderDirectory ),
			];

		}

	}


	/**
	* I initialize the experience data for the given user.
	*/
	public string function setup( required string email ) {

		var token = createUuid().lcase();
		var subfolderDirectory = "#dataDirectory#/#token#";

		email = email.lcase().trim();

		lock
			type = "exclusive"
			name = subfolderDirectory
			timeout = 5
			{

			if ( ! directoryExists( subfolderDirectory ) ) {

				directoryCreate( subfolderDirectory );

			}

			userProxy.write(
				subfolderDirectory,
				{
					email,
					ipAddress: cgi.remote_addr
				}
			);
			contactsProxy.write(
				subfolderDirectory,
				[
					[
						name: emailToName( email ),
						phone: "",
						isPrimary: true
					],
					// Default some empty contacts to help the user understand the full
					// value-add of the page and providing necessary contact information
					// to the sitter.
					[
						name: "Spouse",
						isPrimary: false
					],
					[
						name: "Police Department",
						isPrimary: false
					],
					[
						name: "Fire Department",
						isPrimary: false
					],
					[
						name: "Daytime Vet",
						isPrimary: false
					],
					[
						name: "Emergency Vet",
						isPrimary: false
					],
				]
			);
			drinksProxy.write(
				subfolderDirectory,
				[
					[
						name: "Celcius",
						description: "Peach Vibe",
						isSelected: false
					],
					[
						name: "Celcius",
						description: "Sparkling Wild Berry",
						isSelected: false
					],
					[
						name: "Seltzer",
						description: "Any flavor",
						isSelected: false
					],
				]
			);
			snacksProxy.write(
				subfolderDirectory,
				[
					[
						name: "Cape Cod Potato Chips",
						description: "Mesquite BBQ",
						isSelected: false
					],
					[
						name: "Cape Cod Potato Chips",
						description: "Original",
						isSelected: false
					],
					[
						name: "Cape Cod Potato Chips",
						description: "Sea Salt & Pepper",
						isSelected: false
					],
					[
						name: "Pretzel Chips",
						description: "Salt & Pepper",
						isSelected: false
					],
					[
						name: "Sun Chips",
						description: "Original",
						isSelected: false
					],
				]
			);
			mealsProxy.write(
				subfolderDirectory,
				[
					[
						name: "Pizza",
						description: "",
						isSelected: false
					],
				]
			);

		}

		return token;

	}


	/**
	* I write the data model to the experience-specific sub-folder.
	*/
	public void function write(
		required string subfolderName,
		required struct model
		) {

		var subfolderDirectory = "#dataDirectory#/#subfolderName#";

		lock
			type = "exclusive"
			name = subfolderDirectory
			timeout = 5
			{

			if ( ! directoryExists( subfolderDirectory ) ) {

				directoryCreate( subfolderDirectory );

			}

			contactsProxy.write( subfolderDirectory, model.contacts );
			snacksProxy.write( subfolderDirectory, model.snacks );
			drinksProxy.write( subfolderDirectory, model.drinks );
			mealsProxy.write( subfolderDirectory, model.meals );

		}

	}

}

<cfscript>

	include "./partials/mixins.cfm";

	// ------------------------------------------------------------------------------- //
	// ------------------------------------------------------------------------------- //

	param name="url.token" type="regex" pattern=TOKEN_PARAM_REGEX;
	param name="form.removeRowID" type="numeric" default=0;

	data = application.dataGateway.read( url.token );

	// Allow up to 20 drinks (arbitrary).
	while ( data.drinks.len() < 20 ) {

		data.drinks.append([
			name: "",
			description: "",
			isSelected: false
		]);

	}

	// Process row removal.
	if ( isPost() && form.removeRowID ) {

		data.drinks = flattenForm( form );
		data.drinks.deleteAt( form.removeRowID );

	}

	// Process form data.
	if ( isPost() && ! form.removeRowID ) {

		data.drinks = flattenForm( form )
		data.drinks = filterInPopulated( data.drinks, [ "name", "description" ] );
		data.drinks = arraySortOnKeys( data.drinks, [ "name", "description" ] );

		application.dataGateway.write( url.token, data );

		goto( "./manifest.cfm?token=#efu( url.token )#" );

	}

</cfscript>
<cfoutput>

	<h1>
		#withTitle( "Edit Drinks" )#
	</h1>

	<form method="post" action="#postBackAction()#">

		<button type="submit" class="visuallyHidden">
			<!---
				I need a visually hidden submit button at the top of the form so that the
				Enter key doesn't accidentally use the "Remove" button to submit the form.
			--->
		</button>

		<table border="1">
		<thead>
			<tr>
				<th>
					<label id="name-label" for="name-1">
						Name
					</label>
				</th>
				<th>
					<label id="description-label" for="description-1">
						Description
					</label>
				</th>

				<th>
					<!--- Remove. --->
				</th>
			</tr>
		</thead>
		<tbody>
			<cfloop array="#data.drinks#" item="drink" index="rowID">
				<tr>
					<td>
						<input
							id="name-#rowID#"
							aria-labeledby="name-label"
							type="text"
							name="name[]"
							value="#efa( drink.name )#"
							maxlength="50"
						/>
					</td>
					<td>
						<input
							id="description-#rowID#"
							aria-labeledby="description-label"
							type="text"
							name="description[]"
							value="#efa( drink.description )#"
							maxlength="50"
						/>
					</td>
					<td>
						<input
							type="hidden"
							name="isSelected[]"
							value="#efa( drink.isSelected )#"
						/>

						<button type="submit" name="removeRowID" value="#efa( rowID )#">
							Remove
						</button>
					</td>
				</div>
			</cfloop>
		</tbody>
		</table>


		<p class="d-flex">
			<button type="submit">
				Save
			</button>
			<a href="./manifest.cfm?token=#efu( url.token )#">
				Cancel
			</a>
		</p>
	</form>

</cfoutput>

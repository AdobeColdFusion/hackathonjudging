<cfscript>

	include "./partials/mixins.cfm";

	// ------------------------------------------------------------------------------- //
	// ------------------------------------------------------------------------------- //

	param name="url.token" type="regex" pattern=TOKEN_PARAM_REGEX;
	param name="form.primaryRowID" type="numeric" default=1;
	param name="form.removeRowID" type="numeric" default=0;

	data = application.dataGateway.read( url.token );

	// Allow up to 10 contacts (arbitrary).
	while ( data.contacts.len() < 10 ) {

		data.contacts.append([
			name: "",
			phone: "",
			isPrimary: false
		]);

	}

	// Process row removal.
	if ( isPost() && form.removeRowID ) {

		data.contacts = flattenForm( form );
		data.contacts.deleteAt( form.removeRowID );

	}

	// Process form data.
	if ( isPost() && ! form.removeRowID ) {

		data.contacts = flattenForm( form );
		data.contacts.each(
			( contact, rowID ) => {

				contact.isPrimary = ( rowID == form.primaryRowID );

			}
		);
		data.contacts = filterInPopulated( data.contacts, [ "name", "phone" ] );

		application.dataGateway.write( url.token, data );

		goto( "./manifest.cfm?token=#efu( url.token )#" );

	}

</cfscript>
<cfoutput>

	<h1>
		#withTitle( "Edit Contacts" )#
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
				<th class="w-50">
					<label id="name-label" for="name-1">
						Name
					</label>
				</th>
				<th class="w-50">
					<label id="phone-label" for="phone-1">
						Phone
					</label>
				</th>
				<th>
					<label id="primary-label" for="primary-1">
						Primary
					</label>
				</th>
				<th>
					<!--- Remove. --->
				</th>
			</tr>
		</thead>
		<tbody>

			<cfloop array="#data.contacts#" item="contact" index="rowID">
				<tr>
					<td>
						<input
							id="name-#rowID#"
							aria-labeledby="name-label"
							type="text"
							name="name[]"
							value="#efa( contact.name )#"
							maxlength="50"
						/>
					</td>
					<td>
						<input
							id="phone-#rowID#"
							aria-labeledby="phone-label"
							type="text"
							name="phone[]"
							value="#efa( contact.phone )#"
							maxlength="20"
						/>
					</td>
					<td>
						<input
							type="hidden"
							name="isPrimary[]"
							value="#efa( contact.isPrimary )#"
						/>

						<label class="d-flex isCentered">
							<input
								id="primaryRowID-#rowID#"
								type="radio"
								name="primaryRowID"
								value="#efa( rowID )#"
								<cfif contact.isPrimary>checked</cfif>
							/>
						</label>
					</td>
					<td>
						<button type="submit" name="removeRowID" value="#efa( rowID )#">
							Remove
						</button>
					</td>

				</tr>
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

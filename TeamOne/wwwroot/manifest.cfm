<cfscript>

	include "./partials/mixins.cfm";

	// ------------------------------------------------------------------------------- //
	// ------------------------------------------------------------------------------- //

	param name="url.token" type="regex" pattern=TOKEN_PARAM_REGEX;
	param name="form.action" type="string" default="";
	param name="form.rowID" type="numeric" default=0;

	data = application.dataGateway.read( url.token );

	if ( isPost() ) {

		switch ( form.action ) {
			case "toggleDrink":
				data.drinks[ form.rowID ].isSelected = ! data.drinks[ form.rowID ].isSelected;
			break;
			case "toggleMeal":
				data.meals[ form.rowID ].isSelected = ! data.meals[ form.rowID ].isSelected;
			break;
			case "toggleSnack":
				data.snacks[ form.rowID ].isSelected = ! data.snacks[ form.rowID ].isSelected;
			break;
		}

		application.dataGateway.write( url.token, data );

		// If the update is being made from HTMX, we can just let the page re-render since
		// we're going to be plucking parts of the UI out. However, if this is a regular
		// request, we want to refresh the page so the user doesn't accidentally re-submit
		// the form on page refresh.
		if ( ! isHtmx() ) {

			goto( postBackUrl() );

		}

	}

</cfscript>
<cfoutput>

	<h1>
		#withTitle( "Sitter Snacks" )#
	</h1>

	<p class="mb-30">
		Keeping your sitter happy, one snack at a time.
	</p>

	<div class="d-flex mb-10">
		<h2>
			Contacts
		</h2>
		<p class="ms-auto">
			<a href="./contacts.cfm?token=#efu( url.token )#">Configure Contacts</a> &rarr;
		</p>
	</div>

	<hr class="mb-20" />

	<cfif data.contacts.len()>

		<table border="1">
		<thead>
			<tr>
				<th class="w-40">
					Name
				</th>
				<th>
					Phone
				</th>
				<th class="w-15 text-center">
					Primary
				</th>
			</tr>
		</thead>
		<tbody>
			<cfloop array="#data.contacts#" item="contact">
				<tr>
					<td>
						#efh( contact.name )#
					</td>
					<td>
						#efh( contact.phone )#
					</td>
					<td class="text-center">
						<cfif contact.isPrimary>
							Yes
						</cfif>
					</td>
				</tr>
			</cfloop>
		</tbody>
		</table>

	</cfif>

	<cfif ! data.contacts.len()>
		<p class="mb-30">
			You have no contacts.
		</p>
	</cfif>


	<div class="d-flex mb-10">
		<h2>
			Drinks
		</h2>
		<p class="ms-auto">
			<a href="./drinks.cfm?token=#efu( url.token )#">Configure Drinks</a> &rarr;
		</p>
	</div>

	<hr class="mb-20" />

	<cfif data.drinks.len()>

		<table border="1">
		<thead>
			<tr>
				<th class="w-40">
					Name
				</th>
				<th>
					Description
				</th>
				<th class="w-15 text-center">
					Desired
				</th>
			</tr>
		</thead>
		<tbody>
			<cfloop array="#data.drinks#" item="drink" index="rowID">
				<tr
					id="drink-#rowID#"
					class="#classNames({ isSelected: drink.isSelected })#">
					<td>
						#efh( drink.name )#
					</td>
					<td>
						#efh( drink.description )#
					</td>
					<td>

						<form
							method="post"
							hx-post="#postBackAction()#"
							hx-trigger="submit, click from:closest tr"
							hx-target="closest tr"
							hx-select="##drink-#rowID#"
							hx-swap="outerHTML"
							hx-sync="this">

							<input type="hidden" name="action" value="toggleDrink" />
							<input type="hidden" name="rowID" value="#efa( rowID )#" />

							<button type="submit" class="w-100">
								#yesNoFormat( drink.isSelected )#
							</button>
						</form>

					</td>
				</tr>
			</cfloop>
		</tbody>
		</table>

	</cfif>

	<cfif ! data.drinks.len()>
		<p class="mb-30">
			You have no drinks.
		</p>
	</cfif>


	<div class="d-flex mb-10">
		<h2>
			Snacks
		</h2>
		<p class="ms-auto">
			<a href="./snacks.cfm?token=#efu( url.token )#">Configure Snacks</a> &rarr;
		</p>
	</div>

	<hr class="mb-20" />

	<cfif data.snacks.len()>

		<table border="1">
		<thead>
			<tr>
				<th class="w-40">
					Name
				</th>
				<th>
					Description
				</th>
				<th class="w-15 text-center">
					Desired
				</th>
			</tr>
		</thead>
		<tbody>
			<cfloop array="#data.snacks#" item="snack" index="rowID">
				<tr
					id="snack-#rowID#"
					class="#classNames({ isSelected: snack.isSelected })#">
					<td>
						#efh( snack.name )#
					</td>
					<td>
						#efh( snack.description )#
					</td>
					<td>

						<form
							method="post"
							hx-post="#postBackAction()#"
							hx-trigger="submit, click from:closest tr"
							hx-target="closest tr"
							hx-select="##snack-#rowID#"
							hx-swap="outerHTML"
							hx-sync="this">

							<input type="hidden" name="action" value="toggleSnack" />
							<input type="hidden" name="rowID" value="#efa( rowID )#" />

							<button type="submit" class="w-100">
								#yesNoFormat( snack.isSelected )#
							</button>
						</form>

					</td>
				</tr>
			</cfloop>
		</tbody>
		</table>

	</cfif>

	<cfif ! data.snacks.len()>
		<p class="mb-30">
			You have no snacks.
		</p>
	</cfif>
		

	<div class="d-flex mb-10">
		<h2>
			Meals
		</h2>
		<p class="ms-auto">
			<a href="./meals.cfm?token=#efu( url.token )#">Configure Meals</a> &rarr;
		</p>
	</div>

	<hr class="mb-20" />

	<cfif data.meals.len()>

		<table border="1">
		<thead>
			<tr>
				<th class="w-40">
					Name
				</th>
				<th>
					Description
				</th>
				<th class="w-15 text-center">
					Desired
				</th>
			</tr>
		</thead>
		<tbody>
			<cfloop array="#data.meals#" item="meal" index="rowID">
				<tr
					id="meal-#rowID#"
					class="#classNames({ isSelected: meal.isSelected })#">
					<td>
						#efh( meal.name )#
					</td>
					<td>
						#efh( meal.description )#
					</td>
					<td>

						<form
							method="post"
							hx-post="#postBackAction()#"
							hx-trigger="submit, click from:closest tr"
							hx-target="closest tr"
							hx-select="##meal-#rowID#"
							hx-swap="outerHTML"
							hx-sync="this">

							<input type="hidden" name="action" value="toggleMeal" />
							<input type="hidden" name="rowID" value="#efa( rowID )#" />

							<button type="submit" class="w-100">
								#yesNoFormat( meal.isSelected )#
							</button>
						</form>

					</td>
				</tr>
			</cfloop>
		</tbody>
		</table>

	</cfif>

	<cfif ! data.meals.len()>
		<p class="mb-30">
			You have no meals.
		</p>
	</cfif>

	<hr />
	<hr class="mb-20" />

	<p class="text-center mb-25">
		Share this page with your sitter so they can make their selections:
	</p>

	<div class="d-flex isCentered mb-20">
		<img
			src="qrcode.cfm?token=#efu( url.token )#"
			title="ColdFusion Logo Colors"
		/>
	</div>

	<hr />
	<hr class="mb-20" />

	<p>
		<a href="#postBackUrl()#&init=1">Re-init</a> the ColdFusion application.
	</p>

</cfoutput>

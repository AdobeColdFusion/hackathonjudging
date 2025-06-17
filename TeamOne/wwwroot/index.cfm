<cfscript>

	include "./partials/mixins.cfm";

	// ------------------------------------------------------------------------------- //
	// ------------------------------------------------------------------------------- //

	param name="form.email" type="string" default="";

	if ( isPost() ) {

		token = application.dataGateway.setup( form.email.trim() );

		goto( "manifest.cfm?token=#efu( token )#" );

	}

</cfscript>
<cfoutput>

	<h1 class="mb-20">
		#withTitle( "Sitter Snacks" )#
	</h1>

	<form method="post" action="#postBackAction()#">
		<label for="email" class="d-flex mb-10">
			Sign-up With Your Email:
		</label>

		<p class="d-flex">
			<input
				id="email"
				type="text"
				name="email"
				value=""
				maxlength="75"
			/>
			<button type="submit" class="text-nowrap">
				Create a Snacktacular!
			</button>
		</p>

	</form>

</cfoutput>

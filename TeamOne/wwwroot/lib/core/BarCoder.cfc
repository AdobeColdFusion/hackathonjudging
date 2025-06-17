component {

	/**
	* I initialize the bar code generator.
	*/
	public void function init() {

		variables.ErrorCorrectionLevel = fromJars( "com.google.zxing.qrcode.decoder.ErrorCorrectionLevel" );
		variables.EncodeHintType = fromJars( "com.google.zxing.EncodeHintType" );
		variables.MatrixToImageWriter = fromJars( "com.google.zxing.client.j2se.MatrixToImageWriter" );
		variables.QRCodeWriter = fromJars( "com.google.zxing.qrcode.QRCodeWriter" );
		variables.QR_CODE = fromJars( "com.google.zxing.BarcodeFormat" ).QR_CODE;

	}

	// ---
	// PUBLIC METHODS.
	// ---

	/**
	* I generate a QR code for the given value.
	*/
	public struct function generateBarcode(
		required string value,
		numeric width = 0,
		numeric height = 0
		) {

		var bitMatrix = QRCodeWriter.encode(
			value,
			QR_CODE,
			width,
			height,
			{
				// Error correction is the % of data that can be corrupted and still have the
				// QR-code be readable. Blows my mind that this is a thing!
				// --
				// H = ~30% correction
				// L = ~7% correction
				// M = ~15% correction
				// Q = ~25% correction
				"#EncodeHintType.ERROR_CORRECTION#": ErrorCorrectionLevel.H,
				// This is the size of the "quiet zone" around the barcode. The larger the
				// quiet zone, the easier it is to identify and scan.
				"#EncodeHintType.MARGIN#": 2
			}
		);

		// Implicitly encoded using PNG image format.
		return {
			binary: matrixToBlob( bitMatrix, "7cadff", "002258" ),
			// We passed-in the dimensions above; however, those are the "preferred"
			// dimensions. The image will be rendered larger if there's more data than
			// will fit in the preferred dimensions. As such, we should return the image
			// size that was ultimately rendered.
			width: bitMatrix.getWidth(),
			height: bitMatrix.getHeight()
		};

	}

	// ---
	// PRIVATE METHODS.
	// ---

	/**
	* I create a Java class from the given JAR files using an isolated classloader.
	*/
	private any function fromJars( required string classname ) {

		var jarPaths = [
			expandPath( "/lib/vendor/com.google.zxing/3.5.3/core-3.5.3.jar" ),
			expandPath( "/lib/vendor/com.google.zxing/3.5.3/javase-3.5.3.jar" )
		];

		return createObject( "java", classname, jarPaths );

	}


	/**
	* I convert the given barcode BitMatrix into a blob / binary object that represents
	* the rendered image in the given format.
	*/
	private binary function matrixToBlob(
		required any bitMatrix,
		string onColorHex = "000000",
		string offColorHex = "ffffff",
		string imageType = "png"
		) {

		if ( onColorHex.len() < 8 ) {

			onColorHex = "ff#onColorHex#";

		}

		if ( offColorHex.len() < 8 ) {

			offColorHex = "ff#offColorHex#";

		}

		// Note: Adobe ColdFusion can only handle SIGNED integers. As such, in order to
		// properly encode our ALPHA channel, we have to use the two's complement version
		// of the UNSIGNED version. Hence the maths.
		var imageConfig = fromJars( "com.google.zxing.client.j2se.MatrixToImageConfig" ).init(
			( inputBaseN( onColorHex, 16 ) - 4294967296 ),
			( inputBaseN( offColorHex, 16 ) - 4294967296 )
		);
		var byteStream = createObject( "java", "java.io.ByteArrayOutputStream" ).init();

		MatrixToImageWriter.writeToStream( bitMatrix, imageType, byteStream, imageConfig );

		return byteStream.toByteArray();

	}

}

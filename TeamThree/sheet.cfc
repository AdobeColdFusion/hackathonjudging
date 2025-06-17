component {

    /**
     * Export a query's data to excel including dynamically generated validation and format
     * based on the data type in database
     *
     * Right now, this function only supports a single query (no joins)
     *
     * @data
     * @tableName
     */
    public string function exportWithDynamicValidation(required query data, required string tableName) {
        // Get the table metadata
        var metaDataQ = queryExecute(
            '
             select column_name, udt_name, is_nullable, character_maximum_length, numeric_precision, numeric_precision_radix, numeric_scale, datetime_precision
             from information_schema.columns
             where table_name = :table
            ',
            {'table': {value: arguments.tableName, cf_sql_type: 'cf_sql_varchar'}}
        );

        // Map column name to info
        var metaData = {};
        metaDataQ.each((row) => {
            metaData[row.column_name] = {
                type: row.udt_name,
                size: row.character_maximum_length,
                precision: row.numeric_precision,
                scale: row.numeric_scale == '' ? row.numeric_precision_radix == '' ? 0 : row.numeric_precision_radix : row.numeric_scale
            }
        });

        // Began spreadsheet process. Create file.
        var filename = createUUID();
        var sheet = spreadsheetNew('validation', true);
        sheet.addRow(data.columnList);

        // Add query data preserving order
        var columns = listToArray(data.columnList, ',');
        data.each((row) => {
            var curr = [];
            columns.each((col) => {
                curr.append(row[col]);
            });
            sheet.addRow(curr.toList(','));
        });

        // Add validation and color highlighting
        var columns = listToArray(data.columnList, ',');
        for (var i = 1; i <= columns.len(); i++) {
            var validation = {
                regions: [
                    {
                        startRow: 2,
                        startColumn: i,
                        endRow: data.recordcount(),
                        endColumn: i
                    }
                ],
                alertTitle: 'Data validation failure'
            };

            var format = {bold: 'true', underline: 'true', alignment: 'center'};

            switch (lCase(metaData[columns[i]].type)) {
                case 'int4':
                    format.color = 'blue';

                    var num = numFromPrecisionScale(metaData[columns[i]].precision, metaData[columns[i]].scale);
                    validation.validationType = 'Integer';
                    validation.operator = 'between';
                    validation.minValue = lsParseNumber(num) * -1;
                    validation.maxValue = lsParseNumber(num);
                    break;
                case 'numeric':
                case 'float4':
                    format.color = 'gold';

                    var num = numFromPrecisionScale(metaData[columns[i]].precision, metaData[columns[i]].scale);
                    validation.validationType = 'Double';
                    validation.operator = 'between';
                    validation.minValue = lsParseNumber(num) * -1;
                    validation.maxValue = lsParseNumber(num);
                    break;
                case 'date':
                    format.color = 'green';
                    break;
                case 'varchar':
                    format.color = 'red';
                    validation.validationType = 'Text_Length';
                    validation.operator = 'between';
                    validation.minValue = 1;
                    validation.maxValue = metaData[columns[i]].size;
                    break;
                default:
                    continue;
            }

            if (validation.keyExists('validationType')) {
                spreadsheetAddDataValidationRule(sheet, validation);
            }
            spreadsheetFormatCell(sheet, format, 1, i);
        }

        spreadsheetwrite(sheet, '#application.path#/out/#filename#.xlsx');
        return filename;
    }


    // Generate the upper limit of a number based on the supplied precision, scale ie. numeric(precision, scale)
    public string function numFromPrecisionScale(required numeric precision, required numeric scale) {
        var start = '9';

        for (var i = 1; i <= precision - scale - 1; i++) {
            start &= '9';
        }

        if (scale > 0) {
            start &= '.';
            for (var i = 1; i <= scale; i++) {
                start &= '9';
            }
        }
        return start;
    }

}

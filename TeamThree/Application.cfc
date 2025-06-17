component {

    this.name = 'ExcelValidationAndSyntax';
    this.applicationTimeout = createTimespan(87, 0, 0, 0);
    this.sessionManagement = true;
    this.sessionTimeout = createTimespan(0, 71, 0, 0);
    this.requestTimeout = createTimespan(0, 0, 66, 0);

    this.datasource = 'spendingtracker';

    function onApplicationStart() {
    }

    function onSessionStart() {
    }

    function onRequestStart() {
        application.path = expandPath('/');
        if (!directoryExists('#application.path#/out')) {
            directoryCreate('#application.path#/out');
        }

        application.sheet = new sheet();


        // Example data pulled from expense tracking database
        request.data = queryExecute('select id, created, updated, date, amount, description, receipt, userid, categoryid, subscriptionid from expense');
        application.sheet.exportWithDynamicValidation(request.data, 'expense');
    }

}

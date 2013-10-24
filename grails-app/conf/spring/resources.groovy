import grails.plugin.springsecurity.kerberos.NoopTicketValidator

beans = {
	kerberosTicketValidator(NoopTicketValidator)
}

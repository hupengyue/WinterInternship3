
# cas登录流程

## 当浏览器输入：http://10.6.130.110:8087/apollo-web/web/role.action 之后

代码跳转流程
----------------------------------------------------------------------------
WebStatFilter.doFilter(){
    行123 chain.doFilter()
}
----------------------------------------------------------------------------

SingleSignOutFilter.doFilter(){ 
    行80 filterChain。doFilter();

}
----------------------------------------------------------------------------
CasAuthenticationFilter.doFilter(){
    行166，判断此url是不是要保护的app网址，如果是：往下继续进行
    行222：判断ticket是不是为空，如果不为空{
	    行224调用：filterChain.doFilter(request, response);并返回；
	}
    如果ticket为空：那说明该用户是没有进行过验证的，cas client会重定向用户请求到cas server；
    行240，判断url是不是外部链接，如果不是{
        从数据库的Menu表里面，查找到所有可以访问的app模块，检查是否有这个模块，如果有这个模块：
        将要访问的目标url编码到service参数，行260，此时url变为http://10.6.130.110/cas/login?service=http%3A%2F%2F10.6.130.110%3A8087%2Fapollo-web%2Fweb%2Frole.action
    }
}


## 当在浏览器输入正确的用户名和密码之后：

----------------------------------------------------------------------------
AuthenticationViaFormAction.submit(){
    行86：ticketGrantingTicketIdList <-- 从context中取出TGTIdList
    行92：如果cookie中有TGT的内容（根据TGTId，可以取到TGT的内容）{
	    cookieTgt = true;
	}
	行104：如果有TGT：{
	    1，如果cookieTgt为真，认证ST，调用：serviceTicketId = this.centralAuthenticationService.grantServiceTicket(ticketGrantingTicketId, service, null);
	}else {
	    2，行110：根据credentials认证ST，调用：serviceTicketId = this.centralAuthenticationService.grantServiceTicket(ticketGrantingTicketId, service, credentials);
	}
	如果有TGTId，在取TGT对象的过程中抛出异常，{
	    跳转到行136：销毁这个TGT的对象，调用this.centralAuthenticationService.destroyTicketGrantingTicket(ticketGrantingTicketId);
	}
	3，行150：如果没有TGT，就产生TGT：调用centralAuthenticationService.createTicketGrantingTicket(credentials)
	
}
----------------------------------------------------------------------------
1,GenerateServiceTicketAction(AbstractAction).execute(){
    1.1，行188，根据TGT产生ST，调用doExecute(context);
}

----------------------------------------------------------------------------
1.1, GenerateServiceTicketAction.doexecute(Context context){
    1.1.1 也是2， 行45：产生ST，返回STId，调用：final String serviceTicketId = this.centralAuthenticationService
	                                            .grantServiceTicket(ticketGrantingTicket, service);
	构造带有ST的url，向具体的app发送：一个具体的例子：http://10.6.130.110:8087/apollo-web/web/role.action?ticket=ST-1-lVApdjLe11HZs1QGeQfM-cas
	不知道什么机制，就请求此构造的url，
	1.1.1.1，
	
}
----------------------------------------------------------------------------
1.1.1，CentralAuthenticationServiceImpl.grantServiceTicket(final String ticketGrantingTicketId, final Service service, final Credentials credentials){
    行234：从ConcurrentHashMap里面取出TGT对应的xml文件
    如果TGT对象不为null：synchronized(TGT){
	    如果TGT已经过期了，那么从ConcurrentHashMap里面删除此TGT对象；
	}
	行287，产生一个生成uniqueST的生成器，调用final UniqueTicketIdGenerator serviceTicketUniqueTicketIdGenerator = this.uniqueTicketIdGeneratorsForService.get(service.getClass().getName());
	行290，生成与此TGT对应的ST，将构造好的ST对象添加到concurrentHashMap，同时将userStatus保存到Ehcache缓存中；调用：this.ticketRegistry.addTicket(ticketGrantingTicket);
	返回STId；
}

----------------------------------------------------------------------------


2，CentralAuthenticationServiceImpl.grantServiceTicket(){
	行234：从ConcurrentHashMap里面取出TGT对应的xml文件
    如果TGT对象不为null：synchronized(TGT){
	    如果TGT已经过期了，那么从ConcurrentHashMap里面删除此TGT对象；
	}
	行287，产生一个生成uniqueST的生成器，调用final UniqueTicketIdGenerator serviceTicketUniqueTicketIdGenerator = this.uniqueTicketIdGeneratorsForService.get(service.getClass().getName());
	行290，生成与此TGT对应的ST，将构造好的ST对象添加到concurrentHashMap，同时将userStatus保存到Ehcache缓存中；调用：this.ticketRegistry.addTicket(ticketGrantingTicket);
	返回STId；

}

----------------------------------------------------------------------------
3，CentralAuthenticationServiceImpl.createTicketGrantingTicket(final Credentials credentials){
    3.1, 行497：认证登录的用户，调用this.authenticationManager.authenticate(credentials);
	3.2，行500：如果认证成功：那么就产生TGT对象
	3.3，行505：将构造好的TGT对象添加到concurrentHashMap，同时将userStatus保存到Ehcache缓存中；调用：this.ticketRegistry.addTicket(ticketGrantingTicket);
    返回TGT的id值

}
----------------------------------------------------------------------------
函数功能：
    根据ticketId取ticket对象
2.1，HikTicketRegistry(AbstractTicketRegistry).getTicket(){
    行35：根据ticketId取ticket对象：调用this.getTicket(ticketId);
}

----------------------------------------------------------------------------
3.1，AuthenticationManagerImpl(AbstractAuthenticationManager).authenticate(final Credentials credentials){
    3.1.1, 行41，认证登录的用户并且获取Principal：调用authenticateAndObtainPrincipal(credentials);
	返回Principal对象；
}
----------------------------------------------------------------------------
3.2，
----------------------------------------------------------------------------
3.3，HikTicketRegistry.addTicket(Ticket ticket){
    行41：将输入参数ticket划分为ST/TGT，分门别类保存到同一个ConsurrentHashMap里面，根据不同的id取xml
	3.3.1，行51，将用户的在线状态保存到Ehcache里面，调用：userStatusService.saveUserStatus(ticket.getId(), hikUsernamePasswordCredentials.getUser().getId(), hikUsernamePasswordCredentials.getUsername(), Integer.parseInt(hikUsernamePasswordCredentials.getLoginType()), 
							                                hikUsernamePasswordCredentials.getUser().getDeptIndexCode(), hikUsernamePasswordCredentials.getClientIP(), hikUsernamePasswordCredentials.getClientMAC(), 
							                                hikUsernamePasswordCredentials.getService()!= null ? hikUsernamePasswordCredentials.getService() : hikUsernamePasswordCredentials.getServiceIP());
}
----------------------------------------------------------------------------
3.1.1，AuthenticationManagerImpl.authenticateAndObtainPrincipal(Credentials credentials){
    3.1.1.1,行84，认证登录用户，调用：boolean auth = authenticationHandler.authenticate(credentials);
	3.1.1.2,行122，程序如果能运行到这行，说明，授权用户成功，将credentials解析为Principal，调用final Principal principal = credentialsToPrincipalResolver.resolvePrincipal(credentials);返回Principal
	如果构造Principal对象成功：那么就用Principal对象构造一个Pair对象，并返回；
}

----------------------------------------------------------------------------
3.3.1，

----------------------------------------------------------------------------
1.1.1.1，SingleSignOutFilter(){
    1.1.1.1.1，行80：过滤请求的url，调用filterChain.doFilter(servletRequest, servletResponse);
}


----------------------------------------------------------------------------

3.1.1.1，HikUsernamePasswordHandler.authenticate(credentials){
    行209：授权用户的过程就是到数据库里面找有此用户名和密码的用户，如果能找到，返回true；
}
----------------------------------------------------------------------------
3.1.1.2，Principal HikcredentialsToPrincipalResolver(AbstractPersonDirectoryCredentialsToPrincipalResolver).credentialsToPrincipalResolver.resolvePrincipal(credentials){
    行44，将credentials中主要的信息拼接为stringbuilder，调用final String principalId = extractPrincipalId(credentials);
	然后用此String对象构造一个SimplePrincipal对象，并返回；
}

----------------------------------------------------------------------------

1.1.1.1.1, CasAuthenticationFilter.doFilter(servletRequest, servletResponse){
    1.1.1.1.1.1, 行224, ？？？，调用filterChain.doFilter(request, response);
}
----------------------------------------------------------------------------
1.1.1.1.1.1, Cas20ProxyReceivingTicketValidationfilter(AbstractTicketValidationFilter).doFilter(request, response){
    1.1.1.1.1.1.1, 行165，调用preFilter();
    行171，从request中取ticket，如果ticket不为null{
	    1.1.1.1.1.1.2，行180，验证ticket，调用：final Assertion assertion = this.ticketValidator.validate(ticket, constructServiceUrl(request, response));
	}
	行195，如果验证ST成功了，那么{
	    行193，构造一个重定向的url，调用：String redirectUrl = this.cleanupUrl(constructServiceUrl(request, response));
		行195，发出请求，显示具体的app，调用：response.sendRedirect(redirectUrl);
		返回；
	}
}
----------------------------------------------------------------------------
1.1.1.1.1.1.1, Cas20ProxyReceivingTicketValidationfilter.preFilter(){
    行207，生成一个验证器，调用：Cas20ServiceTicketValidator validator =  (Cas20ServiceTicketValidator)this.findTicketValidator();
	行124，返回true；
	
}

----------------------------------------------------------------------------
1.1.1.1.1.1.2，Cas20ProxyReceivingTicketValidator(AbstractUrlBasedTicketValidator).validate(ticket, constructServiceUrl(request, response)){
    行209，构造了一个url：一个例子：http://10.6.130.110/cas/serviceValidate?ticket=ST-2-dJnk2k3gFG9dh0joHFsv-cas&service=http%3A%2F%2F10.6.130.110%3A8087%2Fapollo-web%2Fweb%2Frole.action%3Bjsessionid%3D1obgnxq0hrwt212umtiyzlzqg7
    行216，发出请求：得到验证的结果：调用：final String serverResponse = retrieveResponseFromServer(new URL(validationUrl), ticket);	
    行226，返回解析验证的结果；
}

----------------------------------------------------------------------------


----------------------------------------------------------------------------


----------------------------------------------------------------------------


----------------------------------------------------------------------------

----------------------------------------------------------------------------

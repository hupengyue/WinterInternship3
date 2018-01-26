cas登录流程
========================================================================================================================================================
当浏览器输入：http://10.6.130.110:8087/apollo-web/web/role.action 之后

代码跳转流程
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
WebStatFilter.doFilter(){
    行123 chain.doFilter()
}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

SingleSignOutFilter.doFilter(){ 
    行80 filterChain。doFilter();

}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CasAuthenticationFilter.doFilter(){
    行155，如果session不为null{
	    行156，从session中取出存储的assertion：从session中取出键名为“_const_cas_assertion_”的值，
		调用：assertion = (Assertion)session.getAttribute(CONST_CAS_ASSERTION);
		assertion的核心内容的一个例子：assertion.principal.name = 1&&admin&&10.6.130.110&&10.6.130.110&&&&TGT-7-VZETezdZLxRFXOZ6VEfTdKwWB63q7Lb3uMpUceiTdagNMazwQV-cas）
	}
	行166，判断此url是不是要保护的app网址，如果是：往下继续进行
	
	行191～行215，如果assertion不为null（assertion不为null说明是这种情况：已经登录和验证成功，cas验证过了，TGT, ST都已经产生和经过验证，用户再次访问同一个app，assertion.principal.name = 1&&admin&&10.6.130.110&&10.6.130.110&&&&TGT-7-VZETezdZLxRFXOZ6VEfTdKwWB63q7Lb3uMpUceiTdagNMazwQV-cas）{
	    10，行198，当登录成功之后，再次访问同一个app，app向cas-service请求更新TGT的过期时间
        调用：SessionDateHandler.getInstance().flushTgt(session.getId(), assertion.getPrincipal(), urlPre);
		1.1.1.1.1.1, 行213，先运行到函数1.1.1.1.1.1,的行210的else分支（什么也不干），又继续运行到行214：进行正常的增删改查的api的调用，
		调用：filterChain.doFilter(request, response);
		行214：返回；
	}
    
	如果assertion为null，那进行下面的代码：
	行222～行226：判断ST是不是为空，如果ST不为空(说明是这种情况：已经认证了用户并产生TGT，并且产生ST之后，url中带上ST再次访问此app){
	    1.1.1.1.1.1, 行224，向cas请求认证此ST，调用：filterChain.doFilter(request, response);
		行225，返回；
	}
	
	
    行230以后的代码，如果代码运行到这一行，说明是这样的情况：assertion为空，并且ST也为空；
	（那说明：该用户是没有进行过cas验证登录用户的情况，那么cas client（即app）
	会重定向用户请求到cas server进行登录用户的验证；进行下面的代码：
	
    行240，判断url是不是外部链接，如果不是{
        从数据库的Menu表里面，查找到所有可以访问的app模块，检查是否有这个模块，如果有这个模块{
            行258，将要访问的目标url编码到service参数，调用：modifiedServiceUrl = serviceUrl.substring(0, serviceUrl.indexOf(request.getContextPath()) + request.getContextPath().length()) +  menuUrl;一个具体的例子：此时url变为http://10.6.130.110/cas/login?service=http%3A%2F%2F10.6.130.110%3A8087%2Fapollo-web%2Fweb%2Frole.action
		}
    }
	行289，组装重定向的url，调用：final String urlToRedirectTo = CommonUtils.constructRedirectUrl(this.casServerLoginUrl, getServiceParameterName(),
				    modifiedServiceUrl, this.renew, this.gateway);一个例子：http://10.6.130.110/cas/login?service=http%3A%2F%2F10.6.130.110%3A8087%2Fapollo-web%2Fweb%2Frole.action
    
	如果requestType不为空{
	} else（即：如果requestType为空）{
	    0.0，行309, 显示输入用户名和密码的登录界面，调用：response.sendRedirect(urlToRedirectTo);
    }	
}



========================================================================================================================================================

0.0，显示输入用户名和密码的登录界面，当在浏览器输入正确的用户名和密码之后：

--------------------------------------------------------------------------------------------------------------------------------------------------------
函数功能：
    根据有无TGT做不同的事情：
	如果没有TGT，那么就先认证用户的存在性，如果认证成功，那么产生TGT；
	如果有TGT，那么，如果没有ST，那么，依据TGT产生ST。
AuthenticationViaFormAction.submit(){
    行85～行95：取TGTIdList的过程：
	行86，利用WebUtils从context中取出TGTIdList，调用：String ticketGrantingTicketIds = WebUtils.getTicketGrantingTicketId(context);
    行89，如果获取不到TGT，从cookie中再尝试获取一次，{
	    行92：如果cookie中有TGT的内容（根据TGTId，可以取到TGT的内容）{
	        cookieTgt = true;
		}
	}
	行104：如果有TGT：{
	    1，如果cookieTgt为真，认证ST，调用：serviceTicketId = this.centralAuthenticationService.grantServiceTicket(ticketGrantingTicketId, service, null);
	}else {
	    2，行110：根据credentials认证ST，调用：serviceTicketId = this.centralAuthenticationService.grantServiceTicket(ticketGrantingTicketId, service, credentials);
	}
	如果有TGTId，在取TGT对象的过程中抛出异常，{
	    跳转到行136：销毁这个TGT的对象，调用this.centralAuthenticationService.destroyTicketGrantingTicket(ticketGrantingTicketId);
	}
	3，行150：如果没有TGT，就产生TGT，并且同时将产生的TGT设置到requestScope里面：
	调用：WebUtils.putTicketGrantingTicketInRequestScope(context, this.centralAuthenticationService.createTicketGrantingTicket(credentials));
	
}
--------------------------------------------------------------------------------------------------------------------------------------------------------
1,GenerateServiceTicketAction(AbstractAction).execute(){
    1.1，行188，根据TGT产生ST，调用：result = doExecute(context);
	1.2，行189，？？？不知道干了什么，调用：doPostExecute(context);
	返回 result;(result是一个Event对象，表示产生ST这个动作是成功的或者失败的)
}

--------------------------------------------------------------------------------------------------------------------------------------------------------
1.1, GenerateServiceTicketAction.doexecute(Context context){
    1.1.1 也是2， 行45：产生ST，返回STId，调用：final String serviceTicketId = this.centralAuthenticationService
	                                            .grantServiceTicket(ticketGrantingTicket, service);
	行51～行63，构造带有ST的url，调用：encodeUrl += maoStr;比如：一个具体的例子：http://10.6.130.110:8087/apollo-web/web/role.action?ticket=ST-1-lVApdjLe11HZs1QGeQfM-cas
	1.1.2，然后将此url放到了context里面，调用：context.getRequestScope().put("encodeUrl", encodeUrl);
	不知道什么机制，就请求此构造的url，胡鹏跃猜想：靠的是webFlow的xml文件，来走的这个cas认证的流程
	1.1.1.0，行67，调用继承自AbstractAction.success();并返回一个Event对象，表示产生ST这个动作是成功的；
	1.1.1.1，
	
}
--------------------------------------------------------------------------------------------------------------------------------------------------------
1.1.1，CentralAuthenticationServiceImpl.grantServiceTicket(final String ticketGrantingTicketId, final Service service, final Credentials credentials){
    行234：从ConcurrentHashMap里面取出TGT对应的xml文件
    如果TGT对象不为null：synchronized(TGT){
	    如果TGT已经过期了，那么从ConcurrentHashMap里面删除此TGT对象；
	}
	行287，产生一个用于生成uniqueST的生成器，调用final UniqueTicketIdGenerator serviceTicketUniqueTicketIdGenerator = this.uniqueTicketIdGeneratorsForService.get(service.getClass().getName());
	行290，生成与此TGT对应的ST，将构造好的ST对象添加到concurrentHashMap，同时将userStatus保存到Ehcache缓存中；调用：this.ticketRegistry.addTicket(ticketGrantingTicket);
	返回STId；
}

--------------------------------------------------------------------------------------------------------------------------------------------------------


2，CentralAuthenticationServiceImpl.grantServiceTicket(){
	行234：从ConcurrentHashMap里面取出TGT对应的xml文件
    如果TGT对象不为null：synchronized(TGT){
	    如果TGT已经过期了，那么从ConcurrentHashMap里面删除此TGT对象；
	}
	行287，产生一个生成uniqueST的生成器，调用final UniqueTicketIdGenerator serviceTicketUniqueTicketIdGenerator = this.uniqueTicketIdGeneratorsForService.get(service.getClass().getName());
	行290，生成与此TGT对应的ST，将构造好的ST对象添加到concurrentHashMap，同时将userStatus保存到Ehcache缓存中；调用：this.ticketRegistry.addTicket(ticketGrantingTicket);
	返回STId；

}

--------------------------------------------------------------------------------------------------------------------------------------------------------
3，CentralAuthenticationServiceImpl.createTicketGrantingTicket(final Credentials credentials){
    3.1, 行497：认证登录的用户，调用this.authenticationManager.authenticate(credentials);
	3.2，行500：如果认证成功：那么就产生TGT对象
	3.3，行505：将构造好的TGT对象添加到concurrentHashMap，同时将userStatus保存到Ehcache缓存中；调用：this.ticketRegistry.addTicket(ticketGrantingTicket);
    返回TGT的id值

}
--------------------------------------------------------------------------------------------------------------------------------------------------------
函数功能：
    根据ticketId取ticket对象
2.1，HikTicketRegistry(AbstractTicketRegistry).getTicket(){
    行35：根据ticketId取ticket对象：调用this.getTicket(ticketId);
}

--------------------------------------------------------------------------------------------------------------------------------------------------------
3.1，AuthenticationManagerImpl(AbstractAuthenticationManager).authenticate(final Credentials credentials){
    3.1.1, 行41，认证登录的用户并且获取Principal：调用authenticateAndObtainPrincipal(credentials);
	返回Principal对象；
}
--------------------------------------------------------------------------------------------------------------------------------------------------------
3.2，
--------------------------------------------------------------------------------------------------------------------------------------------------------
3.3，HikTicketRegistry.addTicket(Ticket ticket){
    行41：将输入参数ticket划分为ST/TGT，分门别类保存到同一个ConsurrentHashMap里面，根据不同的id取xml
	3.3.1，行51，将用户的在线状态保存到Ehcache里面，调用：userStatusService.saveUserStatus(ticket.getId(), hikUsernamePasswordCredentials.getUser().getId(), hikUsernamePasswordCredentials.getUsername(), Integer.parseInt(hikUsernamePasswordCredentials.getLoginType()), 
							                                hikUsernamePasswordCredentials.getUser().getDeptIndexCode(), hikUsernamePasswordCredentials.getClientIP(), hikUsernamePasswordCredentials.getClientMAC(), 
							                                hikUsernamePasswordCredentials.getService()!= null ? hikUsernamePasswordCredentials.getService() : hikUsernamePasswordCredentials.getServiceIP());
    3.3.2，行64，更新用户的userStatus，调用：UserStatus userStatus =userStatusService.getUserStatus(ticket.getId());															
}
--------------------------------------------------------------------------------------------------------------------------------------------------------
3.1.1，AuthenticationManagerImpl.authenticateAndObtainPrincipal(Credentials credentials){
    3.1.1.1,行84，认证登录用户，调用：boolean auth = authenticationHandler.authenticate(credentials);
	3.1.1.2,行122，程序如果能运行到这行，说明，授权用户成功，将credentials解析为Principal，调用final Principal principal = credentialsToPrincipalResolver.resolvePrincipal(credentials);返回Principal
	如果构造Principal对象成功：那么就用Principal对象构造一个Pair对象，并返回；
}

--------------------------------------------------------------------------------------------------------------------------------------------------------
函数功能：
    保存一些登录用户的必要的信息到Ehcache里面
3.3.1，UserStatusServiceImpl.saveUserStatus(String sessionId, String userId, 
            String userName, int loginType, String orgId, 
			String cuIp, String cuMac, String enterService) {


}

--------------------------------------------------------------------------------------------------------------------------------------------------------

3.3.2，UserStatusServiceImpl.getUserStatus(String sessionId) {


}
--------------------------------------------------------------------------------------------------------------------------------------------------------
1.1.1.1，SingleSignOutFilter(){
    1.1.1.1.1，行80：过滤请求的url，调用filterChain.doFilter(servletRequest, servletResponse);
}


--------------------------------------------------------------------------------------------------------------------------------------------------------

3.1.1.1，HikUsernamePasswordHandler.authenticate(credentials){
    行209：授权用户的过程就是到数据库里面找有此用户名和密码的用户，如果能找到，返回true；
}
--------------------------------------------------------------------------------------------------------------------------------------------------------
3.1.1.2，Principal HikcredentialsToPrincipalResolver(AbstractPersonDirectoryCredentialsToPrincipalResolver).credentialsToPrincipalResolver.resolvePrincipal(credentials){
    行44，将credentials中主要的信息拼接为stringbuilder，调用final String principalId = extractPrincipalId(credentials);
	然后用此String对象构造一个SimplePrincipal对象，并返回；
}

--------------------------------------------------------------------------------------------------------------------------------------------------------

1.1.1.1.1, CasAuthenticationFilter.doFilter(servletRequest, servletResponse){
    行222，判断ST是否为空，如果ST不为null{
        1.1.1.1.1.1, 行224, 验证ST的有效性，调用filterChain.doFilter(request, response);
	}
}
--------------------------------------------------------------------------------------------------------------------------------------------------------
1.1.1.1.1.1, Cas20ProxyReceivingTicketValidationfilter(AbstractTicketValidationFilter).doFilter(request, response){
    1.1.1.1.1.1.1, 行165，调用preFilter();
    行171，从request中取ticket，如果ticket（即ST）不为null{
	    1.1.1.1.1.1.2，行180，验证ticket，返回一个Assertion的对象，调用：final Assertion assertion = this.ticketValidator.validate(ticket, constructServiceUrl(request, response));
        将验证ST的结果assertion设置到request中，调用：request.setAttribute(CONST_CAS_ASSERTION, assertion);
		行187，如果启用session，那么{
		    将验证ST的结果assertion设置到request的session中，后面已经登录的用户如果第二次登录此app，直接从session里面取出assertion，调用：request.getSession().setAttribute(CONST_CAS_ASSERTION, assertion);
		}
		行195，如果验证ST成功了，那么{
			行193，构造一个重定向的url，调用：String redirectUrl = this.cleanupUrl(constructServiceUrl(request, response));
			行195，发出请求，显示具体的app，调用：response.sendRedirect(redirectUrl);
			返回；
		}
	} 行210，else（如果ticket（即ST）为null，说明：不用验证ST）{
	    什么也不干，继续运行到行214。
	}
	行214，进行正常的增删改查的api的调用，调用：filterChain.doFilter(request, response);
}
--------------------------------------------------------------------------------------------------------------------------------------------------------
1.1.1.1.1.1.1, Cas20ProxyReceivingTicketValidationfilter.preFilter(){
    行187，取出目标模块的url，调用：String requestUrl = request.getRequestURL() + "";一个例子：requestUrl = http://10.6.130.110:8087/apollo-web/web/role.action?ticket=ST-1-WDVezarnOcGG7WhKZC7P-cas
	行188，取出ST，调用：String queryStr = request.getQueryString();一个例子：queryStr = ticket=ST-1-WDVezarnOcGG7WhKZC7P-cas
	行189，判断queryStr(即ST)是否为空：如果不为空，{
	    组装一个url：调用：requestUrl = requestUrl + "?" + queryStr;一个例子：requestUrl = http://10.6.130.110:8087/apollo-web/web/role.action?ticket=ST-1-WDVezarnOcGG7WhKZC7P-cas
	}
	行207，生成一个验证器，调用：Cas20ServiceTicketValidator validator =  (Cas20ServiceTicketValidator)this.findTicketValidator();
	行214，返回true；
	
}

--------------------------------------------------------------------------------------------------------------------------------------------------------
作为cas-client，解析cas-server发过来的url，
1.1.1.1.1.1.2，Cas20ProxyReceivingTicketValidator(AbstractUrlBasedTicketValidator).validate(ticket, constructServiceUrl(request, response)){
    行209，构造了一个url：一个例子：http://10.6.130.110/cas/serviceValidate?ticket=ST-2-dJnk2k3gFG9dh0joHFsv-cas&service=http%3A%2F%2F10.6.130.110%3A8087%2Fapollo-web%2Fweb%2Frole.action%3Bjsessionid%3D1obgnxq0hrwt212umtiyzlzqg7
    1.1.1.1.1.1.2.1, 行216，cas-client向cas-server发出验证ST的请求：得到验证的结果：调用：final String serverResponse = retrieveResponseFromServer(new URL(validationUrl), ticket);	
    ？？？不知道怎么个调用的过程，直接跳转到1.1.1.1.1.1.2.2
	行226，返回解析验证的结果；
}

--------------------------------------------------------------------------------------------------------------------------------------------------------

1.1.1.1.1.1.2.1,发出的请求，被1.1.1.1.1.1.3，拦截并处理：

--------------------------------------------------------------------------------------------------------------------------------------------------------



--------------------------------------------------------------------------------------------------------------------------------------------------------



--------------------------------------------------------------------------------------------------------------------------------------------------------
1.1.1.1.1.1.3，ServiceValidateController.handleRequestInternal(final HttpServletRequest request, final HttpServletResponse response){
    行143，验证ST的有效性，调用：1.1.1.1.1.1.2.2, final Assertion assertion = this.centralAuthenticationService.validateServiceTicket(serviceTicketId, service);
	
}
--------------------------------------------------------------------------------------------------------------------------------------------------------

函数功能：
    认证ST的合法性（ST没失效，ST和service是配对的，ST里面可以取出TGT）
1.1.1.1.1.1.2.2, CentralAuthenticationServiceImpl.validateServiceTicket(final String serviceTicketId, final Service service){
    行391，从concurrentHashMap那里取出xml文本，再从中提取出ST，调用：final ServiceTicket serviceTicket = (ServiceTicket) this.serviceTicketRegistry.getTicket(serviceTicketId, ServiceTicket.class);
	行400，如果ST为空，就报错；
	如果ST不为空{
	    synchronized(ST){
		    如果ST过期了，报错；
			如果ST没过期，那么{
			    判断此ST是否对应这个service，如果不对应，报错；
				如果ST和service是配对的，那么{
				    行417，从ST里取出TGT，
					行423：从TGT里面取出最后一个Authentication; 调用：final Authentication authentication = tgt.getChainedAuthentications().get(authenticationChainSize - 1);
					行426：从Authentication里面取出Principal
					
				}
			}
		}
	}
	行476：返回结果，调用：new ImmutableAssertionImpl(authentications, serviceTicket.getService(), serviceTicket.isFromNewLogin());
}

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------




========================================================================================================================================================

第二次，再次访问同一个app
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
函数功能：
    app向cas-service请求：刷新TGT的过期时间
	
10，SessionDateHandler.flushTgt(String sessionId, Principal principal, String prefixUrl) {
		如果TGT没过期{
			行76，刷新session的过期时间，调用：sessionDateMappingStorage.addSessionDateById(sessionId, now);
			从principal里面取出TGT，如果TGT不为null{
				app向cas-service请求：更新TGT的过期时间，调用：String result = CommonUtils.getResponseFromServer(url, "utf-8");    
			}
			
		}
}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


========================================================================================================================================================
当一个登录的用户已经在cas验证过登录了，产生了TGT，再次直接登录cas或者，登录第二个app，app发现没有局部session，重定向到cas:

AuthInterceptor.preHandler(HttpServletRequest request, HttpServletResponse response, Object handler){
    行77，刷新TGT的最后更新的时间，调用：session.setAttribute(SessionConstants.TGT_LASTFLUSHTIMEINMILL, now);
	行85，从session中取出登录的user，调用：User user = (User)session.getAttribute(SessionConstants.USER);
	行87，如果user为null{
	    行88：从request里面直接取出username，调用：String userName = getUsername(request, session);
		行90，synchronized (sysObject) {
		    从数据库里面由username找出user对象；
			行95，行96，将user的必要信息设置到session里面
		}
	}
	行103，如果user不为null{
	    行104，从concurrentHashMap里面取出TGTId对应的xml，（如果xml为null，那就返回null）
		如果TGT不为null{
		    刷新TGT的最后更新的时间；
		
		} else（TGT对应的xml为null，说明虽然TGTId还存在着，但是这个TGT已经过期了，已经删除了TGTId对应的xml文件里）{
		    删除这个无用的session；
		}
	}
	21,行127，验证失败，重新产生和认证TGT，调用：jumpLogin(request, response);
	行128，返回false；
	

}

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
21,

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
不知道怎么就跳转到了：
CleanUserStatusTask.cleanUserStatus(){
    行39，找到所有缓存着的userStatus
	
	如果userStatus的更新时间为null{
	
	} else {
	    如果userStatus时间已经过期{
		    删除这个已经过期的userStatus
		}
	}
}


-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


#  http协议
## post请求
http协议规定,post请求分为三个部分,状态行,请求头,消息主体.类似于下面这样:
<method> <request -URL> <version>
<headers>

<entity-body>

post提交的数据必须放在消息主体(entity-body)中,比如,RestTemplate中需要将具体请求的参数放入MultiValueMap <String, Object > map里面,再用此map和headers构造一个HttpEntity对象:
HttpEntity<MultiValueMap<String, Object>> entity = new HttpEntity<MultiValueMap<String, Object>>(map, headers);
但是，实际上，开发者可以自己决定主体的格式，常见的格式有两种：
token=12345&id=getUser；
或者
{token:1111; id:getUser}
数据发送到服务器，服务器端必须能够正确的解析，才能正确得到客户端传入的参数。服务器端的语言：python和php等的framwork都内置了解析常见数据格式的功能。服务器端通常根据客户端传入的headers中Content-Type字段，来获知客户端请求中的消息主体，是用哪种方式编码的，然后根据这种方式对主体进行解析并得到请求传入的具体的参数值。

headers中Content-Type字段的可以设置的常见的值为：

application/x-www-form-urlencoded
总结：application/x-www-form-urlencoded～HttpServletRequest.getParameter()取数据（来源于网上：getParameter()只能获取在url串当中的入参）
这是一种最常见的POST提交数据的方式了。请求类似于下面这样：

完整的请求头信息：
headers = {

Cookie=JSESSIONID=105iya17xq8at127snvji4mio9, 

Accept=*/*, 

Cache-Control=no-cache, 

Connection=keep-alive, 

User-Agent=Apache-HttpClient/4.5.2 (Java/1.8.0_152-release), 

Host=10.6.130.110,
 
Accept-Encoding=gzip,deflate, 

Content-Length=50, 

Content-Type=application/x-www-form-urlencoded; //很明显Content-Type被设置为application/x-www-form-urlencoded

charset=GBK}

对应与此Content-Type的请求参数的格式：
token=12345&id=getUser
其中，提交的数据按照key1=value1&key2=value2的格式进行编码，key和value都进行了url转码。

Controller获取客户端发送的数据的情况：
数据是从HttpServletRequest.getParameter()方法里面获取到的即：
    String paramToken = request.getParameter("token");
	String paramId = request.getParameter("id");

	paramToken，paramId都是正确的客户端传过来的值；

但是：
    1），
	HttpServletRequest.getReader()会报错的
	BufferedReader bufferedReader = request.getReader();	
    2），
	Scanner scanner = new Scanner(request.getInputStream(), "UTF-8").useDelimiter("\\A");
	scanner.hasNext();//为假，scanner里面没有任何的数据
	
application/json
总结：application/json～HttpServletRequest.getReader()取客户端传进来的参数数据。

告诉服务器，消息主体是序列化之后的JSON字符串。json格式支持比键值对复杂的多的结构数据，这一点很有用。
headers = {

Accept=text/plain, application/json, application/*+json, */*, 

Cache-Control=no-cache, 

Connection=keep-alive, 
User-Agent=Java/1.8.0_66, 
Host=10.6.130.110, 
Pragma=no-cache, 
Content-Length=75, 
Content-Type=application/json}

Controller获取客户端发送的数据的情况：
数据是从HttpServletRequest.getReader()方法里面获取到的即：

	BufferedReader bufferedReader = request.getReader();

	String str,wholeStr = "";
	while((str = bufferedReader.readLine())!=null){
		wholeStr+=str;
	}
	whileStr 存储的值为：{"token":["5D877242155AFE74E053455C920AEF7A"],"id":["system/user/getuser"]}
	
但是：
	String paramToken = request.getParameter("token");
	String paramId = request.getParameter("id");

	paramToken，paramId都是null；
	
	Scanner scanner = new Scanner(request.getInputStream(), "UTF-8").useDelimiter("\\A");
	
	request.getInputStream()也会报错，na，即：
	at org.eclipse.jetty.server.Request.getInputStream(Request.java:645) ~[na:na]
	at vision.apollo.cas.adaptors.eportal.action.BaseConfigAction.extractPostRequestBodyByStream(BaseConfigAction.java:309) ~[classes/:na]
	

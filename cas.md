IDEA打包命令：
	clean install -Dmaven.javadoc.skip=true -Dcobertura.skip=true -Dautoconfig.skip=true -Dmaven.test.skip=true 
	
========================================================================================================================================================
eclipse版本信息：
	Eclipse Java EE IDE for Web Developers.

	Version: Luna Release (4.4.0)
	Build id: 20140612-0600

	(c) Copyright Eclipse contributors and others 2000, 2014.  All rights reserved. Eclipse and the Eclipse logo are trademarks of the Eclipse Foundation, Inc., https://www.eclipse.org/. The Eclipse logo cannot be altered without Eclipse's permission. Eclipse logos are provided for use under the Eclipse logo and trademark guidelines, https://www.eclipse.org/logotm/. Oracle and Java are trademarks or registered trademarks of Oracle and/or its affiliates. Other names may be trademarks of their respective owners.

	This product includes software developed by other open source projects including the Apache Software Foundation, https://www.apache.org/.

尝试1：错误，eclipse-jee-luna-SR2-win32-x86_64；版本信息是：Version: Luna Service Release (4.4.2)，无JEF enhance的功能

尝试2：http://www.eclipse.org/downloads/packages/eclipse-ide-java-ee-developers/lunar

========================================================================================================================================================
	
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
	

刘建平: 

专网是43段的   公安网是10段的   中间有边界，根据规定无法直接打通 只能打通几个端口

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


chenzhe8:

各位好：
怀化项目和第三方对接在开发完成后现场测试发现在从我们平台去第三方平台进行token校验时候,
因为两个网段不通的关系导致请求无法发出去。现场同事给的意见是网络边界可以对指定端口进行放行来处理。
为了实现指定请求端口功能，我们一方面在调研相关的技术实现，一方面进行相应的测试，
但是在测试过程中又发现几点问题：
1、一旦制定端口，该请求都要经过该端口发送出去，因为端口不能复用，请求只有排队依次发出去；
2、基于网络通信的一些基本原理，端口使用过后需要经过释放，才能被下次请求使用，
而网络层为了保障通信质量，释放是需要时间的，一般默认为4分钟，可以设置改到30秒，
也就是说当有并发请求时，用户至少要等待30秒以上才能打开页面，这肯定是不能让用户接受的。

基于以上考量，我方认为应该基于项目现场的网络环境重新设计对接方案。


-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
蒋东林5:

刘工，这我看到过了，我是这样想的。怀化有个特色，小范围的走双网卡服务器暂时是默认的。
那么能否直接中转方式，如8200→中间件（类似双网域mq）→警务平台来实现？

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
chenzhe8:

如果有双网卡服务器的话，理论上可以在双网卡服务器上部署一个代理服务器，这样平台把请求代理到双网卡服务器，由双网卡服务器转发到警务平台

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

寒假所用到的技术：

完全跨单点域登录技术
web flow技术

cas项目中需要处理的问题：
1，？？？在怀化项目中，残留的问题：如果cas已经登录过，（胡鹏跃登录），app再用蔡益达登录之后，再次访问cas主页，显示的是胡鹏跃，而不是蔡益达？？？

1，需要根据会话ID(即sessionId)能访问到这个session。因为根据前面登出流程说明，认证中心的登出请求不是直接来自连接的浏览器用户，可能来自某应用系统。（所以，应用系统必须保存全局sessionId）
hpyps：
以STId为key，存储在currentHashMap里面，对应的value为一个xml文件，里面有此app对应的全局会话的Id，即TGTId；
而，以TGTId为key，存储在currentHashMap里面，对应的value为一个xml文件，里面有此全局会话已经认证过的app列表（即用STList表示，一个app～一个STId）；

认证中心也必须能够通知注册的系统应用进行登出。（所以，认证中心也应该保存应用系统的局部sessionId）
这些请求，都是系统之间的交互，不经过用户浏览器。系统要有根据sessionId访问session的能力。同时，在认证中心中，还需要维护全局会话ID和已登录系统本地局部会话ID的关系，以便认证中心能够通知已登录的系统进行登出处理。

2,CAS还允许直接校验非login.jsp页面传过来的用户名和密码的校验请求。这个功能是用于非web应用的SSO，这在后面的桌面SSO中会用到的。（https://yq.aliyun.com/articles/338905）
hpyps：对应于海康的remoteLogin登录的流程。remoteLogin还可以进行改造。

网上的帖子：
    1，《SSO CAS单点系列》之 15分钟让你了解SSO技术到底是个什么鬼！
	2016-01-08 11:33:44
	hpyps：http协议是无状态的协议。为了保存登录用户的会话标识，使用cookie机制，cookie代表一小撮数据。服务器通过HTTP相应创建好cookie后，浏览器会存储起来，browser下次向server发送请求的时候，会自动的带上cookie给服务器端，服务器端识别出cookie中代表的用户信息，就能知道这是一个已经登录过的用户。利用cookie机制，我们可以把某个用户的登录状态保存在里面，这是客户端的保存方式。
	但是，cookie的数据的携带量具有一定的限制。
	所以，更好的方式是服务器端来保存登录用户的状态信息。而cookie改存服务器端保存登录用户信息的句柄。即：用户登录成功之后，服务器便会为此用户创建一个唯一的登录会话，并将会话的标识ID通过cookie返回给浏览器，浏览器下一次向服务器请求时，会自动带上这个ID，服务器根据cookie中的ID找到服务器端存储的登录用户的信息，从而判断出是否是已经登录过的用户。
	
	对应cookie来说，出于安全性的考虑，它有一个作用域的问题，这个作用域由属性Domain和Path共同决定的。也就是说，如果浏览器发送的请求，不在此cookie的作用域范围之内的，请求是不会带上此cookie的。（cookie如同一个人手中的会员卡，卡上面只有一个卡号，所有的用户信息，都能通过此卡号到发出此会员卡的店内获取（等价于用户信息都在服务器端存储），作用域就如同不同的店铺发出不同的会员卡，肯德基的会员卡和全家的会员卡不能通用的，如果肯德基连锁店中的店铺A，发出了自己A店铺特殊的会员卡，那么，当你下次访问这个A店铺的时候，需要带上A店铺自己发布的会员卡和肯德基连锁店通用的会员卡，而不会带上访问全家连锁店的会员卡）。
	path是访问路径，我们可以定义/根路径让其作用于所用的路径。但是，。domain就不一样了，我们不能定义顶级域名如com，让其对于所有的吃哦买网站都起作用。最大范围，我们只能定义到二级域名，如：taobao.com，而，通常情况下，一个企业可能包含有多个二级域名，如taobao.com, tmail.com, alitrip.com等等，所以，可以作用在taobao之下的cookie，便不能作用于tmail和alitrip之下了。	解决单系统问题的cookie机制不起作用了，多系统不能共享同一个会话，这就是问题的所在。

    2，《SSO CAS单点系列》之 实现一个SSO认证服务器是这样的！
	2016-01-08 13:23:00
帖子地址：http://www.imooc.com/article/3558
Hpyps：帖子里面主要论述了：实现认证服务器时要注意的三个关键问题。

    3，《SSO CAS单点系列》之 自己动手实现一个属于自己的SSO认证服务器！
	2016-01-08 14:02:01
Hpyps：帖子里面只有代码的片段，和主要的几个接口的设计文档：输入输出以及接口的功能。
    4，《SSO CAS单点系列》之 实操！轻松玩转SSO CAS就这么简单(相遇篇)
	2016-01-08 15:09:42
	《SSO CAS单点系列》之 实操！轻松玩转SSO CAS就这么简单(相识篇)
	2016-01-12 09:47:26 
	
	《SSO CAS单点系列》之 支持Web应用跨域登录CAS（千斤干货）
	hpyps：在原有的应用系统页面进行登录认证中心，如，不发生跳转，我们需要使用Ajax方式。而最常用的XML HttpRequest Ajax方式调用，存在一个跨域的问题。即，为了安全，Ajax本身是不允许跨域调用的。

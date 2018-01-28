remoteLogin-webflow.xml(D:\HPY\jinhua\imp\sso\cas\src\main\webapp\WEB-INF\remoteLogin-webflow.xml)
此xml文件之中，抽象出remoteLogin登录的流程：

remoteLoginAction(尝试取tgt，)，调用：101

ticketGrantingTicketExisitsCheck（检查TGT是否存在，如果存在->跳到serviceAuthorizationCheck，调用102；如果不存在->跳到isMockLogin（从cas客户端的模拟登录））

serviceAuthorizationCheck（提前检查一下要访问的service是否是本系统有的：serviceAuthorizationCheck.java: 如果没有service，直接返回success；如果有service{如果系统找不到此service，报错；如果是注册的服务但是未启用，报错；其余情况，返回success；}）如果没报错，->realSubmit

realSubmit（调用103，：remoteAuthenticationViaFormAction.submit(flowRequestContext, messageContext)，如果返回success，->跳转到sendTicketGrantingTicket（将新的TGT设置到cookie中）; 如果返回error，->跳转到remoteCallbackView报错的页面）

sendTicketGrantingTicket(调用104，：sendTicketGrantingTicketAction.java: 此类处理TGT的创建和销毁工作：如果没有TGT，直接返回success；行37：从context中取出TGT（这是新的TGT）；行38：从cookie中能够取出TGT（这是旧的TGT）&& 旧的TGT确实存在，就把新的TGT加入到cookie中，把旧的TGT销毁掉（即：旧的TGT销毁并用新的TGT替代之）)进行完流程之后，跳到serviceCheck；

serviceCheck(检查flowScope中的service是否存在（又跳转到了remoteLogin），如果存在,->跳转到generateServiceTicket（这种情况，说明是：先访问一个app（即service），发现没登录，重定向到cas进行登录，认证了用户之后，产生TGT，需要先产生ST，接着再重定向到app）；如果不存在,->跳转到casloginDesion)

generateServiceTicket(行46：产生ST，组装一个带有此ST的url，具体调用：1.1.1，返回success)如果返回success，那么->跳转到warn

warn（根据flowScope中的warnCookieValue的值的真与假来判断，如果为真，->跳转到showWarningView; 如果为假，->跳转到redirect）

redirect(根据flowScope.service.getResponse(requestScope.serviceTicketId)的值的有无，如果有，那么->跳转到postRedirectDecision)

postRedirectDecision(根据requestScope.response.responseType.name() == 'POST' 如果等于，->跳转到postView；如果不等于，跳转到->redirectView)

postView 渲染view属性定义的那个视图，一个例子：view="postResponseView"

redirectView 渲染view属性定义的那个视图，如果添加了“externalRedirect:”前缀的话，将会重定向到流程外部的页面，一个例子：view="externalRedirect:${requestScope.response.url}"

========================================================================================================================================================
函数功能：
    构造函数
ExternalRedirectAction.ExternalRedirectAction(final RequestContext context){
    
}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
函数功能：
    切换transition的函数:根据前一个transition执行的结果，来判断下一步该执行哪个transition；
	
1007，protected void ActionState.doEnter(RequestControlContext context){
    行101，执行action，获取执行的结果，调用：1006，Event event = ActionExecutor.execute(action, context);
	行105，调用1007.1，context.handleEvent(event);
	行106，返回；
}

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

1007.1，public boolean RequestControlContextImpl.handleEvent(Event event){
    行210，返回，，调用1007.1.1，return flowExecution.handleEvent(event, this);
}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
1007.1.1，
public boolean FlowExecutionImpl.handleEvent(Event event){

    行388，返回， ，调用1007.1.1.1，：return getActiveSessionInternal().getFlow().handleEvent(context);
}

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
1007.1.1.1，
public boolean Flow.handleEvent(RequestControlContext context){
    获取现在所处的状态：一个例子：[ActionState@267dc857 id = 'realSubmit', flow = 'remoteLogin', entryActionList = list[[empty]], exceptionHandlerSet = list[[empty]], actionList = list[[AnnotatedAction@2138976a targetAction = [EvaluateAction@700fc692 expression = remoteAuthenticationViaFormAction.submit(flowRequestContext, messageContext), resultExpression = [null]], attributes = map[[empty]]]], transitions = list[[Transition@4e40dc01 on = warn, to = warn], [Transition@6379aee on = success, to = sendTicketGrantingTicket], [Transition@6351de85 on = error, to = remoteCallbackView], [Transition@6de4af2b on = accountDisabled, to = casAccountDisabledView], [Transition@250cd642 on = mustChangePassword, to = casMustChangePassView], [Transition@1f56d8e7 on = accountLocked, to = casAccountLockedView], [Transition@729e987e on = badHours, to = casBadHoursView], [Transition@3a4becf1 on = badWorkstation, to = casBadWorkstationView], [Transition@79b6833c on = passwordExpired, to = casExpiredPassView]], exitActionList = list[[empty]]]
	调用：1007.1.1.1.1，return currentState.handleEvent(context);
}

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

1007.1.1.1.1，
public boolean TransitionableState.handleEvent(RequestControlContext context){
    根据返回的transition，执行to代表的那个action，调用1007.1.1.1.1.1，：return context.execute(getRequiredTransition(context));
}

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
1007.1.1.1.1.1，
public Transition ActionState.getRequiredTransition(RequestContext context){
    调用1007.1.1.1.1.1.1，    
}

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
函数功能：
    遍历this中所有的transition的数组transitions，从数组中找到与返回的结果匹配那个的那个transition
1007.1.1.1.1.1.1，
public Transition TransitionSet.getTransition(RequestContext context){
    返回：一个例子[Transition@6379aee on = success, to = sendTicketGrantingTicket]
}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
1006，public static Event ActionExecutor.execute(Action action, RequestContext context){
    行51，调用：Event event = action.execute(context);
	行55，返回，行51，调用的结果：return event;
}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
1005，public Event AnnotatedAction.execute(RequestContext context){
    行145，执行指定的action，获取执行的结果，调用：1004，Event result = getTargetAction().execute(context);
	行146，返回，调用postProcessResult方法的结果，调用：return postProcessResult(result);
}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
函数功能：
    
1004，public final Event AbstractAction.execute(RequestContext context){
    行188，执行action，获取执行的结果，调用：1003，result = doExecute(context);
	行195，返回行188调用所返回的result；
}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
函数功能：
    
1003，protected Event EvaluateAction.doExecute(RequestContext context){
    行75：从context里面获取result，
	如果result是Action的派生类的对象{
        行77：直接返回 “ 执行指定的action ”的结果，调用: 1002，return ActionExecutor.execute((Action) result, context);
	}esle{
	    如果resultExpression不为bull{
		    
		}
	}
	行82：调用：1003.1，return resultEventFactory.createResultEvent(this, result, context);
}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
1003.1，
public Event resultEventFactory.createResultEvent(Object source, Object resultObject, RequestContext context){
    只有一行：直接返回调用1003.1.1，的结果，return selector.forResult(resultObject).createResultEvent(source, resultObject, context);
}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
1003.1.1，
public ResultEventFactory ResultEventFactorySelector.forResult(Object result){
    如果result为null{
	
	}else（如果result不为null）{
	    返回结果，获取result的类的信息，掉用1003.1.1.1，：return forType(result.getClass());
	}
}

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
1003.1.1.1，
protected ResultEventFactorySelector.ResultEventFactory forType(Class resultType){
    
}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
函数功能：
    执行指定的action
1002，public static Event ASbstractExecutor.execute(Action action, RequestContext context){
    行51，执行指定的action，调用：1001，Event event = action.execute(context);
	行55，返回行51的返回值event；
}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

1001，public final Event AbstractAction.execute(RequestContext context{
    行188，执行action-state里面具体的evaluate expression，调用: result = doExecute(context);
	行195，返回result；
}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
在remoteLogin-webflow.xml文件中，
行28～行30，
    <on-start>
        <evaluate expression="remoteLoginAction" />
    </on-start>
	
注意：<evaluate expression="">=后面的内容不是一个具体的方法的调用，而是一个类的名字，所以：这个类：RemoteLoginAction是一个bean，
需要继承自AbstractAction父类，实现doExecute();doExecute方法是对应处理此阶段业务的方法。
海康源代码中的注解：
<!--  on-start标签定义了用户第一次进入流程中的预处理动作， 	该标签对应spring中的id为initialFlowSetupAction的bean。
    	查看该bean（InitialFlowSetupAction）的代码，该类需要继承自AbstractAction。
    	AbstractAction方法是org.springframework.webflow.action包中的类，是webflow中的基础类。
    	该类中的doExecute方法是对应处理业务的方法，就犹如servlet中的service方法一样。
    	该方法的参数是RequestContext对象，该参数是一个流程的容器。
    	该方法从request中获取TGT，并且构建一个临时的service对象（不同域注册的service）。
    	并且，将TGT和service放在FlowScope作用域中。 -->
		
101，RemoteLoginAction.doExecute(){
    行53：判断是否是重定向：调用：boolean redirect = ImpPropertiesManager.getInstance().getProperties("cas.redirect", "false").equals("true");
	行57：如果redirect为真{
	
	}行71：else(redirect为假){
	    不知道在干什么？？？
	}
	行81：从url的参数里面再取一把tgt；
	行92：不管tgt是否为null，将tgt放入flow中，调用：context.getFlowScope().put("ticketGrantingTicketId", tgt);
	行95：从context里面取出service，调用：final Service service = WebUtils.getService(this.argumentExtractors, context);
	行102：将service放入flowScope中，
}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
函数功能：
    提前检查一下要访问的service是否是本系统有的
102，ServiceAuthorizationCheck.doExecute(final RequestContext context){
    行54：从context里面取service，调用：final Service service = WebUtils.getService(context);
	行56：如果service为null{
	    返回success；
	}
	如果service不为null：进行如下的代码逻辑：
	{
	    如果系统找不到此service，报错；
		如果是注册的服务但是未启用，报错；
		其余情况，返回success；
	}
	
}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 在remoteLogin-webflow文件中，
 行153，<evaluate expression="remoteAuthenticationViaFormAction.submit(flowRequestContext, messageContext)" />
 此时，<evaluate expression="">，=后面的内容不是一个类的名字，而是一个具体的类的方法的调用，所以：这个类RemoteAuthenticationViaFormAction：不需要从AbstractAction派生。
103，remoteAuthenticationViaFormAction.submit(flowRequestContext, messageContext){

}
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
104，
protected Event sendTicketGrantingTicketAction.doExecute(final RequestContext context){
    如果没有TGT，{
	    直接返回success；
	}
	行47：从context中取出TGT（这是新的TGT）；调用104.1，：public void addCookie(final HttpServletRequest request, final HttpServletResponse response, final String cookieValue)
	行48：从cookie中能够取出TGT（这是旧的TGT）&& 旧的TGT确实存在，就把新的TGT加入到cookie中，把旧的TGT销毁掉（即：旧的TGT销毁并用新的TGT替代之）)进行完流程之后，跳到serviceCheck；
}

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
104.1，
public void CookieRetrievingCookieGemerator.addCookie(final HttpServletRequest request, final HttpServletResponse response, final String cookieValue){
    如果从request里面可以取到名为“rememberMe”的值，{
	    创建cookie，将TGTId放进去，调用：super.addCookie(response, cookieValue);
	}
}

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


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
    根据有无TGT做不同的事情：（TGT的有无即代表全局会话是否存在，即：TGTId对应的XML文件存在，标识该用户已经在CAS登录和验证）
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
	行104：如果有TGTId：{
	    1，如果cookieTgt为真，{
		    认证ST，调用：serviceTicketId =      this.centralAuthenticationService.grantServiceTicket(ticketGrantingTicketId, service, null);
		}else (如果cookieTgt为假){
			2，行110：根据credentials认证ST，调用：serviceTicketId = this.centralAuthenticationService.grantServiceTicket(ticketGrantingTicketId, service, credentials);
		}
		行113，将STId放入RequestScope里面，调用：WebUtils.putServiceTicketInRequestScope(context, serviceTicketId);
		如果有TGTId，在取TGT对象的过程中抛出异常，{
            跳转到行136：销毁这个TGT的对象，调用this.centralAuthenticationService.destroyTicketGrantingTicket(ticketGrantingTicketId);
		}
	}
	3，行150：如果没有TGT，就产生TGT，（调用：this.centralAuthenticationService.createTicketGrantingTicket(credentials)）
	4，并且，同时将产生的TGT设置到requestScope里面，调用：
	WebUtils.putTicketGrantingTicketInRequestScope(context, this.centralAuthenticationService.createTicketGrantingTicket(credentials));
	
}
--------------------------------------------------------------------------------------------------------------------------------------------------------
1,GenerateServiceTicketAction(AbstractAction).execute(){
    1.1，行188，根据TGT产生ST，调用：result = doExecute(context);
	1.2，行189，？？？不知道干了什么，调用：doPostExecute(context);
	返回 result;(result是一个Event对象，表示产生ST这个动作是成功的或者失败的)
}

--------------------------------------------------------------------------------------------------------------------------------------------------------
函数功能：
    产生ST，并且，将ST组装到一个service的url，cas认证中心访问这个带有ST的service，
	
1.1, GenerateServiceTicketAction.doexecute(Context context){
    1.1.1 也是2， 行45：产生ST，返回STId，调用：final String serviceTicketId = this.centralAuthenticationService
	                                            .grantServiceTicket(ticketGrantingTicket, service);
	行51～行63，构造带有ST的url，调用：encodeUrl += maoStr;比如：一个具体的例子：http://10.6.130.110:8087/apollo-web/web/role.action?ticket=ST-1-lVApdjLe11HZs1QGeQfM-cas
	1.1.2，行65：然后将此url放到了context里面，调用：context.getRequestScope().put("encodeUrl", encodeUrl);
	行67，返回success；请求此构造的url，胡鹏跃猜想：靠的是webFlow的xml文件，来走的这个cas认证的流程
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
4,
public static void WebUtils.putTicketGrantingTicketInRequestScope(final RequestContext context, final String ticketValue) {
    行76：将TGTId放入RequestContext，调用：context.getRequestScope().put("ticketGrantingTicketId", ticketValue);
	行78：将TGTId放入？？？，调用：context.getFlowScope().put("ticketGrantingTicketId", ticketValue);
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
HikTicketRegistry类主要功能：ticket的管理，包括：添加（addTicket），查找（getTicket），删除（deleteTicket）
    addTicket：将ST/TGT分类放在同一个concurrentHashMap下面；
	getTicket：根据ticketId，到concurrentHashMap 里面取xml文件，再转换成ticket，并返回ticket；
	deleteTicket，根据ticketId，从concurrentHashMap里面删除ticket；作为ticket的定时的清除器的实现函数，被HikTicketRegistryCleaner.run()方法行45被调用；行46，清除Ehcache缓存里面的userStatus的数据
	

继承关系：
HikTicketRegistry extends DefaultTicketRegistry extends AbstractTicketRegistry implements TicketRegistry
tgt对应的存储的xml的一个例子：
DEBUG vision.apollo.cas.adaptors.auth.HikTicketRegistry - HikTicketRegistry put ticket:
TGT-1-fesmEObqhBAdXGdGAW9PmKfXBYdrSboLuwJTZuBH6BlYmRSJgN-cas, to: Ticket_Key_Map, 

xml:<?xml version="1.0" encoding="UTF-8"?>

<tickets>
  <ticket>
    <class>TicketGrantingTicketImpl</class>
    <expired>false</expired>
    <authentication principal="1&amp;&amp;admin&amp;&amp; &amp;&amp; &amp;&amp; " authenticatedDate="2018-01-28 18:52:40"/>
    <id>TGT-1-fesmEObqhBAdXGdGAW9PmKfXBYdrSboLuwJTZuBH6BlYmRSJgN-cas</id>
    <expirationPolicy>1500000</expirationPolicy>
    <lastTimeUsed>1517136760591</lastTimeUsed>
    <previousLastTimeUsed>1517136760222</previousLastTimeUsed>
    <creationTime>1517136760222</creationTime>
    <countOfUses>0</countOfUses>
  </ticket>
</tickets>
3.3，public void HikTicketRegistry.addTicket(Ticket ticket){
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
函数功能：
    cas认证中心验证app返回的ST的有效性
	
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
-------------------------------------------------------------------------------

    2，《SSO CAS单点系列》之 实现一个SSO认证服务器是这样的！
	2016-01-08 13:23:00
	帖子地址：http://www.imooc.com/article/3558
	
Hpyps：帖子里面主要论述了：实现认证服务器时要注意的三个关键问题。
-------------------------------------------------------------------------------
    3，《SSO CAS单点系列》之 自己动手实现一个属于自己的SSO认证服务器！
	2016-01-08 14:02:01
	
Hpyps：帖子里面只有代码的片段，和主要的几个接口的设计文档：输入输出以及接口的功能。
-------------------------------------------------------------------------------

    4，《SSO CAS单点系列》之 实操！轻松玩转SSO CAS就这么简单(相遇篇)
	2016-01-08 15:09:42
	
hpyps:
    引入了cas；并介绍了一种开源的cas架构:Apereo；后文下载和使用了Apereo；体验课一下。没有剖析源代码和代码的组成架构。
-------------------------------------------------------------------------------

	《SSO CAS单点系列》之 实操！轻松玩转SSO CAS就这么简单(相识篇)
	2016-01-12 09:47:26 
hpyps: 
	tgt并没有放到session中，cas全局会话的实现并没有直接使用session机制，而是利用了cookie自己实现的，这个cookie叫做TGC，里面存放了TGTId，认证中心的服务端实现了TGC
	cas-server-core提供的核心模块只有两个部分，一是票据ST，包括票据的产生，查询，删除，存储等各种操作。另一个是认证，提供多种认证方式。
    作为独立运行的Web应用，CAS还需要提供与浏览器用户的交互，与需要认证的应用系统交互，这些逻辑，绝大部分放在sso/cas/src/main/java/webapp
	CAS认证中心采用SpringMVC+Spring WebFlow实现的方式.
	
	CAS应用的整体架构，官方提供了一个比较清晰的架构图：
	CAS Server分为webflow的流程抽象；ticketing模块（包括TGT和ST）；authentication认证模块，认证分为不同的方式：数据库校验，那就要和对应的数据库进行通信。
	
	CAS Clients：？？？
-------------------------------------------------------------------------------
    《SSO CAS单点系列》之 实操！轻松玩转SSO CAS就这么简单(相知篇)
	2016-01-12 10:06:10
	hpyps：ticketRegistryCleaner，定时任务采用Spring集成的Quartz实现？？？
	tgt的时效是被动后验方式，在这种情况下，我们需要一个清除器来定期的清除内存中的还未经过处理的ticket。这个清除器在ticketRegistry.xml文件中定义，叫ticketRegistryCleaner，定时任务采用Spring集成的Quartz实现？？？
	TGT的Id在客户端TGTCookie中，因此要保持全局会话，不仅服务器端的TGT这个票据对象要存在，同时，TGC这个Cookie也不能过期。在ticketGrantingTicketGenerator.xml中，缺省情况下，p:cookieMaxAge="-1"表示TGC长期有效，不需要修改，所以，只需要服务器端用Policy控制TGT的有效期就可以了。
	
-------------------------------------------------------------------------------
    《SSO CAS单点系列》之 大型互联网应用基于CAS的SSO架构(精华)
	2016-01-14 15:06:18
	hpyps：主要介绍了为什么cas要用集群，以及用redis来实现集群的方式。
	
	认证中心这个关键部件通常需要进行集群，单个认证中心提供服务是非常危险的。
	当我们使用CAS作为sso的解决方案的时候，cas server作为认证中心就会涉及到集群的问题。对cas server来说，缺省是单应用实例运行的，多实例集群运行，我们需要做特殊考虑。
	考虑集群，就要考虑应用中有哪些点和状态相关，这些状态相关的点和应用的运行环境密切相关。在多实例运行下，运行环境是分布式的，这些状态相关的点需要考虑，在分布式环境下，如何保持状态的的一致性
	鉴于cas的实现方式，状态相关点有两个。一是cas登录登出的流程，采用webflow实现，流程状态存储于session中。二是票据的存储，缺省是在JVM的内存中。
	那么cas集群，我们需要保证多个实例下，session中的状态以及票据存储状态是一致的。常用的方案是共享，也就是说，在多cas实例下，他们的session和票据是共享的，这样就解决了一致性的问题。（hpyps：就如同struts2一样，controller是多实例的，所以，一个controller内部的方法共享类定义的属性的值，而不是像springmvc一样单例的，每个@RequestMapping的方法单例的，只处理本方法传入的变量的数据）
	cas在tomcat下面运行的话，官方提出的建议是利用tomcat集群进行session的复制（session Replication）。在高并发的状态下，这种session的复制效率不是很高，节点数增多是更是如此。实战中应用很少。
	我们可以采用共享session的技术。在笔者的实践中，则采用了另外一种更为灵活的方案。那就是session sticky技术。
	
-------------------------------------------------------------------------------
	《SSO CAS单点系列》之 支持Web应用跨域登录CAS（千斤干货）
	2016-01-15 17:07:23
	？？？It和execution参数是什么？
	-------------------------------------------------------------------------------
	
	？？？如何启用的webflow？浏览器输入：http://10.6.130.110/cas/remoteLogin?token=5D877242155AFE74E053455C920AEF7A
	首先在cas-servlet.xml文件中
	配置了<flow-executor>
	flow-executor就是通过id来找出要具体执行的flow，具体有几个flow，每个flow的id都叫什么，在<flow-registry >进行详细的定义
	
	flowUrlHandler可以从HttpServletRequest中，根据url解析出webflow的Id，
	
	配置了webflow的<flow-registry >
	里面详细定义了flow的id名字叫什么，这个id的flow对应的流程的具体的定义的文件的路径是什么，一个例子：<webflow:flow-location path="/WEB-INF/login-webflow.xml" id="login" />（flow的id为login，这个flow 的具体的流程详细见这个路径下的文件的定义：path="/WEB-INF/login-webflow.xml"）
	-------------------------------------------------------------------------------
	public final HandlerExecutionChain AbstractHandlerMapping.getHandler(HttpServletRequest request){
	    行298，根据request中的url来获取处理此url的handler，调用10002，Object handler = getHandlerInternal(request);
	}
	-------------------------------------------------------------------------------
	
	10002，
	protected Object CharacterEncodingFilter.getHandlerInternal(HttpServletRequest request){
	    行92，从request中尝试获取一个flowId，调用10001，
		行96，从判断是不是一个bean
		行106，从flowRegistry里面，判断有没有一个flow的Id匹配这个flowId，如果有{
		    行111，用此flowId，创建一个flowHandler，并且返回，调用：return createDefaultFlowHandler(flowId);
		}
	}
	-------------------------------------------------------------------------------
	函数功能：
	尝试从request里面获取flowId
	10001，
	public String DefaultFlowUrlHandler.getFlowId(HttpServletRequest request){
	
	}
	
	-------------------------------------------------------------------------------
	为什么进入了remoteLogin-webflow文件中，定义好的流程？而不是login-webflow文件中，定义的？哪个文件做了配置，以实现的区分？
	hpyps：在原有的应用系统页面进行登录认证中心，如，不发生跳转，我们需要使用Ajax方式。而最常用的XML HttpRequest Ajax方式调用，存在一个跨域的问题。即，为了安全，Ajax本身是不允许跨域调用的。
	而最常使用的xmlhttprequest Ajax方式，存在一个跨域的问题，即，为了安全，Ajax本身是不允许跨域调用的。
	在应用页面中，如何达到远程登录cas的效果？摆在我们面前有两道坎儿需要克服：
	首先是远程获取It金额execution参数值的问题。cas登录的form提交，不仅有username和password两个参数，还包括It和execution，It防止重复提交，execution保证走的同一个webflow流程。在进行远程提交的时候，我们需要远程得到cas动态产生着两个参数，从而保证能够向cas进行正确的form提交。？？？
	
-------------------------------------------------------------------------------
	《SSO CAS单点系列》之 APP原生应用如何访问CAS认证中心(系列结束)
	2016-01-20 18:09:02
	
-------------------------------------------------------------------------------
	《Spring Web Flow 2.0 入门》
	https://www.ibm.com/developerworks/cn/education/java/j-spring-webflow/index.html
	web应用程序中的三种范围：
	request范围中的对象是和客户的每一次具体的请求绑定在一起的。每次请求结束都会销毁对象，而，新的请求过来的时候，又会去创建新的对象。request范围适合存放数据量较大的临时数据。
	
	session范围中的对象是跟会话（session）绑定在一起的，每次会话结束会销毁这些对象。新的会话又会创建新的对象。http协议本身是无状态的。session范围适合存放本次会话需要保留的数据。
	
	application范围的对象是跟应用程序本身绑定在一起的，从servlet API的角度来说，就是存放在servletContext中的对象，他们随着Servlet的启动而创建，Servlet关闭时才会销毁。application范围适合存放那些与应用程序全局相关的数据。
	
	从现实应用的角度来说，session的范围很“鸡肋”，把大量的数据放入session会导致严重的效率问题，在分布式的环境中处理session，更是一不小心就会出错。request的范围虽说能存放大量的数据，但是，范围有限。
	spring web flow提供了解决方案：
	flow范围：
	conversation范围：
	
	spring Web Flow的基本的元素：
	Flow可以看作是客户端和服务器端的一次对话（conversation）。Flow的完成要由分多个步骤来实现，在spring Web Flow的语义里面，步骤的含义就是state。springwebflow提供了五种state。分别是Action state，view state，subflow state， decision state， end state
	这些state可用于定义flow执行过程中的各个步骤。除了end state，其他state都可以转换到别的state，在state中，通过定义transition来实现到其他state的转换。转换的发生，一般由事件（event）来触发的。
	
	
========================================================================================================================================================
#有关IDEA的总结

##打包命令：
	clean install -Dmaven.javadoc.skip=true -Dcobertura.skip=true -Dautoconfig.skip=true -Dmaven.test.skip=true 

##快捷键
###寻找某个接口方法的具体实现方法：
    ctrl+Alt+B
###已知文件名，直接选中文件名，打开同名的文件
	ctrl+shift+N
###调试快捷键
    F7，进入到代码；
	Alt+shift+F7, 强制进入到代码；
	F8，跳到下一步；
	shift+F8，跳到下一个断点
	Alt+F9, 运行到光标处。
	调试功能的使用方法的总结帖子：
	http://blog.csdn.net/qq_27093465/article/details/64124330
========================================================================================================================================================
#海康用的eclipse
##海康用的eclipse版本信息：
	Eclipse Java EE IDE for Web Developers.

	Version: Luna Release (4.4.0)
	Build id: 20140612-0600

	(c) Copyright Eclipse contributors and others 2000, 2014.  All rights reserved. Eclipse and the Eclipse logo are trademarks of the Eclipse Foundation, Inc., https://www.eclipse.org/. The Eclipse logo cannot be altered without Eclipse's permission. Eclipse logos are provided for use under the Eclipse logo and trademark guidelines, https://www.eclipse.org/logotm/. Oracle and Java are trademarks or registered trademarks of Oracle and/or its affiliates. Other names may be trademarks of their respective owners.

	This product includes software developed by other open source projects including the Apache Software Foundation, https://www.apache.org/.

##尝试1：
    结果：错误，eclipse-jee-luna-SR2-win32-x86_64；版本信息是：Version: Luna Service Release (4.4.2)，无JEF enhance的功能

##尝试2：    
    下载的路径为：http://www.eclipse.org/downloads/packages/eclipse-ide-java-ee-developers/lunar
    结果：虽然是正确的Luna版本，但是没有JEF加强的插件。公司给的带JEF的eclipse的软件包里面，看文件的目录，也不知道有关JEF的插件是哪个。

##尝试3：
    看来只能用IDEA了，依据caiyida的指导，可以跑起来项目了。

##用IDEA配置Apollo+sso项目的具体的过程：

###导入maven项目
	修改本地的maven仓库的地址:
	File->settings->左上角搜索框搜索”maven”, local repository修改为本地的maven的目录。如D:/.m2/repository
###配置tomcat：
    新建一个本地的tomcat,在server标签页下面:将After launch前面的勾去掉；Apollo将http port修改为8087，JMX port不变。
	在Deployment标签页下面,新建一个apollo-web:war exploded.
    在右侧的Application context框内输入: /apollo-web
    新建一个war exploded artifact
### 将IDEA切换到terminal窗口,输入:
	mvn clean install -Dmaven.javadoc.skip=true -Dcobertura.skip=true -Dautoconfig.skip=true -Dmaven.test.skip=true
	最后看到 BUILD SUCCESS

### 新开一个idea，导入cas项目
	配置tomcat，修改名为name为cas；去掉After launch的前面的勾；将http port改为8082 ； jmx port修改为1100
    在deployment标签页下面.新建一个cas:war exploded.
    在右侧的Application context框内输入: /cas
    新建一个war exploded artifact

### 访问cas登录页面输入：
    127.0.0.1:8082/cas

### 访问apollo-web系统，输入：
	http://127.0.0.1:8087/apollo-web/web/user.action


========================================================================================================================================================

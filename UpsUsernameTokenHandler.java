package vision.apollo.cas.adaptors.ups;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import jef.tools.collection.CollectionUtil;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.jasig.cas.authentication.handler.*;
import org.jasig.cas.authentication.principal.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import vision.apollo.cas.adaptors.auth.HikHandlerAsyncHelper;
import vision.apollo.cas.adaptors.auth.HikHandlerHelper;
import vision.apollo.cas.adaptors.auth.common.LocalThreadContext;
import vision.apollo.cas.adaptors.common.constants.LoginType;
import vision.apollo.cas.adaptors.eportal.action.TokenValidateResult;
import vision.apollo.cas.adaptors.storage.UserStatus;
import vision.apollo.cas.adaptors.userStatus.IUserStatusService;
import vision.apollo.cas.constants.ErrorCodeConstants;
import vision.apollo.publicservice.module.license.service.RemoteLicenseService;
import vision.apollo.sso.api.util.StringUtil;
import vision.apollo.ups.bo.RemoteUserResult;
//import vision.apollo.ups.bo.Result;
import vision.apollo.ups.constant.UpsConstants;
import vision.apollo.ups.domain.User;
import vision.apollo.ups.param.Param4User;
import vision.apollo.ups.remote.RemoteUserService;
import vision.apollo.util.ImpPropertiesManager;

import javax.annotation.PostConstruct;
import java.rmi.RemoteException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * CAS在权限系统中鉴权实现
 * 基于token进行
 * @author hupengyue 2018/01/06
 */
public class UpsUsernameTokenHandler implements AuthenticationHandler {
	private static final Logger log = LoggerFactory.getLogger(UpsUsernameTokenHandler.class);
	@Autowired
	private RemoteUserService remoteUserService;
	@Autowired
	private RemoteLicenseService remoteLicenseService;
	@Autowired
	private IUserStatusService userStatusService;
	@Autowired
	private HikHandlerHelper handlerHelper;
	@Autowired
	private HikHandlerAsyncHelper asyncHelper;

	private final static int EXPIRED_DAY = -15;

	private Set<Integer> controlledLoginTypes;
	
	private static final String VALIDATE_URL_POST = "&id=system/user/getuser";
	private static final Integer  STATUS_FAILURE= 0;
	private static final Integer  STATUS_SUCCESS= 1;
	private static final Integer  STATUS_TOKEN_EXPIRED_TIME= -1;

	@PostConstruct
	public void init() {
		this.controlledLoginTypes = handlerHelper.getControlledLoginTypes();
	}
	
	/**
	 * 校验license是否过期
	 * @throws BadCredentialsAuthenticationException
	 */
	private void licenseCheck() throws BadCredentialsAuthenticationException{
		Map<String, Object> licenseMap = null;
		try {
			licenseMap = remoteLicenseService.getLicenseExpiredInfo();
		} catch (RemoteException e) {
			log.error(e.getMessage(), e);
			throw new RemoteBadCredentialsAuthenticationException(ErrorCodeConstants.ERROR_RPC_INVOKE);
		}
		if (licenseMap==null || (Integer)licenseMap.get("leftDays") < EXPIRED_DAY) {
			throw new RemoteBadCredentialsAuthenticationException(ErrorCodeConstants.ERROR_LICENSE_INVALID);
		}
	}
	
	/**
	 *
	 * @param errorCode
	 * @return
    */
	private static RemoteUserResult buildRemoteUserResult(String errorCode){
		RemoteUserResult remoteResult = new RemoteUserResult();
		remoteResult.setResultCode(errorCode);
		if(ErrorCodeConstants.ERROR_RPC_INVOKE.equals(errorCode)){
			remoteResult.setMessage("远程服务调用失败，请联系管理员");
		}else if(ErrorCodeConstants.ERROR_LICENSE_INVALID.equals(errorCode)){
			remoteResult.setMessage("License已失效，禁止登录。");
		}else if(ErrorCodeConstants.ERROR_SYSTEM.equals(errorCode)){
			remoteResult.setMessage("系统错误，请联系管理员");
		}else if(ErrorCodeConstants.ERROR_LOGIN_EXCEED.equals(errorCode)){
			remoteResult.setMessage("您的账号在另一处登录，被迫下线");
		}else if(ErrorCodeConstants.ERROR_USER_ONLINENUMBER_EXCEED.equals(errorCode)){
			remoteResult.setMessage("该用户在线数已到达上限");
		}
		return remoteResult;
	}
	
	@Override
	public boolean authenticate(Credentials credentials) throws AuthenticationException {
		UpsUsernameTokenCredentials c = (UpsUsernameTokenCredentials)credentials;
		Integer loginType = handlerHelper.getLoginType(c);


		//校验证书是否过期
		licenseCheck();

		TokenValidateResult result = null;
		try {
			result = this.checkTokenAvailable(c.getToken());
		} catch (Exception e) {
			log.debug("UpsUsernameTokenHandler_authenticate() : " + e.toString());
			log.error("UpsUsernameTokenHandler_authenticate() : " + e.toString());
			RemoteUserResult remoteUserResult = new RemoteUserResult();
			remoteUserResult.setMessage("token校验远程服务调用失败，请联系管理员");
			RemoteUserResultHolder.setRemoteUserResult(remoteUserResult);
			throw new BadCredentialsAuthenticationException(ErrorCodeConstants.ERROR_RPC_INVOKE, e.getMessage());
		}
		
		if(this.STATUS_SUCCESS == result.getStatus()){
			//调用远程接口，看当前用户是否存在并且有效
			List<User> userList = null;
			try {//从result的username字段里面取出的是身份证，去数据库ups_user表里面匹配的是code字段
				userList = remoteUserService.findUsers(Param4User.build().setCode(result.getUsername()).setStatus(1));
			} catch (RemoteException e) {
				log.debug("UpsUsernameTokenHandler_authenticate() : " + e.toString());
				log.error("UpsUsernameTokenHandler_authenticate() : " + e.toString());
				RemoteUserResult remoteUserResult = new RemoteUserResult();
				remoteUserResult.setMessage("远程服务调用失败，请联系管理员");
				RemoteUserResultHolder.setRemoteUserResult(remoteUserResult);
				throw new RemoteBadCredentialsAuthenticationException(ErrorCodeConstants.ERROR_RPC_INVOKE);	
			}

			if (CollectionUtils.isNotEmpty(userList)) {
				c.setUsername(userList.get(0).getName());
				c.setUser(userList.get(0));
				asyncHelper.updateUserLogin(userList.get(0));
			} else {
				RemoteUserResult remoteUserResult = new RemoteUserResult();
				remoteUserResult.setMessage("用户无此权限");
				RemoteUserResultHolder.setRemoteUserResult(remoteUserResult);
				throw new BadCredentialsAuthenticationException(ErrorCodeConstants.ERROR_USER_NON_AVAILABLE, "用户无此权限");
			}
		} else {
			log.debug("token校验失败, message : " + null == result.getMessage()?"":result.getMessage()+", status : "+ result.getStatus());
			RemoteUserResult remoteUserResult = new RemoteUserResult();
			remoteUserResult.setMessage("token校验失败, message : " + result.getMessage()+", status : "+ result.getStatus());
			RemoteUserResultHolder.setRemoteUserResult(remoteUserResult);
			throw new BadCredentialsAuthenticationException(ErrorCodeConstants.ERROR_THIRD_TOKEN_EXPIRED, "token校验失败, message : " + null == result.getMessage()?"":result.getMessage()+", status : "+ result.getStatus());
		}
		LocalThreadContext.setObject("credentials", c);
		return true;
	}
	
	/**
	 * 检查token是否有效
	 *
	 *
	 * @param token @return
	 * @param username
	 */
	private TokenValidateResult checkTokenAvailable(String token) throws AuthenticationException {
		String validateUrlPre = ImpPropertiesManager.getInstance().getProperties("third_token_url");
		if(StringUtil.isNullOrEmpty(validateUrlPre)){
			throw  new RuntimeException("无法获取token校验地址");
		}
//		String validateUrl = validateUrlPre+"?token="+token + VALIDATE_URL_POST;
		String validateUrl = validateUrlPre;
		RestTemplate restTemplate = new RestTemplate();
		//设置请求的header
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		
		// #1,无token信息
//		JSONObject reqVO = new JSONObject(12);
//		reqVO.put("token", token);
//		reqVO.put("id", "system/user/getuser");
//        String jsonPost = reqVO.toString();
		
		//# #2.1 MediaType.\JSON "Data":"System.ArgumentException:Invalid JSON primitive: token.\r\n   #2.2 MediaType.APPLICATION_FORM_URLENCODED:org.springframework.http.InvalidMediaTypeException: Invalid media type "application / json; charset=gb2312": Invalid token character ' ' in token "application "
//		HttpEntity<String> entity = new HttpEntity<String>("token="+token+VALIDATE_URL_POST, headers);
		
		// #3, MediaType.APPLICATION_FORM_URLENCODED:org.springframework.http.InvalidMediaTypeException: Invalid media type "application / json; charset=gb2312": Invalid token character ' ' in token "application "
		//设置请求参数
		MultiValueMap<String, Object> map = new LinkedMultiValueMap<String,Object>();
		map.add("token", token);
		map.add("id", "system/user/getuser");		
		HttpEntity<MultiValueMap<String, Object>> entity = new HttpEntity<MultiValueMap<String, Object>>(map, headers);
		log.debug("starting restTemplate.postForEntity({}, {}, String.class)",validateUrl,entity);
		//执行请求，发送Post，并返回一个ResponseEntity<String>对象
		ResponseEntity<String> response = restTemplate.postForEntity(validateUrl, entity, String.class);
		log.debug("after restTemplate.postForEntity({}, {}, String.class)",validateUrl,entity);
		log.debug("response.toString() = {}"+response.toString());
		String body = response.getBody();
		log.debug("checkTokenAvailable(): restTemplate.postForEntity({}, String.class) = {}",validateUrl,response);
		log.debug("headers = "+headers +", " + " entity = "+ entity + ", body = " + body);
		JSONObject object = JSON.parseObject(body);
		TokenValidateResult result = new TokenValidateResult();
		//请求失败
		if(!this.STATUS_SUCCESS.equals(Integer.parseInt(object.getString("Status")))){
			result.setStatus(Integer.parseInt(object.getString("Status")));
			result.setMessage(object.getString("Data"));
			log.error("checkTicketAvailable 请求失败, object.getString(Data) = {}"+ object.getString("Data"));
			return result;
		}
		result.setStatus(this.STATUS_SUCCESS);
		JSONObject data = object.getJSONObject("Data");
		if(null == data){
			result.setStatus(this.STATUS_FAILURE);
			result.setMessage("从警务云系统返回data为null");
			log.error("checkTicketAvailable: object.getJSONObject(data):, "+data +" , "+ object.getString("Data"));
			return result;
		}
		String userName = data.getString("SFZ");
		if(StringUtils.isBlank(userName)){
			result.setStatus(this.STATUS_FAILURE);
			result.setMessage("从警务云系统返回data中SFZ字段为null");
			log.error("从警务云系统返回data中SFZ字段为null, "+ "data.getString(SFZ) : "+ data.getString("SFZ"));
			return result;
		}
		result.setUsername(userName);
		return result;
	}
	
	@Override
    public boolean supports(Credentials credentials) {
		return credentials.getClass() == UpsUsernameTokenCredentials.class;
    }
	
	private void loginTypeControlCheck(Integer loginType, User u) throws RemoteBadCredentialsAuthenticationException {
		//用户登录策略 如：仅对web登录和csc客户端做控制
		if(this.controlledLoginTypes != null && this.controlledLoginTypes.contains(loginType)){
			int currentOnlineNumber = userStatusService.getOnlineUserNumber(u.getName(), this.controlledLoginTypes);
			if(u.getOnlineNumber() > 0 && u.getOnlineNumber() <= currentOnlineNumber){ //0表示不限, 如果在线数有限制，并且在线数等于可在线数
				if(u.getTickable() == UpsConstants.USER_LOGIN_STRATEGY_TICKABLE){
					userStatusService.deleteLongestUpdateSessionId(u.getName()); //踢掉最久不操作的
				}else if(u.getOnlineNumber() == 1){ //如果可在线数为1， 即只能一处登录并且不能挤掉已登录者
					List<UserStatus> list = userStatusService.getUserStatusByLoginTypes(u.getName(), this.controlledLoginTypes);
					if( list == null || list.size() == 0 ){
						throw new RemoteBadCredentialsAuthenticationException(ErrorCodeConstants.ERROR_SYSTEM);
					}
					String[] args = new String[2];
					args[0] = list.get(0).getIp();
					args[1] = LoginType.findLoginType(list.get(0).getLoginType()).toString();
					log.debug("用户{}已在{}处使用{}登录，不能重复登录", u.getName(), args[0], args[1]);
					throw new RemoteBadCredentialsAuthenticationException(ErrorCodeConstants.ERROR_LOGIN_EXCEED);
				}else{
					log.debug("用户{}在线数已到达上限了", u.getName());
					throw new RemoteBadCredentialsAuthenticationException(ErrorCodeConstants.ERROR_USER_ONLINENUMBER_EXCEED);
				}
			}
		}
	}
	private PasswordEncoder passwordEncoder = new PlainTextPasswordEncoder();
	
	/**
     * Method to return the PasswordEncoder to be used to encode passwords.
     * 
     * @return the PasswordEncoder associated with this class.
     */
    protected final PasswordEncoder getPasswordEncoder() {
        return this.passwordEncoder;
    }
	
	/**
     * Sets the PasswordEncoder to be used with this class.
     * 
     * @param passwordEncoder the PasswordEncoder to use when encoding
     * passwords.
     */
    public final void setPasswordEncoder(final PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
    
    
    public static class RemoteBadCredentialsAuthenticationException extends BadCredentialsAuthenticationException{
		private RemoteUserResult remoteUserResult;

		public RemoteBadCredentialsAuthenticationException(String errorCode) {
			super(errorCode);
			this.remoteUserResult = buildRemoteUserResult(errorCode);
		}

		public RemoteBadCredentialsAuthenticationException(String errorCode, RemoteUserResult remoteUserResult) {
			super(errorCode);
			this.remoteUserResult = remoteUserResult;
		}

		public RemoteUserResult getRemoteUserResult() {
			return remoteUserResult;
		}

		public void setRemoteUserResult(RemoteUserResult remoteUserResult) {
			this.remoteUserResult = remoteUserResult;
		}
	}
}

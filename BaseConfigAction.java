package vision.apollo.cas.adaptors.eportal.action;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import vision.apollo.cas.adaptors.common.constants.GlobalProperties;
import vision.apollo.cas.adaptors.common.constants.SessionConstants;
import vision.apollo.cas.adaptors.common.web.AjaxResult;
import vision.apollo.cas.adaptors.common.web.BaseAction;
import vision.apollo.cas.adaptors.common.web.ReqIdLogger;
import vision.apollo.cas.adaptors.eportal.po.Dictionary;
import vision.apollo.cas.adaptors.eportal.service.BaseConfigService;
import vision.apollo.cas.adaptors.eportal.vo.BgConfig;
import vision.apollo.cas.adaptors.eportal.vo.CopyrightConfig;
import vision.apollo.cas.adaptors.eportal.vo.LogoConfig;
import vision.apollo.ups.constant.UpsConstants;
import vision.apollo.ups.domain.User;

/**
 * @author jinyunfeng3
 *
 */
@Controller
public class BaseConfigAction extends BaseAction {
	
	private static final String BASEVIEW = "/module/baseconfig/";
	
	private ReqIdLogger log = ReqIdLogger.getLogger(BaseConfigAction.class);

	@Autowired
	private BaseConfigService baseConfigService;	
	
	/**
	 * 配置管理首页
	 * @author linchanglei 2016年2月2日 下午2:10:34
	 */
	public String toManagerPage(){
		User user = (User)getSession().getAttribute(UpsConstants.USER);
		Boolean isAdmin = false;
		if (getSession().getAttribute(SessionConstants.USER_IS_ADMIN) != null) {
			isAdmin = (Boolean) getSession().getAttribute(
					SessionConstants.USER_IS_ADMIN);
		}
		if ("admin".equals(user.getName())){
			return "baseconfig-head";
		}else{
			if(isAdmin){
				return "baseconfig-head";
			}
		}
		return BASEVIEW + "index";
	}
	
	/**
	 * 显示标题设置页
	 * @param model
	 * @return
	 */
	@RequestMapping("/baseconfig-logo.action")
	public String showLogoConfig(Map<String,Object> model) {		
		try{
			LogoConfig	logoConfig = baseConfigService.getLogoConfig();
			logoConfig = baseConfigService.getLogoConfig();
			//多线路
			if(null != logoConfig){
				String img = logoConfig.getLogoImg();
				if(img != null && img.startsWith(GlobalProperties.getEPORTAL_FILEPATH())){
					img = "http://" + getRequest().getServerName() + ":" + getRequest().getServerPort() + img;
					logoConfig.setLogoImg(img);
				}
			}
			model.put("logoConfig", logoConfig);
		}catch(Exception e){
			log.error("获取头部样式配置失败：", e);
		}
		return BASEVIEW + "baseconfig-logo";
	}
	
	/**
	 * 显示背景设置页
	 * @param model
	 * @return
	 */
	@RequestMapping("/baseconfig-bg.action")
	public String showBgConfig(Map<String,Object> model) {
		BgConfig bgConfig = baseConfigService.getBgConfig();
		if(null != bgConfig){
			String img = bgConfig.getLoginBg();
			if(img != null && img.startsWith(GlobalProperties.getEPORTAL_FILEPATH())){
				img = "http://" + getRequest().getServerName() + ":" + getRequest().getServerPort() + img;
				bgConfig.setLoginBg(img);
			}
			img = bgConfig.getImgBg();
			if(img != null && img.startsWith(GlobalProperties.getEPORTAL_FILEPATH())){
				img = "http://" + getRequest().getServerName() + ":" + getRequest().getServerPort() + img;
				bgConfig.setImgBg(img);
			}
			img = bgConfig.getClientBg();
			if(img != null && img.startsWith(GlobalProperties.getEPORTAL_FILEPATH())){
				img = "http://" + getRequest().getServerName() + ":" + getRequest().getServerPort() + img;
				bgConfig.setClientBg(img);
			}
		}
		model.put("bgConfig", bgConfig);
		return BASEVIEW + "baseconfig-bg";
	}
	
	/**
	 * 显示版权设置页
	 * @return
	 */
	@RequestMapping("/baseconfig-copyright.action")
	public String showCopyrightConfig(Map<String,Object> model) {
		CopyrightConfig copyrightConfig = baseConfigService.getCopyrightConfig();
		model.put("copyrightConfig", copyrightConfig);
		return BASEVIEW + "baseconfig-copyright";
	}
	
	/**
	 * 显示字典设置页
	 * @param model
	 * @return
	 */
	@RequestMapping("/baseconfig-dict.action")
	public String showDictConfig(Map<String,Object> model){
		List<Dictionary> dictionary = new ArrayList<Dictionary>();
		dictionary = baseConfigService.getAllDict();
		model.put("dictionary",dictionary);
		return BASEVIEW + "baseconfig-dict";
	}
				
	/**
	 * 保存标题设置
	 * @param logoConfig
	 * @return
	 */
	@RequestMapping("/baseConfig!saveLogoConfig.action")
	@ResponseBody
	public AjaxResult saveLogoConfig(LogoConfig	logoConfig){
		AjaxResult ajax = new AjaxResult();
		try {
			if (logoConfig!=null){
				//icon多线路
				String icon = logoConfig.getLogoImg();
				if(icon.startsWith("http://")){
					int ids = icon.indexOf(GlobalProperties.getEPORTAL_FILEPATH());
					if(ids > -1){
						icon = icon.substring(ids, icon.length());
					}
				}
				logoConfig.setLogoImg(icon);
				baseConfigService.saveLogoConfig(logoConfig);
				setLog("保存","设置","头部样式" ,getUser().getName()+"设置头部样式");
			}
		} catch (Exception e) {
			log.error("保存头部样式失败：", e);
			ajax.setSuccess(false);
			ajax.setErrCode("2000");
			ajax.setErrMsg("保存头部样式失败!");
		}
		return ajax;
	}
	
	/**
	 * 保存背景设置
	 * @param bgConfig
	 * @return
	 */
	@RequestMapping("/baseConfig!saveBgConfig.action")
	@ResponseBody
	public AjaxResult saveBgConfig(BgConfig bgConfig) {
		AjaxResult ajax = new AjaxResult();
		try {
			if (bgConfig!=null){
				baseConfigService.saveBgConfig(bgConfig);
				setLog("保存","设置","背景样式" ,getUser().getName()+"设置背景样式");
			}
		} catch (Exception e) {
			log.error("保存背景信息失败：", e);
			ajax.setSuccess(false);
			ajax.setErrCode("2000");
			ajax.setErrMsg("保存背景信息失败！");
		}
		return ajax;
	}
	
	/**
	 * 保存版权设置
	 * @param copyrightConfig
	 * @return
	 */
	@RequestMapping("/baseConfig!saveCopyrightConfig.action")
	@ResponseBody
	public AjaxResult saveCopyrightConfig(CopyrightConfig copyrightConfig) {
		AjaxResult ajax = new AjaxResult();
		try {
			if (copyrightConfig!=null){
				baseConfigService.saveCopyrightConfig(copyrightConfig);
				setLog("保存","设置","版权信息" ,getUser().getName()+"设置版权信息");
			}
		} catch (Exception e) {
			log.error("保存版权信息失败：", e);
			ajax.setSuccess(false);
			ajax.setErrCode("2000");
			ajax.setErrMsg("保存版权信息失败！");
		}
		return ajax;
	}

	/**
	 * 保存字典项设置
	 * @param dictionary
	 * @return
	 */
	@RequestMapping("/baseConfig!saveDict.action")
	@ResponseBody
	public AjaxResult saveDict(Dictionary dictionary){
		AjaxResult ajax = new AjaxResult();
		try {
			if (dictionary != null && StringUtils.isNotBlank(dictionary.getId()) && StringUtils.isNotBlank(dictionary.getVal())){
				dictionary.setNote(dictionary.getVal());
				baseConfigService.saveDict(dictionary);
				setLog("保存","设置",dictionary.getId(),getUser().getName()+"修改字典,"+dictionary.getId()+":"+dictionary.getVal());
			}
		} catch (Exception e) {
			log.error("保存字典信息失败：", e);
			ajax.setSuccess(false);
			ajax.setErrCode("2000");
			ajax.setErrMsg("保存字典信息失败！");
		}
		return ajax;
	}
	
	@RequestMapping(value = "/test.action",method = RequestMethod.POST)
	@ResponseBody
	public Map test(HttpServletRequest request, String token) throws IOException{
		String paramToken = request.getParameter("token");
		String paramId = request.getParameter("id");
//		BufferedReader bufferedReader = request.getReader();
//
//		String str,wholeStr = "";
//		while((str = bufferedReader.readLine())!=null){
//			wholeStr+=str;
//		}
		Map<String, Object> result = new HashMap<String, Object>();
		Map<String, String> data = new HashMap<String, String>(3);
		if("5D877242155AFE74E053455C920AEF7A".equals(getToken())){//验证成功，返回用户的信息
			data.put("SFZ", "Abc123");
			data.put("USERNAME", "admin");
			data.put("DEPT", "zzzz");
			data.put("CODE", "cccc");
			result.put("Status", "1");
			result.put("Data",data);
		} else{
			data.put("message", "/test.action：请求失败，原因是xxaaa");
			result.put("Status", "0");
			result.put("Data", "请求失败，原因是xxx");
		}
		return result;
	}
	private String token = "5D877242155AFE74E053455C920AEF7A";
	public String getToken() {
		return token;
	}
	public void setToken(String token) {
		this.token = token;
	}
}

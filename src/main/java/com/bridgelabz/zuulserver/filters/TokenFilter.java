package com.bridgelabz.zuulserver.filters;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;

import com.bridgelabz.zuulserver.utility.JWTokenProvider;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

public class TokenFilter extends ZuulFilter {

	@Autowired
	private JWTokenProvider tokenProvider;

	@Override
	public boolean shouldFilter() {
		return true;
	}

	@Override
	public String filterType() {
		return "pre";
	}

	@Override
	public int filterOrder() {
		return 1;
	}

	@Override
	public Object run() {

		RequestContext ctx = RequestContext.getCurrentContext();
		HttpServletRequest request = ctx.getRequest();

		if (!request.getRequestURI().startsWith("/user/")) {
			String token = request.getHeader("Authorization");

			String userId = tokenProvider.parseJWT(token);

			ctx.addZuulRequestHeader("userId", userId);

			return "Successfully authorized";
		}
		return "";
	}

}
